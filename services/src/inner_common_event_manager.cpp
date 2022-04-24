/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "inner_common_event_manager.h"

#include "common_event_constant.h"
#include "common_event_record.h"
#include "common_event_sticky_manager.h"
#include "common_event_subscriber_manager.h"
#include "common_event_support.h"
#include "common_event_support_mapper.h"
#include "event_log_wrapper.h"
#include "ipc_skeleton.h"
#include "nlohmann/json.hpp"
#include "os_account_manager_helper.h"
#include "system_time.h"
#include "want.h"

namespace OHOS {
namespace EventFwk {
InnerCommonEventManager::InnerCommonEventManager() : controlPtr_(std::make_shared<CommonEventControlManager>()),
    staticSubscriberManager_(std::make_shared<StaticSubscriberManager>())
{}

bool InnerCommonEventManager::PublishCommonEvent(const CommonEventData &data, const CommonEventPublishInfo &publishInfo,
    const sptr<IRemoteObject> &commonEventListener, const struct tm &recordTime, const pid_t &pid, const uid_t &uid,
    const Security::AccessToken::AccessTokenID &callerToken, const int32_t &userId, const std::string &bundleName,
    const sptr<IRemoteObject> &service)
{
    EVENT_LOGI("enter %{public}s(pid = %{public}d, uid = %{public}d), event = %{public}s to userId = %{public}d",
        bundleName.c_str(), pid, uid, data.GetWant().GetAction().c_str(), userId);

    if (data.GetWant().GetAction().empty()) {
        EVENT_LOGE("the commonEventdata action is null");
        return false;
    }

    if ((!publishInfo.IsOrdered()) && (commonEventListener != nullptr)) {
        EVENT_LOGE("When publishing unordered events, the subscriber object is not required.");
        return false;
    }

    std::string action = data.GetWant().GetAction();
    bool isSystemEvent = DelayedSingleton<CommonEventSupport>::GetInstance()->IsSystemEvent(action);
    int32_t user = userId;
    bool isSubsystem = false;
    bool isSystemApp = false;
    bool isProxy = false;
    if (!CheckUserId(pid, uid, callerToken, isSubsystem, isSystemApp, isProxy, user)) {
        return false;
    }

    if (isSystemEvent) {
        EVENT_LOGI("System common event");
        if (!isSystemApp && !isSubsystem) {
            EVENT_LOGE(
                "No permission to send a system common event from %{public}s(pid = %{public}d, uid = %{public}d)"
                ", userId = %{public}d",
                bundleName.c_str(), pid, uid, userId);
            return false;
        }
    }

    if (staticSubscriberManager_ != nullptr) {
        staticSubscriberManager_->PublishCommonEvent(data, publishInfo, callerToken, user, service);
    }

    CommonEventRecord eventRecord;
    eventRecord.commonEventData = std::make_shared<CommonEventData>(data);
    eventRecord.publishInfo = std::make_shared<CommonEventPublishInfo>(publishInfo);
    eventRecord.recordTime = recordTime;
    eventRecord.pid = pid;
    eventRecord.uid = uid;
    eventRecord.userId = user;
    eventRecord.bundleName = bundleName;
    eventRecord.isSubsystem = isSubsystem;
    eventRecord.isSystemApp = isSystemApp;
    eventRecord.isProxy = isProxy;
    eventRecord.isSystemEvent = isSystemEvent;

    if (publishInfo.IsSticky()) {
        if (!ProcessStickyEvent(eventRecord, callerToken)) {
            return false;
        }
    }

    if (!controlPtr_) {
        EVENT_LOGE("CommonEventControlManager ptr is nullptr");
        return false;
    }
    controlPtr_->PublishCommonEvent(eventRecord, commonEventListener);

    std::string mappedSupport = "";
    if (DelayedSingleton<CommonEventSupportMapper>::GetInstance()->GetMappedSupport(
        eventRecord.commonEventData->GetWant().GetAction(), mappedSupport)) {
        Want want = eventRecord.commonEventData->GetWant();
        want.SetAction(mappedSupport);
        CommonEventRecord mappedEventRecord = eventRecord;
        mappedEventRecord.commonEventData->SetWant(want);
        controlPtr_->PublishCommonEvent(mappedEventRecord, commonEventListener);
    }

    return true;
}

bool InnerCommonEventManager::SubscribeCommonEvent(const CommonEventSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &commonEventListener, const struct tm &recordTime, const pid_t &pid, const uid_t &uid,
    const Security::AccessToken::AccessTokenID &callerToken, const std::string &bundleName)
{
    EVENT_LOGI("enter %{public}s(pid = %{public}d, uid = %{public}d, userId = %{public}d)",
        bundleName.c_str(), pid, uid, subscribeInfo.GetUserId());

    if (subscribeInfo.GetMatchingSkills().CountEvent() == 0) {
        EVENT_LOGE("the subscriber has no event");
        return false;
    }
    if (commonEventListener == nullptr) {
        EVENT_LOGE("InnerCommonEventManager::SubscribeCommonEvent:commonEventListener == nullptr");
        return false;
    }

    CommonEventSubscribeInfo subscribeInfo_(subscribeInfo);
    int32_t userId = subscribeInfo_.GetUserId();
    bool isSubsystem = false;
    bool isSystemApp = false;
    bool isProxy = false;
    if (!CheckUserId(pid, uid, callerToken, isSubsystem, isSystemApp, isProxy, userId)) {
        return false;
    }
    subscribeInfo_.SetUserId(userId);

    std::shared_ptr<CommonEventSubscribeInfo> sp = std::make_shared<CommonEventSubscribeInfo>(subscribeInfo_);

    // create EventRecordInfo here
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.pid = pid;
    eventRecordInfo.uid = uid;
    eventRecordInfo.bundleName = bundleName;
    eventRecordInfo.isSubsystem = isSubsystem;
    eventRecordInfo.isSystemApp = isSystemApp;
    eventRecordInfo.isProxy = isProxy;

    auto record = DelayedSingleton<CommonEventSubscriberManager>::GetInstance()->InsertSubscriber(
        sp, commonEventListener, recordTime, eventRecordInfo);

    PublishStickyEvent(sp, record);

    return true;
};

bool InnerCommonEventManager::UnsubscribeCommonEvent(const sptr<IRemoteObject> &commonEventListener)
{
    EVENT_LOGI("enter");

    if (commonEventListener == nullptr) {
        EVENT_LOGE("commonEventListener == nullptr");
        return false;
    }

    if (!controlPtr_) {
        EVENT_LOGE("CommonEventControlManager ptr is nullptr");
        return false;
    }

    std::shared_ptr<OrderedEventRecord> sp = controlPtr_->GetMatchingOrderedReceiver(commonEventListener);
    if (sp) {
        EVENT_LOGI("Unsubscribe the subscriber who is waiting to receive finish feedback");
        int code = sp->commonEventData->GetCode();
        std::string data = sp->commonEventData->GetData();
        controlPtr_->FinishReceiverAction(sp, code, data, sp->resultAbort);
    }

    DelayedSingleton<CommonEventSubscriberManager>::GetInstance()->RemoveSubscriber(commonEventListener);

    return true;
}

bool InnerCommonEventManager::GetStickyCommonEvent(const std::string &event, CommonEventData &eventData)
{
    EVENT_LOGI("enter");

    return DelayedSingleton<CommonEventStickyManager>::GetInstance()->GetStickyCommonEvent(event, eventData);
}

void InnerCommonEventManager::DumpState(const std::string &event, const int32_t &userId,
    std::vector<std::string> &state)
{
    EVENT_LOGI("enter");

    DelayedSingleton<CommonEventSubscriberManager>::GetInstance()->DumpState(event, userId, state);

    DelayedSingleton<CommonEventStickyManager>::GetInstance()->DumpState(event, userId, state);

    if (!controlPtr_) {
        EVENT_LOGE("CommonEventControlManager ptr is nullptr");
        return;
    }
    controlPtr_->DumpState(event, userId, state);

    controlPtr_->DumpHistoryState(event, userId, state);
    return;
}

void InnerCommonEventManager::FinishReceiver(
    const sptr<IRemoteObject> &proxy, const int &code, const std::string &receiverData, const bool &abortEvent)
{
    EVENT_LOGI("enter");

    if (!controlPtr_) {
        EVENT_LOGE("CommonEventControlManager ptr is nullptr");
        return;
    }

    std::shared_ptr<OrderedEventRecord> sp = controlPtr_->GetMatchingOrderedReceiver(proxy);
    if (sp) {
        controlPtr_->FinishReceiverAction(sp, code, receiverData, abortEvent);
    }

    return;
}

bool InnerCommonEventManager::Freeze(const uid_t &uid)
{
    EVENT_LOGI("enter");

    DelayedSingleton<CommonEventSubscriberManager>::GetInstance()->UpdateFreezeInfo(
        uid, true, SystemTime::GetNowSysTime());

    return true;
}

bool InnerCommonEventManager::Unfreeze(const uid_t &uid)
{
    EVENT_LOGI("enter");

    DelayedSingleton<CommonEventSubscriberManager>::GetInstance()->UpdateFreezeInfo(uid, false);

    if (!controlPtr_) {
        EVENT_LOGE("CommonEventControlManager ptr is nullptr");
        return false;
    }
    return controlPtr_->PublishFreezeCommonEvent(uid);
}

bool InnerCommonEventManager::ProcessStickyEvent(
    const CommonEventRecord &record, const Security::AccessToken::AccessTokenID &callerToken)
{
    EVENT_LOGI("enter");
    const std::string permission = "ohos.permission.COMMONEVENT_STICKY";
    ErrCode result = AccessTokenHelper::VerifyAccessToken(callerToken, permission);
    // Only subsystems and system apps with permissions can publish sticky common events
    if ((!result && record.isSystemApp) || (!record.isProxy && record.isSubsystem)) {
        DelayedSingleton<CommonEventStickyManager>::GetInstance()->UpdateStickyEvent(record);
        return true;
    } else {
        EVENT_LOGE("No permission to send a sticky common event from %{public}s (pid = %{public}d, uid = %{public}d)",
            record.bundleName.c_str(), record.pid, record.uid);
        return false;
    }
}

bool InnerCommonEventManager::CheckUserId(const pid_t &pid, const uid_t &uid,
    const Security::AccessToken::AccessTokenID &callerToken, bool &isSubsystem, bool &isSystemApp, bool &isProxy,
    int32_t &userId)
{
    EVENT_LOGI("enter");

    if (userId < UNDEFINED_USER) {
        EVENT_LOGE("Invalid User ID %{public}d", userId);
        return false;
    }

    isSubsystem = AccessTokenHelper::VerifyNativeToken(callerToken);
    if (!isSubsystem) {
        isSystemApp = DelayedSingleton<BundleManagerHelper>::GetInstance()->CheckIsSystemAppByUid(uid);
    }

    isProxy = pid == UNDEFINED_PID;
    if ((isSystemApp || isSubsystem) && !isProxy) {
        if (userId == CURRENT_USER) {
            DelayedSingleton<OsAccountManagerHelper>::GetInstance()->GetOsAccountLocalIdFromUid(uid, userId);
        } else if (userId == UNDEFINED_USER) {
            userId = ALL_USER;
        }
    } else {
        if (userId == UNDEFINED_USER) {
            DelayedSingleton<OsAccountManagerHelper>::GetInstance()->GetOsAccountLocalIdFromUid(uid, userId);
        } else {
            EVENT_LOGE("No permission to subscribe or send a common event to another user from uid = %{public}d", uid);
            return false;
        }
    }

    return true;
}

bool InnerCommonEventManager::PublishStickyEvent(
    const std::shared_ptr<CommonEventSubscribeInfo> &sp, const std::shared_ptr<EventSubscriberRecord> &subscriberRecord)
{
    EVENT_LOGI("enter");

    if (!sp) {
        EVENT_LOGI("sp is null");
        return false;
    }

    if (!subscriberRecord) {
        EVENT_LOGI("subscriberRecord is null");
        return false;
    }

    std::vector<std::shared_ptr<CommonEventRecord>> commonEventRecords;
    if (DelayedSingleton<CommonEventStickyManager>::GetInstance()->FindStickyEvents(sp, commonEventRecords)) {
        return false;
    }

    for (auto commonEventRecord : commonEventRecords) {
        if (!commonEventRecord) {
            EVENT_LOGW("commonEventRecord is nullptr and get next");
            continue;
        }
        EVENT_LOGI("publish sticky event : %{public}s",
            commonEventRecord->commonEventData->GetWant().GetAction().c_str());
        commonEventRecord->publishInfo->SetOrdered(false);
        if (!controlPtr_) {
            EVENT_LOGE("CommonEventControlManager ptr is nullptr");
            return false;
        }
        controlPtr_->PublishStickyCommonEvent(*commonEventRecord, subscriberRecord);
    }

    return true;
}
}  // namespace EventFwk
}  // namespace OHOS
