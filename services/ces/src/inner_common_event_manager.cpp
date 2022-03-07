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

#include "ability_manager_helper.h"
#include "bundle_manager_helper.h"
#include "common_event_constant.h"
#include "common_event_sticky_manager.h"
#include "common_event_subscriber_manager.h"
#include "common_event_support.h"
#include "common_event_support_mapper.h"
#include "event_log_wrapper.h"
#include "ipc_skeleton.h"
#include "nlohmann/json.hpp"
#include "os_account_manager.h"
#include "system_time.h"
#include "want.h"

namespace OHOS {
namespace EventFwk {
constexpr static char JSON_KEY_COMMON_EVENTS[] = "commonEvents";
constexpr static char JSON_KEY_EVENTS[] = "events";

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

    PublishEventToStaticSubscribers(data, service);

    if ((!publishInfo.IsOrdered()) && (commonEventListener != nullptr)) {
        EVENT_LOGE("When publishing unordered events, the subscriber object is not required.");
        return false;
    }

    std::string action = data.GetWant().GetAction();
    bool isSystemEvent = DelayedSingleton<CommonEventSupport>::GetInstance()->IsSystemEvent(action);
    int32_t userId_ = userId;
    bool isSubsystem = false;
    bool isSystemApp = false;
    bool isProxy = false;
    if (!CheckUserId(pid, uid, callerToken, isSubsystem, isSystemApp, isProxy, userId_)) {
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

    CommonEventRecord eventRecord;
    eventRecord.commonEventData = std::make_shared<CommonEventData>(data);
    eventRecord.publishInfo = std::make_shared<CommonEventPublishInfo>(publishInfo);
    eventRecord.recordTime = recordTime;
    eventRecord.pid = pid;
    eventRecord.uid = uid;
    eventRecord.userId = userId_;
    eventRecord.bundleName = bundleName;
    eventRecord.isSubsystem = isSubsystem;
    eventRecord.isSystemApp = isSystemApp;
    eventRecord.isProxy = isProxy;
    eventRecord.isSystemEvent = isSystemEvent;

    if (publishInfo.IsSticky()) {
        if (!ProcessStickyEvent(eventRecord)) {
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

void InnerCommonEventManager::PublishEventToStaticSubscribers(const CommonEventData &data,
                                                              const sptr<IRemoteObject> &service)
{
    EVENT_LOGI("enter");

    if (staticSubscriberManager_ == nullptr) {
        EVENT_LOGE("staticSubscriberManager_ == nullptr!");
        return;
    }

    std::vector<AppExecFwk::ExtensionAbilityInfo> extensions;
    // get all static subscriber type extensions
    if (!DelayedSingleton<BundleManagerHelper>::GetInstance()->QueryExtensionInfos(extensions)) {
        EVENT_LOGE("QueryExtensionByWant failed");
        return;
    }
    // filter legel extensions and connect them
    for (auto extension : extensions) {
        if (!staticSubscriberManager_->IsStaticSubscriber(extension.bundleName)) {
            continue;
        }
        EVENT_LOGI("find legel extension,bundlename = %{public}s", extension.bundleName.c_str());
        std::vector<std::string> profileInfos;
        if (!DelayedSingleton<BundleManagerHelper>::GetInstance()->GetResConfigFile(extension, profileInfos)) {
            EVENT_LOGE("GetProfile failed");
            return;
        }

        for (auto profile : profileInfos) {
            nlohmann::json jsonObj = nlohmann::json::parse(profile, nullptr, false);
            nlohmann::json commonEventObj = jsonObj[JSON_KEY_COMMON_EVENTS];
            if (commonEventObj.empty()) {
                EVENT_LOGW("invalid common event obj size");
                continue;
            }
            nlohmann::json eventsObj = commonEventObj[0][JSON_KEY_EVENTS];
            if (eventsObj.empty()) {
                EVENT_LOGW("invalid event obj size");
                continue;
            }
            for (auto e : eventsObj) {
                if (e.get<std::string>() == data.GetWant().GetAction()) {
                    Want want;
                    want.SetElementName(extension.bundleName, extension.name);
                    EVENT_LOGI("Ready to connect to extension %{public}s in bundle %{public}s",
                        extension.name.c_str(), extension.bundleName.c_str());
                    DelayedSingleton<AbilityManagerHelper>::GetInstance()->ConnectAbility(want, data, service);
                    break;
                }
            }
        }
    }
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

    DelayedSingleton<CommonEventSubscriberManager>::GetInstance()->InsertSubscriber(
        sp, commonEventListener, recordTime, eventRecordInfo);

    return true;
};

bool InnerCommonEventManager::UnsubscribeCommonEvent(sptr<IRemoteObject> &commonEventListener)
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

bool InnerCommonEventManager::ProcessStickyEvent(const CommonEventRecord &record)
{
    EVENT_LOGI("enter");
    const std::string permission = "ohos.permission.COMMONEVENT_STICKY";
    bool ret = DelayedSingleton<BundleManagerHelper>::GetInstance()->CheckPermission(record.bundleName, permission);
    // Only subsystems and system apps with permissions can publish sticky common events
    if ((ret && record.isSystemApp) || (!record.isProxy && record.isSubsystem)) {
        DelayedSingleton<CommonEventStickyManager>::GetInstance()->UpdateStickyEvent(record);
        ret = true;
    } else {
        EVENT_LOGE("No permission to send a sticky common event from %{public}s (pid = %{public}d, uid = %{public}d)",
            record.bundleName.c_str(), record.pid, record.uid);
    }
    return ret;
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
            AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, userId);
        } else if (userId == UNDEFINED_USER) {
            userId = ALL_USER;
        }
    } else {
        if (userId == UNDEFINED_USER) {
            AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, userId);
        } else {
            EVENT_LOGE("No permission to subscribe or send a common event to another user from uid = %{public}d", uid);
            return false;
        }
    }

    return true;
}
}  // namespace EventFwk
}  // namespace OHOS
