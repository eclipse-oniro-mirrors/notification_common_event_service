/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "common_event_sticky_manager.h"
#include "common_event_subscriber_manager.h"
#include "common_event_support.h"
#include "common_event_support_mapper.h"
#include "event_log_wrapper.h"
#include "nlohmann/json.hpp"
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
    const std::string &bundleName, const sptr<IRemoteObject> &service)
{
    EVENT_LOGI("enter %{public}s(pid = %{public}d, uid = %{public}d), event = %{public}s",
        bundleName.c_str(), pid, uid, data.GetWant().GetAction().c_str());

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
    bool isSystemApp = DelayedSingleton<BundleManagerHelper>::GetInstance()->CheckIsSystemAppByUid(uid);
    if (isSystemEvent) {
        EVENT_LOGI("System common event");
        if (!isSystemApp) {
            EVENT_LOGE(
                "No permission to send a system common event from %{public}s(pid = %{public}d, uid = %{public}d)",
                bundleName.c_str(), pid, uid);
            return false;
        }
    }

    CommonEventRecord eventRecord;
    eventRecord.commonEventData = std::make_shared<CommonEventData>(data);
    eventRecord.publishInfo = std::make_shared<CommonEventPublishInfo>(publishInfo);
    eventRecord.recordTime = recordTime;
    eventRecord.pid = pid;
    eventRecord.uid = uid;
    eventRecord.bundleName = bundleName;
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

    Want want;
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensions;
    // get all static subscriber type extensions
    if (!DelayedSingleton<BundleManagerHelper>::GetInstance()->QueryExtensionInfos(want, extensions)) {
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
            int size = jsonObj[JSON_KEY_COMMON_EVENTS][JSON_KEY_EVENTS].size();
            for (int i = 0; i < size; i++) {
                if (jsonObj[JSON_KEY_COMMON_EVENTS][JSON_KEY_EVENTS][i].get<std::string>() ==
                    data.GetWant().GetAction()) {
                    want.SetElementName(extension.bundleName, extension.moduleName);
                    EVENT_LOGI("Ready to connect to extension %{public}s in bundle %{public}s",
                        extension.moduleName.c_str(), extension.bundleName.c_str());
                    DelayedSingleton<AbilityManagerHelper>::GetInstance()->ConnectAbility(want, data, service);
                    break;
                }
            }
        }
    }
}

bool InnerCommonEventManager::SubscribeCommonEvent(const CommonEventSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &commonEventListener, const struct tm &recordTime, const pid_t &pid, const uid_t &uid,
    const std::string &bundleName)
{
    EVENT_LOGI("enter %{public}s(pid = %{public}d, uid = %{public}d)", bundleName.c_str(), pid, uid);

    if (subscribeInfo.GetMatchingSkills().CountEvent() == 0) {
        EVENT_LOGE("the subscriber has no event");
        return false;
    }
    if (commonEventListener == nullptr) {
        EVENT_LOGE("InnerCommonEventManager::SubscribeCommonEvent:commonEventListener == nullptr");
        return false;
    }

    std::shared_ptr<CommonEventSubscribeInfo> sp = std::make_shared<CommonEventSubscribeInfo>(subscribeInfo);
    DelayedSingleton<CommonEventSubscriberManager>::GetInstance()->InsertSubscriber(
        sp, commonEventListener, recordTime, pid, uid, bundleName);

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

void InnerCommonEventManager::DumpState(const std::string &event, std::vector<std::string> &state)
{
    EVENT_LOGI("enter");

    DelayedSingleton<CommonEventSubscriberManager>::GetInstance()->DumpState(event, state);

    DelayedSingleton<CommonEventStickyManager>::GetInstance()->DumpState(event, state);

    if (!controlPtr_) {
        EVENT_LOGE("CommonEventControlManager ptr is nullptr");
        return;
    }
    controlPtr_->DumpState(event, state);

    controlPtr_->DumpHistoryState(event, state);
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
    const std::string permission = "ohos.permission.COMMONEVENT_STICKY";
    bool ret = DelayedSingleton<BundleManagerHelper>::GetInstance()->CheckPermission(record.bundleName, permission);
    if (!ret) {
        EVENT_LOGE("No permission to send a sticky common event from %{public}s (pid = %{public}d, uid = %{public}d)",
            record.bundleName.c_str(), record.pid, record.uid);
        return ret;
    }
    DelayedSingleton<CommonEventStickyManager>::GetInstance()->UpdateStickyEvent(record);
    return ret;
}
}  // namespace EventFwk
}  // namespace OHOS
