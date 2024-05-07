/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "static_subscriber_manager.h"

#include <fstream>
#include <set>

#include "ability_manager_helper.h"
#include "access_token_helper.h"
#include "bundle_manager_helper.h"
#include "ces_inner_error_code.h"
#include "common_event_constant.h"
#include "common_event_support.h"
#include "event_log_wrapper.h"
#include "event_report.h"
#include "hitrace_meter_adapter.h"
#include "ipc_skeleton.h"
#include "os_account_manager_helper.h"
#include "static_subscriber_data_manager.h"

namespace OHOS {
namespace EventFwk {
namespace {
const std::string CONFIG_APPS = "apps";
constexpr static char JSON_KEY_COMMON_EVENTS[] = "commonEvents";
constexpr static char JSON_KEY_NAME[] = "name";
constexpr static char JSON_KEY_PERMISSION[] = "permission";
constexpr static char JSON_KEY_EVENTS[] = "events";
}

StaticSubscriberManager::StaticSubscriberManager() {}

StaticSubscriberManager::~StaticSubscriberManager() {}

bool StaticSubscriberManager::InitAllowList()
{
    EVENT_LOGD("enter");

    std::vector<AppExecFwk::ApplicationInfo> appInfos {};
    if (!DelayedSingleton<BundleManagerHelper>::GetInstance()
            ->GetApplicationInfos(AppExecFwk::ApplicationFlag::GET_BASIC_APPLICATION_INFO, appInfos)) {
        EVENT_LOGE("GetApplicationInfos failed");
        return false;
    }

    for (auto const &appInfo : appInfos) {
        std::vector<std::string> allowCommonEvents = appInfo.allowCommonEvent;
        std::string bundleName = appInfo.bundleName;
        for (auto e : allowCommonEvents) {
            if (staticSubscribers_.find(bundleName) == staticSubscribers_.end()) {
                std::set<std::string> s = {};
                s.emplace(e);
                StaticSubscriber subscriber = { .events = s};
                staticSubscribers_.insert(std::make_pair(bundleName, subscriber));
            } else {
                staticSubscribers_[bundleName].events.emplace(e);
            }
        }
    }

    hasInitAllowList_ = true;
    return true;
}

bool StaticSubscriberManager::InitValidSubscribers()
{
    EVENT_LOGD("enter");

    if (!validSubscribers_.empty()) {
        validSubscribers_.clear();
    }
    if (!disableEvents_.empty()) {
        disableEvents_.clear();
    }
    std::set<std::string> bundleList;
    DelayedSingleton<StaticSubscriberDataManager>::GetInstance()->
        QueryStaticSubscriberStateData(disableEvents_, bundleList);

    std::vector<AppExecFwk::ExtensionAbilityInfo> extensions;
    // get all static subscriber type extensions
    if (!DelayedSingleton<BundleManagerHelper>::GetInstance()->QueryExtensionInfos(extensions)) {
        EVENT_LOGE("QueryExtensionInfos failed");
        return false;
    }
    // filter legal extensions and add them to valid map
    for (auto extension : extensions) {
        if (staticSubscribers_.find(extension.bundleName) == staticSubscribers_.end()) {
            continue;
        }
        EVENT_LOGD("find legal extension, bundlename = %{public}s", extension.bundleName.c_str());
        AddSubscriber(extension);
    }

    if (bundleList.empty()) {
        hasInitValidSubscribers_ = true;
        return true;
    }

    for (auto bundleName : bundleList) {
        auto finder = staticSubscribers_.find(bundleName);
        if (finder != staticSubscribers_.end()) {
            std::vector<std::string> events;
            for (auto &event : finder->second.events) {
                events.emplace_back(event);
            }
            disableEvents_.emplace(bundleName, events);
        }
    }
    DelayedSingleton<StaticSubscriberDataManager>::GetInstance()->UpdateStaticSubscriberState(disableEvents_);
    hasInitValidSubscribers_ = true;
    return true;
}

bool StaticSubscriberManager::IsDisableEvent(const std::string &bundleName, const std::string &event)
{
    EVENT_LOGD("Called.");
    auto bundleIt = disableEvents_.find(bundleName);
    if (bundleIt == disableEvents_.end()) {
        return false;
    }
    auto eventIt = std::find(bundleIt->second.begin(), bundleIt->second.end(), event);
    if (eventIt != bundleIt->second.end()) {
        return true;
    }
    return false;
}

void StaticSubscriberManager::PublishCommonEventConnecAbility(const CommonEventData &data,
    const sptr<IRemoteObject> &service, const int32_t &userId,
    const std::string &bundleName, const std::string &abilityName)
{
    AAFwk::Want want;
    want.SetElementName(bundleName, abilityName);
    EVENT_LOGD("Ready to connect to subscriber %{public}s in bundle %{public}s",
        abilityName.c_str(), bundleName.c_str());
    DelayedSingleton<AbilityManagerHelper>::GetInstance()->ConnectAbility(want, data, service, userId);
    SendStaticSubscriberStartHiSysEvent(userId, abilityName, bundleName, data.GetWant().GetAction());
}

void StaticSubscriberManager::PublishCommonEventInner(const CommonEventData &data,
    const CommonEventPublishInfo &publishInfo, const Security::AccessToken::AccessTokenID &callerToken,
    const int32_t &userId, const sptr<IRemoteObject> &service, const std::string &bundleName)
{
    auto targetSubscribers = validSubscribers_.find(data.GetWant().GetAction());
    if (targetSubscribers != validSubscribers_.end()) {
        for (auto subscriber : targetSubscribers->second) {
            EVENT_LOGI("subscriber.userId = %{public}d, userId = %{public}d, event = %{public}s", subscriber.userId,
                userId, data.GetWant().GetAction().c_str());
            if (IsDisableEvent(subscriber.bundleName, targetSubscribers->first)) {
                EVENT_LOGD("Current subscriber is disable, subscriber.userId = %{public}d.", subscriber.userId);
                SendStaticEventProcErrHiSysEvent(
                    userId, bundleName, subscriber.bundleName, data.GetWant().GetAction());
                continue;
            }
            if (subscriber.userId < SUBSCRIBE_USER_SYSTEM_BEGIN) {
                EVENT_LOGW("subscriber userId is invalid, subscriber.userId = %{public}d", subscriber.userId);
                SendStaticEventProcErrHiSysEvent(userId, bundleName, subscriber.bundleName, data.GetWant().GetAction());
                continue;
            }
            if ((subscriber.userId > SUBSCRIBE_USER_SYSTEM_END) && (userId != ALL_USER)
                && (subscriber.userId != userId)) {
                EVENT_LOGW("subscriber userId is not match, subscriber.userId = %{public}d, userId = %{public}d",
                    subscriber.userId, userId);
                SendStaticEventProcErrHiSysEvent(userId, bundleName, subscriber.bundleName, data.GetWant().GetAction());
                continue;
            }
            // judge if app is system app.
            if (!DelayedSingleton<BundleManagerHelper>::GetInstance()->
                CheckIsSystemAppByBundleName(subscriber.bundleName, subscriber.userId)) {
                EVENT_LOGW("subscriber is not system app, not allow.");
                continue;
            }
            if (!VerifyPublisherPermission(callerToken, subscriber.permission)) {
                EVENT_LOGW("publisher does not have required permission %{public}s", subscriber.permission.c_str());
                SendStaticEventProcErrHiSysEvent(userId, bundleName, subscriber.bundleName, data.GetWant().GetAction());
                continue;
            }
            if (!VerifySubscriberPermission(subscriber.bundleName, subscriber.userId,
                publishInfo.GetSubscriberPermissions())) {
                EVENT_LOGW("subscriber does not have required permissions");
                SendStaticEventProcErrHiSysEvent(userId, bundleName, subscriber.bundleName, data.GetWant().GetAction());
                continue;
            }
            if (!publishInfo.GetBundleName().empty() && subscriber.bundleName != publishInfo.GetBundleName()) {
                EVENT_LOGW("subscriber bundleName is not match, subscriber.bundleName = %{public}s, "
                    "bundleName = %{public}s", subscriber.bundleName.c_str(), publishInfo.GetBundleName().c_str());
                continue;
            }
            PublishCommonEventConnecAbility(data, service, subscriber.userId, subscriber.bundleName, subscriber.name);
        }
    }
}

void StaticSubscriberManager::PublishCommonEvent(const CommonEventData &data,
    const CommonEventPublishInfo &publishInfo, const Security::AccessToken::AccessTokenID &callerToken,
    const int32_t &userId, const sptr<IRemoteObject> &service, const std::string &bundleName)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    EVENT_LOGD("enter, event = %{public}s, userId = %{public}d", data.GetWant().GetAction().c_str(), userId);

    std::lock_guard<std::mutex> lock(subscriberMutex_);
    if (!hasInitAllowList_ && !InitAllowList()) {
        EVENT_LOGE("failed to init subscriber list");
        return;
    }

    if ((!hasInitValidSubscribers_ ||
        data.GetWant().GetAction() == CommonEventSupport::COMMON_EVENT_BOOT_COMPLETED ||
        data.GetWant().GetAction() == CommonEventSupport::COMMON_EVENT_LOCKED_BOOT_COMPLETED ||
        data.GetWant().GetAction() == CommonEventSupport::COMMON_EVENT_USER_SWITCHED ||
        data.GetWant().GetAction() == CommonEventSupport::COMMON_EVENT_UID_REMOVED ||
        data.GetWant().GetAction() == CommonEventSupport::COMMON_EVENT_USER_STARTED) &&
        !InitValidSubscribers()) {
        EVENT_LOGE("failed to init Init valid subscribers map!");
        return;
    }

    UpdateSubscriber(data);

    PublishCommonEventInner(data, publishInfo, callerToken, userId, service, bundleName);
}

bool StaticSubscriberManager::VerifyPublisherPermission(const Security::AccessToken::AccessTokenID &callerToken,
    const std::string &permission)
{
    EVENT_LOGD("enter");
    if (permission.empty()) {
        EVENT_LOGD("no need permission");
        return true;
    }
    return AccessTokenHelper::VerifyAccessToken(callerToken, permission);
}

bool StaticSubscriberManager::VerifySubscriberPermission(const std::string &bundleName, const int32_t &userId,
    const std::vector<std::string> &permissions)
{
    // get hap tokenid with default instindex(0), this should be modified later.
    Security::AccessToken::AccessTokenID tokenId = AccessTokenHelper::GetHapTokenID(userId, bundleName, 0);
    for (auto permission : permissions) {
        if (permission.empty()) {
            continue;
        }
        if (!AccessTokenHelper::VerifyAccessToken(tokenId, permission)) {
            EVENT_LOGW("subscriber does not have required permission : %{public}s", permission.c_str());
            return false;
        }
    }
    return true;
}

void StaticSubscriberManager::ParseEvents(const std::string &extensionName, const std::string &extensionBundleName,
    const int32_t &extensionUserId, const std::string &profile, bool enable)
{
    EVENT_LOGD("enter, subscriber name = %{public}s, bundle name = %{public}s, userId = %{public}d",
        extensionName.c_str(), extensionBundleName.c_str(), extensionUserId);
    
    if (profile.empty()) {
        EVENT_LOGE("invalid profile");
        return;
    }
    if (!nlohmann::json::accept(profile.c_str())) {
        EVENT_LOGE("invalid format profile");
        return;
    }

    nlohmann::json jsonObj = nlohmann::json::parse(profile, nullptr, false);
    if (jsonObj.is_null() || jsonObj.empty()) {
        EVENT_LOGE("invalid jsonObj");
        return;
    }
    nlohmann::json commonEventsObj = jsonObj[JSON_KEY_COMMON_EVENTS];
    if (commonEventsObj.is_null() || !commonEventsObj.is_array() || commonEventsObj.empty()) {
        EVENT_LOGE("invalid common event obj size");
        return;
    }
    for (auto commonEventObj : commonEventsObj) {
        if (commonEventObj.is_null() || !commonEventObj.is_object()) {
            EVENT_LOGW("invalid common event obj");
            continue;
        }
        if (commonEventObj[JSON_KEY_NAME].is_null() || !commonEventObj[JSON_KEY_NAME].is_string()) {
            EVENT_LOGW("invalid common event ability name obj");
            continue;
        }
        if (commonEventObj[JSON_KEY_NAME].get<std::string>() != extensionName) {
            EVENT_LOGW("extensionName is not match");
            continue;
        }
        if (commonEventObj[JSON_KEY_PERMISSION].is_null() || !commonEventObj[JSON_KEY_PERMISSION].is_string()) {
            EVENT_LOGW("invalid permission obj");
            continue;
        }
        if (commonEventObj[JSON_KEY_EVENTS].is_null() || !commonEventObj[JSON_KEY_EVENTS].is_array() ||
            commonEventObj[JSON_KEY_EVENTS].empty()) {
            EVENT_LOGW("invalid events obj");
            continue;
        }

        for (auto e : commonEventObj[JSON_KEY_EVENTS]) {
            if (e.is_null() || !e.is_string() ||
                (staticSubscribers_[extensionBundleName].events.find(e) ==
                    staticSubscribers_[extensionBundleName].events.end())) {
                EVENT_LOGW("invalid event obj");
                continue;
            }
            StaticSubscriberInfo subscriber = { .name = extensionName,
                .bundleName = extensionBundleName,
                .userId = extensionUserId,
                .permission = commonEventObj[JSON_KEY_PERMISSION].get<std::string>()};
            AddToValidSubscribers(e.get<std::string>(), subscriber);
        }
    }
}

void StaticSubscriberManager::AddSubscriber(const AppExecFwk::ExtensionAbilityInfo &extension)
{
    EVENT_LOGD("enter, subscriber bundlename = %{public}s", extension.bundleName.c_str());

    std::vector<std::string> profileInfos;
    if (!DelayedSingleton<BundleManagerHelper>::GetInstance()->GetResConfigFile(extension, profileInfos)) {
        EVENT_LOGE("GetProfile failed");
        return;
    }
    for (auto profile : profileInfos) {
        int32_t userId = -1;
        if (DelayedSingleton<OsAccountManagerHelper>::GetInstance()->GetOsAccountLocalIdFromUid(
            extension.applicationInfo.uid, userId) != ERR_OK) {
            EVENT_LOGE("GetOsAccountLocalIdFromUid failed, uid = %{public}d", extension.applicationInfo.uid);
            return;
        }
        ParseEvents(extension.name, extension.bundleName, userId, profile);
    }
}

void StaticSubscriberManager::AddToValidSubscribers(const std::string &eventName,
    const StaticSubscriberInfo &subscriber)
{
    if (validSubscribers_.find(eventName) != validSubscribers_.end()) {
        for (auto sub : validSubscribers_[eventName]) {
            if ((sub.name == subscriber.name) &&
                (sub.bundleName == subscriber.bundleName) &&
                (sub.userId == subscriber.userId)) {
                EVENT_LOGD("subscriber already exist, event = %{public}s, bundlename = %{public}s, name = %{public}s,"
                    "userId = %{public}d", eventName.c_str(), subscriber.bundleName.c_str(), subscriber.name.c_str(),
                    subscriber.userId);
                return;
            }
        }
    }
    validSubscribers_[eventName].emplace_back(subscriber);
    EVENT_LOGD("subscriber added, event = %{public}s, bundlename = %{public}s, name = %{public}s, userId = %{public}d",
        eventName.c_str(), subscriber.bundleName.c_str(), subscriber.name.c_str(), subscriber.userId);
}

void StaticSubscriberManager::AddSubscriberWithBundleName(const std::string &bundleName, const int32_t &userId)
{
    EVENT_LOGD("enter, bundleName = %{public}s, userId = %{public}d", bundleName.c_str(), userId);

    std::vector<AppExecFwk::ExtensionAbilityInfo> extensions;
    if (!DelayedSingleton<BundleManagerHelper>::GetInstance()->QueryExtensionInfos(extensions, userId)) {
        EVENT_LOGE("QueryExtensionInfos failed");
        return;
    }

    for (auto extension : extensions) {
        if ((extension.bundleName == bundleName) &&
            staticSubscribers_.find(extension.bundleName) != staticSubscribers_.end()) {
            AddSubscriber(extension);
        }
    }
}

void StaticSubscriberManager::RemoveSubscriberWithBundleName(const std::string &bundleName, const int32_t &userId)
{
    EVENT_LOGD("enter, bundleName = %{public}s, userId = %{public}d", bundleName.c_str(), userId);

    for (auto it = validSubscribers_.begin(); it != validSubscribers_.end();) {
        auto subIt = it->second.begin();
        while (subIt != it->second.end()) {
            if ((subIt->bundleName == bundleName) && (subIt->userId == userId)) {
                EVENT_LOGD("remove subscriber, event = %{public}s, bundlename = %{public}s, userId = %{public}d",
                    it->first.c_str(), bundleName.c_str(), userId);
                subIt = it->second.erase(subIt);
            } else {
                subIt++;
            }
        }
        if (it->second.empty()) {
            validSubscribers_.erase(it++);
        } else {
            it++;
        }
    }

    auto bundleIt = disableEvents_.find(bundleName);
    if (bundleIt == disableEvents_.end()) {
        EVENT_LOGD("Bundle name is not existed.");
        return;
    }
    disableEvents_.erase(bundleIt);
    auto result =
        DelayedSingleton<StaticSubscriberDataManager>::GetInstance()->DeleteDisableEventElementByBundleName(bundleName);
    if (result != ERR_OK) {
        EVENT_LOGE("Remove disable event by bundle name failed.");
    }
}

void StaticSubscriberManager::UpdateSubscriber(const CommonEventData &data)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    EVENT_LOGD("enter");

    if ((data.GetWant().GetAction() != CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED) &&
        (data.GetWant().GetAction() != CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED) &&
        (data.GetWant().GetAction() != CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED)) {
        EVENT_LOGD("no need to update map");
        return;
    }

    std::string bundleName = data.GetWant().GetElement().GetBundleName();
    int32_t uid = data.GetWant().GetIntParam(AppExecFwk::Constants::UID, -1);
    int32_t userId = -1;
    if (DelayedSingleton<OsAccountManagerHelper>::GetInstance()->GetOsAccountLocalIdFromUid(uid, userId) != ERR_OK) {
        EVENT_LOGW("GetOsAccountLocalIdFromUid failed, uid = %{public}d", uid);
        return;
    }
    std::vector<int> osAccountIds;
    if (DelayedSingleton<OsAccountManagerHelper>::GetInstance()->QueryActiveOsAccountIds(osAccountIds) != ERR_OK) {
        EVENT_LOGW("failed to QueryActiveOsAccountIds!");
        return;
    }
    if (find(osAccountIds.begin(), osAccountIds.end(), userId) == osAccountIds.end()) {
        EVENT_LOGW("userId is not active, no need to update.");
        return;
    }
    EVENT_LOGD("active uid = %{public}d, userId = %{public}d", uid, userId);
    if (data.GetWant().GetAction() == CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED) {
        EVENT_LOGD("UpdateSubscribersMap bundle %{public}s ready to add", bundleName.c_str());
        AddSubscriberWithBundleName(bundleName, userId);
    } else if (data.GetWant().GetAction() == CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED) {
        EVENT_LOGD("UpdateSubscribersMap bundle %{public}s ready to remove", bundleName.c_str());
        RemoveSubscriberWithBundleName(bundleName, userId);
    } else {
        EVENT_LOGD("UpdateSubscribersMap bundle %{public}s ready to update", bundleName.c_str());
        RemoveSubscriberWithBundleName(bundleName, userId);
        AddSubscriberWithBundleName(bundleName, userId);
    }
}

void StaticSubscriberManager::SendStaticEventProcErrHiSysEvent(int32_t userId, const std::string &publisherName,
    const std::string &subscriberName, const std::string &eventName)
{
    EventInfo eventInfo;
    eventInfo.userId = userId;
    eventInfo.publisherName = publisherName;
    eventInfo.subscriberName = subscriberName;
    eventInfo.eventName = eventName;
    EventReport::SendHiSysEvent(STATIC_EVENT_PROC_ERROR, eventInfo);
}

void StaticSubscriberManager::SendStaticSubscriberStartHiSysEvent(int32_t userId, const std::string &publisherName,
    const std::string &subscriberName, const std::string &eventName)
{
    EventInfo eventInfo;
    eventInfo.userId = userId;
    eventInfo.publisherName = publisherName;
    eventInfo.subscriberName = subscriberName;
    eventInfo.eventName = eventName;
    EventReport::SendHiSysEvent(STATIC_SUBSCRIBER_START, eventInfo);
}

int32_t StaticSubscriberManager::UpdateDisableEvents(
    const std::string &bundleName, const std::vector<std::string> &events, bool enable)
{
    EVENT_LOGD("Called.");
    auto finder = disableEvents_.find(bundleName);
    if (finder == disableEvents_.end()) {
        if (!enable) {
            disableEvents_.emplace(bundleName, events);
        }
        return DelayedSingleton<StaticSubscriberDataManager>::GetInstance()->
            UpdateStaticSubscriberState(disableEvents_);
    }

    for (auto &event : events) {
        auto &currentEvents = finder->second;
        auto iter = std::find(currentEvents.begin(), currentEvents.end(), event);
        if (enable) {
            if (iter == currentEvents.end()) {
                continue;
            }
            if (iter != currentEvents.end()) {
                currentEvents.erase(iter);
            }
        } else {
            if (iter == currentEvents.end()) {
                currentEvents.emplace_back(event);
            }
        }
    }

    if (finder->second.empty()) {
        disableEvents_.erase(finder);
    }

    return DelayedSingleton<StaticSubscriberDataManager>::GetInstance()->UpdateStaticSubscriberState(disableEvents_);
}

int32_t StaticSubscriberManager::SetStaticSubscriberState(bool enable)
{
    EVENT_LOGD("Called.");
    auto bundleName =
        DelayedSingleton<BundleManagerHelper>::GetInstance()->GetBundleName(IPCSkeleton::GetCallingUid());
    auto staticSubscriberEvent = staticSubscribers_.find(bundleName);
    if (staticSubscriberEvent == staticSubscribers_.end()) {
        EVENT_LOGE("Cannot find static subscriber bundle name.");
        return ERR_INVALID_OPERATION;
    }
    std::vector<std::string> events;
    for (const auto &event : staticSubscriberEvent->second.events) {
        events.emplace_back(event);
    }
    return UpdateDisableEvents(bundleName, events, enable);
}

int32_t StaticSubscriberManager::SetStaticSubscriberState(const std::vector<std::string> &events, bool enable)
{
    EVENT_LOGD("Called.");
    auto bundleName =
        DelayedSingleton<BundleManagerHelper>::GetInstance()->GetBundleName(IPCSkeleton::GetCallingUid());
    return UpdateDisableEvents(bundleName, events, enable);
}
}  // namespace EventFwk
}  // namespace OHOS
