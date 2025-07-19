/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include <mutex>
#include <set>

#include "ability_manager_helper.h"
#include "access_token_helper.h"
#include "bool_wrapper.h"
#include "bundle_manager_helper.h"
#include "ces_inner_error_code.h"
#include "common_event_constant.h"
#include "common_event_support.h"
#include "double_wrapper.h"
#include "event_log_wrapper.h"
#include "event_trace_wrapper.h"
#include "event_report.h"
#include "int_wrapper.h"
#include "ipc_skeleton.h"
#include "os_account_manager_helper.h"
#include "static_subscriber_data_manager.h"
#include "string_wrapper.h"
#include "parameters.h"

namespace OHOS {
namespace EventFwk {
namespace {
const std::string CONFIG_APPS = "apps";
constexpr static char JSON_KEY_COMMON_EVENTS[] = "commonEvents";
constexpr static char JSON_KEY_NAME[] = "name";
constexpr static char JSON_KEY_PERMISSION[] = "permission";
constexpr static char JSON_KEY_EVENTS[] = "events";
constexpr static const char* JSON_KEY_FILTER = "filter";
constexpr static const char* JSON_KEY_FILTER_EVENT = "event";
constexpr static const char* JSON_KEY_FILTER_CONDITIONS = "conditions";
constexpr static const char* JSON_KEY_FILTER_CONDITIONS_CODE = "code";
constexpr static const char* JSON_KEY_FILTER_CONDITIONS_DATA = "data";
constexpr static const char* JSON_KEY_FILTER_CONDITIONS_PARAMETERS = "parameters";
static int32_t g_bootDelayTime = OHOS::system::GetIntParameter("bootevent.boot.completed.delay", 0);
constexpr int32_t TIME_UNIT_SIZE = 1000;
}

StaticSubscriberManager::StaticSubscriberManager() {}

StaticSubscriberManager::~StaticSubscriberManager() {}

bool StaticSubscriberManager::InitAllowList()
{
    EVENT_LOGD("enter");

    std::vector<AppExecFwk::ApplicationInfo> appInfos {};
    if (!DelayedSingleton<BundleManagerHelper>::GetInstance()
            ->GetApplicationInfos(AppExecFwk::ApplicationFlag::GET_BASIC_APPLICATION_INFO, appInfos)) {
        EVENT_LOGE_LIMIT("GetApplicationInfos failed");
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
    if (!InitAllowList()) {
        EVENT_LOGE("Failed to init AllowList");
        return false;
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
            EVENT_LOGI("StaticExtension exists, but allowCommonEvent not found, bundlename = %{public}s",
                extension.bundleName.c_str());
            continue;
        }
        EVENT_LOGI("StaticExtension exists, bundlename = %{public}s", extension.bundleName.c_str());
        AddSubscriber(extension);
    }

    if (bundleList.empty()) {
        hasInitValidSubscribers_ = true;
        return true;
    }
    std::lock_guard<ffrt::mutex> lock(disableEventsMutex_);
    if (!disableEvents_.empty()) {
        disableEvents_.clear();
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
    std::lock_guard<ffrt::mutex> lock(disableEventsMutex_);
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
}

void StaticSubscriberManager::PublishCommonEventInner(const CommonEventData &data,
    const CommonEventPublishInfo &publishInfo, const Security::AccessToken::AccessTokenID &callerToken,
    const int32_t &userId, const sptr<IRemoteObject> &service, const std::string &bundleName)
{
    auto targetSubscribers = validSubscribers_.find(data.GetWant().GetAction());
    if (targetSubscribers == validSubscribers_.end()) {
        return;
    }
    std::vector<StaticSubscriberInfo> bootStartHaps {};
    for (auto subscriber : targetSubscribers->second) {
        if (IsDisableEvent(subscriber.bundleName, targetSubscribers->first)) {
            EVENT_LOGW("subscriber %{public}s is disable.", subscriber.bundleName.c_str());
            SendStaticEventProcErrHiSysEvent(userId, bundleName, subscriber.bundleName, data.GetWant().GetAction());
            continue;
        }
        if (subscriber.userId < SUBSCRIBE_USER_SYSTEM_BEGIN) {
            EVENT_LOGW("subscriber %{public}s userId is invalid, subscriber.userId = %{public}d",
                subscriber.bundleName.c_str(), subscriber.userId);
            SendStaticEventProcErrHiSysEvent(userId, bundleName, subscriber.bundleName, data.GetWant().GetAction());
            continue;
        }
        if ((subscriber.userId > SUBSCRIBE_USER_SYSTEM_END) && (userId != ALL_USER)
            && (subscriber.userId != userId)) {
            EVENT_LOGW("subscriber %{public}s userId is not match, subscriber.userId = %{public}d,"
                "userId = %{public}d", subscriber.bundleName.c_str(), subscriber.userId, userId);
            SendStaticEventProcErrHiSysEvent(userId, bundleName, subscriber.bundleName, data.GetWant().GetAction());
            continue;
        }
        if (!CheckSubscriberWhetherMatched(subscriber, publishInfo)) {
            SendStaticEventProcErrHiSysEvent(userId, bundleName, subscriber.bundleName, data.GetWant().GetAction());
            continue;
        }
        if (!VerifyPublisherPermission(callerToken, subscriber.permission)) {
            EVENT_LOGW("publisher does not have required permission %{public}s", subscriber.permission.c_str());
            SendStaticEventProcErrHiSysEvent(userId, bundleName, subscriber.bundleName, data.GetWant().GetAction());
            continue;
        }
        if (!IsFilterParameters(subscriber, data)) {
            EVENT_LOGW("subscriber filter parameters is not match, subscriber.bundleName = %{public}s",
                subscriber.bundleName.c_str());
            continue;
        }
#ifdef WATCH_EVENT_BOOT_COMPLETED_DELAY
        if (data.GetWant().GetAction() == CommonEventSupport::COMMON_EVENT_BOOT_COMPLETED) {
            bootStartHaps.push_back(subscriber);
        } else {
            PublishCommonEventConnecAbility(data, service, subscriber.userId, subscriber.bundleName, subscriber.name);
            EVENT_LOGI("ConnectAbility %{public}s end, Subscriber = %{public}s",
                data.GetWant().GetAction().c_str(), subscriber.bundleName.c_str());
        }
#else
        PublishCommonEventConnecAbility(data, service, subscriber.userId, subscriber.bundleName, subscriber.name);
        EVENT_LOGI("ConnectAbility %{public}s end, Subscriber = %{public}s", data.GetWant().GetAction().c_str(),
                   subscriber.bundleName.c_str());
#endif
    }
#ifdef WATCH_EVENT_BOOT_COMPLETED_DELAY
    if (!bootStartHaps.empty()) {
        if (!ffrt_) {
            EVENT_LOGD("ready to create ffrt");
            ffrt_ = std::make_shared<ffrt::queue>("StaticSubscriberManager");
        }

        std::function<void()> task = [bootStartHaps, data, service]() {
            for (auto subscriber : bootStartHaps) {
                StaticSubscriberManager::GetInstance()->PublishCommonEventConnecAbility(data, service,
                    subscriber.userId, subscriber.bundleName, subscriber.name);
                EVENT_LOGI("ConnectAbility %{public}s end, Subscriber = %{public}s",
                    data.GetWant().GetAction().c_str(), subscriber.bundleName.c_str());
            }
        };
        ffrt_->submit(task, ffrt::task_attr().delay(g_bootDelayTime * TIME_UNIT_SIZE));
    }
#endif
}

bool StaticSubscriberManager::CheckSubscriberBySpecifiedUids(
    const int32_t &subscriberUid, const std::vector<int32_t> &specifiedSubscriberUids)
{
    for (auto it = specifiedSubscriberUids.begin(); it != specifiedSubscriberUids.end(); ++it) {
        if (*it == subscriberUid) {
            return true;
        }
    }
    return false;
}

bool StaticSubscriberManager::CheckSubscriberWhetherMatched(
    const StaticSubscriberInfo &subscriber, const CommonEventPublishInfo &publishInfo)
{
    auto specifiedSubscriberUids = publishInfo.GetSubscriberUid();
    auto specifiedSubscriberType = publishInfo.GetSubscriberType();
    uint16_t filterSettings = publishInfo.GetFilterSettings();
    if (filterSettings == 0) {
        return true;
    }
    uint16_t checkResult = 0;
    if (!publishInfo.GetBundleName().empty() &&
        publishInfo.GetBundleName() == subscriber.bundleName) {
        checkResult |= SUBSCRIBER_FILTER_BUNDLE_INDEX;
    }
    auto isSystemApp = DelayedSingleton<BundleManagerHelper>::GetInstance()->
        CheckIsSystemAppByBundleName(subscriber.bundleName, subscriber.userId);
    bool isTypeMatched = specifiedSubscriberType == static_cast<int32_t>(SubscriberType::ALL_SUBSCRIBER_TYPE) ||
        (specifiedSubscriberType == static_cast<int32_t>(SubscriberType::SYSTEM_SUBSCRIBER_TYPE) && isSystemApp);
    if (specifiedSubscriberType != UNINITIALIZATED_SUBSCRIBER_TYPE && isTypeMatched) {
        checkResult |= SUBSCRIBER_FILTER_SUBSCRIBER_TYPE_INDEX;
    }

    auto subscriberUid = DelayedSingleton<BundleManagerHelper>::GetInstance()->
        GetDefaultUidByBundleName(subscriber.bundleName, subscriber.userId);
    if (!specifiedSubscriberUids.empty() &&
        CheckSubscriberBySpecifiedUids(static_cast<int32_t>(subscriberUid), specifiedSubscriberUids)) {
        checkResult |= SUBSCRIBER_FILTER_SUBSCRIBER_UID_INDEX;
    }
    std::vector<std::string> publisherRequiredPermissions = publishInfo.GetSubscriberPermissions();
    if (!publisherRequiredPermissions.empty() &&
        VerifySubscriberPermission(subscriber.bundleName, subscriber.userId, publisherRequiredPermissions)) {
        checkResult |= SUBSCRIBER_FILTER_PERMISSION_INDEX;
    }
    bool result = false;
    if (publishInfo.GetValidationRule() == ValidationRule::AND) {
        result = (checkResult == filterSettings);
    } else {
        result = ((checkResult & filterSettings) != 0);
    }
    if (!result) {
        EVENT_LOGW("%{public}s not matched,%{public}d_%{public}u_%{public}u", subscriber.bundleName.c_str(),
            static_cast<int32_t>(publishInfo.GetValidationRule()),
            static_cast<uint32_t>(checkResult), static_cast<uint32_t>(filterSettings));
    }
    return result;
}

void StaticSubscriberManager::PublishCommonEvent(const CommonEventData &data,
    const CommonEventPublishInfo &publishInfo, const Security::AccessToken::AccessTokenID &callerToken,
    const int32_t &userId, const sptr<IRemoteObject> &service, const std::string &bundleName)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    EVENT_LOGD("enter, event = %{public}s, userId = %{public}d", data.GetWant().GetAction().c_str(), userId);

    std::lock_guard<ffrt::mutex> lock(subscriberMutex_);
    if ((!hasInitValidSubscribers_ ||
        data.GetWant().GetAction() == CommonEventSupport::COMMON_EVENT_BOOT_COMPLETED ||
        data.GetWant().GetAction() == CommonEventSupport::COMMON_EVENT_LOCKED_BOOT_COMPLETED ||
        data.GetWant().GetAction() == CommonEventSupport::COMMON_EVENT_USER_FOREGROUND) &&
        !InitValidSubscribers()) {
        EVENT_LOGE("Failed to init subscribers");
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
    if (jsonObj.is_null() || jsonObj.empty() || !jsonObj.is_object()) {
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
            ParseFilterObject(commonEventObj[JSON_KEY_FILTER], e.get<std::string>(), subscriber);
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
            EVENT_LOGE("Get userId failed, uid = %{public}d", extension.applicationInfo.uid);
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
    std::lock_guard<ffrt::mutex> lock(disableEventsMutex_);
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
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
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
        EVENT_LOGW_LIMIT("userId is not active, no need to update.");
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

int32_t StaticSubscriberManager::UpdateDisableEvents(
    const std::string &bundleName, const std::vector<std::string> &events, bool enable)
{
    EVENT_LOGD("Called.");
    std::lock_guard<ffrt::mutex> lock(disableEventsMutex_);
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

void StaticSubscriberManager::ParseFilterObject(
    const nlohmann::json &filterObj, const std::string &eventName, StaticSubscriberInfo &subscriber)
{
    if (filterObj.is_null() || !filterObj.is_array() || filterObj.empty()) {
        EVENT_LOGD("invalid filterObj size");
        return;
    }
    for (auto filter : filterObj) {
        if (filter.is_null() || !filter.is_object()) {
            EVENT_LOGD("invalid filter");
            continue;
        }
        if (filter[JSON_KEY_FILTER_EVENT].is_null() || !filter[JSON_KEY_FILTER_EVENT].is_string()) {
            EVENT_LOGD("invalid common event ability name obj");
            continue;
        }
        if (filter[JSON_KEY_FILTER_EVENT].get<std::string>() != eventName) {
            EVENT_LOGD("eventName is not match");
            continue;
        }
        const auto &conditions = filter.find(JSON_KEY_FILTER_CONDITIONS);
        if (conditions == filter.end() || conditions->is_null() || !conditions->is_object()) {
            EVENT_LOGD("conditions null");
            continue;
        }
        ParseConditions(*conditions, eventName, subscriber);
        return;
    }
}

void StaticSubscriberManager::ParseConditions(
    const nlohmann::json &conditions, const std::string &eventName, StaticSubscriberInfo &subscriber)
{
    const auto &code = conditions.find(JSON_KEY_FILTER_CONDITIONS_CODE);
    if (code != conditions.end()) {
        if (code->is_number_integer()) {
            subscriber.filterCode = code->get<int32_t>();
        } else {
            EVENT_LOGW("event: %{public}s, the filter code only supports int32", eventName.c_str());
        }
    }

    const auto &data = conditions.find(JSON_KEY_FILTER_CONDITIONS_DATA);
    if (data != conditions.end()) {
        if (data->is_string()) {
            subscriber.filterData = data->get<std::string>();
        } else {
            EVENT_LOGW("event: %{public}s, the filter data only supports string", eventName.c_str());
        }
    }

    const auto &parameters = conditions.find(JSON_KEY_FILTER_CONDITIONS_PARAMETERS);
    if (parameters != conditions.end() && parameters->is_object()) {
        for (const auto &[paramName, paramValue] : parameters->items()) {
            AddFilterParameter(paramName, paramValue, subscriber.filterParameters);
        }
    }
}

void StaticSubscriberManager::AddFilterParameter(const std::string &paramName, const nlohmann::json &paramValue,
    std::map<std::string, ParameterType> &filterParameters)
{
    if (paramValue.is_null()) {
        EVENT_LOGW("invalid parameter: %{public}s, parameter value is null", paramName.c_str());
        return;
    }
    ParameterType parameter;
    if (paramValue.is_boolean()) {
        parameter = paramValue.get<bool>();
    } else if (paramValue.is_number_integer()) {
        parameter = paramValue.get<int32_t>();
    } else if (paramValue.is_number_float()) {
        parameter = paramValue.get<double>();
    } else if (paramValue.is_string()) {
        parameter = paramValue.get<std::string>();
    } else {
        EVENT_LOGW("invalid parameter: %{public}s. supported types are bool, number, and string", paramName.c_str());
        return;
    }
    filterParameters.insert({ paramName, parameter });
}

bool StaticSubscriberManager::IsFilterParameters(
    const StaticSubscriberInfo &staticSubscriberInfo, const CommonEventData &data) const
{
    Want want = data.GetWant();
    if (!CheckFilterCodeAndData(staticSubscriberInfo, data)) {
        return false;
    }
    if (!CheckFilterParameters(staticSubscriberInfo.filterParameters, want)) {
        return false;
    }
    return true;
}

bool StaticSubscriberManager::CheckFilterCodeAndData(
    const StaticSubscriberInfo &staticSubscriberInfo, const CommonEventData &data) const
{
    if (staticSubscriberInfo.filterCode.has_value()) {
        auto filterCode = staticSubscriberInfo.filterCode.value();
        if (filterCode != data.GetCode()) {
            EVENT_LOGW("filter code:%{public}d not equal event code:%{public}d", filterCode, data.GetCode());
            return false;
        }
    }
    if (staticSubscriberInfo.filterData.has_value()) {
        auto filterData = staticSubscriberInfo.filterData.value();
        if (filterData != data.GetData()) {
            EVENT_LOGW(
                "filter data:%{public}s not equal event data:%{public}s", filterData.c_str(), data.GetData().c_str());
            return false;
        }
    }
    return true;
}

bool StaticSubscriberManager::CheckFilterParameters(
    const std::map<std::string, ParameterType> &filterParameters, const Want &want) const
{
    for (const auto &[paramName, paramValue] : filterParameters) {
        if (!want.HasParameter(paramName)) {
            EVENT_LOGW("filter parameter: %{public}s is missing", paramName.c_str());
            return false;
        }
        if (std::holds_alternative<bool>(paramValue)) {
            if (!CheckSpecificParam(
                paramName, std::get<bool>(paramValue), want, AAFwk::IBoolean::Query, AAFwk::Boolean::Unbox)) {
                return false;
            }
        } else if (std::holds_alternative<int32_t>(paramValue)) {
            if (!CheckSpecificParam(
                paramName, std::get<int32_t>(paramValue), want, AAFwk::IInteger::Query, AAFwk::Integer::Unbox)) {
                return false;
            }
        } else if (std::holds_alternative<double>(paramValue)) {
            if (!CheckSpecificParam(
                paramName, std::get<double>(paramValue), want, AAFwk::IDouble::Query, AAFwk::Double::Unbox)) {
                return false;
            }
        } else if (std::holds_alternative<std::string>(paramValue)) {
            if (!CheckSpecificParam(
                paramName, std::get<std::string>(paramValue), want, AAFwk::IString::Query, AAFwk::String::Unbox)) {
                return false;
            }
        } else {
            EVENT_LOGW(
                "invalid parameter: %{public}s. supported types are bool, number, and string", paramName.c_str());
            return false;
        }
    }
    return true;
}

template<typename T, typename QueryFunc, typename UnboxFunc>
bool StaticSubscriberManager::CheckSpecificParam(
    const std::string &paramName, const T &paramValue, const Want &want, QueryFunc queryFunc, UnboxFunc unboxFunc) const
{
    auto* ao = queryFunc(want.GetParams().GetParam(paramName));
    if (ao == nullptr) {
        EVENT_LOGW("%{public}s ao null", paramName.c_str());
        return false;
    }
    auto wantValue = unboxFunc(ao);
    if (wantValue != paramValue) {
        EVENT_LOGW("key:%{public}s not equal want", paramName.c_str());
        return false;
    }
    return true;
}
}  // namespace EventFwk
}  // namespace OHOS
