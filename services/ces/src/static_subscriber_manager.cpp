/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <iostream>
#include <fstream>

#include "ability_manager_helper.h"
#include "bundle_manager_helper.h"
#include "common_event_support.h"
#include "event_log_wrapper.h"

namespace OHOS {
namespace EventFwk {
namespace {
const std::string STATIC_SUBSCRIBER_CONFIG_FILE = "/system/etc/static_subscriber_config.json";
const std::string CONFIG_APPS = "apps";
constexpr static char JSON_KEY_COMMON_EVENTS[] = "commonEvents";
constexpr static char JSON_KEY_EVENTS[] = "events";
}

StaticSubscriberManager::StaticSubscriberManager() {}

StaticSubscriberManager::~StaticSubscriberManager() {}

bool StaticSubscriberManager::InitAllowList()
{
    EVENT_LOGI("enter");

    nlohmann::json jsonObj;
    std::ifstream jfile(STATIC_SUBSCRIBER_CONFIG_FILE);
    if (!jfile.is_open()) {
        EVENT_LOGI("json file can not open");
        hasInitAllowList_ = false;
        return false;
    }
    jfile >> jsonObj;
    jfile.close();

    for (auto j : jsonObj[CONFIG_APPS]) {
        subscriberList_.emplace_back(j.get<std::string>());
    }
    hasInitAllowList_ = true;
    return true;
}

bool StaticSubscriberManager::InitValidSubscribers()
{
    EVENT_LOGI("enter");

    std::vector<AppExecFwk::ExtensionAbilityInfo> extensions;
    // get all static subscriber type extensions
    if (!DelayedSingleton<BundleManagerHelper>::GetInstance()->QueryExtensionInfos(extensions)) {
        EVENT_LOGE("QueryExtensionInfos failed");
        return false;
    }
    // filter legel extensions and connect them
    for (auto extension : extensions) {
        if (find(subscriberList_.begin(), subscriberList_.end(), extension.bundleName) == subscriberList_.end()) {
            continue;
        }
        EVENT_LOGI("find legel extension, bundlename = %{public}s", extension.bundleName.c_str());
        AddSubscriber(extension);
    }
    hasInitValidSubscribers_ = true;
    return true;
}

void StaticSubscriberManager::PublishCommonEvent(const CommonEventData &data, const sptr<IRemoteObject> &service)
{
    EVENT_LOGI("enter, event = %{public}s", data.GetWant().GetAction().c_str());

    std::lock_guard<std::mutex> lock(subscriberMutex_);
    if (!hasInitAllowList_ && !InitAllowList()) {
        EVENT_LOGE("failed to init subscriber list");
        return;
    }

    if ((!hasInitValidSubscribers_ ||
        data.GetWant().GetAction() == CommonEventSupport::COMMON_EVENT_BOOT_COMPLETED ||
        data.GetWant().GetAction() == CommonEventSupport::COMMON_EVENT_LOCKED_BOOT_COMPLETED) &&
        !InitValidSubscribers()) {
        EVENT_LOGE("failed to init Init valid subscribers map!");
        return;
    }

    UpdateSubscriber(data);

    auto targetExtensions = validSubscribers_.find(data.GetWant().GetAction());
    if (targetExtensions != validSubscribers_.end()) {
        for (auto extension : targetExtensions->second) {
            AAFwk::Want want;
            want.SetElementName(extension.bundleName, extension.name);
            EVENT_LOGI("Ready to connect to extension %{public}s in bundle %{public}s",
                extension.name.c_str(), extension.bundleName.c_str());
            DelayedSingleton<AbilityManagerHelper>::GetInstance()->ConnectAbility(want, data, service);
        }
    }
}

nlohmann::json StaticSubscriberManager::ParseEvents(const std::string &profile)
{
    EVENT_LOGI("enter");

    nlohmann::json ret;
    nlohmann::json jsonObj = nlohmann::json::parse(profile, nullptr, false);
    if (jsonObj.is_null() || jsonObj.empty()) {
        EVENT_LOGE("invalid jsonObj");
        return ret;
    }
    nlohmann::json commonEventObj = jsonObj[JSON_KEY_COMMON_EVENTS];
    if (commonEventObj.is_null() || commonEventObj.empty()) {
        EVENT_LOGE("invalid common event obj size");
        return ret;
    }
    ret = commonEventObj[0][JSON_KEY_EVENTS];
    return ret;
}

void StaticSubscriberManager::AddSubscriber(const AppExecFwk::ExtensionAbilityInfo &extension)
{
    EVENT_LOGI("enter, subscriber bundlename = %{public}s", extension.bundleName.c_str());

    std::vector<std::string> profileInfos;
    if (!DelayedSingleton<BundleManagerHelper>::GetInstance()->GetResConfigFile(extension, profileInfos)) {
        EVENT_LOGE("GetProfile failed");
        return;
    }
    for (auto profile : profileInfos) {
        nlohmann::json eventsObj = ParseEvents(profile);
        if (eventsObj.is_null()) {
            continue;
        }
        for (auto e : eventsObj) {
            AddToValidSubscribers(e.get<std::string>(), extension);
        }
    }
}

void StaticSubscriberManager::AddToValidSubscribers(const std::string &eventName,
    const AppExecFwk::ExtensionAbilityInfo &extension)
{
    if (validSubscribers_.find(eventName) != validSubscribers_.end()) {
        for (auto ext : validSubscribers_[eventName]) {
            if ((ext.bundleName == extension.bundleName) && (ext.name == extension.name)) {
                EVENT_LOGI("subscriber already exist, event = %{public}s, bundlename = %{public}s, name = %{public}s",
                    eventName.c_str(), extension.bundleName.c_str(), extension.name.c_str());
                return;
            }
        }
    }
    validSubscribers_[eventName].emplace_back(extension);
    EVENT_LOGI("validSubscribers_ added subscriber, event = %{public}s, bundlename = %{public}s, name = %{public}s",
        eventName.c_str(), extension.bundleName.c_str(), extension.name.c_str());
}

void StaticSubscriberManager::AddSubscriberWithBundleName(const std::string &bundleName)
{
    EVENT_LOGI("enter");

    std::vector<AppExecFwk::ExtensionAbilityInfo> extensions;
    if (!DelayedSingleton<BundleManagerHelper>::GetInstance()->QueryExtensionInfos(extensions)) {
        EVENT_LOGE("QueryExtensionInfos failed");
        return;
    }
    for (auto extension : extensions) {
        if ((extension.bundleName == bundleName) &&
            find(subscriberList_.begin(), subscriberList_.end(), extension.bundleName) != subscriberList_.end()) {
            AddSubscriber(extension);
        }
    }
}

void StaticSubscriberManager::RemoveSubscriberWithBundleName(const std::string &bundleName)
{
    EVENT_LOGI("enter");

    auto it = validSubscribers_.begin();
    while (it != validSubscribers_.end()) {
        auto extensionIt = it->second.begin();
        while (extensionIt != it->second.end()) {
            if (extensionIt->bundleName == bundleName) {
                EVENT_LOGI("validSubscribers_ remove subscriber, event = %{public}s, bundlename = %{public}s",
                    it->first.c_str(), bundleName.c_str());
                extensionIt = it->second.erase(extensionIt);
            } else {
                extensionIt++;
            }
        }
        it++;
    }
}

void StaticSubscriberManager::UpdateSubscriber(const CommonEventData &data)
{
    EVENT_LOGI("enter");

    if ((data.GetWant().GetAction() != CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED) &&
        (data.GetWant().GetAction() != CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED) &&
        (data.GetWant().GetAction() != CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED)) {
        EVENT_LOGI("no need to update map");
        return;
    }

    std::string bundleName = data.GetWant().GetElement().GetBundleName();

    if (data.GetWant().GetAction() == CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED) {
        EVENT_LOGI("UpdateSubscribersMap bundle %{public}s ready to add", bundleName.c_str());
        AddSubscriberWithBundleName(bundleName);
    } else if (data.GetWant().GetAction() == CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED) {
        EVENT_LOGI("UpdateSubscribersMap bundle %{public}s ready to remove", bundleName.c_str());
        RemoveSubscriberWithBundleName(bundleName);
    } else {
        EVENT_LOGI("UpdateSubscribersMap bundle %{public}s ready to update", bundleName.c_str());
        RemoveSubscriberWithBundleName(bundleName);
        AddSubscriberWithBundleName(bundleName);
    }
}
}  // namespace EventFwk
}  // namespace OHOS
