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

#ifndef FOUNDATION_EVENT_CESFWK_SERVICES_INCLUDE_STATIC_SUBSCRIBER_MANAGER_H
#define FOUNDATION_EVENT_CESFWK_SERVICES_INCLUDE_STATIC_SUBSCRIBER_MANAGER_H

#include <map>
#include <string>
#include <vector>

#include "nlohmann/json.hpp"

#include "bundle_manager_helper.h"
#include "common_event_data.h"
#include "singleton.h"

namespace OHOS {
namespace EventFwk {
class StaticSubscriberManager : public DelayedSingleton<StaticSubscriberManager> {
public:
    StaticSubscriberManager();

    virtual ~StaticSubscriberManager();

    void PublishCommonEvent(const CommonEventData &data, const sptr<IRemoteObject> &service);

private:
    bool InitAllowList();
    bool InitValidSubscribers();
    void UpdateSubscriber(const CommonEventData &data);
    nlohmann::json ParseEvents(const std::string &profile);
    void AddSubscriber(const AppExecFwk::ExtensionAbilityInfo &extension);
    void AddToValidSubscribers(const std::string &eventName, const AppExecFwk::ExtensionAbilityInfo &extension);
    void AddSubscriberWithBundleName(const std::string &bundleName);
    void RemoveSubscriberWithBundleName(const std::string &bundleName);

    std::vector<std::string> subscriberList_;
    std::map<std::string, std::vector<AppExecFwk::ExtensionAbilityInfo>> validSubscribers_;
    bool hasInitAllowList_ = false;
    bool hasInitValidSubscribers_ = false;
    std::mutex subscriberMutex_;
};
}  // namespace EventFwk
}  // namespace OHOS

#endif  // FOUNDATION_EVENT_CESFWK_SERVICES_INCLUDE_STATIC_SUBSCRIBER_MANAGER_H
