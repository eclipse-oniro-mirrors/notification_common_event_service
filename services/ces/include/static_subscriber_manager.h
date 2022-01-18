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

#include <string>
#include <vector>

#include "singleton.h"

namespace OHOS {
namespace EventFwk {
class StaticSubscriberManager : public DelayedSingleton<StaticSubscriberManager> {
public:
    StaticSubscriberManager();

    virtual ~StaticSubscriberManager() override;

    /**
     * Check whether the app is static subscriber.
     * @param bundleName the bundleName of a app.
     * @return whether the app is static subscriber or not.
     */
    bool IsStaticSubscriber(const std::string &bundleName);

private:
    bool Init();

    std::vector<std::string> subscriberList_;
    bool isInit_ = false;
};
}  // namespace EventFwk
}  // namespace OHOS

#endif  // FOUNDATION_EVENT_CESFWK_SERVICES_INCLUDE_STATIC_SUBSCRIBER_MANAGER_H
