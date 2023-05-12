/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_COMMON_EVENT_SERVICE_INCLUDE_STATIC_SUBSCRIBER_DATA_MANAGER_H
#define BASE_NOTIFICATION_COMMON_EVENT_SERVICE_INCLUDE_STATIC_SUBSCRIBER_DATA_MANAGER_H

#include <mutex>
#include <set>
#include <string>

#include "singleton.h"

namespace OHOS {
namespace EventFwk {
class StaticSubscriberDataManager : public DelayedSingleton<StaticSubscriberDataManager> {
public:
    StaticSubscriberDataManager();

    virtual ~StaticSubscriberDataManager();

    int32_t InsertDisableStaticSubscribeData(const std::string &bundleName);

    int32_t DeleteDisableStaticSubscribeData(const std::string &bundleName);

    int32_t QueryDisableStaticSubscribeAllData(std::set<std::string> &disableStaticSubscribeAllData);

private:
    static std::mutex dataMutex_;
};
} // namespace EventFwk
} // namespace OHOS
#endif // BASE_NOTIFICATION_COMMON_EVENT_SERVICE_INCLUDE_STATIC_SUBSCRIBER_DATA_MANAGER_H