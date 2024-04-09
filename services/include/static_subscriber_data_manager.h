/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "distributed_kv_data_manager.h"
#include "singleton.h"

namespace OHOS {
namespace EventFwk {
class StaticSubscriberDataManager : public DelayedSingleton<StaticSubscriberDataManager> {
public:
    StaticSubscriberDataManager();

    virtual ~StaticSubscriberDataManager();

    int32_t UpdateStaticSubscriberState(const std::map<std::string, std::vector<std::string>> &disableEvents);

    int32_t QueryStaticSubscriberStateData(
        std::map<std::string, std::vector<std::string>> &disableEvents, std::set<std::string> &bundleList);

    int32_t DeleteDisableEventElementByBundleName(const std::string &bundleName);

private:
    DistributedKv::Status GetKvStore();
    bool CheckKvStore();
    DistributedKv::Value ConvertEventsToValue(const std::vector<std::string> &events);
    bool ConvertValueToEvents(const DistributedKv::Value &value, std::vector<std::string> &events);

    const DistributedKv::AppId appId_ { "static_subscriber_storage" };
    const DistributedKv::StoreId storeId_ { "static_subscriber_infos" };
    DistributedKv::DistributedKvDataManager dataManager_;
    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr_;
    mutable std::mutex kvStorePtrMutex_;
};
} // namespace EventFwk
} // namespace OHOS
#endif // BASE_NOTIFICATION_COMMON_EVENT_SERVICE_INCLUDE_STATIC_SUBSCRIBER_DATA_MANAGER_H