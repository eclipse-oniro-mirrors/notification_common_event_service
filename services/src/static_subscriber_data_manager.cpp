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

#include "static_subscriber_data_manager.h"

#include <unistd.h>

#include "ces_inner_error_code.h"
#include "event_log_wrapper.h"

namespace OHOS {
namespace EventFwk {
namespace {
constexpr int32_t CHECK_INTERVAL = 100000; // 100ms
constexpr int32_t MAX_TIMES = 5;           // 5 * 100ms = 500ms
constexpr const char *STATIC_SUBSCRIBER_STORAGE_DIR = "/data/service/el1/public/database/common_event_service";
const std::string STATIC_SUBSCRIBER_VALUE_DEFAULT = "0";
} // namespace
StaticSubscriberDataManager::StaticSubscriberDataManager() {}

StaticSubscriberDataManager::~StaticSubscriberDataManager()
{
    if (kvStorePtr_ != nullptr) {
        dataManager_.CloseKvStore(appId_, kvStorePtr_);
    }
}

DistributedKv::Status StaticSubscriberDataManager::GetKvStore()
{
    DistributedKv::Options options = {
        .createIfMissing = true,
        .encrypt = false,
        .autoSync = false,
        .syncable = false,
        .area = DistributedKv::EL1,
        .kvStoreType = DistributedKv::KvStoreType::SINGLE_VERSION,
        .baseDir = STATIC_SUBSCRIBER_STORAGE_DIR
    };

    DistributedKv::Status status = dataManager_.GetSingleKvStore(options, appId_, storeId_, kvStorePtr_);
    if (status != DistributedKv::Status::SUCCESS) {
        EVENT_LOGE("return error: %{public}d", status);
    }
    return status;
}

bool StaticSubscriberDataManager::CheckKvStore()
{
    if (kvStorePtr_ != nullptr) {
        return true;
    }
    int32_t tryTimes = MAX_TIMES;
    while (tryTimes > 0) {
        DistributedKv::Status status = GetKvStore();
        if (status == DistributedKv::Status::SUCCESS && kvStorePtr_ != nullptr) {
            return true;
        }
        EVENT_LOGI("try times: %{public}d", tryTimes);
        usleep(CHECK_INTERVAL);
        tryTimes--;
    }
    return kvStorePtr_ != nullptr;
}

int32_t StaticSubscriberDataManager::InsertDisableStaticSubscribeData(const std::string &bundleName)
{
    if (bundleName.empty()) {
        EVENT_LOGW("invalid value!");
        return ERR_INVALID_VALUE;
    }
    DistributedKv::Status status;
    EVENT_LOGD("bundleName = %{public}s", bundleName.c_str());
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            EVENT_LOGE("kvStore is null");
            return ERR_NO_INIT;
        }
        DistributedKv::Key key(bundleName);
        DistributedKv::Value value(STATIC_SUBSCRIBER_VALUE_DEFAULT);
        status = kvStorePtr_->Put(key, value);
    }
    int32_t result = ERR_OK;
    if (status != DistributedKv::Status::SUCCESS) {
        EVENT_LOGE("insert data [%{public}s] to kvStore failed. error code: %{public}d", bundleName.c_str(), status);
        result = ERR_INVALID_OPERATION;
    }

    dataManager_.CloseKvStore(appId_, kvStorePtr_);
    kvStorePtr_ = nullptr;

    return result;
}

int32_t StaticSubscriberDataManager::DeleteDisableStaticSubscribeData(const std::string &bundleName)
{
    if (bundleName.empty()) {
        EVENT_LOGW("invalid value!");
        return ERR_INVALID_VALUE;
    }
    DistributedKv::Status status;
    EVENT_LOGD("bundleName: %{public}s", bundleName.c_str());
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            EVENT_LOGE("kvStore is nullptr");
            return ERR_NO_INIT;
        }
        DistributedKv::Key key(bundleName);
        status = kvStorePtr_->Delete(key);
    }
    int32_t result = ERR_OK;
    if (status != DistributedKv::Status::SUCCESS) {
        EVENT_LOGE("delete data [%{public}s] from kvStore failed. error code: %{public}d", bundleName.c_str(), status);
        result = ERR_INVALID_OPERATION;
    }

    dataManager_.CloseKvStore(appId_, kvStorePtr_);
    kvStorePtr_ = nullptr;

    return result;
}

int32_t StaticSubscriberDataManager::QueryDisableStaticSubscribeAllData(
    std::set<std::string> &disableStaticSubscribeAllData)
{
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            EVENT_LOGE("kvStore is nullptr");
            return ERR_NO_INIT;
        }
    }

    std::vector<DistributedKv::Entry> allEntries;
    DistributedKv::Status status = kvStorePtr_->GetEntries(nullptr, allEntries);
    int32_t result = ERR_OK;
    if (status != DistributedKv::Status::SUCCESS) {
        EVENT_LOGE("get entries failed, error code: %{public}d", status);
        result = ERR_INVALID_OPERATION;
    }

    if (!allEntries.empty()) {
        for (const auto &item : allEntries) {
            disableStaticSubscribeAllData.emplace(item.key.ToString());
            EVENT_LOGI("current disable static subscriber bundle name: %{public}s", item.key.ToString().c_str());
        }
    }

    dataManager_.CloseKvStore(appId_, kvStorePtr_);
    kvStorePtr_ = nullptr;

    return result;
}
} // namespace EventFwk
} // namespace OHOS
