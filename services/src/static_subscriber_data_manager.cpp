/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "bundle_manager_helper.h"
#include "ces_inner_error_code.h"
#include "event_log_wrapper.h"
#include "nlohmann/json.hpp"
#include "os_account_manager_helper.h"

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
        .securityLevel = DistributedKv::SecurityLevel::S1,
        .area = DistributedKv::EL1,
        .kvStoreType = DistributedKv::KvStoreType::SINGLE_VERSION,
        .baseDir = STATIC_SUBSCRIBER_STORAGE_DIR
    };

    DistributedKv::Status status = dataManager_.GetSingleKvStore(options, appId_, storeId_, kvStorePtr_);
    if (status != DistributedKv::Status::SUCCESS) {
        EVENT_LOGE(LOG_TAG_STATIC, "return error: %{public}d", status);
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
        EVENT_LOGW(LOG_TAG_STATIC, "try times: %{public}d", tryTimes);
        usleep(CHECK_INTERVAL);
        tryTimes--;
    }
    return kvStorePtr_ != nullptr;
}

int32_t StaticSubscriberDataManager::UpdateStaticSubscriberState(
    const std::map<std::string, std::vector<std::string>> &disableEvents)
{
    std::map<std::string, std::vector<std::string>> disableEventsDatabase;
    std::set<std::string> bundleList;
    int32_t ret = QueryStaticSubscriberStateData(disableEventsDatabase, bundleList);
    if (ret != ERR_OK) {
        EVENT_LOGE(LOG_TAG_STATIC, "Query static subscriber state data failed.");
        return ret;
    }

    std::lock_guard<ffrt::mutex> lock(kvStorePtrMutex_);
    if (!CheckKvStore()) {
        EVENT_LOGE(LOG_TAG_STATIC, "Kvstore is nullptr.");
        return ERR_NO_INIT;
    }

    for (auto &disableEventsDatabaseIt : disableEventsDatabase) {
        DistributedKv::Key key(disableEventsDatabaseIt.first);
        if (kvStorePtr_->Delete(key) != DistributedKv::Status::SUCCESS) {
            EVENT_LOGE(LOG_TAG_STATIC, "Update data from kvstore failed.");
            dataManager_.CloseKvStore(appId_, kvStorePtr_);
            kvStorePtr_ = nullptr;
            return ERR_INVALID_OPERATION;
        }
    }

    for (auto &disableEventsIt : disableEvents) {
        DistributedKv::Key key(disableEventsIt.first);
        DistributedKv::Value value = ConvertEventsToValue(disableEventsIt.second);
        if (kvStorePtr_->Put(key, value) != DistributedKv::Status::SUCCESS) {
            EVENT_LOGE(LOG_TAG_STATIC, "Update data from kvstore failed.");
            dataManager_.CloseKvStore(appId_, kvStorePtr_);
            kvStorePtr_ = nullptr;
            return ERR_INVALID_OPERATION;
        }
    }

    dataManager_.CloseKvStore(appId_, kvStorePtr_);
    kvStorePtr_ = nullptr;
    return ERR_OK;
}

int32_t StaticSubscriberDataManager::QueryStaticSubscriberStateData(
    std::map<std::string, std::vector<std::string>> &disableEvents, std::set<std::string> &bundleList)

{
    std::lock_guard<ffrt::mutex> lock(kvStorePtrMutex_);
    if (!CheckKvStore()) {
        EVENT_LOGE(LOG_TAG_STATIC, "Kvstore is nullptr.");
        return ERR_NO_INIT;
    }

    std::vector<DistributedKv::Entry> allEntries;
    if (kvStorePtr_->GetEntries(nullptr, allEntries) != DistributedKv::Status::SUCCESS) {
        EVENT_LOGE(LOG_TAG_STATIC, "Get entries failed.");
        return ERR_INVALID_OPERATION;
    }

    if (allEntries.empty()) {
        dataManager_.CloseKvStore(appId_, kvStorePtr_);
        kvStorePtr_ = nullptr;
        EVENT_LOGD(LOG_TAG_STATIC, "The all entries is empty.");
        return ERR_OK;
    }

    int32_t result = ERR_OK;
    std::set<std::string> removeOldkeys;
    std::map<std::string, DistributedKv::Value> migrateValues;
    std::vector<int32_t> userIds;
    DelayedSingleton<OsAccountManagerHelper>::GetInstance()->QueryActiveOsAccountIds(userIds);
    for (const auto &item : allEntries) {
        std::vector<std::string> newKeys;
        result = GetValidKey(item.key.ToString(), userIds, removeOldkeys, newKeys);
        if (result != ERR_OK) {
            EVENT_LOGE(LOG_TAG_STATIC, "get valid key failed key is %{public}s", item.key.ToString().c_str());
            continue;
        }
        if (newKeys.empty()) {
            newKeys.push_back(item.key.ToString());
        } else {
            for (const auto &newKey : newKeys) {
                migrateValues.emplace(newKey, item.value);
            }
        }
        if (item.value.ToString() == STATIC_SUBSCRIBER_VALUE_DEFAULT) {
            for (const auto &nk : newKeys) {
                bundleList.emplace(nk);
            }
        } else {
            std::vector<std::string> values;
            if (!ConvertValueToEvents(item.value, values)) {
                EVENT_LOGE(LOG_TAG_STATIC, "Failed to convert vector from value.");
                result = ERR_INVALID_OPERATION;
                break;
            }
            for (const auto &nk : newKeys) {
                disableEvents.emplace(nk, values);
            }
        }
    }

    UpdateDistributedKv(removeOldkeys, migrateValues);
    dataManager_.CloseKvStore(appId_, kvStorePtr_);
    kvStorePtr_ = nullptr;
    return result;
}

int32_t StaticSubscriberDataManager::DeleteDisableEventElementByBundleName(const std::string &bundleName)
{
    if (bundleName.empty()) {
        EVENT_LOGE(LOG_TAG_STATIC, "Bundle name is invalid value.");
        return ERR_INVALID_VALUE;
    }

    std::lock_guard<ffrt::mutex> lock(kvStorePtrMutex_);
    if (!CheckKvStore()) {
        EVENT_LOGE(LOG_TAG_STATIC, "Kvstore is nullptr.");
        return ERR_NO_INIT;
    }

    EVENT_LOGD(LOG_TAG_STATIC, "Bundle name is %{public}s.", bundleName.c_str());
    DistributedKv::Key key(bundleName);
    if (kvStorePtr_->Delete(key) != DistributedKv::Status::SUCCESS) {
        EVENT_LOGE(LOG_TAG_STATIC, "Delete data [%{public}s] from kvstore failed.", bundleName.c_str());
        return ERR_INVALID_OPERATION;
    }

    dataManager_.CloseKvStore(appId_, kvStorePtr_);
    kvStorePtr_ = nullptr;
    return ERR_OK;
}

DistributedKv::Value StaticSubscriberDataManager::ConvertEventsToValue(const std::vector<std::string> &events)
{
    nlohmann::json jsonNodes = nlohmann::json::array();
    for (size_t index = 0; index < events.size(); index++) {
        jsonNodes.emplace_back(events[index]);
    }
    return jsonNodes.dump();
}

bool StaticSubscriberDataManager::ConvertValueToEvents(
    const DistributedKv::Value &value, std::vector<std::string> &events)
{
    nlohmann::json jsonObject = nlohmann::json::parse(value.ToString(), nullptr, false);
    if (jsonObject.is_null() || !jsonObject.is_array() || jsonObject.empty()) {
        EVENT_LOGE(LOG_TAG_STATIC, "invalid common event obj size");
        return false;
    }
    if (jsonObject.is_discarded()) {
        EVENT_LOGE(LOG_TAG_STATIC, "Failed to parse json string.");
        return false;
    }
    for (size_t index = 0; index < jsonObject.size(); index++) {
        if (jsonObject[index].is_string()) {
            events.emplace_back(jsonObject[index]);
        }
    }
    return true;
}

int32_t StaticSubscriberDataManager::GetValidKey(const std::string &key, const std::vector<int32_t> &userIds,
    std::set<std::string> &oldkeys, std::vector<std::string> &newkeys)
{
    if (key.empty()) {
        EVENT_LOGE(LOG_TAG_STATIC, "key is empty");
        return ERR_INVALID_VALUE;
    }
    if (std::isdigit(static_cast<unsigned char>(key[0])) != 0) {
        return ERR_OK;
    }
    if (userIds.empty()) {
        EVENT_LOGE(LOG_TAG_STATIC, "userIds is empty");
        return ERR_INVALID_VALUE;
    }
    for (const int32_t userId : userIds) {
        int32_t uid = DelayedSingleton<BundleManagerHelper>::GetInstance()->GetDefaultUidByBundleName(key, userId);
        if (uid < 0) {
            continue;
        }
        std::string newKey = std::to_string(uid) + key;
        oldkeys.emplace(key);
        newkeys.push_back(newKey);
    }
    return ERR_OK;
}

void StaticSubscriberDataManager::UpdateDistributedKv(const std::set<std::string> &oldkeys,
    const std::map<std::string, DistributedKv::Value> &migrateValues)
{
    if (kvStorePtr_ == nullptr) {
        return;
    }
    std::vector<DistributedKv::Key> keyVec;
    keyVec.reserve(oldkeys.size());
    for (const auto &oldKey : oldkeys) {
        keyVec.emplace_back(oldKey);
    }
    if (kvStorePtr_->DeleteBatch(keyVec) != DistributedKv::Status::SUCCESS) {
        EVENT_LOGE(LOG_TAG_STATIC, "Failed to batch delete old keys");
    }
    
    std::vector<DistributedKv::Entry> entryVec;
    entryVec.reserve(migrateValues.size());
    for (const auto &pair : migrateValues) {
        DistributedKv::Entry entry;
        entry.key = DistributedKv::Key(pair.first);
        entry.value = pair.second;
        entryVec.push_back(entry);
    }
    if (kvStorePtr_->PutBatch(entryVec) != DistributedKv::Status::SUCCESS) {
        EVENT_LOGE(LOG_TAG_STATIC, "Failed to batch put new keys");
    }
}
} // namespace EventFwk
} // namespace OHOS
