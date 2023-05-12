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

#include <fstream>
#include <unistd.h>

#include "ces_inner_error_code.h"
#include "directory_ex.h"
#include "event_log_wrapper.h"

namespace OHOS {
namespace EventFwk {
namespace {
const static std::string DISABLE_STATIC_SUBSCRIBER_DATA_FULL_PATH(
    "/data/service/el1/public/common_event_service/disablestaticsubscribe.db");
}
std::mutex StaticSubscriberDataManager::dataMutex_;

StaticSubscriberDataManager::StaticSubscriberDataManager() {}

StaticSubscriberDataManager::~StaticSubscriberDataManager() {}

int32_t StaticSubscriberDataManager::InsertDisableStaticSubscribeData(const std::string &bundleName)
{
    EVENT_LOGD("InsertDisableStaticSubscribeData bundleName: %{public}s", bundleName.c_str());

    if (bundleName.empty()) {
        EVENT_LOGW("Invalid value!");
        return ERR_INVALID_VALUE;
    }

    std::set<std::string> disableStaticSubscribeAllData;
    if ((QueryDisableStaticSubscribeAllData(disableStaticSubscribeAllData) == ERR_OK) &&
        (!disableStaticSubscribeAllData.empty())) {
        if (disableStaticSubscribeAllData.find(bundleName) != disableStaticSubscribeAllData.end()) {
            EVENT_LOGI("Insert bundleName again!");
            return ERR_OK;
        }
    }
    {
        std::lock_guard<std::mutex> lock(dataMutex_);
        std::ofstream file;
        file.open(DISABLE_STATIC_SUBSCRIBER_DATA_FULL_PATH.c_str(), std::ios::out | std::ios::app);
        if (!file.is_open()) {
            EVENT_LOGE("Failed to open file!");
            return ERR_ENOUGH_DATA;
        }
        file << bundleName << std::endl;
        file.close();
    }
    return ERR_OK;
}

int32_t StaticSubscriberDataManager::DeleteDisableStaticSubscribeData(const std::string &bundleName)
{
    EVENT_LOGD("DeleteDisableStaticSubscribeData bundleName: %{public}s", bundleName.c_str());

    if (bundleName.empty()) {
        EVENT_LOGW("Invalid value!");
        return ERR_INVALID_VALUE;
    }

    std::set<std::string> disableStaticSubscribeAllData;
    if (QueryDisableStaticSubscribeAllData(disableStaticSubscribeAllData) == ERR_OK) {
        if (disableStaticSubscribeAllData.find(bundleName) == disableStaticSubscribeAllData.end()) {
            EVENT_LOGI("Delete bundleName is not exist!");
            return ERR_OK;
        }
    }

    if (disableStaticSubscribeAllData.empty()) {
        EVENT_LOGI("disableStaticSubscribeAllData is empty");
        return ERR_OK;
    }
    disableStaticSubscribeAllData.erase(bundleName);
    {
        std::lock_guard<std::mutex> lock(dataMutex_);
        std::ofstream file;
        file.open(DISABLE_STATIC_SUBSCRIBER_DATA_FULL_PATH.c_str(), std::ios::out | std::ios::trunc);
        if (!file.is_open()) {
            EVENT_LOGE("Failed to open file!");
            return ERR_ENOUGH_DATA;
        }
        for (std::string s : disableStaticSubscribeAllData) {
            file << s << std::endl;
        }
        file.close();
    }
    return ERR_OK;
}

int32_t StaticSubscriberDataManager::QueryDisableStaticSubscribeAllData(
    std::set<std::string> &disableStaticSubscribeAllData)
{
    std::lock_guard<std::mutex> lock(dataMutex_);
    std::ifstream file;
    file.open(DISABLE_STATIC_SUBSCRIBER_DATA_FULL_PATH.c_str(), std::ios::in);

    if (!file.is_open()) {
        EVENT_LOGE("Failed to open file!");
        return ERR_NO_INIT;
    }

    std::string data;
    while (getline(file, data)) {
        disableStaticSubscribeAllData.insert(data);
    }
    for (std::string s : disableStaticSubscribeAllData) {
        EVENT_LOGI("disableStaticSubscribeAllData[%{public}s].", s.c_str());
    }
    file.close();
    return ERR_OK;
}
} // namespace EventFwk
} // namespace OHOS
