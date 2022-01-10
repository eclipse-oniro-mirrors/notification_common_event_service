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
#include "nlohmann/json.hpp"

#include "event_log_wrapper.h"

namespace OHOS {
namespace EventFwk {
const std::string STATIC_SUBSCRIBER_CONFIG_FILE = "/system/etc/static_subscriber_config.json";

const std::string CONFIG_APPS = "apps";

StaticSubscriberManager::StaticSubscriberManager() {}

StaticSubscriberManager::~StaticSubscriberManager() {}

bool StaticSubscriberManager::Init()
{
    EVENT_LOGI("enter");

    nlohmann::json jsonObj;
    std::ifstream jfile(STATIC_SUBSCRIBER_CONFIG_FILE);
    if (!jfile.is_open()) {
        EVENT_LOGI("json file can not open");
        isInit_ = false;
        return false;
    }
    jfile >> jsonObj;
    jfile.close();

    int size = jsonObj[CONFIG_APPS].size();
    for (int i = 0; i < size; i++) {
        subscriberList_.emplace_back(jsonObj[CONFIG_APPS][i].get<std::string>());
    }
    isInit_ = true;
    return true;
}

bool StaticSubscriberManager::IsStaticSubscriber(const std::string &bundleName)
{
    EVENT_LOGI("enter");
    if (!isInit_ && !Init()) {
        EVENT_LOGE("failed to init subscriber list");
        return false;
    }
    std::vector<std::string>::iterator iter = subscriberList_.begin();
    iter = find(subscriberList_.begin(), subscriberList_.end(), bundleName);
    if (iter != subscriberList_.end()) {
        return true;
    }
    return false;
}
}  // namespace EventFwk
}  // namespace OHOS
