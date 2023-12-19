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

#include "common_event_permission_manager.h"

#include <algorithm>
#include <string>
#include <unordered_map>
#include <vector>

namespace {
    bool g_mockGetEventPermissionRet = true;
}

namespace OHOS {
namespace EventFwk {
void MockGetEventPermission(bool mockRet)
{
    g_mockGetEventPermissionRet = mockRet;
}
Permission CommonEventPermissionManager::GetEventPermission(const std::string &event)
{   
    Permission per;
    if (true == g_mockGetEventPermissionRet) {
        std::string eventName = "aa";
        per.names.emplace_back(eventName);
        eventMap_.insert(std::make_pair(eventName, per));
        return eventMap_.find(eventName)->second;
    }
    return per;
}
}  // namespace EventFwk
}  // namespace OHOS
