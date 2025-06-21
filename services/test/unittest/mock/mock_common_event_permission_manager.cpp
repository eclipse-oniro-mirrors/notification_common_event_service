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
    OHOS::EventFwk::PermissionState g_mockPermissionState = OHOS::EventFwk::PermissionState::OR;
    int32_t g_mockPermissionSize = 1;
}

namespace OHOS {
namespace EventFwk {
void MockGetEventPermission(bool mockRet, PermissionState mockState, int32_t permissionSize)
{
    g_mockGetEventPermissionRet = mockRet;
    g_mockPermissionState = mockState;
    g_mockPermissionSize = permissionSize;
}

Permission CommonEventPermissionManager::GetEventPermission(const std::string &event)
{   
    Permission per;
    if (true == g_mockGetEventPermissionRet) {
        for (int32_t i = 0; i < g_mockGetEventPermissionRet; i++) {
            per.names.emplace_back("permision_" + std::to_string(i));
        }
        per.state = g_mockPermissionState;
        return per;
    }
    return per;
}
}  // namespace EventFwk
}  // namespace OHOS
