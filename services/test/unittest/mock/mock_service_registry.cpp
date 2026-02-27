/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include "event_log_wrapper.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "mock_service_registry.h"
#include "refbase.h"

namespace OHOS {

using namespace OHOS::EventFwk;
using namespace OHOS::AppExecFwk;

namespace {
sptr<IRemoteObject> g_mockSaProxy = nullptr;
}

void MockSaProxy(sptr<IRemoteObject> mockRet)
{
    g_mockSaProxy = mockRet;
}

sptr<IRemoteObject> MockSystemAbilityManager::GetSystemAbility(int32_t systemAbilityId)
{
    EVENT_LOGD(LOG_TAG_CES, "enter");
    return g_mockSaProxy;
}

sptr<ISystemAbilityManager> SystemAbilityManagerClient::GetSystemAbilityManager()
{
    EVENT_LOGD(LOG_TAG_CES, "enter");
    return sptr<MockSystemAbilityManager>(new MockSystemAbilityManager());
}
} // namespace OHOS
