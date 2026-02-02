/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "ability_manager_helper.h"

namespace {
bool g_isConnectAbilityCalled = false;
}
bool IsConnectAbilityCalled()
{
    return g_isConnectAbilityCalled;
}

void ResetAbilityManagerHelperState()
{
    g_isConnectAbilityCalled = false;
}

namespace OHOS {
namespace EventFwk {
AbilityManagerHelper::AbilityManagerHelper() {}
int AbilityManagerHelper::ConnectAbility(
    const Want &want, const CommonEventData &event, const sptr<IRemoteObject> &callerToken, const int32_t &userId)
{
    g_isConnectAbilityCalled = true;
    return 0;
}

sptr<AAFwk::IAbilityManager> AbilityManagerHelper::GetAbilityMgrProxy()
{
    return nullptr;
}

void AbilityManagerHelper::DisconnectServiceAbilityDelay(
    const sptr<StaticSubscriberConnection> &connection, const std::string &action)
{}
}  // namespace EventFwk
}  // namespace OHOS
