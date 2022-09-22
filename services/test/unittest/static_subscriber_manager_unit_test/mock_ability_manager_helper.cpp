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

#include "ability_manager_helper.h"

namespace {
bool g_IsConnectAbilityCalled = false;
}
bool IsConnectAbilityCalled()
{
    return g_IsConnectAbilityCalled;
}

void ResetConnectAbilityState()
{
    g_IsConnectAbilityCalled = false;
}

namespace OHOS {
namespace EventFwk {
int AbilityManagerHelper::ConnectAbility(
    const Want &want, const CommonEventData &event, const sptr<IRemoteObject> &callerToken, const int32_t &userId)
{
    g_IsConnectAbilityCalled = true;
    return 0;
}

bool AbilityManagerHelper::GetAbilityMgrProxy()
{
    return true;
}

void AbilityManagerHelper::Clear()
{
}
}  // namespace EventFwk
}  // namespace OHOS
