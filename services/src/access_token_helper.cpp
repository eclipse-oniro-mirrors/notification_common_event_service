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

#include "access_token_helper.h"

#include "common_event_permission_manager.h"
#include "event_log_wrapper.h"
#include "privacy_kit.h"

namespace OHOS {
namespace EventFwk {
bool AccessTokenHelper::VerifyNativeToken(const AccessToken::AccessTokenID &callerToken)
{
    AccessToken::ATokenTypeEnum tokenType = AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    return tokenType == AccessToken::ATokenTypeEnum::TOKEN_NATIVE;
}

bool AccessTokenHelper::VerifyAccessToken(const AccessToken::AccessTokenID &callerToken,
    const std::string &permission)
{
    return (AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, permission) ==
        AccessToken::PermissionState::PERMISSION_GRANTED);
}

void AccessTokenHelper::RecordSensitivePermissionUsage(const AccessToken::AccessTokenID &callerToken,
    const std::string &event)
{
    EVENT_LOGI("enter");
    AccessToken::ATokenTypeEnum tokenType = AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    if (tokenType != AccessToken::ATokenTypeEnum::TOKEN_HAP) {
        return;
    }
    Permission permission = DelayedSingleton<CommonEventPermissionManager>::GetInstance()->GetEventPermission(event);
    if (!permission.isSensitive || permission.names.empty()) {
        return;
    }
    for (const auto &permissionName : permission.names) {
        AccessToken::PrivacyKit::AddPermissionUsedRecord(callerToken, permissionName, 1, 0);
    }
}
}  // namespace EventFwk
}  // namespace OHOS
