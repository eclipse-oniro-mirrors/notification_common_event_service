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

using namespace OHOS::Security::AccessToken;
namespace {
bool g_MockVerifyNativeTokenRet = true;
bool g_MockVerifyAccessTokenRet = true;
bool g_MockIsDlpHapRet = true;
int8_t g_TimesBeforeVerifyAccessToken = 0;
int8_t g_CountForVerifyAccessToken = 0;
AccessTokenID g_MockAccessTokenID = 0;
}

void ResetAccessTokenHelperMock()
{
    g_MockVerifyNativeTokenRet = true;
    g_MockVerifyAccessTokenRet = true;
    g_MockIsDlpHapRet = true;
    g_TimesBeforeVerifyAccessToken = 0;
    g_CountForVerifyAccessToken = 0;
    g_MockAccessTokenID = 0;
}

void MockVerifyNativeToken(bool mockRet)
{
    g_MockVerifyNativeTokenRet = mockRet;
}

void MockVerifyAccessToken(bool mockRet, int8_t times = 0)
{
    
    g_MockVerifyAccessTokenRet = mockRet;
    g_TimesBeforeVerifyAccessToken = times;
}

void MockIsDlpHap(bool mockRet)
{
    g_MockIsDlpHapRet = mockRet;
}

void MockGetHapTokenID(AccessTokenID mockRet)
{
    g_MockAccessTokenID = mockRet;
}

namespace OHOS {
namespace EventFwk {
bool AccessTokenHelper::VerifyNativeToken(const AccessTokenID &callerToken)
{
    return g_MockVerifyNativeTokenRet;
}

bool AccessTokenHelper::VerifyAccessToken(const AccessTokenID &callerToken,
    const std::string &permission)
{
    if (g_CountForVerifyAccessToken < g_TimesBeforeVerifyAccessToken) {
        g_CountForVerifyAccessToken++;
        return !g_MockVerifyAccessTokenRet;
    }
    g_TimesBeforeVerifyAccessToken = 0;
    g_CountForVerifyAccessToken = 0;
    return g_MockVerifyAccessTokenRet;
}

void AccessTokenHelper::RecordSensitivePermissionUsage(const AccessTokenID &callerToken,
    const std::string &event)
{
}

bool AccessTokenHelper::IsDlpHap(const AccessTokenID &callerToken)
{
    return g_MockIsDlpHapRet;
}

AccessTokenID AccessTokenHelper::GetHapTokenID(int userID,
    const std::string& bundleName, int instIndex)
{
    return g_MockAccessTokenID;
}
}  // namespace EventFwk
}  // namespace OHOS
