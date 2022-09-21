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
bool g_mockVerifyNativeTokenRet = true;
bool g_mockVerifyAccessTokenRet = true;
bool g_mockIsDlpHapRet = true;
AccessTokenID g_mockAccessTokenID = 0;
}

void MockVerifyNativeToken(bool mockRet)
{
    g_mockVerifyNativeTokenRet = mockRet;
}

void MockVerifyAccessToken(bool mockRet)
{
    g_mockVerifyAccessTokenRet = mockRet;
}

void MockIsDlpHap(bool mockRet)
{
    g_mockIsDlpHapRet = mockRet;
}

void MockGetHapTokenID(AccessTokenID mockRet)
{
    g_mockAccessTokenID = mockRet;
}

namespace OHOS {
namespace EventFwk {
bool AccessTokenHelper::VerifyNativeToken(const AccessTokenID &callerToken)
{
    return g_mockVerifyNativeTokenRet;
}

bool AccessTokenHelper::VerifyAccessToken(const AccessTokenID &callerToken,
    const std::string &permission)
{
    return g_mockVerifyAccessTokenRet;
}

void AccessTokenHelper::RecordSensitivePermissionUsage(const AccessTokenID &callerToken,
    const std::string &event)
{
}

bool AccessTokenHelper::IsDlpHap(const AccessTokenID &callerToken)
{
    return g_mockIsDlpHapRet;
}

AccessTokenID AccessTokenHelper::GetHapTokenID(int userID,
    const std::string& bundleName, int instIndex)
{
    return g_mockAccessTokenID;
}
}  // namespace EventFwk
}  // namespace OHOS
