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

#include "accesstoken_kit.h"
#include "ces_ut_constant.h"


using namespace OHOS::Security::AccessToken;
namespace OHOS {
namespace EventFwk {
namespace {
ATokenTypeEnum g_mockGetTokenTypeFlagRet = ATokenTypeEnum::TOKEN_INVALID;
DlpType g_mockDlpType = DlpType::DLP_COMMON;
ATokenAplEnum g_mockApl = ATokenAplEnum::APL_NORMAL;
bool g_mockVerfyPermisson = true;
}

void MockGetTokenTypeFlag(ATokenTypeEnum mockRet)
{
    g_mockGetTokenTypeFlagRet = mockRet;
}
void MockDlpType(DlpType mockRet)
{
    g_mockDlpType = mockRet;
}
void MockApl(ATokenAplEnum mockRet)
{
    g_mockApl = mockRet;
}

void MockIsVerfyPermisson(bool isVerify)
{
    g_mockVerfyPermisson = isVerify;
}
}
}
namespace OHOS {
namespace Security {
namespace AccessToken {
int AccessTokenKit::VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
    if (!EventFwk::g_mockVerfyPermisson) {
        return PERMISSION_DENIED;
    }

    if (tokenID == EventFwk::NON_NATIVE_TOKEN) {
        return PERMISSION_DENIED;
    }
    return PERMISSION_GRANTED;
}

ATokenTypeEnum AccessTokenKit::GetTokenTypeFlag(AccessTokenID tokenID)
{
    return EventFwk::g_mockGetTokenTypeFlagRet;
}

int AccessTokenKit::GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo& info)
{
    info.dlpType = EventFwk::g_mockDlpType;
    info.apl = EventFwk::g_mockApl;
    return 0;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
