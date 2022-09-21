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

#include "os_account_manager_helper.h"

namespace {
int32_t mockId = 100; // default id when there is no os_account part
bool mockQueryActiveOsAccountIdsRet = true;
bool mockGetOsAccountLocalIdFromUidRet = true;
}

void MockQueryActiveOsAccountIds(bool mockRet, uint8_t mockCase)
{
    mockQueryActiveOsAccountIdsRet = mockRet;
    switch (mockCase) {
        case 1: {
            mockId = 101;
            break;
        }
        default:
            break;
    }
}

void MockGetOsAccountLocalIdFromUid(bool mockRet)
{
    mockGetOsAccountLocalIdFromUidRet = mockRet;
}

namespace OHOS {
namespace EventFwk {
ErrCode OsAccountManagerHelper::QueryActiveOsAccountIds(std::vector<int32_t>& ids)
{
    ids.emplace_back(mockId);
    return mockQueryActiveOsAccountIdsRet ? ERR_OK : ERR_INVALID_OPERATION;
}

ErrCode OsAccountManagerHelper::GetOsAccountLocalIdFromUid(const int32_t uid, int32_t &id)
{
    id = 100;
    return mockGetOsAccountLocalIdFromUidRet ? ERR_OK : ERR_INVALID_OPERATION;
}
}  // namespace EventFwk
}  // namespace OHOS