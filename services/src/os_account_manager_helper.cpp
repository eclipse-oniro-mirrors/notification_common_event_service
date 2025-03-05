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
#include "event_log_wrapper.h"

#ifdef HAS_OS_ACCOUNT_PART
#include "os_account_manager.h"
#include "os_account_constants.h"
#endif // HAS_OS_ACCOUNT_PART

namespace OHOS {
namespace EventFwk {
#ifndef HAS_OS_ACCOUNT_PART
namespace {
const int32_t DEFAULT_OS_ACCOUNT_ID = 100; // default id when there is no os_account part
const int32_t UID_TRANSFORM_DIVISOR = 200000;
}
#endif // HAS_OS_ACCOUNT_PART

ErrCode OsAccountManagerHelper::QueryActiveOsAccountIds(std::vector<int32_t>& ids)
{
#ifndef HAS_OS_ACCOUNT_PART
    ids.emplace_back(DEFAULT_OS_ACCOUNT_ID);
    return ERR_OK;
#else
    return AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
#endif // HAS_OS_ACCOUNT_PART
}

ErrCode OsAccountManagerHelper::GetOsAccountLocalIdFromUid(const int32_t uid, int32_t &id)
{
#ifndef HAS_OS_ACCOUNT_PART
    id = uid / UID_TRANSFORM_DIVISOR;
    return ERR_OK;
#else
    return AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, id);
#endif // HAS_OS_ACCOUNT_PART
}

bool OsAccountManagerHelper::CheckUserExists(const int32_t &userId)
{
    bool isAccountExists = false;
    int32_t ret = OHOS::AccountSA::OsAccountManager::IsOsAccountExists(userId, isAccountExists);
    if (ret != ERR_OK) {
        EVENT_LOGE("Failed to call OsAccount, code is %{public}d", ret);
    }
    return isAccountExists;
}

bool OsAccountManagerHelper::IsSystemAccount(int32_t userId)
{
    return userId >= AccountSA::Constants::START_USER_ID && userId <= AccountSA::Constants::MAX_USER_ID;
}
}  // namespace EventFwk
}  // namespace OHOS