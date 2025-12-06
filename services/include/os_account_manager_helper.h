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

#ifndef FOUNDATION_EVENT_CESFWK_SERVICES_INCLUDE_OS_ACCOUNT_MANAGER_HELPER_H
#define FOUNDATION_EVENT_CESFWK_SERVICES_INCLUDE_OS_ACCOUNT_MANAGER_HELPER_H

#include <vector>

#include "errors.h"
#include "singleton.h"

namespace OHOS {
namespace EventFwk {
class OsAccountManagerHelper : public DelayedSingleton<OsAccountManagerHelper> {
public:
    OsAccountManagerHelper() {}
    virtual ~OsAccountManagerHelper() {}

    /**
    * @brief check is system account
    */
    static bool IsSystemAccount(int32_t userId);

    /**
     * Queries active operating system account IDs.
     *
     * @param ids Indicates the account IDs.
     * @return Returns result code.
     */
    ErrCode QueryActiveOsAccountIds(std::vector<int32_t>& ids);

    /**
     * Gets operating system account local ID from uid.
     *
     * @param uid Indicates the uid.
     * @param ids Indicates the account ID.
     * @return Returns result code.
     */
    ErrCode GetOsAccountLocalIdFromUid(const int32_t uid, int32_t &id);

    /**
     * Check the userId whether exists in OsAccount service.
     *
     * @param userId Indicates the current active account ID.
     * @return Returns result.
     */
    bool CheckUserExists(const int32_t &userId);

    /**
     * Gets operating system account local ID from current active.
     *
     * @param id Indicates the current active account ID.
     * @return Returns result code.
     */
    ErrCode GetCurrentActiveUserId(int32_t &id);

    /**
     * Get foreground userIds.
     *
     * @param foregroundUserIds foreground userIds.
     * @return Returns result code.
     */
    ErrCode GetForegroundUserIds(std::vector<int32_t> &foregroundUserIds);
};
}  // namespace EventFwk
}  // namespace OHOS

#endif  // FOUNDATION_EVENT_CESFWK_SERVICES_INCLUDE_OS_ACCOUNT_MANAGER_HELPER_H