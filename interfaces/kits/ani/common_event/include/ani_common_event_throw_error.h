/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_COMMON_EVENT_MANAGER_INCLUDE_ANI_COMMON_EVENT_ERROR_H
#define BASE_NOTIFICATION_COMMON_EVENT_MANAGER_INCLUDE_ANI_COMMON_EVENT_ERROR_H

#include <string>
#include <vector>
#include "ces_inner_error_code.h"
#include "event_log_wrapper.h"

namespace OHOS {
namespace EventManagerFwkAni {
static const std::unordered_map<int32_t, std::string> ERROR_CODE_TO_MESSAGE {
    {Notification::ERR_NOTIFICATION_CES_COMMON_PERMISSION_DENIED,
        "The application dose not have permission to call the interface"},
    {Notification::ERR_NOTIFICATION_CES_COMMON_NOT_SYSTEM_APP, "The application is not system application"},
    {Notification::ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, "The param input is invalid"},
    {Notification::ERR_NOTIFICATION_CES_COMMON_SYSTEMCAP_NOT_SUPPORT, "The want action send by event is null"},
    {Notification::ERR_NOTIFICATION_CES_SANDBOX_NOT_SUPPORT, "The sandbox application can not send common event"},
    {Notification::ERR_NOTIFICATION_CES_WANT_ACTION_IS_NULL, "The want action send by event is null"},
    {Notification::ERR_NOTIFICATION_CES_EVENT_FREQ_TOO_HIGH, "The common event send frequency too high"},
    {Notification::ERR_NOTIFICATION_CES_NOT_SA_SYSTEM_APP,
        "The application can not send common event, it may be not SA app or System app"},
    {Notification::ERR_NOTIFICATION_CES_NO_SUBSCRIBER, "The subscriber can not found"},
    {Notification::ERR_NOTIFICATION_CES_USERID_INVALID, "he usreId is invalid"},
    {Notification::ERR_NOTIFICATION_SEND_ERROR, "The message send error"},
    {Notification::ERR_NOTIFICATION_CESM_ERROR, "The CEMS error"},
    {Notification::ERR_NOTIFICATION_SYS_ERROR, "The system error"},
};

inline std::string FindCesErrMsg(const int32_t errCode)
{
    auto findMsg = ERROR_CODE_TO_MESSAGE.find(errCode);
    if (findMsg == ERROR_CODE_TO_MESSAGE.end()) {
        EVENT_LOGE("FindCesErrMsg Inner error.");
        return "Inner error.";
    }
    return findMsg->second;
}

} // namespace EventManagerFwkAni
} // OHOS
#endif // BASE_NOTIFICATION_COMMON_EVENT_MANAGER_INCLUDE_ANI_COMMON_EVENT_ERROR_H