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

#ifndef BASE_NOTIFICATION_COMMON_EVENT_MANAGER_INCLUDE_ANI_EVENT_ERRORS_UTILS_H
#define BASE_NOTIFICATION_COMMON_EVENT_MANAGER_INCLUDE_ANI_EVENT_ERRORS_UTILS_H

#include <ani.h>
#include <string>

#include "errors.h"

namespace OHOS {
namespace EventManagerFwkAni {
using namespace std;

constexpr const char *BUSINESS_ERROR_CLASS = "L@ohos/base/BusinessError;";
constexpr const char *ERROR_CLASS_NAME = "Lescompat/Error;";

constexpr const char* ERROR_MSG_PERMISSION_DENIED = "The application does not have permission to call the interface.";
constexpr const char* ERROR_MSG_NOT_SYSTEM_APP = "The application is not system-app, can not use system-api.";
constexpr const char* ERROR_MSG_INVALID_PARAM = "Invalid input parameter.";
constexpr const char* ERROR_MSG_CAPABILITY_NOT_SUPPORT = "Capability not support.";
constexpr const char* ERROR_MSG_INNER = "Internal error.";
constexpr const char* ERROR_MSG_RESOLVE_ABILITY = "The specified ability does not exist.";
constexpr const char* ERROR_MSG_INVALID_ABILITY_TYPE = "Incorrect ability type.";
constexpr const char* ERROR_MSG_INVISIBLE = "Failed to start the invisible ability.";
constexpr const char* ERROR_MSG_STATIC_CFG_PERMISSION = "The specified process does not have the permission.";
constexpr const char* ERROR_MSG_CROSS_USER = "Cross-user operations are not allowed.";
constexpr const char* ERROR_MSG_CROWDTEST_EXPIRED = "The crowdtesting application expires.";
constexpr const char* ERROR_MSG_WUKONG_MODE = "An ability cannot be started or stopped in Wukong mode.";
constexpr const char* ERROR_MSG_NOT_TOP_ABILITY = "The ability is not on the top of the UI.";
constexpr const char* ERROR_MSG_FREE_INSTALL_TIMEOUT = "Installation-free timed out.";
constexpr const char* ERROR_MSG_INVALID_CALLER = "The caller has been released.";
constexpr const char* ERROR_MSG_NOT_SELF_APPLICATION = "The target application is not the current application.";
constexpr const char* ERROR_MSG_INVALID_CONTEXT = "The context does not exist.";

enum {
    // success
    ERROR_OK = 0,

    // no such permission.
    ERROR_CODE_PERMISSION_DENIED = 201,

    // non-system-app use system-api.
    ERROR_CODE_NOT_SYSTEM_APP = 202,

    // invalid param.
    ERROR_CODE_INVALID_PARAM = 401,

    // capability not support.
    ERROR_CODE_CAPABILITY_NOT_SUPPORT = 801,

    // common inner error.
    ERROR_CODE_INNER = 16000050,

    // can not find target ability.
    ERROR_CODE_RESOLVE_ABILITY = 16000001,

    // ability type is wrong.
    ERROR_CODE_INVALID_ABILITY_TYPE = 16000002,

    // no start invisible ability permission.
    ERROR_CODE_NO_INVISIBLE_PERMISSION = 16000004,

    // check static permission failed.
    ERROR_CODE_STATIC_CFG_PERMISSION = 16000005,

    // no permission to cross user.
    ERROR_CODE_CROSS_USER = 16000006,

    // crowdtest app expiration.
    ERROR_CODE_CROWDTEST_EXPIRED = 16000008,

    // wukong mode.
    ERROR_CODE_WUKONG_MODE = 16000009,

    // context is invalid.
    ERROR_CODE_INVALID_CONTEXT = 16000011,

    // not top ability, not enable to free install.
    ERROR_CODE_NOT_TOP_ABILITY = 16000053,

    // free install timeout.
    ERROR_CODE_FREE_INSTALL_TIMEOUT = 16000055,

    // invalid caller.
    ERROR_CODE_INVALID_CALLER = 16200001,

    // not self application.
    ERROR_NOT_SELF_APPLICATION = 16300003,
};

static std::unordered_map<int32_t, const char*> ERR_CODE_MAP = {
    { ERROR_CODE_PERMISSION_DENIED, ERROR_MSG_PERMISSION_DENIED },
    { ERROR_CODE_NOT_SYSTEM_APP, ERROR_MSG_NOT_SYSTEM_APP },
    { ERROR_CODE_INVALID_PARAM, ERROR_MSG_INVALID_PARAM },
    { ERROR_CODE_CAPABILITY_NOT_SUPPORT, ERROR_MSG_CAPABILITY_NOT_SUPPORT },
    { ERROR_CODE_INNER, ERROR_MSG_INNER },
    { ERROR_CODE_RESOLVE_ABILITY, ERROR_MSG_RESOLVE_ABILITY },
    { ERROR_CODE_INVALID_ABILITY_TYPE, ERROR_MSG_INVALID_ABILITY_TYPE },
    { ERROR_CODE_INVALID_CONTEXT, ERROR_MSG_INVALID_CONTEXT },
    { ERROR_CODE_NO_INVISIBLE_PERMISSION, ERROR_MSG_INVISIBLE },
    { ERROR_CODE_STATIC_CFG_PERMISSION, ERROR_MSG_STATIC_CFG_PERMISSION },
    { ERROR_CODE_CROSS_USER, ERROR_MSG_CROSS_USER },
    { ERROR_CODE_CROWDTEST_EXPIRED, ERROR_MSG_CROWDTEST_EXPIRED },
    { ERROR_CODE_WUKONG_MODE, ERROR_MSG_WUKONG_MODE },
    { ERROR_CODE_NOT_TOP_ABILITY, ERROR_MSG_NOT_TOP_ABILITY },
    { ERROR_CODE_FREE_INSTALL_TIMEOUT, ERROR_MSG_FREE_INSTALL_TIMEOUT },
    { ERROR_CODE_INVALID_CALLER, ERROR_MSG_INVALID_CALLER },
    { ERROR_NOT_SELF_APPLICATION, ERROR_MSG_NOT_SELF_APPLICATION },
};

int32_t GetExternalCode(int32_t errCode);
std::string FindErrorMsg(const int32_t errCode);
ani_object CreateError(ani_env *env, ani_int code, const std::string &msg);
ani_object WrapError(ani_env *env, const std::string &msg);
void ThrowError(ani_env *env, int32_t errCode);
void ThrowErrorByNativeError(ani_env *env, int32_t innerCode);
} // namespace EventManagerFwkAni
} // namespace OHOS
#endif // BASE_NOTIFICATION_COMMON_EVENT_MANAGER_INCLUDE_ANI_EVENT_ERRORS_UTILS_H