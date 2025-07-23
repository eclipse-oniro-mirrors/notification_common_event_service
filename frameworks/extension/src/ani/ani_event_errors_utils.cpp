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
#include "ani_event_errors_utils.h"

#include "event_log_wrapper.h"

namespace OHOS {
namespace EventManagerFwkAni {
void ThrowError(ani_env *env, ani_object err)
{
    if (env == nullptr) {
        EVENT_LOGE("null env");
        return;
    }
    env->ThrowError(static_cast<ani_error>(err));
}

void ThrowError(ani_env *env, int32_t errCode, const std::string &errorMsg)
{
    if (env == nullptr) {
        EVENT_LOGE("null env");
        return;
    }
    ThrowError(env, CreateError(env, errCode, errorMsg));
}

void ThrowError(ani_env *env, int32_t errCode)
{
    if (env == nullptr) {
        EVENT_LOGE("null env");
        return;
    }
    ThrowError(env, errCode, FindErrorMsg(errCode));
}

void ThrowErrorByNativeError(ani_env *env, int32_t innerCode)
{
    if (env == nullptr) {
        EVENT_LOGE("null env");
        return;
    }
    int32_t errCode = GetExternalCode(innerCode);
    ThrowError(env, errCode, FindErrorMsg(errCode));
}

ani_object WrapError(ani_env *env, const std::string &msg)
{
    if (env == nullptr) {
        EVENT_LOGE("null env");
        return nullptr;
    }
    ani_status status = ANI_ERROR;
    ani_string aniMsg = nullptr;
    if ((status = env->String_NewUTF8(msg.c_str(), msg.size(), &aniMsg)) != ANI_OK) {
        EVENT_LOGE("String_NewUTF8 failed %{public}d", status);
        return nullptr;
    }
    ani_ref undefRef;
    if ((status = env->GetUndefined(&undefRef)) != ANI_OK) {
        EVENT_LOGE("GetUndefined failed %{public}d", status);
        return nullptr;
    }
    ani_class cls = nullptr;
    if ((status = env->FindClass(ERROR_CLASS_NAME, &cls)) != ANI_OK) {
        EVENT_LOGE("FindClass failed %{public}d", status);
        return nullptr;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", "Lstd/core/String;Lescompat/ErrorOptions;:V", &method)) !=
        ANI_OK) {
        EVENT_LOGE("Class_FindMethod failed %{public}d", status);
        return nullptr;
    }
    ani_object obj = nullptr;
    if ((status = env->Object_New(cls, method, &obj, aniMsg, undefRef)) != ANI_OK) {
        EVENT_LOGE("Object_New failed %{public}d", status);
        return nullptr;
    }
    return obj;
}

ani_object CreateError(ani_env *env, ani_int code, const std::string &msg)
{
    if (env == nullptr) {
        EVENT_LOGE("null env");
        return nullptr;
    }
    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    if ((status = env->FindClass(BUSINESS_ERROR_CLASS, &cls)) != ANI_OK) {
        EVENT_LOGE("FindClass failed %{public}d", status);
        return nullptr;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", "ILescompat/Error;:V", &method)) != ANI_OK) {
        EVENT_LOGE("Class_FindMethod failed %{public}d", status);
        return nullptr;
    }
    ani_object error = WrapError(env, msg);
    if (error == nullptr) {
        EVENT_LOGE("error nulll");
        return nullptr;
    }
    ani_object obj = nullptr;
    ani_int iCode(code);
    if ((status = env->Object_New(cls, method, &obj, iCode, error)) != ANI_OK) {
        EVENT_LOGE("Object_New failed %{public}d", status);
        return nullptr;
    }
    return obj;
}

int32_t GetExternalCode(int32_t errCode)
{
    for (const auto &errorConvert : ERRORS_CONVERT) {
        if (errCode == errorConvert.second) {
            return errCode;
        }
        if (errCode == errorConvert.first) {
            return errorConvert.second;
        }
    }
    return ERROR_CODE_INNER;
}

std::string FindErrorMsg(const int32_t errCode)
{
    auto findMsg = ERR_CODE_MAP.find(errCode);
    if (findMsg == ERR_CODE_MAP.end()) {
        EVENT_LOGE("FindAnsErrMsg Inner error.");
        return "Inner error.";
    }
    return findMsg->second;
}
} //namespace EventManagerFwkAni
} //namespace OHOS