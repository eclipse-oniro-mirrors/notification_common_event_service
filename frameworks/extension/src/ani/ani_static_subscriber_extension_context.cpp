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
#include "ani_static_subscriber_extension_context.h"

#include "ability_manager_client.h"
#include "ani_common_want.h"
#include "ani_common_start_options.h"
#include "ani_event_errors_utils.h"
#include "ets_extension_context.h"
#include "event_log_wrapper.h"
#include "native_engine/native_engine.h"

namespace OHOS {
namespace EventManagerFwkAni {
using namespace OHOS::AbilityRuntime;

void StsStaticSubscriberExtensionContext::StartAbilityInner([[maybe_unused]] ani_env *env,
    [[maybe_unused]] ani_object aniObj, ani_object wantObj)
{
    EVENT_LOGD(LOG_TAG_CES, "StartAbilityInner");
    AAFwk::Want want;
    ErrCode innerErrCode = ERR_OK;
    if (!AppExecFwk::UnwrapWant(env, wantObj, want)) {
        EVENT_LOGE(LOG_TAG_CES, "UnwrapWant filed");
        ThrowError(env, ERROR_CODE_INVALID_PARAM);
        return;
    }
    auto context = GetAbilityContext();
    if (context == nullptr) {
        EVENT_LOGE(LOG_TAG_CES, "GetAbilityContext is nullptr");
        ThrowError(env, ERROR_CODE_INVALID_CONTEXT);
        return;
    }
    innerErrCode = context->StartAbility(want);
    if (innerErrCode != ERR_OK) {
        EVENT_LOGE(LOG_TAG_CES, "StartAbility failed, code = %{public}d", innerErrCode);
        OHOS::EventManagerFwkAni::ThrowErrorByNativeError(env, innerErrCode);
        ThrowErrorByNativeError(env, innerErrCode);
    }
}

std::shared_ptr<StaticSubscriberExtensionContext> StsStaticSubscriberExtensionContext::GetAbilityContext()
{
    return context_.lock();
}

StsStaticSubscriberExtensionContext* StsStaticSubscriberExtensionContext::GetAbilityContext(ani_env *env,
    ani_object obj)
{
    ani_long nativeContextLong;
    ani_status status = ANI_ERROR;
    if (env == nullptr) {
        EVENT_LOGD(LOG_TAG_CES, "null env");
        return nullptr;
    }

    status = env->Object_GetFieldByName_Long(obj, "nativeStaticSubscriberExtensionContext", &nativeContextLong);
    if (status != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES, "get property status: %{public}d", status);
        return nullptr;
    }
    if (nativeContextLong == 0) {
        EVENT_LOGE(LOG_TAG_CES, "nativeContextLong is zero");
        return nullptr;
    }
    return reinterpret_cast<StsStaticSubscriberExtensionContext*>(nativeContextLong);
}

ani_object CreateStaticSubscriberExtensionContext(ani_env *env,
    std::shared_ptr<StaticSubscriberExtensionContext> context)
{
    if (env == nullptr) {
        EVENT_LOGE(LOG_TAG_CES, "null env");
        return nullptr;
    }
    std::shared_ptr<OHOS::AppExecFwk::AbilityInfo> abilityInfo = nullptr;
    if (context) {
        abilityInfo = context->GetAbilityInfo();
    }
    auto stsStaticSubscriberExtensionContext = new (std::nothrow) StsStaticSubscriberExtensionContext(context);
    if (stsStaticSubscriberExtensionContext == nullptr) {
        EVENT_LOGE(LOG_TAG_CES, "null sts context");
        return nullptr;
    }
    ani_object contextObj = nullptr;
    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    ani_method method = nullptr;
    if ((status = env->FindClass(STATIC_SUBSCRIBER_EXTENSION_CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES, "find class status : %{public}d", status);
        delete stsStaticSubscriberExtensionContext;
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", "l:", &method)) != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES, "find Method status: %{public}d", status);
        delete stsStaticSubscriberExtensionContext;
        return nullptr;
    }
    ani_long nativeContextLong = reinterpret_cast<ani_long>(stsStaticSubscriberExtensionContext);
    if ((status = env->Object_New(cls, method, &contextObj, nativeContextLong)) != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES, "new Object status: %{public}d", status);
        delete stsStaticSubscriberExtensionContext;
        return nullptr;
    }
    OHOS::AbilityRuntime::CreateEtsExtensionContext(env, cls, contextObj, context, abilityInfo);
    return contextObj;
}
} // EventManagerFwkAni
} // OHOS