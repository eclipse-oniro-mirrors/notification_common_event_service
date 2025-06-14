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
#include "ani_common_event_throw_error.h"
#include "ani_common_want.h"
#include "ani_common_start_options.h"
#include "ets_extension_context.h"
#include "event_log_wrapper.h"
#include "native_engine/native_engine.h"
#include "sts_error_utils.h"

namespace OHOS {
namespace EventManagerFwkAni {
namespace {
using namespace OHOS::EventFwk;
using namespace OHOS::AbilityRuntime;

class StsStaticSubscriberExtensionContext final {
public:
    static StsStaticSubscriberExtensionContext& GetInstance()
    {
        static StsStaticSubscriberExtensionContext instance;
        return instance;
    }

    void StartAbilityInner([[maybe_unused]] ani_env *env,
        [[maybe_unused]] ani_object aniObj, ani_object wantObj, ani_object call);
    static StaticSubscriberExtensionContext* GetAbilityContext(ani_env *env, ani_object obj);

private:
    explicit StsStaticSubscriberExtensionContext() = default;
    ~StsStaticSubscriberExtensionContext() = default;
};

constexpr const char* STATIC_SUBSCRIBER_EXTENSION_CONTEXT_CLASS_NAME =
    "L@ohos/application/StaticSubscriberExtensionContext/StaticSubscriberExtensionContext;";
}

static void StartAbility([[maybe_unused]] ani_env *env,
    [[maybe_unused]] ani_object aniObj, ani_object wantObj, ani_object call)
{
    EVENT_LOGD("StartAbility");
    StsStaticSubscriberExtensionContext::GetInstance().StartAbilityInner(env, aniObj, wantObj, call);
}

void StsStaticSubscriberExtensionContext::StartAbilityInner([[maybe_unused]] ani_env *env,
    [[maybe_unused]] ani_object aniObj, ani_object wantObj, ani_object call)
{
    EVENT_LOGD("StartAbilityInner");
    AAFwk::Want want;
    ani_object aniObject = nullptr;
    ErrCode innerErrCode = ERR_OK;
    if (!AppExecFwk::UnwrapWant(env, wantObj, want)) {
        EVENT_LOGE("UnwrapWant filed");
        aniObject = CreateStsInvalidParamError(env, "UnwrapWant filed");
        AppExecFwk::AsyncCallback(env, call, aniObject, nullptr);
        return;
    }
    auto context = StsStaticSubscriberExtensionContext::GetAbilityContext(env, aniObj);
    if (context == nullptr) {
        EVENT_LOGE("GetAbilityContext is nullptr");
        innerErrCode = static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
        aniObject = CreateStsError(env, static_cast<AbilityErrorCode>(innerErrCode));
        AppExecFwk::AsyncCallback(env, call, aniObject, nullptr);
        return;
    }
        innerErrCode = context->StartAbility(want);
}

StaticSubscriberExtensionContext* StsStaticSubscriberExtensionContext::GetAbilityContext(ani_env *env, ani_object obj)
{
    EVENT_LOGD("GetAbilityContext");
    ani_class cls = nullptr;
    ani_long nativeContextLong;
    ani_field contextField = nullptr;
    ani_status status = ANI_ERROR;
    if (env == nullptr) {
        EVENT_LOGD("null env");
        return nullptr;
    }
    if ((status = env->FindClass(STATIC_SUBSCRIBER_EXTENSION_CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
        EVENT_LOGD("GetAbilityContext find class status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindField(cls, "nativeStaticSubscriberExtensionContext", &contextField)) != ANI_OK) {
        EVENT_LOGD("GetAbilityContext find field status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_GetField_Long(obj, contextField, &nativeContextLong)) != ANI_OK) {
        EVENT_LOGD("GetAbilityContext get filed status: %{public}d", status);
        return nullptr;
    }
    return (StaticSubscriberExtensionContext*)nativeContextLong;
}

ani_object CreateStaticSubscriberExtensionContext(ani_env *env,
    std::shared_ptr<StaticSubscriberExtensionContext> context,
    const std::shared_ptr<OHOS::AppExecFwk::OHOSApplication> &application)
{
    if (env == nullptr) {
        EVENT_LOGE("null env");
        return nullptr;
    }
    std::shared_ptr<OHOS::AppExecFwk::AbilityInfo> abilityInfo = nullptr;
    if (context) {
        abilityInfo = context->GetAbilityInfo();
    }
    ani_class cls = nullptr;
    ani_object contextObj = nullptr;
    ani_field field = nullptr;
    ani_method method = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass(STATIC_SUBSCRIBER_EXTENSION_CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
        EVENT_LOGE("find class status : %{public}d", status);
        return nullptr;
    }
    std::array functions = {
        ani_native_function { "nativeStartAbilitySync", "L@ohos/app/ability/Want/Want;:V",
            reinterpret_cast<void*>(StartAbility) },
    };
    if ((status = env->Class_BindNativeMethods(cls, functions.data(), functions.size())) != ANI_OK) {
        EVENT_LOGE("bind method status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        EVENT_LOGE("find Method status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &contextObj)) != ANI_OK) {
        EVENT_LOGE("new Object status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindField(cls, "nativeStaticSubscriberExtensionContext", &field)) != ANI_OK) {
        EVENT_LOGE("find field status: %{public}d", status);
        return nullptr;
    }
    ani_long nativeContextLong = (ani_long)context.get();
    if ((status = env->Object_SetField_Long(contextObj, field, nativeContextLong)) != ANI_OK) {
        EVENT_LOGE("set field status: %{public}d", status);
        return nullptr;
    }
    if (application == nullptr) {
        EVENT_LOGE("application null");
        return nullptr;
    }
    OHOS::AbilityRuntime::CreatEtsExtensionContext(env, cls, contextObj, context, context->GetAbilityInfo());
    return contextObj;
}
} // EventManagerFwkAni
} // OHOS