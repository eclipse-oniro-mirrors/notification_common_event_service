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

#include "js_static_subscriber_extension_context.h"

#include "ability_business_error.h"
#include "event_log_wrapper.h"
#include "js_error_utils.h"
#include "js_extension_context.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "napi/native_api.h"
#include "napi_common_want.h"
#include "want.h"

namespace OHOS {
namespace EventFwk {
namespace {
constexpr size_t ARGC_ZERO = 0;
constexpr size_t ARGC_ONE = 1;
constexpr size_t ARGC_TWO = 2;
class JsStaticSubscriberExtensionContext final {
public:
    explicit JsStaticSubscriberExtensionContext(const std::shared_ptr<StaticSubscriberExtensionContext>& context)
        : context_(context) {}
    ~JsStaticSubscriberExtensionContext() = default;

    static void Finalizer(napi_env env, void* data, void* hint)
    {
        EVENT_LOGI("Finalizer is called");
        std::unique_ptr<JsStaticSubscriberExtensionContext>(
            static_cast<JsStaticSubscriberExtensionContext*>(data));
    }

    static napi_value StartAbility(napi_env env, napi_callback_info info);
private:
    napi_value OnStartAbility(napi_env env, napi_callback_info info, bool isStartRecent = false);
    std::weak_ptr<StaticSubscriberExtensionContext> context_;
};
} // namespace

napi_value JsStaticSubscriberExtensionContext::StartAbility(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("called.");
    JsStaticSubscriberExtensionContext* me =
        AbilityRuntime::CheckParamsAndGetThis<JsStaticSubscriberExtensionContext>(env, info);
    return (me != nullptr) ? me->OnStartAbility(env, info) : nullptr;
}

napi_value JsStaticSubscriberExtensionContext::OnStartAbility(napi_env env, napi_callback_info info,
    bool isStartRecent)
{
    EVENT_LOGD("called.");
    napi_value undefined = nullptr;
    napi_get_undefined(env, &undefined);

    size_t argc = ARGC_TWO;
    napi_value argv[ARGC_TWO] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc == ARGC_ZERO) {
        EVENT_LOGE("Not enough params");
        AbilityRuntime::ThrowTooFewParametersError(env);
        return undefined;
    }

    AAFwk::Want want;
    AppExecFwk::UnwrapWant(env, argv[0], want);
    EVENT_LOGI("Start ability, ability name is %{public}s.", want.GetElement().GetAbilityName().c_str());

    auto innerErrorCode = std::make_shared<int32_t>(ERR_OK);
    AbilityRuntime::NapiAsyncTask::ExecuteCallback execute = [weak = context_, want, innerErrorCode]() {
        auto context = weak.lock();
        if (!context) {
            EVENT_LOGW("context is released");
            *innerErrorCode = static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
            return;
        }
        *innerErrorCode = context->StartAbility(want);
    };

    AbilityRuntime::NapiAsyncTask::CompleteCallback complete =
        [innerErrorCode](napi_env env, AbilityRuntime::NapiAsyncTask& task, int32_t status) {
            if (*innerErrorCode == ERR_OK) {
                napi_value taskUndefined = nullptr;
                napi_get_undefined(env, &taskUndefined);
                task.Resolve(env, taskUndefined);
            } else {
                task.Reject(env, AbilityRuntime::CreateJsErrorByNativeErr(env, *innerErrorCode));
            }
        };

    napi_value lastParam = (argc > ARGC_ONE) ? argv[ARGC_ONE] : nullptr;
    napi_value result = nullptr;

    AbilityRuntime::NapiAsyncTask::Schedule("JsStaticSubscriberExtensionContext::OnStartAbility", env,
        CreateAsyncTaskWithLastParam(env, lastParam, std::move(execute), std::move(complete), &result));

    return result;
}

napi_value CreateJsStaticSubscriberExtensionContext(napi_env env,
    std::shared_ptr<StaticSubscriberExtensionContext> context)
{
    EVENT_LOGI("Create js static subscriber extension context");
    std::shared_ptr<OHOS::AppExecFwk::AbilityInfo> abilityInfo = nullptr;
    if (context) {
        abilityInfo = context->GetAbilityInfo();
    }

    napi_value objValue = CreateJsExtensionContext(env, context, abilityInfo);
    std::unique_ptr<JsStaticSubscriberExtensionContext> jsContext =
        std::make_unique<JsStaticSubscriberExtensionContext>(context);
    napi_wrap(env, objValue, jsContext.release(), JsStaticSubscriberExtensionContext::Finalizer, nullptr, nullptr);

    const char* moduleName = "JsStaticSubscriberExtensionContext";
    AbilityRuntime::BindNativeFunction(env, objValue, "startAbility", moduleName,
        JsStaticSubscriberExtensionContext::StartAbility);
    return objValue;
}
} // namespace EventFwk
} // namespace OHOS
