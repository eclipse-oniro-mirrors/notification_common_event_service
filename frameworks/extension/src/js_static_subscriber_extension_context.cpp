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
constexpr size_t ARGC_TWO = 2;
class JsStaticSubscriberExtensionContext final {
public:
    explicit JsStaticSubscriberExtensionContext(const std::shared_ptr<StaticSubscriberExtensionContext>& context)
        : context_(context) {}
    ~JsStaticSubscriberExtensionContext() = default;

    static void Finalizer(NativeEngine* engine, void* data, void* hint)
    {
        EVENT_LOGI("Finalizer is called");
        std::unique_ptr<JsStaticSubscriberExtensionContext>(
            static_cast<JsStaticSubscriberExtensionContext*>(data));
    }

    static NativeValue* StartAbility(NativeEngine* engine, NativeCallbackInfo* info);
private:

    NativeValue* OnStartAbility(NativeEngine& engine, NativeCallbackInfo& info, bool isStartRecent = false);
    std::weak_ptr<StaticSubscriberExtensionContext> context_;
};
} // namespace

NativeValue* JsStaticSubscriberExtensionContext::StartAbility(NativeEngine* engine, NativeCallbackInfo* info)
{
    EVENT_LOGI("OnStartAbility is called.");
    JsStaticSubscriberExtensionContext* me =
        AbilityRuntime::CheckParamsAndGetThis<JsStaticSubscriberExtensionContext>(engine, info);
    return (me != nullptr) ? me->OnStartAbility(*engine, *info) : nullptr;
}

NativeValue* JsStaticSubscriberExtensionContext::OnStartAbility(NativeEngine& engine, NativeCallbackInfo& info,
    bool isStartRecent)
{
    EVENT_LOGI("OnStartAbility is called.");

    if (info.argc == ARGC_ZERO || info.argc > ARGC_TWO) {
        EVENT_LOGE("Not enough params");
        AbilityRuntime::ThrowTooFewParametersError(engine);
        return engine.CreateUndefined();
    }

    AAFwk::Want want;
    OHOS::AppExecFwk::UnwrapWant(reinterpret_cast<napi_env>(&engine), reinterpret_cast<napi_value>(info.argv[0]), want);
    decltype(info.argc) unwrapArgc = 1;
    EVENT_LOGI("Start ability, ability name is %{public}s.", want.GetElement().GetAbilityName().c_str());

    auto innerErrorCode = std::make_shared<int32_t>(ERR_OK);
    AbilityRuntime::AsyncTask::ExecuteCallback execute = [weak = context_, want, innerErrorCode]() {
        auto context = weak.lock();
        if (!context) {
            EVENT_LOGW("context is released");
            *innerErrorCode = static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
            return;
        }

        *innerErrorCode = context->StartAbility(want);
    };

    AbilityRuntime::AsyncTask::CompleteCallback complete =
        [innerErrorCode](NativeEngine& engine, AbilityRuntime::AsyncTask& task, int32_t status) {
            if (*innerErrorCode == ERR_OK) {
                task.Resolve(engine, engine.CreateUndefined());
            } else {
                task.Reject(engine, AbilityRuntime::CreateJsErrorByNativeErr(engine, *innerErrorCode));
            }
        };

    NativeValue* lastParam = (info.argc > unwrapArgc) ? info.argv[unwrapArgc] : nullptr;
    NativeValue* result = nullptr;

    AbilityRuntime::AsyncTask::Schedule("JsAbilityContext::OnStartAbility", engine,
        CreateAsyncTaskWithLastParam(engine, lastParam, std::move(execute), std::move(complete), &result));

    return result;
}

NativeValue* CreateJsStaticSubscriberExtensionContext(NativeEngine& engine,
    std::shared_ptr<StaticSubscriberExtensionContext> context)
{
    EVENT_LOGI("Create js static subscriber extension context");
    std::shared_ptr<OHOS::AppExecFwk::AbilityInfo> abilityInfo = nullptr;
    if (context) {
        abilityInfo = context->GetAbilityInfo();
    }

    NativeValue* objValue = CreateJsExtensionContext(engine, context, abilityInfo);
    NativeObject* object = AbilityRuntime::ConvertNativeValueTo<NativeObject>(objValue);

    std::unique_ptr<JsStaticSubscriberExtensionContext> jsContext =
        std::make_unique<JsStaticSubscriberExtensionContext>(context);
    object->SetNativePointer(jsContext.release(), JsStaticSubscriberExtensionContext::Finalizer, nullptr);

    const char* moduleName = "JsStaticSubscriberExtensionContext";
    AbilityRuntime::BindNativeFunction(engine, *object, "startAbility", moduleName,
        JsStaticSubscriberExtensionContext::StartAbility);
    return objValue;
}
} // namespace EventFwk
} // namespace OHOS
