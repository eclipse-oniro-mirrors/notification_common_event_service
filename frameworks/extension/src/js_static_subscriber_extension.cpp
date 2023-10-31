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

#include "js_static_subscriber_extension.h"

#include "ability_info.h"
#include "ability_handler.h"
#include "event_log_wrapper.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "js_static_subscriber_extension_context.h"
#include "napi_common_want.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_remote_object.h"
#include "static_subscriber_stub_impl.h"

namespace OHOS {
namespace EventFwk {
namespace {
constexpr size_t ARGC_ONE = 1;
}

using namespace OHOS::AppExecFwk;

napi_value AttachStaticSubscriberExtensionContext(napi_env env, void* value, void*)
{
    EVENT_LOGD("AttachStaticSubscriberExtensionContext");
    if (value == nullptr) {
        EVENT_LOGE("invalid parameter.");
        return nullptr;
    }

    auto ptr = reinterpret_cast<std::weak_ptr<StaticSubscriberExtensionContext>*>(value)->lock();
    if (ptr == nullptr) {
        EVENT_LOGE("invalid context.");
        return nullptr;
    }

    napi_value object = CreateJsStaticSubscriberExtensionContext(env, ptr);
    auto napiContextObj = AbilityRuntime::JsRuntime::LoadSystemModuleByEngine(env,
        "application.StaticSubscriberExtensionContext", &object, 1)->GetNapiValue();
    napi_coerce_to_native_binding_object(env, napiContextObj, AbilityRuntime::DetachCallbackFunc,
        AttachStaticSubscriberExtensionContext, value, nullptr);
    auto workContext = new (std::nothrow) std::weak_ptr<StaticSubscriberExtensionContext>(ptr);

    napi_wrap(env, napiContextObj, workContext,
        [](napi_env, void* data, void*) {
            EVENT_LOGI("Finalizer for weak_ptr static subscriber extension context is called");
            delete static_cast<std::weak_ptr<StaticSubscriberExtensionContext>*>(data);
        }, nullptr, nullptr);
    return napiContextObj;
}

JsStaticSubscriberExtension* JsStaticSubscriberExtension::Create(
    const std::unique_ptr<AbilityRuntime::Runtime>& runtime)
{
    return new (std::nothrow) JsStaticSubscriberExtension(static_cast<AbilityRuntime::JsRuntime&>(*runtime));
}

JsStaticSubscriberExtension::JsStaticSubscriberExtension(AbilityRuntime::JsRuntime& jsRuntime)
    : jsRuntime_(jsRuntime) {}
JsStaticSubscriberExtension::~JsStaticSubscriberExtension()
{
    EVENT_LOGD("Js static subscriber extension destructor.");
    auto context = GetContext();
    if (context) {
        context->Unbind();
    }

    jsRuntime_.FreeNativeReference(std::move(jsObj_));
}

void JsStaticSubscriberExtension::Init(const std::shared_ptr<AppExecFwk::AbilityLocalRecord>& record,
    const std::shared_ptr<AppExecFwk::OHOSApplication>& application,
    std::shared_ptr<AppExecFwk::AbilityHandler>& handler,
    const sptr<IRemoteObject>& token)
{
    StaticSubscriberExtension::Init(record, application, handler, token);
    if (Extension::abilityInfo_->srcEntrance.empty()) {
        EVENT_LOGE("srcEntrance of abilityInfo is empty");
        return;
    }

    std::string srcPath(Extension::abilityInfo_->moduleName + "/");
    srcPath.append(Extension::abilityInfo_->srcEntrance);
    srcPath.erase(srcPath.rfind('.'));
    srcPath.append(".abc");

    std::string moduleName(Extension::abilityInfo_->moduleName);
    moduleName.append("::").append(abilityInfo_->name);
    EVENT_LOGD("moduleName: %{public}s, srcPath: %{public}s.", moduleName.c_str(), srcPath.c_str());
    AbilityRuntime::HandleScope handleScope(jsRuntime_);
    napi_env env = jsRuntime_.GetNapiEnv();

    jsObj_ = jsRuntime_.LoadModule(moduleName, srcPath, abilityInfo_->hapPath,
        abilityInfo_->compileMode == CompileMode::ES_MODULE);
    if (jsObj_ == nullptr) {
        EVENT_LOGE("Failed to load module");
        return;
    }
    napi_value obj = jsObj_->GetNapiValue();
    if (obj == nullptr) {
        EVENT_LOGE("Failed to get static subscriber extension object");
        return;
    }

    auto context = GetContext();
    if (context == nullptr) {
        EVENT_LOGE("Failed to get context");
        return;
    }

    napi_value contextObj = CreateJsStaticSubscriberExtensionContext(env, context);
    auto shellContextRef = AbilityRuntime::JsRuntime::LoadSystemModuleByEngine(
        env, "application.StaticSubscriberExtensionContext", &contextObj, ARGC_ONE);
    napi_value nativeObj = shellContextRef->GetNapiValue();
    if (nativeObj == nullptr) {
        EVENT_LOGE("Failed to get context native object");
        return;
    }

    auto workContext = new (std::nothrow) std::weak_ptr<StaticSubscriberExtensionContext>(context);
    napi_coerce_to_native_binding_object(env, nativeObj, AbilityRuntime::DetachCallbackFunc,
        AttachStaticSubscriberExtensionContext, workContext, nullptr);
    context->Bind(jsRuntime_, shellContextRef.release());
    napi_set_named_property(env, obj, "context", nativeObj);

    EVENT_LOGD("Set static subscriber extension context");
    napi_wrap(env, nativeObj, workContext,
        [](napi_env, void* data, void*) {
        EVENT_LOGI("Finalizer for weak_ptr static subscriber extension context is called");
        delete static_cast<std::weak_ptr<StaticSubscriberExtensionContext>*>(data);
        }, nullptr, nullptr);

    EVENT_LOGI("Init end.");
}

void JsStaticSubscriberExtension::OnStart(const AAFwk::Want& want)
{
    EVENT_LOGD("%{public}s called.", __func__);
    Extension::OnStart(want);
}

void JsStaticSubscriberExtension::OnStop()
{
    EVENT_LOGD("%{public}s called.", __func__);
    Extension::OnStop();
}

sptr<IRemoteObject> JsStaticSubscriberExtension::OnConnect(const AAFwk::Want& want)
{
    EVENT_LOGD("%{public}s called.", __func__);
    Extension::OnConnect(want);
    sptr<StaticSubscriberStubImpl> remoteObject = new (std::nothrow) StaticSubscriberStubImpl(
        std::static_pointer_cast<JsStaticSubscriberExtension>(shared_from_this()));
    return remoteObject->AsObject();
}

void JsStaticSubscriberExtension::OnDisconnect(const AAFwk::Want& want)
{
    EVENT_LOGD("%{public}s called.", __func__);
    Extension::OnDisconnect(want);
}

void JsStaticSubscriberExtension::OnReceiveEvent(std::shared_ptr<CommonEventData> data)
{
    EVENT_LOGD("%{public}s called.", __func__);
    if (handler_ == nullptr) {
        EVENT_LOGE("handler is invalid");
        return;
    }

    auto task = [this, data]() {
        if (data == nullptr) {
            EVENT_LOGE("OnReceiveEvent common event data is invalid");
            return;
        }
        StaticSubscriberExtension::OnReceiveEvent(data);
        if (!jsObj_) {
            EVENT_LOGE("Not found StaticSubscriberExtension.js");
            return;
        }

        AbilityRuntime::HandleScope handleScope(jsRuntime_);
        napi_env env = jsRuntime_.GetNapiEnv();
        napi_value commonEventData = nullptr;
        napi_create_object(env, &commonEventData);
        Want want = data->GetWant();

        napi_value wantAction = nullptr;
        napi_create_string_utf8(env, want.GetAction().c_str(), want.GetAction().size(), &wantAction);
        napi_set_named_property(env, commonEventData, "event", wantAction);
        napi_value wantBundle = nullptr;
        napi_create_string_utf8(env, want.GetBundle().c_str(), want.GetBundle().size(), &wantBundle);
        napi_set_named_property(env, commonEventData, "bundleName", wantBundle);
        napi_value dataCode = nullptr;
        napi_create_int32(env, data->GetCode(), &dataCode);
        napi_set_named_property(env, commonEventData, "code", dataCode);
        napi_value dataNapi = nullptr;
        napi_create_string_utf8(env, data->GetData().c_str(), data->GetData().size(), &dataNapi);
        napi_set_named_property(env, commonEventData, "data", dataNapi);
        napi_value napiParams = AppExecFwk::WrapWantParams(
            env, want.GetParams());
        napi_set_named_property(env, commonEventData, "parameters", napiParams);

        napi_value argv[] = {commonEventData};
        napi_value obj = jsObj_->GetNapiValue();
        if (obj == nullptr) {
            EVENT_LOGE("Failed to get StaticSubscriberExtension object");
            return;
        }

        napi_value method = nullptr;
        napi_get_named_property(env, obj, "onReceiveEvent", &method);
        if (method == nullptr) {
            EVENT_LOGE("Failed to get onReceiveEvent from StaticSubscriberExtension object");
            return;
        }
        napi_call_function(env, obj, method, ARGC_ONE, argv, nullptr);
        EVENT_LOGD("JsStaticSubscriberExtension js receive event called.");
    };
    handler_->PostTask(task, "CommonEvent" + data->GetWant().GetAction());
}
} // namespace EventFwk
} // namespace OHOS
