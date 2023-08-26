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

NativeValue* AttachStaticSubscriberExtensionContext(NativeEngine* engine, void* value, void*)
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

    NativeValue* object = CreateJsStaticSubscriberExtensionContext(*engine, ptr);
    auto contextObj = AbilityRuntime::JsRuntime::LoadSystemModuleByEngine(engine,
        "application.StaticSubscriberExtensionContext", &object, 1)->Get();
    NativeObject* nObject = AbilityRuntime::ConvertNativeValueTo<NativeObject>(contextObj);
    nObject->ConvertToNativeBindingObject(engine,
        AbilityRuntime::DetachCallbackFunc, AttachStaticSubscriberExtensionContext, value, nullptr);
    auto workContext = new (std::nothrow) std::weak_ptr<StaticSubscriberExtensionContext>(ptr);
    nObject->SetNativePointer(workContext,
        [](NativeEngine*, void* data, void*) {
            EVENT_LOGI("Finalizer for weak_ptr static subscriber extension context is called");
            delete static_cast<std::weak_ptr<StaticSubscriberExtensionContext>*>(data);
        }, nullptr);
    return contextObj;
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
    auto& engine = jsRuntime_.GetNativeEngine();

    jsObj_ = jsRuntime_.LoadModule(moduleName, srcPath, abilityInfo_->hapPath,
        abilityInfo_->compileMode == CompileMode::ES_MODULE);
    if (jsObj_ == nullptr) {
        EVENT_LOGE("Failed to load module");
        return;
    }

    NativeObject* obj = AbilityRuntime::ConvertNativeValueTo<NativeObject>(jsObj_->Get());
    if (obj == nullptr) {
        EVENT_LOGE("Failed to get static subscriber extension object");
        return;
    }

    auto context = GetContext();
    if (context == nullptr) {
        EVENT_LOGE("Failed to get context");
        return;
    }

    NativeValue* contextObj = CreateJsStaticSubscriberExtensionContext(engine, context);
    auto shellContextRef = AbilityRuntime::JsRuntime::LoadSystemModuleByEngine(
        &engine, "application.StaticSubscriberExtensionContext", &contextObj, ARGC_ONE);
    contextObj = shellContextRef->Get();
    NativeObject* nativeObj = AbilityRuntime::ConvertNativeValueTo<NativeObject>(contextObj);
    if (nativeObj == nullptr) {
        EVENT_LOGE("Failed to get context native object");
        return;
    }

    auto workContext = new (std::nothrow) std::weak_ptr<StaticSubscriberExtensionContext>(context);
    nativeObj->ConvertToNativeBindingObject(&engine, AbilityRuntime::DetachCallbackFunc,
        AttachStaticSubscriberExtensionContext, workContext, nullptr);
    context->Bind(jsRuntime_, shellContextRef.release());
    obj->SetProperty("context", contextObj);

    EVENT_LOGD("Set static subscriber extension context");
    nativeObj->SetNativePointer(workContext,
        [](NativeEngine*, void* data, void*) {
            EVENT_LOGI("Finalizer for weak_ptr static subscriber extension context is called");
            delete static_cast<std::weak_ptr<StaticSubscriberExtensionContext>*>(data);
        }, nullptr);

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
        NativeEngine& nativeEngine = jsRuntime_.GetNativeEngine();
        NativeValue* jCommonEventData = nativeEngine.CreateObject();
        NativeObject* commonEventData = AbilityRuntime::ConvertNativeValueTo<NativeObject>(jCommonEventData);
        Want want = data->GetWant();
        commonEventData->SetProperty("event",
            nativeEngine.CreateString(want.GetAction().c_str(), want.GetAction().size()));
        commonEventData->SetProperty("bundleName",
            nativeEngine.CreateString(want.GetBundle().c_str(), want.GetBundle().size()));
        commonEventData->SetProperty("code", nativeEngine.CreateNumber(data->GetCode()));
        commonEventData->SetProperty("data",
            nativeEngine.CreateString(data->GetData().c_str(), data->GetData().size()));
        napi_value napiParams = AppExecFwk::WrapWantParams(
            reinterpret_cast<napi_env>(&nativeEngine), want.GetParams());
        NativeValue* nativeParams = reinterpret_cast<NativeValue*>(napiParams);
        commonEventData->SetProperty("parameters", nativeParams);

        NativeValue* argv[] = {jCommonEventData};
        NativeValue* value = jsObj_->Get();
        NativeObject* obj = AbilityRuntime::ConvertNativeValueTo<NativeObject>(value);
        if (obj == nullptr) {
            EVENT_LOGE("Failed to get StaticSubscriberExtension object");
            return;
        }

        NativeValue* method = obj->GetProperty("onReceiveEvent");
        if (method == nullptr) {
            EVENT_LOGE("Failed to get onReceiveEvent from StaticSubscriberExtension object");
            return;
        }
        nativeEngine.CallFunction(value, method, argv, ARGC_ONE);
        EVENT_LOGD("JsStaticSubscriberExtension js receive event called.");
    };
    handler_->PostTask(task);
}
} // namespace EventFwk
} // namespace OHOS
