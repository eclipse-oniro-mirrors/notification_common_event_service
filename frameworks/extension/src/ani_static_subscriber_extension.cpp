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

#include "ani_static_subscriber_extension.h"

#include "ability_handler.h"
#include "ani_common_want.h"
#include "ani_common_event_utils.h"
#include "ani_static_subscriber_extension_context.h"
#include "application_context.h"
#include "context.h"
#include "connection_manager.h"
#include "event_log_wrapper.h"
#include "extension_base.h"
#include "native_engine/native_engine.h"
#include "sts_runtime.h"
#include "static_subscriber_stub_impl.h"

namespace OHOS {
namespace EventManagerFwkAni {
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime;
using namespace OHOS::EventFwk;
using namespace OHOS::EventManagerFwkAni;

StsStaticSubscriberExtension* StsStaticSubscriberExtension::Create(const std::unique_ptr<Runtime>& runtime)
{
    return new StsStaticSubscriberExtension(static_cast<STSRuntime&>(*runtime));
}
StsStaticSubscriberExtension::StsStaticSubscriberExtension(STSRuntime &stsRuntime) : stsRuntime_(stsRuntime) {}
StsStaticSubscriberExtension::~StsStaticSubscriberExtension()
{
    EVENT_LOGD("~StsStaticSubscriberExtension called");
}

void StsStaticSubscriberExtension::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application, std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    if (record == nullptr) {
        EVENT_LOGE("record null");
        return;
    }
    StaticSubscriberExtension::Init(record, application, handler, token);
    if (Extension::abilityInfo_ == nullptr || Extension::abilityInfo_->srcEntrance.empty()) {
        EVENT_LOGE("StaticSubscriberExtension Init abilityInfo error");
        return;
    }
    std::string srcPath(Extension::abilityInfo_->moduleName + "/");
    srcPath.append(Extension::abilityInfo_->srcEntrance);
    auto pos = srcPath.rfind(".");
    if (pos != std::string::npos) {
        srcPath.erase(pos);
        srcPath.append(".abc");
    }
    std::string moduleName(Extension::abilityInfo_->moduleName);
    moduleName.append("::").append(abilityInfo_->name);
    stsObj_ = stsRuntime_.LoadModule(
        moduleName, srcPath, abilityInfo_->hapPath, abilityInfo_->compileMode == AppExecFwk::CompileMode::ES_MODULE,
        false, abilityInfo_->srcEntrance);
    if (stsObj_ == nullptr) {
        EVENT_LOGE("stsObj_ null");
        return;
    }

    auto env = stsRuntime_.GetAniEnv();
    if (env == nullptr) {
        EVENT_LOGE("null env");
        return;
    }
    BindContext(env, application);
    return;
}

void StsStaticSubscriberExtension::BindContext(ani_env* env, const std::shared_ptr<OHOSApplication> &application)
{
    EVENT_LOGD("StsStaticSubscriberExtension BindContext Call");
    auto context = GetContext();
    if (context == nullptr) {
        EVENT_LOGE("Failed to get context");
        return;
    }

    ani_object contextObj = CreateSTSContext(env, context, application);
    if (contextObj == nullptr) {
        EVENT_LOGE("null contextObj");
        return;
    }

    ani_field contextField;
    auto status = env->Class_FindField(stsObj_->aniCls, "context", &contextField);
    if (status != ANI_OK) {
        EVENT_LOGE("Class_GetField context failed");
        ResetEnv(env);
        return;
    }
    ani_ref contextRef = nullptr;
    if (env->GlobalReference_Create(contextObj, &contextRef) != ANI_OK) {
        EVENT_LOGE("GlobalReference_Create contextObj failed");
        return;
    }
    if (env->Object_SetField_Ref(stsObj_->aniObj, contextField, contextRef) != ANI_OK) {
        EVENT_LOGE("Object_SetField_Ref contextObj failed");
        ResetEnv(env);
    }
}

ani_object StsStaticSubscriberExtension::CreateSTSContext(ani_env* env,
    std::shared_ptr<StaticSubscriberExtensionContext> context,
    const std::shared_ptr<OHOSApplication> &application)
{
    ani_object STSContext = CreateStaticSubscriberExtensionContext(env, context, application);
    return STSContext;
}

std::weak_ptr<StsStaticSubscriberExtension> StsStaticSubscriberExtension::GetWeakPtr()
{
    return std::static_pointer_cast<StsStaticSubscriberExtension>(shared_from_this());
}

void StsStaticSubscriberExtension::OnReceiveEvent(std::shared_ptr<CommonEventData> data)
{
    const CommonEventData& commonEventData = *data;
    EVENT_LOGD("OnReceiveEvent execute action = %{public}s", commonEventData.GetWant().GetAction().c_str());

    if (handler_ == nullptr) {
        EVENT_LOGE("handler is invalid");
        return;
    }
    std::weak_ptr<StsStaticSubscriberExtension> wThis = GetWeakPtr();
    auto task = [wThis, commonEventData, this]() {
        std::shared_ptr<StsStaticSubscriberExtension> sThis = wThis.lock();
        if (sThis == nullptr) {
            return;
        }
        ani_env* env = sThis->stsRuntime_.GetAniEnv();
        if (!env) {
            EVENT_LOGE("task env not found env");
            return;
        }

        ani_object ani_data {};
        AniCommonEventUtils::ConvertCommonEventDataToEts(env, ani_data, commonEventData);
        const char* signature  = "commonEvent.commonEventData.CommonEventData:";
        CallObjectMethod(false, "onReceiveEvent", signature, ani_data);
    };
    handler_->PostTask(task, "CommonEvent" + data->GetWant().GetAction());
}

void StsStaticSubscriberExtension::ResetEnv(ani_env* env)
{
    env->DescribeError();
    env->ResetError();
}

void StsStaticSubscriberExtension::OnStart(const AAFwk::Want& want)
{
    EVENT_LOGD("%{public}s called.", __func__);
    Extension::OnStart(want);
}

void StsStaticSubscriberExtension::OnStop()
{
    EVENT_LOGD("%{public}s called.", __func__);
    Extension::OnStop();
}

void StsStaticSubscriberExtension::OnDisconnect(const AAFwk::Want& want)
{
    EVENT_LOGD("%{public}s called.", __func__);
    Extension::OnDisconnect(want);
}

sptr<IRemoteObject> StsStaticSubscriberExtension::OnConnect(const AAFwk::Want& want)
{
    EVENT_LOGD("%{public}s called.", __func__);
    Extension::OnConnect(want);
    sptr<StaticSubscriberStubImpl> remoteObject = new (std::nothrow) StaticSubscriberStubImpl(
        std::static_pointer_cast<StsStaticSubscriberExtension>(shared_from_this()));
    if (remoteObject == nullptr) {
        EVENT_LOGE("failed to create StaticSubscriberStubImpl");
        return nullptr;
    }
    return remoteObject->AsObject();
}

void StsStaticSubscriberExtension::CallObjectMethod(bool withResult, const char *name, const char *signature, ...)
{
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    auto env = stsRuntime_.GetAniEnv();
    if (!env) {
        EVENT_LOGE("env not found StsStaticSubscriberExtensions");
        return;
    }
    if (stsObj_ == nullptr) {
        EVENT_LOGE("stsObj_ nullptr");
        return;
    }
    if ((status = env->Class_FindMethod(stsObj_->aniCls, name, signature, &method)) != ANI_OK) {
        EVENT_LOGE("Class_FindMethod nullptr:%{public}d", status);
        return;
    }
    if (method == nullptr) {
        return;
    }

    ani_ref res = nullptr;
    va_list args;
    if (withResult) {
        va_start(args, signature);
        if ((status = env->Object_CallMethod_Ref_V(stsObj_->aniObj, method, &res, args)) != ANI_OK) {
            EVENT_LOGE("status : %{public}d", status);
        }
        va_end(args);
        return;
    }
    va_start(args, signature);
    if ((status = env->Object_CallMethod_Void_V(stsObj_->aniObj, method, args)) != ANI_OK) {
        EVENT_LOGE("status : %{public}d", status);
    }
    va_end(args);
    return;
}
} // EventManagerFwkAni
} // OHOS
