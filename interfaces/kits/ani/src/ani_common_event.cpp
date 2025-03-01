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

#include "ani_common_event.h"

#include <ani.h>
#include <array>
#include <iostream>
#include <unistd.h>

#include "event_log_wrapper.h"

using namespace OHOS::EventFwk;

static void GetStdString(ani_env* env, ani_string str, std::string& result)
{
    auto ret = ANI_OK;
    ani_size sz {};
    ret = env->String_GetUTF8Size(str, &sz);
    if (ret != ANI_OK) {
        EVENT_LOGE("GetStdString String_GetUTF8Size error. result: %{public}d.", ret);
        return;
    }
    result.resize(sz + 1);
    ret = env->String_GetUTF8SubString(str, 0, sz, result.data(), result.size(), &sz);
    if (ret != ANI_OK) {
        EVENT_LOGE("GetStdString String_GetUTF8Size error. result: %{public}d.", ret);
        return;
    }
    result.resize(sz);
}

static uint32_t publishExecute(ani_env* env, ani_object obj, ani_string eventId)
{
    EVENT_LOGI("publishExecute call.");
    std::string eventIdStr;
    GetStdString(env, eventId, eventIdStr);
    EVENT_LOGI("publishExecute eventIdStr: %{public}s.", eventIdStr.c_str());
    CommonEventData commonEventData;
    CommonEventPublishInfo commonEventPublishInfo;
    Want want;
    want.SetAction(eventIdStr);
    commonEventData.SetWant(want);
    auto errorCode = CommonEventManager::NewPublishCommonEvent(commonEventData, commonEventPublishInfo);
    EVENT_LOGI("publishExecute result: %{public}d.", errorCode);
    return errorCode;
}

static uint32_t publishWithOptionsExecute(ani_env* env, ani_object obj, ani_string eventId, ani_object optionsObject)
{
    EVENT_LOGI("publishWithOptionsExecute call.");
    std::string eventIdStr;
    GetStdString(env, eventId, eventIdStr);
    EVENT_LOGI("publishWithOptionsExecute eventIdStr: %{public}s.", eventIdStr.c_str());
    auto aniResult = ANI_OK;
    ani_ref bundleNameRef {};
    aniResult = env->Object_GetFieldByName_Ref(optionsObject, "bundleName", &bundleNameRef);
    if (aniResult != ANI_OK) {
        EVENT_LOGE("publishWithOptionsExecute Class_FindField error. result: %{public}d.", aniResult);
        return ANI_INVALID_ARGS;
    }
    ani_string bundleName = static_cast<ani_string>(bundleNameRef);
    std::string bundleNameStr;
    GetStdString(env, bundleName, bundleNameStr);
    EVENT_LOGI("publishWithOptionsExecute bundleName: %{public}s.", bundleNameStr.c_str());

    CommonEventData commonEventData;
    CommonEventPublishInfo commonEventPublishInfo;
    commonEventPublishInfo.SetBundleName(bundleNameStr);
    Want want;
    want.SetAction(eventIdStr);
    commonEventData.SetWant(want);
    auto errorCode = CommonEventManager::NewPublishCommonEvent(commonEventData, commonEventPublishInfo);
    EVENT_LOGI("publishWithOptionsExecute result: %{public}d.", errorCode);
    return errorCode;
}

static ani_ref createSubscriberExecute(ani_env* env, ani_object obj, ani_ref optionsRef)
{
    EVENT_LOGI("createSubscriberExecute call.");
    CommonEventSubscribeInfo subscribeInfo;
    auto ret = ANI_OK;
    auto wrapper = new (std::nothrow) SubscriberInstanceWrapper(subscribeInfo);

    ani_class cls;
    ret = env->FindClass("Lsts_common_event/CommonEventSubscriber;", &cls);
    if (ret != ANI_OK) {
        EVENT_LOGE("createSubscriberExecute FindClass error. result: %{public}d.", ret);
        return nullptr;
    }
    ani_method ctor;
    ret = env->Class_FindMethod(cls, "<ctor>", ":V", &ctor);
    if (ret != ANI_OK) {
        EVENT_LOGE("createSubscriberExecute Class_FindMethod error. result: %{public}d.", ret);
        return nullptr;
    }
    ani_object subscriberObj;
    ret = env->Object_New(cls, ctor, &subscriberObj);
    if (ret != ANI_OK) {
        EVENT_LOGE("createSubscriberExecute Object_New error. result: %{public}d.", ret);
        return nullptr;
    }
    ani_field wrapperField;
    ret = env->Class_FindField(cls, "subscriberInstanceWrapper", &wrapperField);
    if (ret != ANI_OK) {
        EVENT_LOGE("createSubscriberExecute Class_FindField error. result: %{public}d.", ret);
        return nullptr;
    }
    ret = env->Object_SetField_Long(subscriberObj, wrapperField, reinterpret_cast<ani_long>(wrapper));
    if (ret != ANI_OK) {
        EVENT_LOGE("createSubscriberExecute Object_SetField_Long error. result: %{public}d.", ret);
        return nullptr;
    }
    ani_ref resultRef = nullptr;
    ret = env->GlobalReference_Create(subscriberObj, &resultRef);
    if (ret != ANI_OK) {
        EVENT_LOGE("createSubscriberExecute GlobalReference_Create error. result: %{public}d.", ret);
        return nullptr;
    }
    EVENT_LOGI("createSubscriberExecute end.");
    return resultRef;
}

static uint32_t subscribeExecute(ani_env* env, ani_object obj, ani_object optionsRef)
{
    EVENT_LOGI("subscribeExecute call.");
    auto ret = ANI_OK;
    ani_class cls;
    ret = env->FindClass("Lsts_common_event/CommonEventSubscriber;", &cls);
    if (ret != ANI_OK) {
        EVENT_LOGE("subscribeExecute FindClass error. result: %{public}d.", ret);
        return ANI_INVALID_ARGS;
    }

    ani_field wrapperField;
    ret = env->Class_FindField(cls, "subscriberInstanceWrapper", &wrapperField);
    if (ret != ANI_OK) {
        EVENT_LOGE("subscribeExecute Class_FindField error. result: %{public}d.", ret);
        return ANI_INVALID_ARGS;
    }

    ani_long wrapper_long {};
    ret = env->Object_GetField_Long(optionsRef, wrapperField, &wrapper_long);
    if (ret != ANI_OK) {
        EVENT_LOGE("subscribeExecute Object_GetField_Long error. result: %{public}d.", ret);
        return ANI_INVALID_ARGS;
    }

    SubscriberInstanceWrapper* wrapper = nullptr;
    wrapper = reinterpret_cast<SubscriberInstanceWrapper*>(wrapper_long);
    if (wrapper == nullptr) {
        EVENT_LOGE("subscribeExecute wrapper is null.");
        return ANI_INVALID_ARGS;
    }
    auto result = CommonEventManager::NewSubscribeCommonEvent(wrapper->GetSubscriber());
    EVENT_LOGI("subscribeExecute result: %{public}d.", result);
    return result;
}

static uint32_t unsubscribeExecute(ani_env* env, ani_object obj, ani_object optionsRef)
{
    EVENT_LOGI("unsubscribeExecute call.");
    auto ret = ANI_OK;
    ani_class cls;
    ret = env->FindClass("Lsts_common_event/CommonEventSubscriber;", &cls);
    if (ret != ANI_OK) {
        EVENT_LOGE("unsubscribeExecute FindClass error. result: %{public}d.", ret);
        return ret;
    }
    ani_field wrapperField;
    ret = env->Class_FindField(cls, "subscriberInstanceWrapper", &wrapperField);
    if (ret != ANI_OK) {
        EVENT_LOGE("unsubscribeExecute Class_FindField error. result: %{public}d.", ret);
        return ret;
    }
    ani_long wrapper_long {};
    ret = env->Object_GetField_Long(optionsRef, wrapperField, &wrapper_long);
    if (ret != ANI_OK) {
        EVENT_LOGE("unsubscribeExecute Object_GetField_Long error. result: %{public}d.", ret);
        return ret;
    }

    SubscriberInstanceWrapper* wrapper = nullptr;
    wrapper = reinterpret_cast<SubscriberInstanceWrapper*>(wrapper_long);
    if (wrapper == nullptr) {
        EVENT_LOGE("unsubscribeExecute wrapper is null.");
        return ANI_INVALID_ARGS;
    }

    auto result = CommonEventManager::NewUnSubscribeCommonEvent(wrapper->GetSubscriber());
    EVENT_LOGI("unsubscribeExecute result: %{public}d.", result);
    return result;
}

ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    EVENT_LOGI("ANI_Constructor call.");
    ani_env* env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        EVENT_LOGE("Unsupported ANI_VERSION_1.");
        return ANI_ERROR;
    }

    static const char* className = "Lsts_common_event/CommonEvent;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        EVENT_LOGE("Not found Class: %{public}s.", className);
        return ANI_INVALID_ARGS;
    }

    std::array methods = {
        ani_native_function { "publishExecute", "Lstd/core/String;:I", reinterpret_cast<void*>(publishExecute) },
        ani_native_function { "publishWithOptionsExecute",
            "Lstd/core/String;Lsts_common_event/CommonEventPublishData;:I",
            reinterpret_cast<void*>(publishWithOptionsExecute) },
        ani_native_function { "createSubscriberExecute",
            "Lsts_common_event/CommonEventSubscribeInfo;:Lsts_common_event/CommonEventSubscriber;",
            reinterpret_cast<void*>(createSubscriberExecute) },
        ani_native_function { "subscribeExecute", "Lsts_common_event/CommonEventSubscriber;:I",
            reinterpret_cast<void*>(subscribeExecute) },
        ani_native_function { "unsubscribeExecute", "Lsts_common_event/CommonEventSubscriber;:I",
            reinterpret_cast<void*>(unsubscribeExecute) },
    };

    if (ANI_OK != env->Class_BindNativeMethods(cls, methods.data(), methods.size())) {
        EVENT_LOGE("Cannot bind native methods to: %{public}s.", className);
        return ANI_INVALID_TYPE;
    };

    *result = ANI_VERSION_1;
    return ANI_OK;
}

SubscriberInstance::SubscriberInstance(const CommonEventSubscribeInfo& sp) : CommonEventSubscriber(sp)
{
    EVENT_LOGD("create SubscriberInstance");
}

SubscriberInstance::~SubscriberInstance()
{
    EVENT_LOGD("destroy SubscriberInstance");
}

void SubscriberInstance::OnReceiveEvent(const CommonEventData& data)
{
    EVENT_LOGD("OnReceiveEvent call");
}

SubscriberInstanceWrapper::SubscriberInstanceWrapper(const CommonEventSubscribeInfo& info)
{
    auto objectInfo = new (std::nothrow) SubscriberInstance(info);
    if (objectInfo == nullptr) {
        EVENT_LOGE("objectInfo is null");
        return;
    }

    EVENT_LOGI("Constructor objectInfo");
    subscriber = std::shared_ptr<SubscriberInstance>(objectInfo);
    if (subscriber == nullptr) {
        EVENT_LOGE("subscriber is null");
        return;
    }
}

std::shared_ptr<SubscriberInstance> SubscriberInstanceWrapper::GetSubscriber()
{
    return subscriber;
}