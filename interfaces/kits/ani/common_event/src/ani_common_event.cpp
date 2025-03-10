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

#include "ani_common_event_utils.h"
#include "event_log_wrapper.h"
namespace OHOS {
namespace EventManagerFwkAni {

using namespace OHOS::EventFwk;

std::atomic_ullong SubscriberInstance::subscriberID_ = 0;
static std::map<std::shared_ptr<SubscriberInstance>, std::shared_ptr<AsyncCommonEventResult>> subscriberInstances;
static std::mutex subscriberInsMutex;

static uint32_t publishExecute(ani_env* env, ani_string eventId)
{
    EVENT_LOGI("publishExecute call.");
    std::string eventIdStr;
    AniCommonEventUtils::GetStdString(env, eventId, eventIdStr);
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

static uint32_t publishWithOptionsExecute(ani_env* env, ani_string eventId, ani_object optionsObject)
{
    EVENT_LOGI("publishWithOptionsExecute call.");
    std::string eventIdStr;
    AniCommonEventUtils::GetStdString(env, eventId, eventIdStr);
    EVENT_LOGI("publishWithOptionsExecute eventIdStr: %{public}s.", eventIdStr.c_str());

    CommonEventData commonEventData;
    CommonEventPublishInfo commonEventPublishInfo;
    Want want;
    want.SetAction(eventIdStr);
    commonEventData.SetWant(want);

    AniCommonEventUtils::ConvertCommonEventPublishData(
        env, optionsObject, want, commonEventData, commonEventPublishInfo);
    auto errorCode = CommonEventManager::NewPublishCommonEvent(commonEventData, commonEventPublishInfo);
    EVENT_LOGI("publishWithOptionsExecute result: %{public}d.", errorCode);
    return errorCode;
}

static ani_ref createSubscriberExecute(ani_env* env, ani_object infoObject)
{
    EVENT_LOGI("createSubscriberExecute call.");
    CommonEventSubscribeInfo subscribeInfo;
    AniCommonEventUtils::ConvertCommonEventSubscribeInfo(env, infoObject, subscribeInfo);
    auto ret = ANI_OK;
    auto wrapper = new (std::nothrow) SubscriberInstanceWrapper(subscribeInfo);
    ani_class cls;
    ret = env->FindClass("LcommonEvent/commonEventSubscriber/CommonEventSubscriberInner;", &cls);
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

    ani_method wrapperField;
    ret = env->Class_FindMethod(cls, "<set>subscriberInstanceWrapper", nullptr, &wrapperField);
    if (ret != ANI_OK) {
        EVENT_LOGE("createSubscriberExecute Class_FindField error. result: %{public}d.", ret);
        return nullptr;
    }

    ret = env->Object_CallMethod_Void(subscriberObj, wrapperField, reinterpret_cast<ani_long>(wrapper));
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

static uint32_t subscribeExecute(ani_env* env, ani_object optionsRef, ani_ref callbackRef)
{
    EVENT_LOGI("subscribeExecute call.");
    auto ret = ANI_OK;

    ani_long wrapper_long {};
    ret = env->Object_GetPropertyByName_Long(optionsRef, "subscriberInstanceWrapper", &wrapper_long);
    if (ret != ANI_OK) {
        EVENT_LOGE("subscribeExecute Object_GetPropertyByName_Long error. result: %{public}d.", ret);
        return ANI_INVALID_ARGS;
    }

    SubscriberInstanceWrapper* wrapper = nullptr;
    wrapper = reinterpret_cast<SubscriberInstanceWrapper*>(wrapper_long);
    if (wrapper == nullptr) {
        EVENT_LOGE("subscribeExecute wrapper is null.");
        return ANI_INVALID_ARGS;
    }
    auto subscriberInstance = GetSubscriberByWrapper(wrapper);
    if (subscriberInstance == nullptr) {
        EVENT_LOGE("subscriberInstance is null.");
        return ANI_INVALID_ARGS;
    }
    subscriberInstance->SetEnv(env);
    subscriberInstance->SetCallbackRef(callbackRef);
    auto result = CommonEventManager::NewSubscribeCommonEvent(subscriberInstance);
    EVENT_LOGI("subscribeExecute result: %{public}d.", result);
    return result;
}

static uint32_t unsubscribeExecute(ani_env* env, ani_object optionsRef)
{
    EVENT_LOGI("unsubscribeExecute call.");
    auto ret = ANI_OK;

    ani_long wrapper_long {};
    ret = env->Object_GetPropertyByName_Long(optionsRef, "subscriberInstanceWrapper", &wrapper_long);
    if (ret != ANI_OK) {
        EVENT_LOGE("subscribeExecute Object_GetPropertyByName_Long error. result: %{public}d.", ret);
        return ANI_INVALID_ARGS;
    }

    SubscriberInstanceWrapper* wrapper = nullptr;
    wrapper = reinterpret_cast<SubscriberInstanceWrapper*>(wrapper_long);
    if (wrapper == nullptr) {
        EVENT_LOGE("unsubscribeExecute wrapper is null.");
        return ANI_INVALID_ARGS;
    }

    auto subscriberInstance = GetSubscriberByWrapper(wrapper);
    if (subscriberInstance == nullptr) {
        EVENT_LOGE("subscriberInstance is null.");
        return ANI_INVALID_ARGS;
    }
    auto result = CommonEventManager::NewUnSubscribeCommonEvent(subscriberInstance);
    EVENT_LOGI("unsubscribeExecute result: %{public}d.", result);
    return result;
}

std::shared_ptr<SubscriberInstance> GetSubscriberByWrapper(SubscriberInstanceWrapper* wrapper)
{
    if (wrapper->GetSubscriber() == nullptr) {
        EVENT_LOGE("subscriber is null");
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(subscriberInsMutex);
    for (auto subscriberInstance : subscriberInstances) {
        if (subscriberInstance.first.get() == wrapper->GetSubscriber().get()) {
            return subscriberInstance.first;
        }
    }
    return wrapper->GetSubscriber();
}

SubscriberInstance::SubscriberInstance(const CommonEventSubscribeInfo& sp) : CommonEventSubscriber(sp)
{
    EVENT_LOGI("create SubscriberInstance");
    id_ = ++subscriberID_;
}

SubscriberInstance::~SubscriberInstance()
{
    EVENT_LOGI("destroy SubscriberInstance");
}

void SubscriberInstance::OnReceiveEvent(const CommonEventData& data)
{
    EVENT_LOGI("OnReceiveEvent execute action = %{public}s", data.GetWant().GetAction().c_str());
    if (this->IsOrderedCommonEvent()) {
        std::lock_guard<std::mutex> lock(subscriberInsMutex);
        for (auto subscriberInstance : subscriberInstances) {
            if (subscriberInstance.first.get() == this) {
                subscriberInstances[subscriberInstance.first] = GoAsyncCommonEvent();
                break;
            }
        }
    }
    ani_object ani_data {};
    AniCommonEventUtils::ConvertCommonEventDataToEts(env_, ani_data, data);
    // Call JS by CallbackRef
}

unsigned long long SubscriberInstance::GetID()
{
    return id_.load();
}

void SubscriberInstance::SetEnv(ani_env* env)
{
    EVENT_LOGD("Enter");
    env_ = env;
}

void SubscriberInstance::SetCallbackRef(const ani_ref& ref)
{
    std::lock_guard<std::mutex> lockRef(refMutex_);
    ref_ = ref;
}

void SubscriberInstance::ClearEnv()
{
    EVENT_LOGD("Env expired, clear SubscriberInstance env");
    std::lock_guard<std::mutex> lock(envMutex_);
    env_ = nullptr;
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

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    EVENT_LOGI("ANI_Constructor call.");
    ani_env* env;
    ani_status status = ANI_ERROR;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        EVENT_LOGE("Unsupported ANI_VERSION_1.");
        return ANI_ERROR;
    }

    ani_namespace kitNs;
    status = env->FindNamespace("L@ohos/commonEventManager/commonEventManager;", &kitNs);
    if (status != ANI_OK) {
        EVENT_LOGE("Not found L@ohos/commonEventManager/commonEventManager.");
        return ANI_INVALID_ARGS;
    }

    std::array methods = {
        ani_native_function { "publishExecute", "Lstd/core/String;:I",
            reinterpret_cast<void*>(OHOS::EventManagerFwkAni::publishExecute) },
        ani_native_function { "publishWithOptionsExecute",
            "Lstd/core/String;LcommonEvent/commonEventPublishData/CommonEventPublishData;:I",
            reinterpret_cast<void*>(OHOS::EventManagerFwkAni::publishWithOptionsExecute) },
        ani_native_function { "createSubscriberExecute",
            "LcommonEvent/commonEventSubscribeInfo/CommonEventSubscribeInfo;:LcommonEvent/commonEventSubscriber/"
            "CommonEventSubscriber;",
            reinterpret_cast<void*>(OHOS::EventManagerFwkAni::createSubscriberExecute) },
        ani_native_function {
            "subscribeExecute", nullptr, reinterpret_cast<void*>(OHOS::EventManagerFwkAni::subscribeExecute) },
        ani_native_function { "unsubscribeExecute", "LcommonEvent/commonEventSubscriber/CommonEventSubscriber;:I",
            reinterpret_cast<void*>(OHOS::EventManagerFwkAni::unsubscribeExecute) },
    };

    status = env->Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size());
    if (status != ANI_OK) {
        EVENT_LOGE("Cannot bind native methods to L@ohos/event/common_event_manager/commonEventManager");
        return ANI_INVALID_TYPE;
    }

    *result = ANI_VERSION_1;
    return ANI_OK;
}
}

} // namespace EventManagerFwkAni
} // namespace OHOS
