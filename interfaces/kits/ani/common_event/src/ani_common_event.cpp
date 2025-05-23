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

static uint32_t publishAsUserExecute(ani_env* env, ani_string eventId, ani_int userId)
{
    EVENT_LOGD("publishAsUserExecute call.");
    std::string eventIdStr;
    AniCommonEventUtils::GetStdString(env, eventId, eventIdStr);
    EVENT_LOGD("publishAsUserExecute eventIdStr: %{public}s, userId: %{public}d", eventIdStr.c_str(), userId);

    CommonEventData commonEventData;
    CommonEventPublishInfo commonEventPublishInfo;
    Want want;
    want.SetAction(eventIdStr);
    commonEventData.SetWant(want);

    auto errorCode = CommonEventManager::NewPublishCommonEventAsUser(commonEventData, commonEventPublishInfo, userId);
    EVENT_LOGD("publishAsUserExecute result: %{public}d.", errorCode);
    return errorCode;
}

static uint32_t publishAsUserWithOptionsExecute(ani_env* env, ani_string eventId, ani_int userId,
    ani_object optionsObject)
{
    EVENT_LOGD("publishAsUserWithOptionsExecute call.");
    std::string eventIdStr;
    AniCommonEventUtils::GetStdString(env, eventId, eventIdStr);
    EVENT_LOGD("publishAsUserWithOptionsExecute eventIdStr: %{public}s, userId: %{public}d",
        eventIdStr.c_str(), userId);

    CommonEventData commonEventData;
    CommonEventPublishInfo commonEventPublishInfo;
    Want want;
    want.SetAction(eventIdStr);
    commonEventData.SetWant(want);

    AniCommonEventUtils::ConvertCommonEventPublishData(
        env, optionsObject, want, commonEventData, commonEventPublishInfo);
    auto errorCode = CommonEventManager::NewPublishCommonEventAsUser(commonEventData, commonEventPublishInfo, userId);
    EVENT_LOGD("publishAsUserWithOptionsExecute result: %{public}d.", errorCode);
    return errorCode;
}

static ani_ref createSubscriberExecute(ani_env* env, ani_object infoObject)
{
    EVENT_LOGI("createSubscriberExecute call.");
    CommonEventSubscribeInfo subscribeInfo;
    AniCommonEventUtils::ConvertCommonEventSubscribeInfo(env, infoObject, subscribeInfo);
    subscribeInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::ThreadMode::HANDLER);
    auto ret = ANI_OK;
    auto wrapper = new (std::nothrow) SubscriberInstanceWrapper(subscribeInfo);
    if (wrapper == nullptr) {
        return nullptr;
    }
    ani_class cls;
    ret = env->FindClass("LcommonEvent/commonEventSubscriber/CommonEventSubscriberInner;", &cls);
    if (ret != ANI_OK) {
        EVENT_LOGE("createSubscriberExecute FindClass error. result: %{public}d.", ret);
        delete wrapper;
        wrapper = nullptr;
        return nullptr;
    }
    ani_method ctor;
    ret = env->Class_FindMethod(cls, "<ctor>", "J:V", &ctor);
    if (ret != ANI_OK) {
        EVENT_LOGE("createSubscriberExecute Class_FindMethod error. result: %{public}d.", ret);
        delete wrapper;
        wrapper = nullptr;
        return nullptr;
    }
    ani_object subscriberObj;
    ret = env->Object_New(cls, ctor, &subscriberObj, reinterpret_cast<ani_long>(wrapper));
    if (ret != ANI_OK) {
        EVENT_LOGE("createSubscriberExecute Object_New error. result: %{public}d.", ret);
        delete wrapper;
        wrapper = nullptr;
        return nullptr;
    }

    EVENT_LOGI("createSubscriberExecute end.");
    return subscriberObj;
}

static uint32_t subscribeExecute(ani_env* env, ani_ref subscribeRef, ani_object callback)
{
    EVENT_LOGI("subscribeExecute call.");
    auto ret = ANI_OK;

    ani_long wrapper_long {};
    ret = env->Object_GetPropertyByName_Long(
        static_cast<ani_object>(subscribeRef), "subscriberInstanceWrapper", &wrapper_long);
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

    ani_ref resultRef = nullptr;
    ret = env->GlobalReference_Create(callback, &resultRef);
    if (ret != ANI_OK) {
        EVENT_LOGE("createSubscriberExecute GlobalReference_Create error. result: %{public}d.", ret);
        return ANI_INVALID_ARGS;
    }
    if (resultRef == nullptr) {
        EVENT_LOGE("subscribeExecute resultRef is null.");
    }
    subscriberInstance->SetEnv(env);
    subscriberInstance->SetCallback(static_cast<ani_object>(resultRef));

    ani_vm* etsVm;
    ret = env->GetVM(&etsVm);
    if (ret != ANI_OK) {
        EVENT_LOGE("OnReceiveEvent GetVM error. result: %{public}d.", ret);
        return ANI_INVALID_ARGS;
    }
    subscriberInstance->SetVm(etsVm);
    auto result = CommonEventManager::NewSubscribeCommonEvent(subscriberInstance);

    EVENT_LOGI("subscribeExecute result: %{public}d.", result);
    return result;
}

static uint32_t unsubscribeExecute(ani_env* env, ani_ref subscribeRef)
{
    EVENT_LOGI("unsubscribeExecute call.");
    auto ret = ANI_OK;

    ani_long wrapper_long {};
    ret = env->Object_GetPropertyByName_Long(
        static_cast<ani_object>(subscribeRef), "subscriberInstanceWrapper", &wrapper_long);
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
    if (env_ != nullptr && callback_ != nullptr) {
        env_->GlobalReference_Delete(callback_);
    }
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

    ani_env* etsEnv;
    ani_status aniResult = ANI_OK;
    aniResult = etsVm_->GetEnv(ANI_VERSION_1, &etsEnv);
    if (aniResult != ANI_OK) {
        EVENT_LOGE("subscribeCallbackThreadFunciton GetEnv error. result: %{public}d.", aniResult);
        return;
    }

    ani_object ani_data {};
    AniCommonEventUtils::ConvertCommonEventDataToEts(etsEnv, ani_data, data);

    ani_ref nullObject;
    aniResult = etsEnv->GetNull(&nullObject);
    if (aniResult != ANI_OK) {
        EVENT_LOGE("subscribeCallbackThreadFunciton GetNull error. result: %{public}d.", aniResult);
    }

    auto fnObject = reinterpret_cast<ani_fn_object>(reinterpret_cast<ani_ref>(callback_));
    if (fnObject == nullptr) {
        EVENT_LOGE("subscribeCallbackThreadFunciton fnObject is null.");
        return;
    }

    EVENT_LOGI("FunctionalObject_Call.");
    std::vector<ani_ref> args = { nullObject, reinterpret_cast<ani_ref>(ani_data) };
    ani_ref result;
    aniResult = etsEnv->FunctionalObject_Call(fnObject, args.size(), args.data(), &result);
    if (aniResult != ANI_OK) {
        EVENT_LOGE("subscribeCallbackThreadFunciton FunctionalObject_Call error. result: %{public}d.", aniResult);
    }
}

unsigned long long SubscriberInstance::GetID()
{
    return id_.load();
}

void SubscriberInstance::SetEnv(ani_env* env)
{
    EVENT_LOGD("SetEnv");
    std::lock_guard<std::mutex> lock(envMutex_);
    env_ = env;
}

void SubscriberInstance::SetVm(ani_vm* etsVm)
{
    EVENT_LOGD("SetVm");
    etsVm_ = etsVm;
}

void SubscriberInstance::SetCallback(const ani_object& callback)
{
    std::lock_guard<std::mutex> lockRef(callbackMutex_);
    callback_ = callback;
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

static void clean([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object)
{
    ani_long ptr;
    if (ANI_OK != env->Object_GetFieldByName_Long(object, "ptr", &ptr)) {
        return;
    }
    delete reinterpret_cast<SubscriberInstanceWrapper *>(ptr);
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
        ani_native_function { "publishAsUserExecute", "Lstd/core/String;I:I",
            reinterpret_cast<void*>(OHOS::EventManagerFwkAni::publishAsUserExecute) },
        ani_native_function { "publishAsUserWithOptionsExecute",
            "Lstd/core/String;ILcommonEvent/commonEventPublishData/CommonEventPublishData;:I",
            reinterpret_cast<void*>(OHOS::EventManagerFwkAni::publishAsUserWithOptionsExecute) },
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

    ani_class cls;
    status = env->FindClass("LcommonEvent/commonEventSubscriber/Cleaner;", &cls);
    if (status != ANI_OK) {
        EVENT_LOGE("Not found LcommonEvent/commonEventSubscriber/Cleaner");
        return ANI_INVALID_ARGS;
    }
    std::array cleanMethod = {
        ani_native_function{"clean", nullptr, reinterpret_cast<void *>(OHOS::EventManagerFwkAni::clean)}};
    status = env->Class_BindNativeMethods(cls, cleanMethod.data(), cleanMethod.size());
    if (status != ANI_OK) {
        EVENT_LOGE("Cannot bind native methods to LcommonEvent/commonEventSubscriber/Cleaner");
        return ANI_INVALID_TYPE;
    }

    *result = ANI_VERSION_1;
    return ANI_OK;
}
}

} // namespace EventManagerFwkAni
} // namespace OHOS
