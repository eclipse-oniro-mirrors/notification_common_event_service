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
#include "ani_common_event_throw_error.h"
#include "ces_inner_error_code.h"
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
    AniCommonEventUtils::ConvertCommonEventPublishData(
        env, optionsObject, want, commonEventData, commonEventPublishInfo);
    commonEventData.SetWant(want);
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
    if (result == ANI_OK) {
        EVENT_LOGD("result is ANI_OK");
        std::lock_guard<std::mutex> lock(subscriberInsMutex);
        subscriberInstances[subscriberInstance] = subscriberInstance->GoAsyncCommonEvent();
    } else {
        subscriberInstance = nullptr;
    }
    EVENT_LOGI("subscribeExecute result: %{public}d.", result);
    return result;
}

static int32_t removeSubscriberInstance(ani_env* env, SubscriberInstanceWrapper* wrapper)
{
    int32_t result = ERR_OK;
    std::lock_guard<std::mutex> lock(subscriberInsMutex);
    for (auto iter = subscriberInstances.begin(); iter != subscriberInstances.end();) {
        if (iter->first.get() == wrapper->GetSubscriber().get()) {
            result = CommonEventManager::NewUnSubscribeCommonEvent(iter->first);
            ani_ref callbackRef = static_cast<ani_ref>(iter->first->GetCallback());
            if (result == ANI_OK && callbackRef != nullptr) {
                env->GlobalReference_Delete(callbackRef);
            }
            iter = subscriberInstances.erase(iter);
        } else {
            ++iter;
        }
    }
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
    auto result = removeSubscriberInstance(env, wrapper);
    EVENT_LOGI("unsubscribeExecute result: %{public}d.", result);
    return result;
}

static uint32_t removeStickyCommonEventExecute(ani_env* env, ani_string eventId)
{
    EVENT_LOGD("removeStickyCommonEventExecute call");
    std::string eventIdStr;
    AniCommonEventUtils::GetStdString(env, eventId, eventIdStr);
    EVENT_LOGD("removeStickyCommonEventExecute eventIdStr: %{public}s.", eventIdStr.c_str());
    int returncode = CommonEventManager::RemoveStickyCommonEvent(eventIdStr);
    EVENT_LOGD("removeStickyCommonEventExecute result: %{public}d.", returncode);
    return returncode;
}

static uint32_t setStaticSubscriberStateExecute(ani_env* env, ani_boolean enable)
{
    EVENT_LOGD("setStaticSubscriberStateExecute call");
    int returncode = CommonEventManager::SetStaticSubscriberState(enable);
    if (returncode != ERR_OK) {
        EVENT_LOGE("setStaticSubscriberStateExecute failed with error: %{public}d", returncode);
        if (returncode != Notification::ERR_NOTIFICATION_CES_COMMON_NOT_SYSTEM_APP &&
            returncode != Notification::ERR_NOTIFICATION_SEND_ERROR) {
            returncode = Notification::ERR_NOTIFICATION_CESM_ERROR;
        }
    }
    EVENT_LOGD("setStaticSubscriberStateExecute result: %{public}d", returncode);
    return returncode;
}

static uint32_t setStaticSubscriberStateWithEventsExecute(ani_env* env, ani_boolean enable, ani_object events)
{
    EVENT_LOGD("setStaticSubscriberStateWithEventsExecute call");
    std::vector<std::string> eventList;
    AniCommonEventUtils::GetStdStringArrayClass(env, events, eventList);
    int returncode = (events == nullptr) ?
        CommonEventManager::SetStaticSubscriberState(enable) :
        CommonEventManager::SetStaticSubscriberState(eventList, enable);
    if (returncode != ERR_OK) {
        EVENT_LOGE("setStaticSubscriberStateWithEventsExecute failed with error: %{public}d", returncode);
        if (returncode != Notification::ERR_NOTIFICATION_CES_COMMON_NOT_SYSTEM_APP &&
            returncode != Notification::ERR_NOTIFICATION_SEND_ERROR) {
            returncode = Notification::ERR_NOTIFICATION_CESM_ERROR;
        }
    }
    EVENT_LOGD("setStaticSubscriberStateWithEventsExecute result: %{public}d.", returncode);
    return returncode;
}

std::shared_ptr<SubscriberInstance> GetSubscriber(ani_env* env, ani_ref subscribeRef)
{
    EVENT_LOGD("GetSubscriber excute");
    auto ret = ANI_OK;

    ani_long wrapper_long {};
    ret = env->Object_GetPropertyByName_Long(
        static_cast<ani_object>(subscribeRef), "subscriberInstanceWrapper", &wrapper_long);
    if (ret != ANI_OK) {
        EVENT_LOGE("subscribeExecute Object_GetPropertyByName_Long error. result: %{public}d.", ret);
        return nullptr;
    }

    SubscriberInstanceWrapper* wrapper = nullptr;
    wrapper = reinterpret_cast<SubscriberInstanceWrapper*>(wrapper_long);
    if (wrapper == nullptr) {
        EVENT_LOGE("unsubscribeExecute wrapper is null.");
        return nullptr;
    }
    return GetSubscriberByWrapper(wrapper);
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

ani_object SubscriberInstance::GetCallback()
{
    std::lock_guard<std::mutex> lockRef(callbackMutex_);
    return callback_;
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
    SubscriberInstanceWrapper* wrapper = nullptr;
    wrapper = reinterpret_cast<SubscriberInstanceWrapper*>(ptr);
    if (wrapper == nullptr) {
        EVENT_LOGE("clean wrapper is null.");
        return;
    }
    auto result = removeSubscriberInstance(env, wrapper);
    EVENT_LOGD("clean result: %{public}d.", result);
    return;
}

std::shared_ptr<AsyncCommonEventResult> GetAsyncCommonEventResult(ani_env* env, ani_object object)
{
    EVENT_LOGD("subscriberInstance GetAsyncCommonEventResult.");
    auto subscriberInstance = GetSubscriber(env, object);
    if (subscriberInstance == nullptr) {
        EVENT_LOGE("subscriberInstance is null.");
        return nullptr;
    }
    if (subscriberInstances.size() == 0) {
        EVENT_LOGE("subscriberInstances is null.");
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(subscriberInsMutex);
    for (auto subscriberRes : subscriberInstances) {
        if (subscriberRes.first.get() == subscriberInstance.get()) {
            return subscriberInstances[subscriberRes.first];
        }
    }
    return nullptr;
}

static ani_double getCode(ani_env *env, ani_object object)
{
    EVENT_LOGD("subscriberInstance getCode.");
    auto subscriberRes = GetAsyncCommonEventResult(env, object);
    int32_t code = 0;
    if (subscriberRes != nullptr) {
        code = subscriberRes->GetCode();
    }
    ani_double returncode = static_cast<ani_double>(code);
    return returncode;
}

static uint32_t setCode(ani_env *env, ani_object object, ani_int code)
{
    EVENT_LOGD("subscriberInstance setCode.");
    int32_t returncode = 0;
    auto subscriberRes = GetAsyncCommonEventResult(env, object);
    if (subscriberRes == nullptr) {
        EVENT_LOGE("subscriberRes is null");
        return returncode;
    }
    bool returnBoolean = subscriberRes->SetCode(code);
    if (!returnBoolean) {
        EVENT_LOGE("subscriberRes is null");
        return returncode;
    }
    return returncode;
}

static ani_string getData(ani_env *env, ani_object object)
{
    EVENT_LOGD("subscriberInstance getData.");
    auto subscriberRes = GetAsyncCommonEventResult(env, object);
    std::string str = "";
    if (subscriberRes != nullptr) {
        str = subscriberRes->GetData();
    }
    ani_string aniResult = nullptr;
    AniCommonEventUtils::GetAniString(env, str, aniResult);
    return aniResult;
}

static uint32_t setData(ani_env *env, ani_object object, ani_string data)
{
    EVENT_LOGD("subscriberInstance setData.");
    int32_t returncode = 0;
    auto subscriberRes = GetAsyncCommonEventResult(env, object);
    if (subscriberRes == nullptr) {
        EVENT_LOGE("subscriberRes is null");
        return returncode;
    }
    std::string stdData;
    AniCommonEventUtils::GetStdString(env, data, stdData);
    ani_boolean returnBoolean = static_cast<ani_boolean>(subscriberRes->SetData(stdData));
    if (!returnBoolean) {
        EVENT_LOGE("subscriberRes is null");
        return returncode;
    }
    return returncode;
}

static uint32_t setCodeAndData(ani_env *env, ani_object object, ani_int code, ani_string data)
{
    EVENT_LOGD("subscriberInstance setCodeAndData.");
    int32_t returncode = 0;
    auto subscriberRes = GetAsyncCommonEventResult(env, object);
    if (subscriberRes == nullptr) {
        EVENT_LOGE("subscriberRes is null");
        return returncode;
    }
    std::string stdData;
    int32_t intCode = static_cast<ani_boolean>(code);
    AniCommonEventUtils::GetStdString(env, data, stdData);
    bool returnBoolean = subscriberRes->SetCodeAndData(intCode, stdData);
    if (!returnBoolean) {
        EVENT_LOGE("subscriberRes is null");
        return returncode;
    }
    return returncode;
}

static ani_boolean isOrderedCommonEvent(ani_env *env, ani_object object)
{
    EVENT_LOGD("subscriberInstance isOrderedCommonEvent.");
    auto subscriberRes = GetAsyncCommonEventResult(env, object);
    ani_boolean returnBoolean = ANI_FALSE;
    if (subscriberRes != nullptr) {
        returnBoolean = subscriberRes->IsOrderedCommonEvent() ? ANI_TRUE : ANI_FALSE;
    }
    return returnBoolean;
}

static ani_boolean isStickyCommonEvent(ani_env *env, ani_object object)
{
    EVENT_LOGD("subscriberInstance isStickyCommonEvent.");
    auto subscriberRes = GetAsyncCommonEventResult(env, object);
    ani_boolean returnBoolean = ANI_FALSE;
    if (subscriberRes != nullptr) {
        returnBoolean = subscriberRes->IsStickyCommonEvent() ? ANI_TRUE : ANI_FALSE;
    }
    return returnBoolean;
}

static uint32_t abortCommonEvent(ani_env *env, ani_object object)
{
    EVENT_LOGD("subscriberInstance abortCommonEvent.");
    int32_t returncode = 0;
    auto subscriberRes = GetAsyncCommonEventResult(env, object);
    if (subscriberRes == nullptr) {
        EVENT_LOGE("subscriberRes is null");
        return returncode;
    }
    if (!(subscriberRes->AbortCommonEvent())) {
        return returncode;
    }
    return returncode;
}

static uint32_t clearAbortCommonEvent(ani_env *env, ani_object object)
{
    EVENT_LOGD("subscriberInstance clearAbortCommonEvent.");
    int32_t returncode = 0;
    auto subscriberRes = GetAsyncCommonEventResult(env, object);
    if (subscriberRes == nullptr) {
        EVENT_LOGE("subscriberRes is null");
        return returncode;
    }
    if (!(subscriberRes->ClearAbortCommonEvent())) {
        return returncode;
    }
    return returncode;
}

static ani_boolean getAbortCommonEvent(ani_env *env, ani_object object)
{
    EVENT_LOGD("subscriberInstance getAbortCommonEvent.");
    auto subscriberRes = GetAsyncCommonEventResult(env, object);
    ani_boolean returnBoolean = ANI_FALSE;
    if (subscriberRes != nullptr) {
        returnBoolean = subscriberRes->GetAbortCommonEvent() ? ANI_TRUE : ANI_FALSE;
    }
    return returnBoolean;
}

static ani_object getSubscribeInfo(ani_env *env, ani_object object)
{
    EVENT_LOGD("subscriberInstance getSubscribeInfo.");
    auto subscriberInstance = GetSubscriber(env, object);
    ani_object infoObject {};
    if (subscriberInstance == nullptr) {
        EVENT_LOGE("subscriberInstance is null.");
        ani_ref nullObject;
        env->GetNull(&nullObject);
        return static_cast<ani_object>(nullObject);
    }
    AniCommonEventUtils::GetCommonEventSubscribeInfoToEts(env, subscriberInstance, infoObject);
    if (infoObject == nullptr) {
        EVENT_LOGE("infoObject is null.");
        ani_ref nullObject;
        env->GetNull(&nullObject);
        return static_cast<ani_object>(nullObject);
    }
    return infoObject;
}

static uint32_t finishCommonEvent(ani_env *env, ani_object object)
{
    EVENT_LOGD("subscriberInstance finishCommonEvent.");
    auto subscriberRes = GetAsyncCommonEventResult(env, object);
    int32_t returncode = 0;
    if (subscriberRes == nullptr) {
        EVENT_LOGE("subscriberRes is null");
        return returncode;
    }
    if (!(subscriberRes->FinishCommonEvent())) {
        return returncode;
    }
    return returncode;
}

static std::array commonEventSubscriberFunctions = {
    ani_native_function{"nativeGetCode", nullptr, reinterpret_cast<void *>(OHOS::EventManagerFwkAni::getCode)},
    ani_native_function{"nativeSetCode", nullptr, reinterpret_cast<void *>(OHOS::EventManagerFwkAni::setCode)},
    ani_native_function{"nativeGetData", nullptr, reinterpret_cast<void *>(OHOS::EventManagerFwkAni::getData)},
    ani_native_function{"nativeSetData", nullptr, reinterpret_cast<void *>(OHOS::EventManagerFwkAni::setData)},
    ani_native_function{"nativeSetCodeAndData", nullptr,
        reinterpret_cast<void *>(OHOS::EventManagerFwkAni::setCodeAndData)},
    ani_native_function{"nativeIsOrderedCommonEvent", nullptr,
        reinterpret_cast<void *>(OHOS::EventManagerFwkAni::isOrderedCommonEvent)},
    ani_native_function{"nativeIsStickyCommonEvent", nullptr,
        reinterpret_cast<void *>(OHOS::EventManagerFwkAni::isStickyCommonEvent)},
    ani_native_function{"nativeAbortCommonEvent", nullptr,
        reinterpret_cast<void *>(OHOS::EventManagerFwkAni::abortCommonEvent)},
    ani_native_function{"nativeClearAbortCommonEvent", nullptr,
        reinterpret_cast<void *>(OHOS::EventManagerFwkAni::clearAbortCommonEvent)},
    ani_native_function{"nativeGetAbortCommonEvent", nullptr,
        reinterpret_cast<void *>(OHOS::EventManagerFwkAni::getAbortCommonEvent)},
    ani_native_function{"nativeGetSubscribeInfo", nullptr,
        reinterpret_cast<void *>(OHOS::EventManagerFwkAni::getSubscribeInfo)},
    ani_native_function{"nativeFinishCommonEvent", nullptr,
        reinterpret_cast<void *>(OHOS::EventManagerFwkAni::finishCommonEvent)},
};

ani_status init(ani_env *env, ani_namespace kitNs)
{
    ani_status status = ANI_ERROR;
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
        ani_native_function { "removeStickyCommonEventExecute", "Lstd/core/String;:I",
            reinterpret_cast<void*>(OHOS::EventManagerFwkAni::removeStickyCommonEventExecute) },
        ani_native_function { "setStaticSubscriberStateExecute", "Z:I",
            reinterpret_cast<void*>(OHOS::EventManagerFwkAni::setStaticSubscriberStateExecute) },
        ani_native_function { "setStaticSubscriberStateWithEventsExecute", nullptr,
            reinterpret_cast<void*>(OHOS::EventManagerFwkAni::setStaticSubscriberStateWithEventsExecute) },
    };

    status = env->Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size());
    if (status != ANI_OK) {
        EVENT_LOGE("Cannot bind native methods to L@ohos/event/common_event_manager/commonEventManager");
        return ANI_INVALID_TYPE;
    }
    return status;
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
    status = init(env, kitNs);
    if (status != ANI_OK) {
        EVENT_LOGE("Cannot bind native methods to L@ohos/events/emitter/emitter");
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

    ani_class commonEventSubscriberCls;
    status = env->FindClass("LcommonEvent/commonEventSubscriber/CommonEventSubscriberInner;",
        &commonEventSubscriberCls);
    if (status != ANI_OK) {
        EVENT_LOGE("Not found LcommonEvent/commonEventSubscriber/CommonEventSubscriberInner");
        return ANI_INVALID_ARGS;
    }
    status = env->Class_BindNativeMethods(commonEventSubscriberCls, commonEventSubscriberFunctions.data(),
        commonEventSubscriberFunctions.size());
    if (status != ANI_OK) {
        EVENT_LOGE("Cannot bind native methods to LcommonEvent/commonEventSubscriber/CommonEventSubscriberInner");
        return ANI_INVALID_TYPE;
    }
    *result = ANI_VERSION_1;
    return ANI_OK;
}
}

} // namespace EventManagerFwkAni
} // namespace OHOS
