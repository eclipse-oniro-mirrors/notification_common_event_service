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
#include "ces_inner_error_code.h"
#include "event_log_wrapper.h"

#include "interop_js/arkts_esvalue.h"
#include "interop_js/arkts_interop_js_api.h"

#include <algorithm>

namespace OHOS {
namespace EventManagerFwkAni {

std::atomic_ullong SubscriberInstance::subscriberID_ = 0;
static std::map<std::shared_ptr<SubscriberInstance>, std::shared_ptr<AsyncCommonEventResult>> subscriberInstances;
static ffrt::mutex subscriberInsMutex;
static ffrt::mutex transferRelationMutex;
static std::vector<std::shared_ptr<SubscriberInstanceRelationship>> transferRelations;

ani_class subscriberCls;
ani_method subscriberCtor;

static uint32_t publishExecute(ani_env* env, ani_string eventId)
{
    std::string eventIdStr;
    AniCommonEventUtils::GetStdString(env, eventId, eventIdStr);
    EVENT_LOGD("publishExecute eventIdStr: %{public}s.", eventIdStr.c_str());
    CommonEventData commonEventData;
    CommonEventPublishInfo commonEventPublishInfo;
    Want want;
    want.SetAction(eventIdStr);
    commonEventData.SetWant(want);
    auto errorCode = CommonEventManager::NewPublishCommonEvent(commonEventData, commonEventPublishInfo);
    EVENT_LOGD("publishExecute result: %{public}d.", errorCode);
    return errorCode;
}

static uint32_t publishWithOptionsExecute(ani_env* env, ani_string eventId, ani_object optionsObject)
{
    std::string eventIdStr;
    AniCommonEventUtils::GetStdString(env, eventId, eventIdStr);
    EVENT_LOGD("publishWithOptionsExecute eventIdStr: %{public}s.", eventIdStr.c_str());

    CommonEventData commonEventData;
    CommonEventPublishInfo commonEventPublishInfo;
    Want want;
    want.SetAction(eventIdStr);
    AniCommonEventUtils::ConvertCommonEventPublishData(
        env, optionsObject, want, commonEventData, commonEventPublishInfo);
    commonEventData.SetWant(want);
    auto errorCode = CommonEventManager::NewPublishCommonEvent(commonEventData, commonEventPublishInfo);
    EVENT_LOGD("publishWithOptionsExecute result: %{public}d.", errorCode);
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

ani_ref CreateSubscriberRef(ani_env* env, SubscriberInstanceWrapper *subscriberWrapper)
{
    if (env == nullptr || subscriberCls == nullptr || subscriberCtor == nullptr) {
        EVENT_LOGE("CreateSubscriberRef error. has nullptr");
        return nullptr;
    }
    ani_object subscriberObj;
    auto ret = env->Object_New(subscriberCls, subscriberCtor, &subscriberObj,
        reinterpret_cast<ani_long>(subscriberWrapper));
    if (ret != ANI_OK) {
        EVENT_LOGE("createSubscriberExecute Object_New error. result: %{public}d.", ret);
        return nullptr;
    }
    return subscriberObj;
}

static ani_ref createSubscriberExecute(ani_env* env, ani_object infoObject)
{
    ani_object nullObj = AniCommonEventUtils::GetNullObject(env);
    CommonEventSubscribeInfo subscribeInfo;
    AniCommonEventUtils::ConvertCommonEventSubscribeInfo(env, infoObject, subscribeInfo);
    subscribeInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::ThreadMode::HANDLER);
    auto wrapper = new (std::nothrow) SubscriberInstanceWrapper(subscribeInfo);
    if (wrapper == nullptr) {
        EVENT_LOGE("null wrapper");
        return nullObj;
    }
    ani_ref subscriberObj = CreateSubscriberRef(env, wrapper);
    if (subscriberObj == nullptr) {
        EVENT_LOGE("null subscriberObj");
        delete wrapper;
        wrapper = nullptr;
        return nullObj;
    }
    return subscriberObj;
}

static uint32_t subscribeExecute(ani_env* env, ani_ref subscribeRef, ani_object callback)
{
    EVENT_LOGD("subscribeExecute call.");
    auto subscriberInstance = GetSubscriber(env, subscribeRef);
    if (subscriberInstance == nullptr) {
        EVENT_LOGE("subscriberInstance is null.");
        return ANI_INVALID_ARGS;
    }

    ani_ref resultRef = nullptr;
    auto ret = env->GlobalReference_Create(callback, &resultRef);
    if (ret != ANI_OK || resultRef == nullptr) {
        EVENT_LOGE("GlobalReference_Create error. result: %{public}d.", ret);
        return ANI_INVALID_ARGS;
    }
    subscriberInstance->SetCallback(static_cast<ani_object>(resultRef));
    ani_vm* etsVm;
    ret = env->GetVM(&etsVm);
    if (ret != ANI_OK) {
        EVENT_LOGE("GetVM error. result: %{public}d.", ret);
        return ANI_INVALID_ARGS;
    }
    subscriberInstance->SetVm(etsVm);
    auto relation = GetTransferRelation(subscriberInstance, nullptr);
    int32_t result = ERR_OK;
    if (relation != nullptr) {
        std::lock_guard<ffrt::mutex> lock(relation->relationMutex_);
        if (!relation->aniSubscriber_ && !relation->napiSubscriber_) {
            result = CommonEventManager::NewSubscribeCommonEvent(subscriberInstance);
            if (result == ERR_OK) {
                relation->aniSubscriber_ = subscriberInstance;
                std::lock_guard<ffrt::mutex> lock(subscriberInsMutex);
                subscriberInstances[subscriberInstance] = subscriberInstance->GoAsyncCommonEvent();
            }
            return result;
        }
        EVENT_LOGW("transfered already subscribe");
        return result;
    }
    result = CommonEventManager::NewSubscribeCommonEvent(subscriberInstance);
    if (result == ERR_OK) {
        std::lock_guard<ffrt::mutex> lock(subscriberInsMutex);
        subscriberInstances[subscriberInstance] = subscriberInstance->GoAsyncCommonEvent();
    }
    return result;
}


static uint32_t subscribeToEventExecute(ani_env* env, ani_ref subscribeRef, ani_object callback)
{
    EVENT_LOGD("subscribeToEventExecute call.");
    auto subscriberInstance = GetSubscriber(env, subscribeRef);
    if (subscriberInstance == nullptr) {
        EVENT_LOGE("subscriberInstance is null.");
        return ANI_INVALID_ARGS;
    }
    ani_ref resultRef = nullptr;
    auto ret = env->GlobalReference_Create(callback, &resultRef);
    if (ret != ANI_OK || resultRef == nullptr) {
        EVENT_LOGE("GlobalReference_Create error. result: %{public}d.", ret);
        return ANI_INVALID_ARGS;
    }
    subscriberInstance->SetCallback(static_cast<ani_object>(resultRef));
    subscriberInstance->SetIsToEvent(true);
    ani_vm* etsVm;
    ret = env->GetVM(&etsVm);
    if (ret != ANI_OK) {
        EVENT_LOGE("GetVM error. result: %{public}d.", ret);
        return ANI_INVALID_ARGS;
    }
    subscriberInstance->SetVm(etsVm);
    auto relation = GetTransferRelation(subscriberInstance, nullptr);
    int32_t result = ERR_OK;
    if (relation != nullptr) {
        std::lock_guard<ffrt::mutex> lock(relation->relationMutex_);
        if (!relation->aniSubscriber_ && !relation->napiSubscriber_) {
            result = CommonEventManager::NewSubscribeCommonEvent(subscriberInstance);
            if (result == ERR_OK) {
                relation->aniSubscriber_ = subscriberInstance;
                std::lock_guard<ffrt::mutex> lock(subscriberInsMutex);
                subscriberInstances[subscriberInstance] = subscriberInstance->GoAsyncCommonEvent();
            }
            return result;
        }
        EVENT_LOGW("transfered already subscribe");
        return result;
    }
    result = CommonEventManager::NewSubscribeCommonEvent(subscriberInstance);
    if (result == ERR_OK) {
        std::lock_guard<ffrt::mutex> lock(subscriberInsMutex);
        subscriberInstances[subscriberInstance] = subscriberInstance->GoAsyncCommonEvent();
    }
    return result;
}

int32_t UnsubscribeAndRemoveInstance(ani_env* env, const std::shared_ptr<SubscriberInstance> &subscriber)
{
    auto result = CommonEventManager::NewUnSubscribeCommonEvent(subscriber);
    if (result != ERR_OK) {
        EVENT_LOGE("unsubscribe failed result: %{public}d.", result);
        return result;
    }
    std::lock_guard<ffrt::mutex> lock(subscriberInsMutex);
    auto item = subscriberInstances.find(subscriber);
    if (item != subscriberInstances.end()) {
        ani_ref callbackRef = static_cast<ani_ref>(item->first->GetCallback());
        if (callbackRef != nullptr) {
            env->GlobalReference_Delete(callbackRef);
            item->first->SetCallback(nullptr);
        }
        subscriberInstances.erase(item);
    }
    return result;
}

static uint32_t unsubscribeExecute(ani_env* env, ani_ref subscribeRef)
{
    auto subscriberInstance = GetSubscriber(env, subscribeRef);
    if (subscriberInstance == nullptr) {
        EVENT_LOGE("subscriberInstance is null.");
        return ANI_INVALID_ARGS;
    }
    int32_t result = ERR_OK;
    auto relation = GetTransferRelation(subscriberInstance, nullptr);
    if (relation == nullptr) {
        EVENT_LOGD("no transfered");
        return UnsubscribeAndRemoveInstance(env, subscriberInstance);
    }
    std::lock_guard<ffrt::mutex> lock(relation->relationMutex_);
    if (relation->napiSubscriber_) {
        result = EventManagerFwkNapi::UnsubscribeAndRemoveInstance(relation->napiSubscriber_->GetEnv(),
            relation->napiSubscriber_);
        relation->napiSubscriber_ = nullptr;
    } else if (relation->aniSubscriber_) {
        result = UnsubscribeAndRemoveInstance(env, relation->aniSubscriber_);
        relation->aniSubscriber_ = nullptr;
    } else {
        EVENT_LOGD("transfered no subscribe");
    }
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
    std::lock_guard<ffrt::mutex> lock(subscriberInsMutex);
    auto item = subscriberInstances.find(wrapper->GetSubscriber());
    if (item != subscriberInstances.end()) {
        return item->first;
    }
    return wrapper->GetSubscriber();
}

SubscriberInstance::SubscriberInstance(const CommonEventSubscribeInfo& sp) : CommonEventSubscriber(sp)
{
    EVENT_LOGD("create SubscriberInstance");
    id_ = ++subscriberID_;
}

SubscriberInstance::~SubscriberInstance()
{}

void SubscriberInstance::OnReceiveEvent(const CommonEventData& data)
{
    EVENT_LOGD("execute action = %{public}s", data.GetWant().GetAction().c_str());
    if (this->IsOrderedCommonEvent()) {
        auto asyncCommonEvent = GoAsyncCommonEvent();
        auto thisSubscriber = shared_from_this();
        auto relation = GetTransferRelation(thisSubscriber, nullptr);
        if (relation != nullptr) {
            std::lock_guard<ffrt::mutex> lock(relation->relationMutex_);
            for (const auto &subscriber : relation->napiSubscribers_) {
                EventManagerFwkNapi::SetAsyncCommonEventResultWithLocked(subscriber, asyncCommonEvent);
            }
            std::lock_guard<ffrt::mutex> lockSubscriberIns(subscriberInsMutex);
            for (const auto &subscriber : relation->aniSubscribers_) {
                subscriberInstances[subscriber] = asyncCommonEvent;
            }
        } else {
            std::lock_guard<ffrt::mutex> lock(subscriberInsMutex);
            subscriberInstances[thisSubscriber] = asyncCommonEvent;
        }
    }

    ani_env* etsEnv;
    ani_status aniResult = etsVm_->GetEnv(ANI_VERSION_1, &etsEnv);
    if (aniResult != ANI_OK) {
        EVENT_LOGE("GetEnv error. result: %{public}d.", aniResult);
        return;
    }

    ani_object ani_data {};
    AniCommonEventUtils::ConvertCommonEventDataToEts(etsEnv, ani_data, data);

    ani_ref nullObject;
    aniResult = etsEnv->GetNull(&nullObject);
    if (aniResult != ANI_OK) {
        EVENT_LOGE("GetNull error. result: %{public}d.", aniResult);
    }

    auto fnObject = reinterpret_cast<ani_fn_object>(reinterpret_cast<ani_ref>(callback_));
    if (fnObject == nullptr) {
        EVENT_LOGE("fnObject is null.");
        return;
    }
    std::vector<ani_ref> args;
    if (!GetIsToEvent()) {
        args.push_back(nullObject);
    }
    args.push_back(reinterpret_cast<ani_ref>(ani_data));
    ani_ref result;
    aniResult = etsEnv->FunctionalObject_Call(fnObject, args.size(), args.data(), &result);
    if (aniResult != ANI_OK) {
        EVENT_LOGE("FunctionalObject_Call error. result: %{public}d.", aniResult);
    }
}

unsigned long long SubscriberInstance::GetID()
{
    return id_.load();
}

void SubscriberInstance::SetVm(ani_vm* etsVm)
{
    EVENT_LOGD("SetVm");
    etsVm_ = etsVm;
}

ani_vm* SubscriberInstance::GetVm()
{
    return etsVm_;
}

void SubscriberInstance::SetCallback(const ani_object& callback)
{
    std::lock_guard<ffrt::mutex> lockRef(callbackMutex_);
    callback_ = callback;
}

ani_object SubscriberInstance::GetCallback()
{
    std::lock_guard<ffrt::mutex> lockRef(callbackMutex_);
    return callback_;
}

void SubscriberInstance::SetIsToEvent(bool isToEvent)
{
    std::lock_guard<ffrt::mutex> lockRef(isToEventMutex_);
    isToEvent_ = isToEvent;
}

bool SubscriberInstance::GetIsToEvent()
{
    std::lock_guard<ffrt::mutex> lockRef(isToEventMutex_);
    return isToEvent_;
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

std::shared_ptr<SubscriberInstanceRelationship> GetTransferRelation(std::shared_ptr<SubscriberInstance> aniSubscriber,
    std::shared_ptr<EventManagerFwkNapi::SubscriberInstance> napiSubscriber)
{
    std::lock_guard<ffrt::mutex> lock(transferRelationMutex);
    for (auto const &item : transferRelations) {
        if (napiSubscriber != nullptr) {
            auto subscriberItem = std::find(item->napiSubscribers_.begin(), item->napiSubscribers_.end(),
                napiSubscriber);
            if (subscriberItem != item->napiSubscribers_.end()) {
                return item;
            }
        } else if (aniSubscriber != nullptr) {
            auto subscriberItem = std::find(item->aniSubscribers_.begin(), item->aniSubscribers_.end(),
                aniSubscriber);
            if (subscriberItem != item->aniSubscribers_.end()) {
                return item;
            }
        }
    }
    return nullptr;
}

static ani_ref transferToStaticSubscriber(ani_env *env, [[maybe_unused]] ani_class, ani_object input)
{
    ani_ref undefinedRef {};
    env->GetUndefined(&undefinedRef);
    EventManagerFwkNapi::SubscriberInstanceWrapper *wrapper = nullptr;
    arkts_esvalue_unwrap(env, input, (void **)&wrapper);
    if (wrapper == nullptr) {
        EVENT_LOGE("null wrapper");
        return undefinedRef;
    }
    auto napiSubscriber = wrapper->GetSubscriber();
    auto aniWrapper = new (std::nothrow) SubscriberInstanceWrapper(napiSubscriber->GetSubscribeInfo());
    if (aniWrapper == nullptr) {
        EVENT_LOGE("null aniWrapper");
        return undefinedRef;
    }
    ani_ref subscriberObj = CreateSubscriberRef(env, aniWrapper);
    if (subscriberObj == nullptr) {
        delete aniWrapper;
        aniWrapper = nullptr;
        return undefinedRef;
    }
    SetNapiSubscriberCallback(napiSubscriber);
    auto asyncCommonEventResult = EventManagerFwkNapi::GetAsyncCommonEventResult(napiSubscriber);

    auto relation = GetTransferRelation(nullptr, napiSubscriber);
    if (relation != nullptr) {
        relation->aniSubscribers_.push_back(aniWrapper->GetSubscriber());
        if (asyncCommonEventResult != nullptr || napiSubscriber->GetCallbackRef() != nullptr) {
            std::lock_guard<ffrt::mutex> lock(subscriberInsMutex);
            subscriberInstances[aniWrapper->GetSubscriber()] = asyncCommonEventResult;
        }
        return subscriberObj;
    }
    relation = std::make_shared<SubscriberInstanceRelationship>();
    relation->aniSubscribers_.push_back(aniWrapper->GetSubscriber());
    relation->napiSubscribers_.push_back(napiSubscriber);
    if (asyncCommonEventResult != nullptr || napiSubscriber->GetCallbackRef() != nullptr) {
        relation->napiSubscriber_ = napiSubscriber;
        std::lock_guard<ffrt::mutex> lock(subscriberInsMutex);
        subscriberInstances[aniWrapper->GetSubscriber()] = asyncCommonEventResult;
    }
    {
        std::lock_guard<ffrt::mutex> lock(transferRelationMutex);
        transferRelations.push_back(relation);
    }
    return subscriberObj;
}

static int32_t unsubscribeCallback(const std::shared_ptr<EventManagerFwkNapi::SubscriberInstance> &napiSubscriber)
{
    int32_t result = ERR_OK;
    auto relation = GetTransferRelation(nullptr, napiSubscriber);
    if (relation == nullptr) {
        EVENT_LOGW("no transfer");
        return result;
    }
    std::lock_guard<ffrt::mutex> lock(relation->relationMutex_);
    if (relation->napiSubscriber_ != nullptr) {
        result = EventManagerFwkNapi::UnsubscribeAndRemoveInstance(relation->napiSubscriber_->GetEnv(),
            relation->napiSubscriber_);
        relation->napiSubscriber_ = nullptr;
    } else if (relation->aniSubscriber_ != nullptr) {
        ani_env* etsEnv;
        ani_status aniResult = ANI_OK;
        ani_options aniArgs {0, nullptr};
        aniResult = relation->aniSubscriber_->GetVm()->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &etsEnv);
        if (aniResult != ANI_OK) {
            EVENT_LOGE("GetEnv error. result: %{public}d.", aniResult);
            return aniResult;
        }
        result = UnsubscribeAndRemoveInstance(etsEnv, relation->aniSubscriber_);
        relation->aniSubscriber_->GetVm()->DetachCurrentThread();
        relation->aniSubscriber_ = nullptr;
    }
    return result;
}

static int32_t subscribeCallback(const std::shared_ptr<EventManagerFwkNapi::SubscriberInstance> &napiSubscriber)
{
    auto relation = GetTransferRelation(nullptr, napiSubscriber);
    if (relation == nullptr) {
        EVENT_LOGW("no transfer");
        return CommonEventManager::NewSubscribeCommonEvent(napiSubscriber);
    }
    std::lock_guard<ffrt::mutex> lock(relation->relationMutex_);
    if (relation->napiSubscriber_ || relation->aniSubscriber_) {
        EVENT_LOGW("transfered subscriber already subscribed");
        return ERR_OK;
    }
    auto result = CommonEventManager::NewSubscribeCommonEvent(napiSubscriber);
    if (result == ERR_OK) {
        relation->napiSubscriber_ = napiSubscriber;
    }
    return result;
};

static int32_t gcCallback(const std::shared_ptr<EventManagerFwkNapi::SubscriberInstance> &napiSubscriber)
{
    auto relation = GetTransferRelation(nullptr, napiSubscriber);
    if (relation == nullptr) {
        EVENT_LOGW("no transfer");
        return ERR_OK;
    }
    int32_t result = ERR_OK;
    bool allDestroyed = false;
    {
        std::lock_guard<ffrt::mutex> lock(relation->relationMutex_);
        auto subscriberItem = std::find(relation->napiSubscribers_.begin(), relation->napiSubscribers_.end(),
            napiSubscriber);
        if (subscriberItem != relation->napiSubscribers_.end()) {
            relation->napiSubscribers_.erase(subscriberItem);
        }
        if (relation->aniSubscribers_.empty() && relation->napiSubscribers_.empty()) {
            if (relation->napiSubscriber_) {
                result = EventManagerFwkNapi::UnsubscribeAndRemoveInstance(relation->napiSubscriber_->GetEnv(),
                    relation->napiSubscriber_);
                relation->napiSubscriber_ = nullptr;
            } else if (relation->aniSubscriber_) {
                ani_env* etsEnv;
                ani_status aniResult = ANI_OK;
                ani_options aniArgs {0, nullptr};
                aniResult = relation->aniSubscriber_->GetVm()->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &etsEnv);
                if (aniResult != ANI_OK) {
                    EVENT_LOGE("GetEnv error. result: %{public}d.", aniResult);
                    return aniResult;
                }
                result = UnsubscribeAndRemoveInstance(etsEnv, relation->aniSubscriber_);
                relation->aniSubscriber_->GetVm()->DetachCurrentThread();
                relation->aniSubscriber_ = nullptr;
            }
            allDestroyed = true;
        }
    }
    if (allDestroyed) {
        std::lock_guard<ffrt::mutex> lock(transferRelationMutex);
        auto item = std::find(transferRelations.begin(), transferRelations.end(), relation);
        if (item != transferRelations.end()) {
            transferRelations.erase(item);
        }
    }
    return result;
};

static void asyncResultCloneCallback(const std::shared_ptr<EventManagerFwkNapi::SubscriberInstance> &napiSubscriber,
    const std::shared_ptr<EventFwk::AsyncCommonEventResult> result)
{
    auto relation = GetTransferRelation(nullptr, napiSubscriber);
    if (relation == nullptr) {
        EVENT_LOGW("no transfer");
        return;
    }
    std::lock_guard<ffrt::mutex> lock(relation->relationMutex_);
    for (const auto &subscriber : relation->napiSubscribers_) {
        EventManagerFwkNapi::SetAsyncCommonEventResult(subscriber, result);
    }
    std::lock_guard<ffrt::mutex> lockSubscriberIns(subscriberInsMutex);
    for (const auto &subscriber : relation->aniSubscribers_) {
        subscriberInstances[subscriber] = result;
    }
    return;
};

static ani_ref transferToDynamicSubscriber(ani_env *env, [[maybe_unused]] ani_class, ani_object input)
{
    ani_ref undefinedRef {};
    env->GetUndefined(&undefinedRef);
    napi_env jsEnv;
    arkts_napi_scope_open(env, &jsEnv);
    auto aniSubscriber = GetSubscriber(env, static_cast<ani_ref>(input));
    if (aniSubscriber == nullptr) {
        EVENT_LOGE("aniSubscriber is null.");
        return undefinedRef;
    }
    napi_value napiSubscriberValue = EventManagerFwkNapi::TransferedCommonEventSubscriberConstructor(jsEnv,
        aniSubscriber->GetSubscribeInfo());
    if (napiSubscriberValue == nullptr) {
        EVENT_LOGE("napiSubscriberValue is null.");
        return undefinedRef;
    }
    ani_ref result {};
    arkts_napi_scope_close_n(jsEnv, 1, &napiSubscriberValue, &result);

    auto napiSubscriber = EventManagerFwkNapi::GetSubscriber(jsEnv, napiSubscriberValue);
    SetNapiSubscriberCallback(napiSubscriber);
    auto asyncResult = GetAsyncCommonEventResult(aniSubscriber);

    auto relation = GetTransferRelation(aniSubscriber, nullptr);
    if (relation != nullptr) {
        relation->napiSubscribers_.push_back(napiSubscriber);
        if (asyncResult != nullptr || aniSubscriber->GetCallback() != nullptr) {
            EventManagerFwkNapi::SetAsyncCommonEventResultWithLocked(napiSubscriber, asyncResult);
        }
        return result;
    }
    relation = std::make_shared<SubscriberInstanceRelationship>();
    relation->aniSubscribers_.push_back(aniSubscriber);
    relation->napiSubscribers_.push_back(napiSubscriber);
    if (asyncResult != nullptr || aniSubscriber->GetCallback() != nullptr) {
        relation->aniSubscriber_ = aniSubscriber;
        EventManagerFwkNapi::SetAsyncCommonEventResultWithLocked(napiSubscriber, asyncResult);
    }
    {
        std::lock_guard<ffrt::mutex> lock(transferRelationMutex);
        transferRelations.push_back(relation);
    }
    return result;
}

void SetNapiSubscriberCallback(std::shared_ptr<EventManagerFwkNapi::SubscriberInstance> subscriberInstance)
{
    subscriberInstance->SetAniAsyncResultCloneCallback(asyncResultCloneCallback);
    subscriberInstance->SetAniGcCallback(gcCallback);
    subscriberInstance->SetAniUnsubscribeCallback(unsubscribeCallback);
    subscriberInstance->SetAniSubscribeCallback(subscribeCallback);
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
    auto subscriberInstance = GetSubscriberByWrapper(wrapper);
    if (subscriberInstance == nullptr) {
        EVENT_LOGE("subscriberInstance is null.");
        return;
    }
    auto relation = GetTransferRelation(subscriberInstance, nullptr);
    if (relation == nullptr) {
        EVENT_LOGW("no transfer");
        UnsubscribeAndRemoveInstance(env, subscriberInstance);
        return;
    }
    bool allDestroyed = false;
    {
        std::lock_guard<ffrt::mutex> lock(relation->relationMutex_);
        auto subscriberItem = std::find(relation->aniSubscribers_.begin(), relation->aniSubscribers_.end(),
            subscriberInstance);
        if (subscriberItem != relation->aniSubscribers_.end()) {
            relation->aniSubscribers_.erase(subscriberItem);
        }
        if (relation->aniSubscribers_.empty() && relation->napiSubscribers_.empty()) {
            if (relation->napiSubscriber_ != nullptr) {
                EventManagerFwkNapi::UnsubscribeAndRemoveInstance(relation->napiSubscriber_->GetEnv(),
                    relation->napiSubscriber_);
            } else if (relation->aniSubscriber_ != nullptr) {
                UnsubscribeAndRemoveInstance(env, relation->aniSubscriber_);
            }
            allDestroyed = true;
        }
    }
    if (allDestroyed) {
        std::lock_guard<ffrt::mutex> lock(transferRelationMutex);
        auto item = std::find(transferRelations.begin(), transferRelations.end(), relation);
        if (item != transferRelations.end()) {
            transferRelations.erase(item);
        }
    }
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
    return GetAsyncCommonEventResult(subscriberInstance);
}

std::shared_ptr<AsyncCommonEventResult> GetAsyncCommonEventResult(std::shared_ptr<SubscriberInstance> subscriber)
{
    if (subscriber == nullptr) {
        EVENT_LOGE("subscriberInstance is null.");
        return nullptr;
    }
    if (subscriberInstances.size() == 0) {
        EVENT_LOGE("subscriberInstances is null.");
        return nullptr;
    }
    std::lock_guard<ffrt::mutex> lock(subscriberInsMutex);
    for (auto subscriberRes : subscriberInstances) {
        if (subscriberRes.first.get() == subscriber.get()) {
            return subscriberRes.second;
        }
    }
    return nullptr;
}

static ani_int getCode(ani_env *env, ani_object object)
{
    EVENT_LOGD("subscriberInstance getCode.");
    auto subscriberRes = GetAsyncCommonEventResult(env, object);
    int32_t code = 0;
    if (subscriberRes != nullptr) {
        code = subscriberRes->GetCode();
    }
    return code;
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
    ani_object nullObj = AniCommonEventUtils::GetNullObject(env);
    if (subscriberInstance == nullptr) {
        EVENT_LOGE("subscriberInstance is null.");
        return nullObj;
    }
    AniCommonEventUtils::GetCommonEventSubscribeInfoToEts(env, subscriberInstance, infoObject);
    if (infoObject == nullptr) {
        EVENT_LOGE("infoObject is null.");
        return nullObj;
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

static std::array commonEventSubscriberStaticFunctions = {
    ani_native_function{"transferToDynamicSubscriber", nullptr,
        reinterpret_cast<void *>(OHOS::EventManagerFwkAni::transferToDynamicSubscriber)},
    ani_native_function{"transferToStaticSubscriber", nullptr,
        reinterpret_cast<void *>(OHOS::EventManagerFwkAni::transferToStaticSubscriber)},
};

static std::array commonEventManagerMethods = {
    ani_native_function { "publishExecute", "C{std.core.String}:i",
        reinterpret_cast<void*>(OHOS::EventManagerFwkAni::publishExecute) },
    ani_native_function { "publishWithOptionsExecute",
        "C{std.core.String}C{commonEvent.commonEventPublishData.CommonEventPublishData}:i",
        reinterpret_cast<void*>(OHOS::EventManagerFwkAni::publishWithOptionsExecute) },
    ani_native_function { "publishAsUserExecute", "C{std.core.String}i:i",
        reinterpret_cast<void*>(OHOS::EventManagerFwkAni::publishAsUserExecute) },
    ani_native_function { "publishAsUserWithOptionsExecute",
        "C{std.core.String}iC{commonEvent.commonEventPublishData.CommonEventPublishData}:i",
        reinterpret_cast<void*>(OHOS::EventManagerFwkAni::publishAsUserWithOptionsExecute) },
    ani_native_function { "createSubscriberExecute",
        "C{commonEvent.commonEventSubscribeInfo.CommonEventSubscribeInfo}:X{C{commonEvent.commonEventSubscriber."
        "CommonEventSubscriber}N}",
        reinterpret_cast<void*>(OHOS::EventManagerFwkAni::createSubscriberExecute) },
    ani_native_function {
        "subscribeExecute", nullptr, reinterpret_cast<void*>(OHOS::EventManagerFwkAni::subscribeExecute) },
    ani_native_function {
        "subscribeToEventExecute",
        nullptr, reinterpret_cast<void*>(OHOS::EventManagerFwkAni::subscribeToEventExecute) },
    ani_native_function { "unsubscribeExecute", "C{commonEvent.commonEventSubscriber.CommonEventSubscriber}:i",
        reinterpret_cast<void*>(OHOS::EventManagerFwkAni::unsubscribeExecute) },
    ani_native_function { "removeStickyCommonEventExecute", "C{std.core.String}:i",
        reinterpret_cast<void*>(OHOS::EventManagerFwkAni::removeStickyCommonEventExecute) },
    ani_native_function { "setStaticSubscriberStateExecute", "z:i",
        reinterpret_cast<void*>(OHOS::EventManagerFwkAni::setStaticSubscriberStateExecute) },
    ani_native_function { "setStaticSubscriberStateWithEventsExecute", nullptr,
        reinterpret_cast<void*>(OHOS::EventManagerFwkAni::setStaticSubscriberStateWithEventsExecute) },
};


ani_status init(ani_env *env, ani_namespace kitNs)
{
    ani_status status = ANI_ERROR;
    status =
        env->Namespace_BindNativeFunctions(kitNs, commonEventManagerMethods.data(), commonEventManagerMethods.size());
    if (status != ANI_OK) {
        EVENT_LOGE("Cannot bind native methods to @ohos.commonEventManager.commonEventManager");
        return ANI_INVALID_TYPE;
    }

    status = env->FindClass("commonEvent.commonEventSubscriber.CommonEventSubscriberInner",
        &subscriberCls);
    if (status != ANI_OK) {
        EVENT_LOGE("Not found commonEvent.commonEventSubscriber.CommonEventSubscriberInner");
        return ANI_INVALID_ARGS;
    }
    status = env->Class_BindNativeMethods(subscriberCls, commonEventSubscriberFunctions.data(),
        commonEventSubscriberFunctions.size());
    if (status != ANI_OK) {
        EVENT_LOGE("Cannot bind native methods to commonEvent.commonEventSubscriber.CommonEventSubscriberInner");
        return ANI_INVALID_TYPE;
    }
    status = env->Class_BindStaticNativeMethods(subscriberCls, commonEventSubscriberStaticFunctions.data(),
        commonEventSubscriberStaticFunctions.size());
    if (status != ANI_OK) {
        EVENT_LOGE("Cannot bind static methods to commonEvent.commonEventSubscriber.CommonEventSubscriberInner");
        return ANI_INVALID_TYPE;
    }
    status = env->Class_FindMethod(subscriberCls, "<ctor>", "l:", &subscriberCtor);
    if (status != ANI_OK) {
        EVENT_LOGE("Class_FindMethod error. result: %{public}d.", status);
        return ANI_INVALID_TYPE;
    }
    return status;
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    EVENT_LOGD("ANI_Constructor call.");
    ani_env* env;
    ani_status status = ANI_ERROR;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        EVENT_LOGE("Unsupported ANI_VERSION_1.");
        return ANI_ERROR;
    }

    ani_namespace kitNs;
    status = env->FindNamespace("@ohos.commonEventManager.commonEventManager", &kitNs);
    if (status != ANI_OK) {
        EVENT_LOGE("Not found @ohos.commonEventManager.commonEventManager.");
        return ANI_INVALID_ARGS;
    }
    status = init(env, kitNs);
    if (status != ANI_OK) {
        EVENT_LOGE("Cannot bind native methods to L@ohos/events/emitter/emitter");
        return ANI_INVALID_TYPE;
    }

    ani_class cls;
    status = env->FindClass("commonEvent.commonEventSubscriber.Cleaner", &cls);
    if (status != ANI_OK) {
        EVENT_LOGE("Not found commonEvent.commonEventSubscriber.Cleaner");
        return ANI_INVALID_ARGS;
    }
    std::array cleanMethod = {
        ani_native_function{"clean", nullptr, reinterpret_cast<void *>(OHOS::EventManagerFwkAni::clean)}};
    status = env->Class_BindNativeMethods(cls, cleanMethod.data(), cleanMethod.size());
    if (status != ANI_OK) {
        EVENT_LOGE("Cannot bind native methods to commonEvent.commonEventSubscriber.Cleaner");
        return ANI_INVALID_TYPE;
    }
    *result = ANI_VERSION_1;
    return ANI_OK;
}
}

} // namespace EventManagerFwkAni
} // namespace OHOS
