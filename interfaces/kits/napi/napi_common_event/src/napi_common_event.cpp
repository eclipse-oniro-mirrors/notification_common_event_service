/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "napi_common_event.h"

#include <uv.h>

#include "ces_inner_error_code.h"
#include "event_log_wrapper.h"
#include "napi_common.h"
#include "support.h"

namespace OHOS {
namespace EventManagerFwkNapi {
using namespace OHOS::EventFwk;
using namespace OHOS::Notification;

static const int32_t PUBLISH_MAX_PARA = 2;
static const int32_t ARGS_TWO_EVENT = 2;
static const int32_t INDEX_ZERO = 0;
static const uint32_t INDEX_ONE = 1;
static const int32_t ARGC_ONE = 1;
static const int32_t ARGC_TWO = 2;
static const int32_t PUBLISH_MAX_PARA_AS_USER = 3;
static const int32_t STR_DATA_MAX_SIZE = 64 * 1024;  // 64KB

std::atomic_ullong SubscriberInstance::subscriberID_ = 0;

static napi_value NapiStaicSubscribeInit(napi_env env, napi_value exports)
{
    EVENT_LOGD("called");
    if (env == nullptr || exports == nullptr) {
        EVENT_LOGD("Invalid input parameters");
        return nullptr;
    }

    std::unique_ptr<NapiStaticSubscribe> napiStaicSubscribe = std::make_unique<NapiStaticSubscribe>();
    napi_wrap(env, exports, napiStaicSubscribe.release(), NapiStaticSubscribe::Finalizer, nullptr, nullptr);
    const char *moduleName = "NapiStaticSubscribe";
    AbilityRuntime::BindNativeFunction(
        env, exports, "setStaticSubscriberState", moduleName, NapiStaticSubscribe::SetStaticSubscriberState);

    return exports;
}

AsyncCallbackInfoUnsubscribe::AsyncCallbackInfoUnsubscribe()
{
    EVENT_LOGD("enter");
}

AsyncCallbackInfoUnsubscribe::~AsyncCallbackInfoUnsubscribe()
{
    EVENT_LOGD("exit");
}

SubscriberInstance::SubscriberInstance(const CommonEventSubscribeInfo &sp) : CommonEventSubscriber(sp)
{
    id_ = ++subscriberID_;
    EVENT_LOGD("Create SubscriberInstance[%{public}llu]", id_.load());
    valid_ = std::make_shared<bool>(false);
}

SubscriberInstance::~SubscriberInstance()
{
    EVENT_LOGD("destroy SubscriberInstance[%{public}llu]", id_.load());
    *valid_ = false;
}

unsigned long long SubscriberInstance::GetID()
{
    return id_.load();
}

SubscriberInstanceWrapper::SubscriberInstanceWrapper(const CommonEventSubscribeInfo &info)
{
    auto objectInfo = new (std::nothrow) SubscriberInstance(info);
    if (objectInfo == nullptr) {
        EVENT_LOGE("objectInfo is null");
        return;
    }

    EVENT_LOGD("Constructor objectInfo");
    subscriber = std::shared_ptr<SubscriberInstance>(objectInfo);
}

std::shared_ptr<SubscriberInstance> SubscriberInstanceWrapper::GetSubscriber()
{
    return subscriber;
}

napi_value SetCommonEventData(const CommonEventDataWorker *commonEventDataWorkerData, napi_value &result)
{
    EVENT_LOGD("enter");

    if (commonEventDataWorkerData == nullptr) {
        EVENT_LOGE("commonEventDataWorkerData is nullptr");
        return nullptr;
    }

    napi_value value = nullptr;

    // event
    napi_create_string_utf8(commonEventDataWorkerData->env,
        commonEventDataWorkerData->want.GetAction().c_str(),
        NAPI_AUTO_LENGTH,
        &value);
    napi_set_named_property(commonEventDataWorkerData->env, result, "event", value);

    // bundleName
    napi_create_string_utf8(commonEventDataWorkerData->env,
        commonEventDataWorkerData->want.GetBundle().c_str(),
        NAPI_AUTO_LENGTH,
        &value);
    napi_set_named_property(commonEventDataWorkerData->env, result, "bundleName", value);

    // code
    napi_create_int32(commonEventDataWorkerData->env, commonEventDataWorkerData->code, &value);
    napi_set_named_property(commonEventDataWorkerData->env, result, "code", value);

    // data
    napi_create_string_utf8(
        commonEventDataWorkerData->env, commonEventDataWorkerData->data.c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(commonEventDataWorkerData->env, result, "data", value);

    // parameters ?: {[key:string] : any}
    AAFwk::WantParams wantParams = commonEventDataWorkerData->want.GetParams();
    napi_value wantParamsValue = nullptr;
    wantParamsValue = OHOS::AppExecFwk::WrapWantParams(commonEventDataWorkerData->env, wantParams);
    if (wantParamsValue) {
        napi_set_named_property(commonEventDataWorkerData->env, result, "parameters", wantParamsValue);
    } else {
        napi_set_named_property(
            commonEventDataWorkerData->env, result, "parameters", NapiGetNull(commonEventDataWorkerData->env));
    }

    return NapiGetNull(commonEventDataWorkerData->env);
}

void UvQueueWorkOnReceiveEvent(uv_work_t *work, int status)
{
    EVENT_LOGD("OnReceiveEvent uv_work_t excute");
    if (work == nullptr) {
        return;
    }
    CommonEventDataWorker *commonEventDataWorkerData = static_cast<CommonEventDataWorker *>(work->data);
    if (commonEventDataWorkerData == nullptr) {
        EVENT_LOGE("OnReceiveEvent commonEventDataWorkerData is nullptr");
        delete work;
        work = nullptr;
        return;
    }
    if (commonEventDataWorkerData->ref == nullptr ||
        (commonEventDataWorkerData->valid == nullptr) || *(commonEventDataWorkerData->valid) == false) {
        EVENT_LOGE("OnReceiveEvent commonEventDataWorkerData ref is null or invalid which may be previously released");
        delete commonEventDataWorkerData;
        commonEventDataWorkerData = nullptr;
        delete work;
        work = nullptr;
        return;
    }
    napi_handle_scope scope;
    napi_open_handle_scope(commonEventDataWorkerData->env, &scope);

    napi_value result = nullptr;
    napi_create_object(commonEventDataWorkerData->env, &result);
    if (SetCommonEventData(commonEventDataWorkerData, result) == nullptr) {
        napi_close_handle_scope(commonEventDataWorkerData->env, scope);
        delete work;
        work = nullptr;
        delete commonEventDataWorkerData;
        commonEventDataWorkerData = nullptr;
        return;
    }

    napi_value undefined = nullptr;
    napi_get_undefined(commonEventDataWorkerData->env, &undefined);

    napi_value callback = nullptr;
    napi_value resultout = nullptr;
    napi_get_reference_value(commonEventDataWorkerData->env, commonEventDataWorkerData->ref, &callback);

    napi_value results[ARGS_TWO_EVENT] = {nullptr};
    results[INDEX_ZERO] = GetCallbackErrorValue(commonEventDataWorkerData->env, NO_ERROR);
    results[INDEX_ONE] = result;
    napi_call_function(
        commonEventDataWorkerData->env, undefined, callback, ARGS_TWO_EVENT, &results[INDEX_ZERO], &resultout);

    napi_close_handle_scope(commonEventDataWorkerData->env, scope);
    delete commonEventDataWorkerData;
    commonEventDataWorkerData = nullptr;
    delete work;
    work = nullptr;
}

void SubscriberInstance::OnReceiveEvent(const CommonEventData &data)
{
    EVENT_LOGD("OnReceiveEvent excute");
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr) {
        EVENT_LOGE("loop instance is null");
        return;
    }

    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        EVENT_LOGE("work is nullptr");
        return;
    }
    CommonEventDataWorker *commonEventDataWorker = new (std::nothrow) CommonEventDataWorker();
    if (commonEventDataWorker == nullptr) {
        EVENT_LOGE("commonEventDataWorker is nullptr");
        delete work;
        work = nullptr;
        return;
    }
    commonEventDataWorker->want = data.GetWant();
    EVENT_LOGD("OnReceiveEvent() action = %{public}s", data.GetWant().GetAction().c_str());
    commonEventDataWorker->code = data.GetCode();
    commonEventDataWorker->data = data.GetData();
    commonEventDataWorker->env = env_;
    commonEventDataWorker->ref = ref_;
    commonEventDataWorker->valid = valid_;

    work->data = reinterpret_cast<void *>(commonEventDataWorker);

    if (this->IsOrderedCommonEvent()) {
        std::lock_guard<std::mutex> lock(subscriberInsMutex);
        for (auto subscriberInstance : subscriberInstances) {
            if (subscriberInstance.first.get() == this) {
                subscriberInstances[subscriberInstance.first].commonEventResult = GoAsyncCommonEvent();
                break;
            }
        }
    }

    int ret = uv_queue_work_with_qos(loop, work, [](uv_work_t *work) {},
        UvQueueWorkOnReceiveEvent, uv_qos_user_initiated);
    if (ret != 0) {
        delete commonEventDataWorker;
        commonEventDataWorker = nullptr;
        delete work;
        work = nullptr;
    }
    EVENT_LOGD("OnReceiveEvent complete");
}

napi_value CreateSubscriber(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("CreateSubscriber excute");

    size_t argc = CREATE_MAX_PARA;
    napi_value argv[CREATE_MAX_PARA] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) {
        EVENT_LOGE("Wrong number of parameters");
        return NapiGetNull(env);
    }

    napi_ref callback = nullptr;
    if (ParseParametersByCreateSubscriber(env, argv, argc, callback) == nullptr) {
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID);
        return NapiGetNull(env);
    }

    AsyncCallbackInfoCreate *asyncCallbackInfo =
        new (std::nothrow) AsyncCallbackInfoCreate {.env = env, .asyncWork = nullptr, .subscribeInfo = nullptr};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGE("asyncCallbackInfo is null");
        return NapiGetNull(env);
    }
    napi_value promise = nullptr;

    PaddingAsyncCallbackInfoCreateSubscriber(env, asyncCallbackInfo, callback, promise);

    napi_create_reference(env, argv[0], 1, &asyncCallbackInfo->subscribeInfo);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "CreateSubscriber", NAPI_AUTO_LENGTH, &resourceName);

    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) { EVENT_LOGD("CreateSubscriber napi_create_async_work start"); },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("CreateSubscriber napi_create_async_work end");
            AsyncCallbackInfoCreate *asyncCallbackInfo = static_cast<AsyncCallbackInfoCreate *>(data);
            if (asyncCallbackInfo) {
                napi_value constructor = nullptr;
                napi_value subscribeInfoRefValue = nullptr;
                napi_get_reference_value(env, asyncCallbackInfo->subscribeInfo, &subscribeInfoRefValue);
                napi_get_reference_value(env, g_CommonEventSubscriber, &constructor);
                napi_new_instance(env, constructor, 1, &subscribeInfoRefValue, &asyncCallbackInfo->result);

                if (asyncCallbackInfo->result == nullptr) {
                    EVENT_LOGE("create subscriber instance failed");
                    asyncCallbackInfo->info.errorCode = ERR_CES_FAILED;
                }
                ReturnCallbackPromise(env, asyncCallbackInfo->info, asyncCallbackInfo->result);
                if (asyncCallbackInfo->info.callback != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->info.callback);
                }
                if (asyncCallbackInfo->subscribeInfo != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->subscribeInfo);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
            EVENT_LOGD("CreateSubscriber work complete end");
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));

    if (asyncCallbackInfo->info.isCallback) {
        EVENT_LOGD("Delete napiCreateSubscriber callback reference.");
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value CreateSubscriberSync(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("CreateSubscriberSync start");

    size_t argc = ARGC_ONE;
    napi_value argv[ARGC_ONE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) {
        EVENT_LOGE("Wrong number of arguments");
        return NapiGetNull(env);
    }

    napi_valuetype valuetype;

    // argv[0]:CommonEventSubscribeInfo
    NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
    if (valuetype != napi_object) {
        EVENT_LOGE("Wrong argument type. object expected.");
        std::string msg = "Incorrect parameter types.The type of param must be object.";
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
        return NapiGetNull(env);
    }

    napi_ref subscribeInfo = nullptr;
    napi_create_reference(env, argv[0], 1, &subscribeInfo);

    napi_value result = nullptr;
    napi_value constructor = nullptr;
    napi_value subscribeInfoRefValue = nullptr;
    napi_get_reference_value(env, subscribeInfo, &subscribeInfoRefValue);
    napi_get_reference_value(env, g_CommonEventSubscriber, &constructor);
    napi_new_instance(env, constructor, 1, &subscribeInfoRefValue, &result);

    if (result == nullptr) {
        EVENT_LOGE("create subscriber instance failed");
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID);
        return NapiGetNull(env);
    }

    if (subscribeInfo != nullptr) {
        napi_delete_reference(env, subscribeInfo);
    }

    return result;
}

std::shared_ptr<AsyncCommonEventResult> GetAsyncResult(const SubscriberInstance *objectInfo)
{
    EVENT_LOGD("GetAsyncResult excute");
    if (!objectInfo) {
        EVENT_LOGE("Invalid objectInfo");
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(subscriberInsMutex);
    for (auto subscriberInstance : subscriberInstances) {
        if (subscriberInstance.first.get() == objectInfo) {
            return subscriberInstance.second.commonEventResult;
        }
    }
    EVENT_LOGW("Unable to found objectInfo");
    return nullptr;
}

std::shared_ptr<SubscriberInstance> GetSubscriber(const napi_env &env, const napi_value &value)
{
    EVENT_LOGD("GetSubscriber excute");

    SubscriberInstanceWrapper *wrapper = nullptr;
    napi_unwrap(env, value, (void **)&wrapper);
    if (wrapper == nullptr) {
        EVENT_LOGW("GetSubscriber wrapper is null");
        return nullptr;
    }

    return wrapper->GetSubscriber();
}

napi_value Subscribe(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("Subscribe excute");

    // Argument parsing
    size_t argc = SUBSCRIBE_MAX_PARA;
    napi_value argv[SUBSCRIBE_MAX_PARA] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < SUBSCRIBE_MAX_PARA) {
        EVENT_LOGE("Wrong number of arguments");
        return NapiGetNull(env);
    }

    napi_ref callback = nullptr;
    std::shared_ptr<SubscriberInstance> subscriber = nullptr;

    if (ParseParametersBySubscribe(env, argv, subscriber, callback) == nullptr) {
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID);
        return NapiGetNull(env);
    }

    AsyncCallbackInfoSubscribe *asyncCallbackInfo =
        new (std::nothrow) AsyncCallbackInfoSubscribe {.env = env, .asyncWork = nullptr, .subscriber = nullptr};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGE("asyncCallbackInfo is nullptr");
        return NapiGetNull(env);
    }
    asyncCallbackInfo->subscriber = subscriber;
    asyncCallbackInfo->callback = callback;

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "Subscribe", NAPI_AUTO_LENGTH, &resourceName);

    // Calling asynchronous functions
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("Subscribe napi_create_async_work excute");
            AsyncCallbackInfoSubscribe *asyncCallbackInfo = static_cast<AsyncCallbackInfoSubscribe *>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->subscriber->SetEnv(env);
                asyncCallbackInfo->subscriber->SetCallbackRef(asyncCallbackInfo->callback);
                asyncCallbackInfo->errorCode = CommonEventManager::NewSubscribeCommonEvent(
                    asyncCallbackInfo->subscriber);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("Subscribe napi_create_async_work end");
            AsyncCallbackInfoSubscribe *asyncCallbackInfo = static_cast<AsyncCallbackInfoSubscribe *>(data);
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
            if (asyncCallbackInfo->errorCode == NO_ERROR) {
                EVENT_LOGD("asyncCallbackInfo is 0");
                std::lock_guard<std::mutex> lock(subscriberInsMutex);
                subscriberInstances[asyncCallbackInfo->subscriber].asyncCallbackInfo.emplace_back(asyncCallbackInfo);
            } else {
                SetCallback(env, asyncCallbackInfo->callback, asyncCallbackInfo->errorCode, NapiGetNull(env));

                if (asyncCallbackInfo->callback != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->callback);
                }

                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));
    return NapiGetNull(env);
}

napi_value Publish(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("NapiPublish start");
    size_t argc = PUBLISH_MAX_PARA_BY_PUBLISHDATA;
    napi_value argv[PUBLISH_MAX_PARA_BY_PUBLISHDATA] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < PUBLISH_MAX_PARA) {
        EVENT_LOGE("Wrong number of arguments.");
        return NapiGetNull(env);
    }

    std::string event;
    CommonEventPublishDataByjs commonEventPublishDatajs;
    napi_ref callback = nullptr;

    if (ParseParametersByPublish(env, argv, argc, event, commonEventPublishDatajs, callback) == nullptr) {
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID);
        return NapiGetNull(env);
    }

    AsyncCallbackInfoPublish *asyncCallbackInfo =
        new (std::nothrow) AsyncCallbackInfoPublish {.env = env, .asyncWork = nullptr};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGD("Create asyncCallbackInfo is fail.");
        return NapiGetNull(env);
    }
    asyncCallbackInfo->callback = callback;

    // CommonEventData::want->action
    Want want;
    want.SetAction(event);
    if (argc == PUBLISH_MAX_PARA_BY_PUBLISHDATA) {
        PaddingCallbackInfoPublish(want, asyncCallbackInfo, commonEventPublishDatajs);
    }
    asyncCallbackInfo->commonEventData.SetWant(want);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "Publish", NAPI_AUTO_LENGTH, &resourceName);

    // Calling Asynchronous functions
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("Publish napi_create_async_work excute");
            AsyncCallbackInfoPublish *asyncCallbackInfo = static_cast<AsyncCallbackInfoPublish *>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->errorCode = CommonEventManager::NewPublishCommonEvent(
                    asyncCallbackInfo->commonEventData, asyncCallbackInfo->commonEventPublishInfo);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("NapiPublish work complete.");
            AsyncCallbackInfoPublish *asyncCallbackInfo = static_cast<AsyncCallbackInfoPublish *>(data);
            if (asyncCallbackInfo) {
                SetCallback(env, asyncCallbackInfo->callback, asyncCallbackInfo->errorCode, NapiGetNull(env));
                if (asyncCallbackInfo->callback != nullptr) {
                    EVENT_LOGD("Delete napiPublish callback reference.");
                    napi_delete_reference(env, asyncCallbackInfo->callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
            EVENT_LOGD("NapiPublish work complete end.");
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));

    return NapiGetNull(env);
}

void NapiStaticSubscribe::Finalizer(napi_env env, void *data, void *hint)
{
    EVENT_LOGD("called");
    delete static_cast<NapiStaticSubscribe *>(data);
}

napi_value PublishAsUser(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("Publish excute");

    size_t argc = PUBLISH_MAX_PARA_BY_USERID;
    napi_value argv[PUBLISH_MAX_PARA_BY_USERID] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < PUBLISH_MAX_PARA_AS_USER) {
        EVENT_LOGE("Wrong number of Parameter.");
        return NapiGetNull(env);
    }

    std::string event;
    int32_t userId = UNDEFINED_USER;
    CommonEventPublishDataByjs commonEventPublishDatajs;
    napi_ref callback = nullptr;

    if (ParseParametersByPublishAsUser(env, argv, argc, event, userId, commonEventPublishDatajs, callback) == nullptr) {
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID);
        return NapiGetNull(env);
    }

    AsyncCallbackInfoPublish *asyncCallbackInfo =
        new (std::nothrow) AsyncCallbackInfoPublish {.env = env, .asyncWork = nullptr};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGE("asyncCallbackInfo is nullptr");
        return NapiGetNull(env);
    }
    asyncCallbackInfo->callback = callback;

    // CommonEventData::want->action.
    Want want;
    want.SetAction(event);
    if (argc == PUBLISH_MAX_PARA_BY_USERID) {
        PaddingCallbackInfoPublish(want, asyncCallbackInfo, commonEventPublishDatajs);
    }
    asyncCallbackInfo->commonEventData.SetWant(want);
    asyncCallbackInfo->userId = userId;

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "Publish", NAPI_AUTO_LENGTH, &resourceName);

    // Calling Asynchronous functions
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("Publish napi_create_async_work start");
            AsyncCallbackInfoPublish *asyncCallbackInfo = static_cast<AsyncCallbackInfoPublish *>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->errorCode = CommonEventManager::NewPublishCommonEventAsUser(
                    asyncCallbackInfo->commonEventData, asyncCallbackInfo->commonEventPublishInfo,
                    asyncCallbackInfo->userId);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("NapiPublishAsUser work complete.");
            AsyncCallbackInfoPublish *asyncCallbackInfo = static_cast<AsyncCallbackInfoPublish *>(data);
            if (asyncCallbackInfo) {
                SetCallback(env, asyncCallbackInfo->callback, asyncCallbackInfo->errorCode, NapiGetNull(env));
                if (asyncCallbackInfo->callback != nullptr) {
                    EVENT_LOGD("Delete NapiPublishAsUser callback reference.");
                    napi_delete_reference(env, asyncCallbackInfo->callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
            EVENT_LOGD("NapiPublishAsUser work complete end.");
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));

    return NapiGetNull(env);
}

napi_value GetSubscriberByUnsubscribe(
    const napi_env &env, const napi_value &value, std::shared_ptr<SubscriberInstance> &subscriber, bool &isFind)
{
    EVENT_LOGD("GetSubscriberByUnsubscribe excute");

    isFind = false;
    subscriber = GetSubscriber(env, value);
    if (subscriber == nullptr) {
        EVENT_LOGE("subscriber is null");
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(subscriberInsMutex);
    for (auto subscriberInstance : subscriberInstances) {
        if (subscriberInstance.first.get() == subscriber.get()) {
            subscriber = subscriberInstance.first;
            isFind = true;
            break;
        }
    }

    return NapiGetNull(env);
}

void NapiDeleteSubscribe(const napi_env &env, std::shared_ptr<SubscriberInstance> &subscriber)
{
    EVENT_LOGD("NapiDeleteSubscribe excute");
    std::lock_guard<std::mutex> lock(subscriberInsMutex);
    auto subscribe = subscriberInstances.find(subscriber);
    if (subscribe != subscriberInstances.end()) {
        for (auto asyncCallbackInfoSubscribe : subscribe->second.asyncCallbackInfo) {
            if (asyncCallbackInfoSubscribe->callback != nullptr) {
                napi_delete_reference(env, asyncCallbackInfoSubscribe->callback);
            }
            delete asyncCallbackInfoSubscribe;
            asyncCallbackInfoSubscribe = nullptr;
            EVENT_LOGD("asyncCallbackInfoSubscribe is null");
        }
        subscriber->SetCallbackRef(nullptr);
        subscriberInstances.erase(subscribe);
    }
}

napi_value Unsubscribe(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("Unsubscribe excute");

    // Argument parsing
    size_t argc = UNSUBSCRIBE_MAX_PARA;
    napi_value argv[UNSUBSCRIBE_MAX_PARA] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) {
        EVENT_LOGE("Wrong number of parameters");
        return NapiGetNull(env);
    }

    napi_ref callback = nullptr;
    std::shared_ptr<SubscriberInstance> subscriber = nullptr;
    napi_value result = nullptr;
    result = ParseParametersByUnsubscribe(env, argc, argv, subscriber, callback);
    if (result == nullptr) {
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID);
        return NapiGetNull(env);
    }
    bool isFind = false;
    napi_get_value_bool(env, result, &isFind);
    if (!isFind) {
        EVENT_LOGE("Unsubscribe failed. The current subscriber does not exist.");
        return NapiGetNull(env);
    }

    AsyncCallbackInfoUnsubscribe *asynccallback = new (std::nothrow) AsyncCallbackInfoUnsubscribe();
    if (asynccallback == nullptr) {
        EVENT_LOGE("asynccallback is nullptr");
        return NapiGetNull(env);
    }
    asynccallback->env = env;
    asynccallback->subscriber = subscriber;
    asynccallback->argc = argc;
    if (argc >= UNSUBSCRIBE_MAX_PARA) {
        asynccallback->callback = callback;
    }

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "Unsubscribe", NAPI_AUTO_LENGTH, &resourceName);

    // Calling Asynchronous functions
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("Unsubscribe napi_create_async_work start");
            AsyncCallbackInfoUnsubscribe *asyncCallbackInfo = static_cast<AsyncCallbackInfoUnsubscribe *>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->errorCode = CommonEventManager::NewUnSubscribeCommonEvent(
                    asyncCallbackInfo->subscriber);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("Unsubscribe napi_create_async_work complete");
            AsyncCallbackInfoUnsubscribe *asyncCallbackInfo = static_cast<AsyncCallbackInfoUnsubscribe *>(data);
            if (asyncCallbackInfo) {
                if (asyncCallbackInfo->argc >= UNSUBSCRIBE_MAX_PARA) {
                    napi_value result = nullptr;
                    napi_get_null(env, &result);
                    SetCallback(env, asyncCallbackInfo->callback, asyncCallbackInfo->errorCode, result);
                }
                if (asyncCallbackInfo->callback != nullptr) {
                    EVENT_LOGD("Delete cancel callback reference.");
                    napi_delete_reference(env, asyncCallbackInfo->callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                NapiDeleteSubscribe(env, asyncCallbackInfo->subscriber);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
        },
        (void *)asynccallback,
        &asynccallback->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asynccallback->asyncWork, napi_qos_user_initiated));
    return NapiGetNull(env);
}

napi_value RemoveStickyCommonEvent(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("RemoveStickyCommonEvent start");

    std::string event;
    CallbackPromiseInfo params;
    napi_value result = ParseParametersByRemoveSticky(env, info, event, params);
    if (result == nullptr) {
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID);
        return NapiGetNull(env);
    }

    AsyncCallbackRemoveSticky *asyncCallbackInfo =
        new (std::nothrow) AsyncCallbackRemoveSticky {.env = env, .asyncWork = nullptr, .event = event};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGE("asyncCallbackInfo is null");
        return NapiGetNull(env);
    }
    napi_value promise = nullptr;
    PaddingCallbackPromiseInfo(env, params.callback, asyncCallbackInfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "removeStickyCommonEvent", NAPI_AUTO_LENGTH, &resourceName);

    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("removeStickyCommonEvent napi_create_async_work start");
            AsyncCallbackRemoveSticky *asyncCallbackInfo = static_cast<AsyncCallbackRemoveSticky *>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.errorCode =
                    CommonEventManager::RemoveStickyCommonEvent(asyncCallbackInfo->event);
            }
        },
        AsyncCompleteCallbackRemoveStickyCommonEvent,
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    napi_status status = napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated);
    if (status != napi_ok) {
        delete asyncCallbackInfo;
        asyncCallbackInfo = nullptr;
        EVENT_LOGE("napi_queue_async_work failed return: %{public}d", status);
        return NapiGetNull(env);
    }

    if (asyncCallbackInfo->info.isCallback) {
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value CommonEventSubscriberConstructor(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("enter");
    napi_value thisVar = nullptr;
    CommonEventSubscribeInfo subscribeInfo;
    if (!ParseParametersConstructor(env, info, thisVar, subscribeInfo)) {
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID);
        return NapiGetNull(env);
    }
    subscribeInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::ThreadMode::HANDLER);
    auto wrapper = new (std::nothrow) SubscriberInstanceWrapper(subscribeInfo);
    if (wrapper == nullptr) {
        EVENT_LOGE("wrapper is null");
        return NapiGetNull(env);
    }

    napi_wrap(env, thisVar, wrapper,
        [](napi_env env, void *data, void *hint) {
            auto *wrapper = reinterpret_cast<SubscriberInstanceWrapper *>(data);
            EVENT_LOGD("Constructor destroy");
            std::lock_guard<std::mutex> lock(subscriberInsMutex);
            for (auto subscriberInstance : subscriberInstances) {
                if (subscriberInstance.first.get() == wrapper->GetSubscriber().get()) {
                    for (auto asyncCallbackInfo : subscriberInstance.second.asyncCallbackInfo) {
                        if (asyncCallbackInfo->callback != nullptr) {
                            napi_delete_reference(env, asyncCallbackInfo->callback);
                        }
                        delete asyncCallbackInfo;
                        asyncCallbackInfo = nullptr;
                    }
                    wrapper->GetSubscriber()->SetCallbackRef(nullptr);
                    CommonEventManager::UnSubscribeCommonEvent(subscriberInstance.first);
                    subscriberInstances.erase(subscriberInstance.first);
                    break;
                }
            }
            delete wrapper;
            wrapper = nullptr;
        },
        nullptr,
        nullptr);

    EVENT_LOGD("end");
    return thisVar;
}

void SetNapiResult(const napi_env &env, const CommonEventSubscribeInfo &subscribeInfo, napi_value &result)
{
    EVENT_LOGD("SetNapiResult start");

    SetEventsResult(env, subscribeInfo.GetMatchingSkills().GetEvents(), result);
    SetPublisherPermissionResult(env, subscribeInfo.GetPermission(), result);
    SetPublisherDeviceIdResult(env, subscribeInfo.GetDeviceId(), result);
    SetPublisherUserIdResult(env, subscribeInfo.GetUserId(), result);
    SetPublisherPriorityResult(env, subscribeInfo.GetPriority(), result);
    SetPublisherBundleNameResult(env, subscribeInfo.GetPublisherBundleName(), result);
}

napi_value GetSubscribeInfoSync(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("GetSubscribeInfoSync start");

    size_t argc = 1;
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, nullptr, &thisVar, NULL));

    std::shared_ptr<SubscriberInstance> subscriber = GetSubscriber(env, thisVar);
    if (subscriber == nullptr) {
        EVENT_LOGE("subscriber is nullptr");
        return NapiGetNull(env);
    }

    napi_value res = nullptr;
    napi_create_object(env, &res);
    SetNapiResult(env, subscriber->GetSubscribeInfo(), res);

    return res;
}

napi_value IsOrderedCommonEventSync(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("isOrderedCommonEventSync start");

    size_t argc = 0;
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, nullptr, &thisVar, NULL));

    std::shared_ptr<SubscriberInstance> subscriber = GetSubscriber(env, thisVar);
    if (subscriber == nullptr) {
        EVENT_LOGE("subscriber is nullptr");
        return NapiGetNull(env);
    }
    bool isOrdered = false;

    std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(subscriber.get());
    if (asyncResult) {
        isOrdered = asyncResult->IsOrderedCommonEvent();
    } else {
        isOrdered = subscriber->IsOrderedCommonEvent();
    }

    napi_value result = nullptr;
    napi_get_boolean(env, isOrdered, &result);

    return result;
}

napi_value GetCodeSync(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("getCodeSync start");
    size_t argc = 1;
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, nullptr, &thisVar, NULL));

    int32_t code = 0;

    std::shared_ptr<SubscriberInstance> subscriber = GetSubscriber(env, thisVar);
    if (subscriber == nullptr) {
        EVENT_LOGE("subscriber is nullptr");
        return NapiGetNull(env);
    }

    std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(subscriber.get());
    if (asyncResult) {
        EVENT_LOGD("get asyncResult success");
        code = asyncResult->GetCode();
    } else {
        EVENT_LOGD("get asyncResult failed");
        code = 0;
    }
    napi_value res = nullptr;
    napi_create_int32(env, code, &res);
    return res;
}

napi_value SetCodeSync(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("setCodeSync start");
    size_t argc = ARGC_ONE;
    napi_value argv[ARGC_ONE] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    int32_t code = 0;
    NAPI_CALL(env, napi_get_value_int32(env, argv[0], &code));

    std::shared_ptr<SubscriberInstance> subscriber = GetSubscriber(env, thisVar);
    if (subscriber == nullptr) {
        EVENT_LOGE("subscriber is nullptr");
        return NapiGetNull(env);
    }

    std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(subscriber.get());
    if (asyncResult) {
        asyncResult->SetCode(code);
    } else {
        EVENT_LOGE("asyncResult is nullptr");
    }

    return NapiGetNull(env);
}

napi_value GetDataSync(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("getDataSync start");
    size_t argc = 1;
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, nullptr, &thisVar, NULL));

    std::shared_ptr<SubscriberInstance> subscriber = GetSubscriber(env, thisVar);
    if (subscriber == nullptr) {
        EVENT_LOGE("subscriber is nullptr");
        return NapiGetNull(env);
    }

    std::string data;

    std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(subscriber.get());
    if (asyncResult) {
        data = asyncResult->GetData();
    } else {
        data = std::string();
    }
    napi_value res = nullptr;
    napi_create_string_utf8(env, data.c_str(), NAPI_AUTO_LENGTH, &res);
    return res;
}

napi_value SetDataSync(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("setDataSync start");
    size_t argc = ARGC_ONE;
    napi_value argv[ARGC_ONE] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    char str[STR_DATA_MAX_SIZE] = {0};
    size_t strLen = 0;
    std::string data;
    NAPI_CALL(env, napi_get_value_string_utf8(env, argv[0], str, STR_DATA_MAX_SIZE, &strLen));
    if (strLen > STR_DATA_MAX_SIZE - 1) {
        EVENT_LOGE("data over size");
        return NapiGetNull(env);
    }
    data = str;

    std::shared_ptr<SubscriberInstance> subscriber = GetSubscriber(env, thisVar);
    if (subscriber == nullptr) {
        EVENT_LOGE("subscriber is nullptr");
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID);
        return NapiGetNull(env);
    }

    std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(subscriber.get());
    if (asyncResult) {
        asyncResult->SetData(data);
    }

    return NapiGetNull(env);
}

napi_value SetCodeAndDataSync(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("setCodeAndDataSync start");
    size_t argc = ARGC_TWO;
    napi_value argv[ARGC_TWO] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    int32_t code = 0;
    NAPI_CALL(env, napi_get_value_int32(env, argv[0], &code));

    char str[STR_DATA_MAX_SIZE] = {0};
    size_t strLen = 0;
    std::string data;
    NAPI_CALL(env, napi_get_value_string_utf8(env, argv[1], str, STR_DATA_MAX_SIZE, &strLen));
    if (strLen > STR_DATA_MAX_SIZE - 1) {
        EVENT_LOGE("data over size");
        std::string msg = "Parameter verification failed. cannot exceed ";
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID,
            msg.append(std::to_string(STR_DATA_MAX_SIZE - 1)).append(" characters"));
        return NapiGetNull(env);;
    }
    data = str;

    std::shared_ptr<SubscriberInstance> subscriber = GetSubscriber(env, thisVar);
    if (subscriber == nullptr) {
        EVENT_LOGE("subscriber is nullptr");
        return NapiGetNull(env);
    }

    std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(subscriber.get());
    if (asyncResult) {
        asyncResult->SetCodeAndData(code, data);
    }
    return NapiGetNull(env);
}

napi_value AbortCommonEventSync(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("abortCommonEventSync start");
    size_t argc = 0;
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, nullptr, &thisVar, NULL));

    std::shared_ptr<SubscriberInstance> subscriber = GetSubscriber(env, thisVar);
    if (subscriber == nullptr) {
        EVENT_LOGE("subscriber is nullptr");
        return NapiGetNull(env);
    }

    std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(subscriber.get());
    if (asyncResult) {
        asyncResult->AbortCommonEvent();
    }

    return NapiGetNull(env);
}

napi_value ClearAbortCommonEventSync(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("clearAbortCommonEventSync start");
    size_t argc = 1;
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, nullptr, &thisVar, NULL));

    std::shared_ptr<SubscriberInstance> subscriber = GetSubscriber(env, thisVar);

    if (subscriber == nullptr) {
        EVENT_LOGE("subscriber is nullptr");
        return NapiGetNull(env);
    }

    std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(subscriber.get());
    if (asyncResult) {
        asyncResult->ClearAbortCommonEvent();
    }

    return NapiGetNull(env);
}

napi_value GetAbortCommonEventSync(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("GetAbortCommonEventSync start");
    size_t argc = 1;

    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, nullptr, &thisVar, NULL));

    std::shared_ptr<SubscriberInstance> subscriber = GetSubscriber(env, thisVar);
    if (subscriber == nullptr) {
        EVENT_LOGE("subscriber is nullptr");
        return NapiGetNull(env);
    }

    bool abortEvent = false;

    std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(subscriber.get());
    if (asyncResult) {
        abortEvent = asyncResult->GetAbortCommonEvent();
    } else {
        abortEvent = false;
    }

    napi_value result = nullptr;
    napi_get_boolean(env, abortEvent, &result);

    return result;
}

napi_value IsStickyCommonEventSync(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("isStickyCommonEventSync start");

    size_t argc = 0;
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, nullptr, &thisVar, NULL));

    std::shared_ptr<SubscriberInstance> subscriber = GetSubscriber(env, thisVar);
    if (subscriber == nullptr) {
        EVENT_LOGE("subscriber is nullptr");
        return NapiGetNull(env);
    }

    bool isSticky = false;

    std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(subscriber.get());
    if (asyncResult) {
        isSticky = asyncResult->IsStickyCommonEvent();
    } else {
        isSticky = subscriber->IsStickyCommonEvent();
    }

    napi_value result = nullptr;
    napi_get_boolean(env, isSticky, &result);

    return result;
}

napi_value GetSubscribeInfo(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("GetSubscribeInfo excute");

    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_ref callback = nullptr;
    if (ParseParametersByGetSubscribeInfo(env, argc, argv, callback) == nullptr) {
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID);
        return NapiGetNull(env);
    }

    AsyncCallbackInfoSubscribeInfo *asyncCallbackInfo =
        new (std::nothrow) AsyncCallbackInfoSubscribeInfo {.env = env, .asyncWork = nullptr};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGE("asyncCallbackInfo failed");
        return NapiGetNull(env);
    }

    asyncCallbackInfo->subscriber = GetSubscriber(env, thisVar);
    if (asyncCallbackInfo->subscriber == nullptr) {
        EVENT_LOGE("subscriber is null");
        delete asyncCallbackInfo;
        return NapiGetNull(env);
    }

    napi_value promise = nullptr;
    PaddingAsyncCallbackInfoGetSubscribeInfo(env, argc, asyncCallbackInfo, callback, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getSubscribeInfo", NAPI_AUTO_LENGTH, &resourceName);
    // napi Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("GetSubscribeInfo napi_create_async_work excute");
            AsyncCallbackInfoSubscribeInfo *asyncCallbackInfo = static_cast<AsyncCallbackInfoSubscribeInfo *>(data);

            PaddingNapiCreateAsyncWorkCallbackInfo(asyncCallbackInfo);
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("GetSubscribeInfo napi_create_async_work complete");
            AsyncCallbackInfoSubscribeInfo *asyncCallbackInfo = static_cast<AsyncCallbackInfoSubscribeInfo *>(data);
            if (asyncCallbackInfo) {
                napi_value result = nullptr;
                napi_create_object(env, &result);
                SetNapiResult(env, asyncCallbackInfo, result);
                ReturnCallbackPromise(env, asyncCallbackInfo->info, result);
                if (asyncCallbackInfo->info.callback != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->info.callback);
                    EVENT_LOGD("Delete napiGetSubscribeInfo callback reference.");
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
            EVENT_LOGD("NapiGetSubscribeInfo work complete end.");
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));

    if (asyncCallbackInfo->info.isCallback) {
        EVENT_LOGD("Delete napiGetSubscribeInfo callback reference.");
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value IsOrderedCommonEvent(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("IsOrderedCommonEvent excute");

    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    napi_ref callback = nullptr;
    if (ParseParametersByIsOrderedCommonEvent(env, argv, argc, callback) == nullptr) {
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID);
        return NapiGetNull(env);
    }

    AsyncCallbackInfoOrderedCommonEvent *asyncCallbackInfo = new (std::nothrow)
        AsyncCallbackInfoOrderedCommonEvent {.env = env, .asyncWork = nullptr};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGD("asyncCallbackInfo failed");
        return NapiGetNull(env);
    }

    asyncCallbackInfo->subscriber = GetSubscriber(env, thisVar);
    if (asyncCallbackInfo->subscriber == nullptr) {
        EVENT_LOGE("subscriber is null");
        delete asyncCallbackInfo;
        return NapiGetNull(env);
    }

    napi_value promise = nullptr;
    PaddingAsyncCallbackInfoIsOrderedCommonEvent(env, argc, asyncCallbackInfo, callback, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "isOrderedCommonEvent", NAPI_AUTO_LENGTH, &resourceName);
    // Calling Asynchronous functions
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("IsOrderedCommonEvent napi_create_async_work start");
            AsyncCallbackInfoOrderedCommonEvent *asyncCallbackInfo =
                static_cast<AsyncCallbackInfoOrderedCommonEvent *>(data);
            if (asyncCallbackInfo) {
                std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(
                    asyncCallbackInfo->subscriber.get());
                if (asyncResult) {
                    asyncCallbackInfo->isOrdered = asyncResult->IsOrderedCommonEvent();
                } else {
                    asyncCallbackInfo->isOrdered = asyncCallbackInfo->subscriber->IsOrderedCommonEvent();
                }
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("IsOrderedCommonEvent napi_create_async_work end");
            AsyncCallbackInfoOrderedCommonEvent *asyncCallbackInfo =
                static_cast<AsyncCallbackInfoOrderedCommonEvent *>(data);
            if (asyncCallbackInfo) {
                napi_value result = nullptr;
                napi_get_boolean(env, asyncCallbackInfo->isOrdered, &result);
                ReturnCallbackPromise(env, asyncCallbackInfo->info, result);
                if (asyncCallbackInfo->info.callback != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->info.callback);
                    EVENT_LOGD("Delete napiIsOrderedCommonEvent callback reference.");
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
            EVENT_LOGD("NapiIsOrderedCommonEvent work complete end.");
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));

    if (asyncCallbackInfo->info.isCallback) {
        EVENT_LOGD("Delete napiIsOrderedCommonEvent callback reference.");
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value IsStickyCommonEvent(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("IsStickyCommonEvent excute");

    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_ref callback = nullptr;
    if (ParseParametersByIsStickyCommonEvent(env, argv, argc, callback) == nullptr) {
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID);
        return NapiGetNull(env);
    }

    AsyncCallbackInfoStickyCommonEvent *asyncCallbackInfo = new (std::nothrow)
        AsyncCallbackInfoStickyCommonEvent {.env = env, .asyncWork = nullptr};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGE("Failed to create asyncCallbackInfo.");
        return NapiGetNull(env);
    }

    asyncCallbackInfo->subscriber = GetSubscriber(env, thisVar);
    if (asyncCallbackInfo->subscriber == nullptr) {
        EVENT_LOGE("subscriber is null");
        delete asyncCallbackInfo;
        return NapiGetNull(env);
    }

    napi_value promise = nullptr;
    PaddingAsyncCallbackInfoIsStickyCommonEvent(env, argc, asyncCallbackInfo, callback, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "isStickyCommonEvent", NAPI_AUTO_LENGTH, &resourceName);
    // Calling Asynchronous functions
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("isStickyCommonEvent napi_create_async_work excute");
            AsyncCallbackInfoStickyCommonEvent *asyncCallbackInfo =
                static_cast<AsyncCallbackInfoStickyCommonEvent *>(data);
            if (asyncCallbackInfo) {
                std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(
                    asyncCallbackInfo->subscriber.get());
                if (asyncResult) {
                    asyncCallbackInfo->isSticky = asyncResult->IsStickyCommonEvent();
                } else {
                    asyncCallbackInfo->isSticky = asyncCallbackInfo->subscriber->IsStickyCommonEvent();
                }
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("isStickyCommonEvent napi_create_async_work end");
            AsyncCallbackInfoStickyCommonEvent *asyncCallbackInfo =
                static_cast<AsyncCallbackInfoStickyCommonEvent *>(data);
            if (asyncCallbackInfo) {
                napi_value result = nullptr;
                napi_get_boolean(env, asyncCallbackInfo->isSticky, &result);
                ReturnCallbackPromise(env, asyncCallbackInfo->info, result);
                if (asyncCallbackInfo->info.callback != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->info.callback);
                    EVENT_LOGD("Delete napiisStickyCommonEvent callback reference.");
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
            EVENT_LOGD("NapiisStickyCommonEvent work complete end.");
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));

    if (asyncCallbackInfo->info.isCallback) {
        EVENT_LOGD("Delete napiisStickyCommonEvent callback reference.");
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value GetCode(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("GetCode excute");
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_ref callback = nullptr;
    if (ParseParametersByGetCode(env, argv, argc, callback) == nullptr) {
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID);
        return NapiGetNull(env);
    }

    AsyncCallbackInfoGetCode *asyncCallbackInfo =
        new (std::nothrow) AsyncCallbackInfoGetCode {.env = env, .asyncWork = nullptr};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGE("asyncCallbackInfo is nullptr");
        return NapiGetNull(env);
    }

    asyncCallbackInfo->subscriber = GetSubscriber(env, thisVar);
    if (asyncCallbackInfo->subscriber == nullptr) {
        EVENT_LOGE("GetSubscriber failed.");
        delete asyncCallbackInfo;
        return NapiGetNull(env);
    }

    napi_value promise = nullptr;
    PaddingAsyncCallbackInfoGetCode(env, argc, asyncCallbackInfo, callback, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getCode", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("GetCode napi_create_async_work excute");
            AsyncCallbackInfoGetCode *asyncCallbackInfo = static_cast<AsyncCallbackInfoGetCode *>(data);
            if (asyncCallbackInfo) {
                std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(
                    asyncCallbackInfo->subscriber.get());
                if (asyncResult) {
                    EVENT_LOGD("get code success");
                    asyncCallbackInfo->code = asyncResult->GetCode();
                } else {
                    EVENT_LOGD("get code failed");
                    asyncCallbackInfo->code = 0;
                }
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("GetCode napi_create_async_work complete");
            AsyncCallbackInfoGetCode *asyncCallbackInfo = static_cast<AsyncCallbackInfoGetCode *>(data);
            if (asyncCallbackInfo) {
                napi_value result = nullptr;
                napi_create_int32(env, asyncCallbackInfo->code, &result);
                ReturnCallbackPromise(env, asyncCallbackInfo->info, result);
                if (asyncCallbackInfo->info.callback != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->info.callback);
                    EVENT_LOGD("Delete napiGetCode callback reference.");
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
            EVENT_LOGD("NapiGetCode work complete end.");
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));

    if (asyncCallbackInfo->info.isCallback) {
        EVENT_LOGD("Delete napiGetCode callback reference.");
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value GetData(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("GetData excute");
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_ref callback = nullptr;
    if (ParseParametersByGetData(env, argv, argc, callback) == nullptr) {
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID);
        return NapiGetNull(env);
    }

    AsyncCallbackInfoGetData *asyncCallbackInfo =
        new (std::nothrow) AsyncCallbackInfoGetData {.env = env, .asyncWork = nullptr};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGE("asyncCallbackInfo is nullptr");
        return NapiGetNull(env);
    }

    asyncCallbackInfo->subscriber = GetSubscriber(env, thisVar);
    if (asyncCallbackInfo->subscriber == nullptr) {
        EVENT_LOGE("Failed to getSubscriber.");
        delete asyncCallbackInfo;
        return NapiGetNull(env);
    }

    napi_value promise = nullptr;
    PaddingAsyncCallbackInfoGetData(env, argc, asyncCallbackInfo, callback, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getData", NAPI_AUTO_LENGTH, &resourceName);
    // Calling Asynchronous functions
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("GetData napi_create_async_work excute");
            AsyncCallbackInfoGetData *asyncCallbackInfo = static_cast<AsyncCallbackInfoGetData *>(data);
            if (asyncCallbackInfo) {
                std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(
                    asyncCallbackInfo->subscriber.get());
                if (asyncResult) {
                    asyncCallbackInfo->data = asyncResult->GetData();
                } else {
                    asyncCallbackInfo->data = std::string();
                }
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("GetData napi_create_async_work end");
            AsyncCallbackInfoGetData *asyncCallbackInfo = static_cast<AsyncCallbackInfoGetData *>(data);
            if (asyncCallbackInfo) {
                napi_value result = nullptr;
                napi_create_string_utf8(env, asyncCallbackInfo->data.c_str(), NAPI_AUTO_LENGTH, &result);
                ReturnCallbackPromise(env, asyncCallbackInfo->info, result);
                if (asyncCallbackInfo->info.callback != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->info.callback);
                    EVENT_LOGD("Delete napiGetData callback reference.");
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
            EVENT_LOGD("NapiGetData work complete end.");
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));

    if (asyncCallbackInfo->info.isCallback) {
        EVENT_LOGD("Delete napiGetData callback reference.");
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value AbortCommonEvent(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("enter");
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_ref callback = nullptr;
    if (ParseParametersByAbort(env, argv, argc, callback) == nullptr) {
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID);
        return NapiGetNull(env);
    }

    AsyncCallbackInfoAbort *asyncCallbackInfo =
        new (std::nothrow) AsyncCallbackInfoAbort {.env = env, .asyncWork = nullptr};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGE("asyncCallbackInfo is null");
        return NapiGetNull(env);
    }

    asyncCallbackInfo->subscriber = GetSubscriber(env, thisVar);
    if (asyncCallbackInfo->subscriber == nullptr) {
        EVENT_LOGE("subscriber is null");
        delete asyncCallbackInfo;
        return NapiGetNull(env);
    }
    napi_value promise = nullptr;
    PaddingAsyncCallbackInfoAbort(env, argc, asyncCallbackInfo, callback, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "abort", NAPI_AUTO_LENGTH, &resourceName);
    // Calling asynchronous function
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("Abort napi_create_async_work excute");
            AsyncCallbackInfoAbort *asyncCallbackInfo = static_cast<AsyncCallbackInfoAbort *>(data);
            if (asyncCallbackInfo) {
                std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(
                    asyncCallbackInfo->subscriber.get());
                if (asyncResult) {
                    asyncCallbackInfo->info.errorCode = asyncResult->AbortCommonEvent() ? NO_ERROR : ERR_CES_FAILED;
                }
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("Abort napi_create_async_work complete");
            AsyncCallbackInfoAbort *asyncCallbackInfo = static_cast<AsyncCallbackInfoAbort *>(data);
            if (asyncCallbackInfo) {
                ReturnCallbackPromise(env, asyncCallbackInfo->info, NapiGetNull(env));
                if (asyncCallbackInfo->info.callback != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->info.callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
                EVENT_LOGD("NapiAbort work complete end.");
            }
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));

    if (asyncCallbackInfo->info.isCallback) {
        EVENT_LOGD("Delete napiAbort callback reference.");
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value ClearAbortCommonEvent(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("ClearAbort start");
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_ref callback = nullptr;
    if (ParseParametersByClearAbort(env, argv, argc, callback) == nullptr) {
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID);
        return NapiGetNull(env);
    }

    AsyncCallbackInfoClearAbort *asyncCallbackInfo =
        new (std::nothrow) AsyncCallbackInfoClearAbort {.env = env, .asyncWork = nullptr};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGE("Create asyncCallbackInfo defeat");
        return NapiGetNull(env);
    }

    asyncCallbackInfo->subscriber = GetSubscriber(env, thisVar);
    if (asyncCallbackInfo->subscriber == nullptr) {
        EVENT_LOGE("subscriber is null");
        delete asyncCallbackInfo;
        return NapiGetNull(env);
    }

    napi_value promise = nullptr;
    PaddingAsyncCallbackInfoClearAbort(env, argc, asyncCallbackInfo, callback, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "clearAbort", NAPI_AUTO_LENGTH, &resourceName);
    // Calling Asynchronous functions
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("ClearAbort napi_create_async_work start");
            AsyncCallbackInfoClearAbort *asyncCallbackInfo = static_cast<AsyncCallbackInfoClearAbort *>(data);
            if (asyncCallbackInfo) {
                std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(
                    asyncCallbackInfo->subscriber.get());
                if (asyncResult) {
                    asyncCallbackInfo->info.errorCode =
                        asyncResult->ClearAbortCommonEvent() ? NO_ERROR : ERR_CES_FAILED;
                }
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("ClearAbort napi_create_async_work complete");
            AsyncCallbackInfoClearAbort *asyncCallbackInfo = static_cast<AsyncCallbackInfoClearAbort *>(data);
            if (asyncCallbackInfo) {
                ReturnCallbackPromise(env, asyncCallbackInfo->info, NapiGetNull(env));
                if (asyncCallbackInfo->info.callback != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->info.callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
                EVENT_LOGD("NapiClearAbort work complete end.");
            }
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));

    if (asyncCallbackInfo->info.isCallback) {
        EVENT_LOGD("Delete napiClearAbort callback reference.");
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value GetAbortCommonEvent(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("GetAbort excute");
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_ref callback = nullptr;
    if (ParseParametersByGetAbort(env, argv, argc, callback) == nullptr) {
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID);
        return NapiGetNull(env);
    }

    AsyncCallbackInfoGetAbort *asyncCallbackInfo =
        new (std::nothrow) AsyncCallbackInfoGetAbort {.env = env, .asyncWork = nullptr};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGE("Create asyncCallbackInfo is failed");
        return NapiGetNull(env);
    }

    asyncCallbackInfo->subscriber = GetSubscriber(env, thisVar);
    if (asyncCallbackInfo->subscriber == nullptr) {
        EVENT_LOGE("subscriber is null");
        delete asyncCallbackInfo;
        return NapiGetNull(env);
    }

    napi_value promise = nullptr;
    PaddingAsyncCallbackInfoGetAbort(env, argc, asyncCallbackInfo, callback, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getAbort", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("Excute create async GetAbort");
            AsyncCallbackInfoGetAbort *asyncCallbackInfo = static_cast<AsyncCallbackInfoGetAbort *>(data);
            if (asyncCallbackInfo) {
                std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(
                    asyncCallbackInfo->subscriber.get());
                if (asyncResult) {
                    asyncCallbackInfo->abortEvent = asyncResult->GetAbortCommonEvent();
                } else {
                    asyncCallbackInfo->abortEvent = false;
                }
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("GetAbort napi_create_async_work complete");
            AsyncCallbackInfoGetAbort *asyncCallbackInfo = static_cast<AsyncCallbackInfoGetAbort *>(data);
            if (asyncCallbackInfo) {
                napi_value result = nullptr;
                napi_get_boolean(env, asyncCallbackInfo->abortEvent, &result);
                ReturnCallbackPromise(env, asyncCallbackInfo->info, result);
                if (asyncCallbackInfo->info.callback != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->info.callback);
                    EVENT_LOGD("Delete napiGetAbort callback reference.");
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
            EVENT_LOGD("NapiGetAbort work complete end.");
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));

    if (asyncCallbackInfo->info.isCallback) {
        EVENT_LOGD("Delete napiGetAbort callback reference.");
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value FinishCommonEvent(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("Finish excute");
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_ref callback = nullptr;
    if (ParseParametersByFinish(env, argv, argc, callback) == nullptr) {
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID);
        return NapiGetNull(env);
    }

    AsyncCallbackInfoFinish *asyncCallbackInfo =
        new (std::nothrow) AsyncCallbackInfoFinish {.env = env, .asyncWork = nullptr};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGE("asyncCallbackInfo is nullptr");
        return NapiGetNull(env);
    }

    asyncCallbackInfo->subscriber = GetSubscriber(env, thisVar);
    if (asyncCallbackInfo->subscriber == nullptr) {
        EVENT_LOGE("subscriber is null");
        delete asyncCallbackInfo;
        return NapiGetNull(env);
    }

    napi_value promise = nullptr;
    PaddingAsyncCallbackInfoFinish(env, argc, asyncCallbackInfo, callback, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "finish", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("Finish napi_create_async_work start");
            AsyncCallbackInfoFinish *asyncCallbackInfo = static_cast<AsyncCallbackInfoFinish *>(data);
            if (asyncCallbackInfo) {
                std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(
                    asyncCallbackInfo->subscriber.get());
                if (asyncResult) {
                    asyncCallbackInfo->info.errorCode = asyncResult->FinishCommonEvent() ? NO_ERROR : ERR_CES_FAILED;
                }
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("Finish napi_create_async_work complete");
            AsyncCallbackInfoFinish *asyncCallbackInfo = static_cast<AsyncCallbackInfoFinish *>(data);
            if (asyncCallbackInfo) {
                ReturnCallbackPromise(env, asyncCallbackInfo->info, NapiGetNull(env));
                if (asyncCallbackInfo->info.callback != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->info.callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
                EVENT_LOGD("NapiFinish work complete end.");
            }
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));

    if (asyncCallbackInfo->info.isCallback) {
        EVENT_LOGD("Delete napiFinish callback reference.");
        return NapiGetNull(env);
    } else {
        return promise;
    }
}
napi_value CommonEventManagerInit(napi_env env, napi_value exports)
{
    EVENT_LOGD("enter");
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("publish", Publish),
        DECLARE_NAPI_FUNCTION("publishAsUser", PublishAsUser),
        DECLARE_NAPI_FUNCTION("createSubscriber", CreateSubscriber),
        DECLARE_NAPI_FUNCTION("createSubscriberSync", CreateSubscriberSync),
        DECLARE_NAPI_FUNCTION("subscribe", Subscribe),
        DECLARE_NAPI_FUNCTION("unsubscribe", Unsubscribe),
        DECLARE_NAPI_FUNCTION("removeStickyCommonEvent", RemoveStickyCommonEvent),
    };

    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));

    OHOS::EventFwkNapi::SupportInit(env, exports);
    return NapiStaicSubscribeInit(env, exports);
}

napi_value CommonEventSubscriberInit(napi_env env, napi_value exports)
{
    EVENT_LOGD("enter");
    napi_value constructor = nullptr;
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("getSubscribeInfo", GetSubscribeInfo),
        DECLARE_NAPI_FUNCTION("getSubscribeInfoSync", GetSubscribeInfoSync),
        DECLARE_NAPI_FUNCTION("isOrderedCommonEvent", IsOrderedCommonEvent),
        DECLARE_NAPI_FUNCTION("isOrderedCommonEventSync", IsOrderedCommonEventSync),
        DECLARE_NAPI_FUNCTION("isStickyCommonEvent", IsStickyCommonEvent),
        DECLARE_NAPI_FUNCTION("isStickyCommonEventSync", IsStickyCommonEventSync),
        DECLARE_NAPI_FUNCTION("getCode", GetCode),
        DECLARE_NAPI_FUNCTION("getCodeSync", GetCodeSync),
        DECLARE_NAPI_FUNCTION("setCode", SetCode),
        DECLARE_NAPI_FUNCTION("setCodeSync", SetCodeSync),
        DECLARE_NAPI_FUNCTION("getData", GetData),
        DECLARE_NAPI_FUNCTION("getDataSync", GetDataSync),
        DECLARE_NAPI_FUNCTION("setData", SetData),
        DECLARE_NAPI_FUNCTION("setDataSync", SetDataSync),
        DECLARE_NAPI_FUNCTION("setCodeAndData", SetCodeAndData),
        DECLARE_NAPI_FUNCTION("setCodeAndDataSync", SetCodeAndDataSync),
        DECLARE_NAPI_FUNCTION("abortCommonEvent", AbortCommonEvent),
        DECLARE_NAPI_FUNCTION("abortCommonEventSync", AbortCommonEventSync),
        DECLARE_NAPI_FUNCTION("clearAbortCommonEvent", ClearAbortCommonEvent),
        DECLARE_NAPI_FUNCTION("clearAbortCommonEventSync", ClearAbortCommonEventSync),
        DECLARE_NAPI_FUNCTION("getAbortCommonEvent", GetAbortCommonEvent),
        DECLARE_NAPI_FUNCTION("getAbortCommonEventSync", GetAbortCommonEventSync),
        DECLARE_NAPI_FUNCTION("finishCommonEvent", FinishCommonEvent),
    };

    NAPI_CALL(env,
        napi_define_class(env,
            "commonEventSubscriber",
            NAPI_AUTO_LENGTH,
            CommonEventSubscriberConstructor,
            nullptr,
            sizeof(properties) / sizeof(*properties),
            properties,
            &constructor));

    napi_create_reference(env, constructor, 1, &g_CommonEventSubscriber);
    napi_set_named_property(env, exports, "commonEventSubscriber", constructor);
    return exports;
}

}  // namespace EventManagerFwkNapi
}  // namespace OHOS
