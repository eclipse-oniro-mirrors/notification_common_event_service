/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "common_event.h"
#include <uv.h>
#include "event_log_wrapper.h"
#include "napi_common.h"
#include "support.h"

namespace OHOS {
namespace EventFwkNapi {
using namespace OHOS::EventFwk;
namespace {
static const int32_t PUBLISH_MAX_PARA = 2;
static const int32_t PUBLISH_MAX_PARA_AS_USER = 3;
static const int32_t GETSUBSCREBEINFO_MAX_PARA = 1;
static const int32_t ARGS_TWO_EVENT = 2;
static const int32_t PARAM0_EVENT = 0;
static const int32_t PARAM1_EVENT = 1;
}

std::atomic_ullong SubscriberInstance::subscriberID_ = 0;

AsyncCallbackInfoUnsubscribe::AsyncCallbackInfoUnsubscribe()
{
    EVENT_LOGD("constructor AsyncCallbackInfoUnsubscribe");
}

AsyncCallbackInfoUnsubscribe::~AsyncCallbackInfoUnsubscribe()
{
    EVENT_LOGD("destructor AsyncCallbackInfoUnsubscribe");
}

SubscriberInstance::SubscriberInstance(const CommonEventSubscribeInfo &sp) : CommonEventSubscriber(sp)
{
    id_ = ++subscriberID_;
    EVENT_LOGD("constructor SubscriberInstance");
    valid_ = std::make_shared<bool>(false);
}

SubscriberInstance::~SubscriberInstance()
{
    EVENT_LOGD("destructor SubscriberInstance[%{public}llu]", id_.load());
    *valid_ = false;
}

unsigned long long SubscriberInstance::GetID()
{
    return id_.load();
}

SubscriberInstanceWrapper::SubscriberInstanceWrapper(const CommonEventSubscribeInfo &info)
{
    EVENT_LOGD("enter");
    auto objectInfo = new (std::nothrow) SubscriberInstance(info);
    if (objectInfo == nullptr) {
        EVENT_LOGE("objectInfo is nullptr");
        return;
    }

    subscriber = std::shared_ptr<SubscriberInstance>(objectInfo);
    EVENT_LOGD("end");
}

std::shared_ptr<SubscriberInstance> SubscriberInstanceWrapper::GetSubscriber()
{
    return subscriber;
}

napi_value SetCommonEventData(const CommonEventDataWorker *commonEventDataWorkerData, napi_value &result)
{
    EVENT_LOGD("enter");

    if (commonEventDataWorkerData == nullptr) {
        EVENT_LOGE("commonEventDataWorkerData is null");
        return nullptr;
    }

    napi_value value = nullptr;

    // get event
    napi_create_string_utf8(commonEventDataWorkerData->env,
        commonEventDataWorkerData->want.GetAction().c_str(),
        NAPI_AUTO_LENGTH,
        &value);
    napi_set_named_property(commonEventDataWorkerData->env, result, "event", value);

    // get bundleName
    EVENT_LOGD("Create bundleName string");
    napi_create_string_utf8(commonEventDataWorkerData->env,
        commonEventDataWorkerData->want.GetBundle().c_str(),
        NAPI_AUTO_LENGTH,
        &value);
    napi_set_named_property(commonEventDataWorkerData->env, result, "bundleName", value);

    // get code
    napi_create_int32(commonEventDataWorkerData->env, commonEventDataWorkerData->code, &value);
    napi_set_named_property(commonEventDataWorkerData->env, result, "code", value);

    // get data
    EVENT_LOGD("Create data string");
    napi_create_string_utf8(
        commonEventDataWorkerData->env, commonEventDataWorkerData->data.c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(commonEventDataWorkerData->env, result, "data", value);

    // parameters ?: {[key:string] : any}
    AAFwk::WantParams wantParams = commonEventDataWorkerData->want.GetParams();
    napi_value wantParamsValue = nullptr;
    wantParamsValue = OHOS::AppExecFwk::WrapWantParams(commonEventDataWorkerData->env, wantParams);
    if (wantParamsValue) {
        EVENT_LOGD("wantParamsValue is not nullptr.");
        napi_set_named_property(commonEventDataWorkerData->env, result, "parameters", wantParamsValue);
    } else {
        napi_set_named_property(
            commonEventDataWorkerData->env, result, "parameters", NapiGetNull(commonEventDataWorkerData->env));
    }

    return NapiGetNull(commonEventDataWorkerData->env);
}

void UvQueueWorkOnReceiveEvent(uv_work_t *work, int status)
{
    EVENT_LOGD("OnReceiveEvent uv_work_t start");
    if (work == nullptr) {
        EVENT_LOGE("work is nullptr");
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
        EVENT_LOGE("failed to set common event data");
        napi_close_handle_scope(commonEventDataWorkerData->env, scope);
        delete work;
        work = nullptr;
        delete commonEventDataWorkerData;
        commonEventDataWorkerData = nullptr;
        return;
    }

    napi_value undefined = nullptr;
    napi_get_undefined(commonEventDataWorkerData->env, &undefined);

    napi_value resultout = nullptr;
    napi_value callback = nullptr;
    napi_get_reference_value(commonEventDataWorkerData->env, commonEventDataWorkerData->ref, &callback);

    napi_value results[ARGS_TWO_EVENT] = {nullptr};
    results[PARAM0_EVENT] = GetCallbackErrorValue(commonEventDataWorkerData->env, NO_ERROR);
    results[PARAM1_EVENT] = result;
    napi_call_function(
        commonEventDataWorkerData->env, undefined, callback, ARGS_TWO_EVENT, &results[PARAM0_EVENT], &resultout);

    napi_close_handle_scope(commonEventDataWorkerData->env, scope);
    delete commonEventDataWorkerData;
    commonEventDataWorkerData = nullptr;
    delete work;
    work = nullptr;
}

void SubscriberInstance::OnReceiveEvent(const CommonEventData &data)
{
    EVENT_LOGD("OnReceiveEvent start");
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr) {
        EVENT_LOGE("loop instance is nullptr");
        return;
    }

    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        EVENT_LOGE("work is null");
        return;
    }
    CommonEventDataWorker *commonEventDataWorker = new (std::nothrow) CommonEventDataWorker();
    if (commonEventDataWorker == nullptr) {
        EVENT_LOGE("commonEventDataWorker is null");
        delete work;
        work = nullptr;
        return;
    }
    commonEventDataWorker->want = data.GetWant();
    EVENT_LOGD("OnReceiveEvent() action: %{public}s.", data.GetWant().GetAction().c_str());
    commonEventDataWorker->code = data.GetCode();
    commonEventDataWorker->data = data.GetData();
    commonEventDataWorker->env = env_;
    commonEventDataWorker->ref = ref_;
    commonEventDataWorker->valid = valid_;

    work->data = reinterpret_cast<void *>(commonEventDataWorker);

    if (this->IsOrderedCommonEvent()) {
        EVENT_LOGD("IsOrderedCommonEvent is true");
        std::lock_guard<std::mutex> lock(subscriberInsMutex);
        for (auto subscriberInstance : subscriberInstances) {
            if (subscriberInstance.first.get() == this) {
                EVENT_LOGD("Get success.");
                subscriberInstances[subscriberInstance.first].commonEventResult = GoAsyncCommonEvent();
                break;
            }
        }
    }

    int ret = uv_queue_work_with_qos(loop, work, [](uv_work_t *work) {},
        UvQueueWorkOnReceiveEvent, uv_qos_user_initiated);
    if (ret != 0) {
        EVENT_LOGE("failed to insert work into queue");
        delete commonEventDataWorker;
        commonEventDataWorker = nullptr;
        delete work;
        work = nullptr;
    }
    EVENT_LOGD("OnReceiveEvent end");
}

napi_value ParseParametersByGetSubscribeInfo(
    const napi_env &env, const size_t &argc, const napi_value (&argv)[1], napi_ref &callback)
{
    napi_valuetype valuetype;

    // argv[0]:callback
    if (argc >= GETSUBSCREBEINFO_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Wrong argument type. Function expected.");
            return nullptr;
        }

        napi_create_reference(env, argv[0], 1, &callback);
    }

    return NapiGetNull(env);
}

napi_value GetSubscribeInfo(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("GetSubscribeInfo start");

    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_ref callback = nullptr;
    if (ParseParametersByGetSubscribeInfo(env, argc, argv, callback) == nullptr) {
        EVENT_LOGE("ParseParametersByGetSubscribeInfo failed");
        return NapiGetNull(env);
    }

    AsyncCallbackInfoSubscribeInfo *asyncCallbackInfo =
        new (std::nothrow) AsyncCallbackInfoSubscribeInfo {.env = env, .asyncWork = nullptr};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGD("asyncCallbackInfo is null");
        return NapiGetNull(env);
    }

    asyncCallbackInfo->subscriber = GetSubscriber(env, thisVar);
    if (asyncCallbackInfo->subscriber == nullptr) {
        EVENT_LOGE("subscriber is nullptr");
        delete asyncCallbackInfo;
        return NapiGetNull(env);
    }

    napi_value promise = nullptr;
    PaddingAsyncCallbackInfoGetSubscribeInfo(env, argc, asyncCallbackInfo, callback, promise);

    EVENT_LOGD("Create getSubscribeInfo string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getSubscribeInfo", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("GetSubscribeInfo napi_create_async_work start");
            AsyncCallbackInfoSubscribeInfo *asyncCallbackInfo = static_cast<AsyncCallbackInfoSubscribeInfo *>(data);
            if (asyncCallbackInfo == nullptr) {
                EVENT_LOGE("asyncCallbackInfo is null");
                return;
            }
            PaddingNapiCreateAsyncWorkCallbackInfo(asyncCallbackInfo);
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("GetSubscribeInfo napi_create_async_work end");
            AsyncCallbackInfoSubscribeInfo *asyncCallbackInfo = static_cast<AsyncCallbackInfoSubscribeInfo *>(data);
            if (asyncCallbackInfo == nullptr) {
                EVENT_LOGE("asyncCallbackInfo is null");
                return;
            }
            napi_value result = nullptr;
            napi_create_object(env, &result);
            SetNapiResult(env, asyncCallbackInfo, result);
            ReturnCallbackPromise(env, asyncCallbackInfo->info, result);
            if (asyncCallbackInfo->info.callback != nullptr) {
                napi_delete_reference(env, asyncCallbackInfo->info.callback);
            }
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
            delete asyncCallbackInfo;
            asyncCallbackInfo = nullptr;
            EVENT_LOGD("delete asyncCallbackInfo");
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));

    if (asyncCallbackInfo->info.isCallback) {
        EVENT_LOGD("Delete GetSubscribeInfo callback reference.");
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

std::shared_ptr<AsyncCommonEventResult> GetAsyncResult(const SubscriberInstance *objectInfo)
{
    EVENT_LOGD("GetAsyncResult start");
    if (!objectInfo) {
        EVENT_LOGE("Invalidity objectInfo");
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(subscriberInsMutex);
    for (auto subscriberInstance : subscriberInstances) {
        if (subscriberInstance.first.get() == objectInfo) {
            return subscriberInstance.second.commonEventResult;
        }
    }
    EVENT_LOGW("No found objectInfo");
    return nullptr;
}

napi_value IsOrderedCommonEvent(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("IsOrderedCommonEvent start");

    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    napi_ref callback = nullptr;
    if (ParseParametersByIsOrderedCommonEvent(env, argv, argc, callback) == nullptr) {
        EVENT_LOGE("ParseParametersByIsOrderedCommonEvent failed");
        return NapiGetNull(env);
    }

    AsyncCallbackInfoOrderedCommonEvent *asyncCallbackInfo = new (std::nothrow)
        AsyncCallbackInfoOrderedCommonEvent {.env = env, .asyncWork = nullptr};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGE("asyncCallbackInfo is null");
        return NapiGetNull(env);
    }

    asyncCallbackInfo->subscriber = GetSubscriber(env, thisVar);
    if (asyncCallbackInfo->subscriber == nullptr) {
        EVENT_LOGD("subscriber is nullptr");
        delete asyncCallbackInfo;
        return NapiGetNull(env);
    }

    napi_value promise = nullptr;
    PaddingAsyncCallbackInfoIsOrderedCommonEvent(env, argc, asyncCallbackInfo, callback, promise);

    EVENT_LOGD("Create isOrderedCommonEvent string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "isOrderedCommonEvent", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("IsOrderedCommonEvent work excute.");
            AsyncCallbackInfoOrderedCommonEvent *asyncCallbackInfo =
                static_cast<AsyncCallbackInfoOrderedCommonEvent *>(data);
            if (asyncCallbackInfo == nullptr) {
                EVENT_LOGE("asyncCallbackInfo is null");
                return;
            }
            std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(asyncCallbackInfo->subscriber.get());
            if (asyncResult) {
                asyncCallbackInfo->isOrdered = asyncResult->IsOrderedCommonEvent();
            } else {
                asyncCallbackInfo->isOrdered = asyncCallbackInfo->subscriber->IsOrderedCommonEvent();
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("IsOrderedCommonEvent napi_create_async_work end");
            AsyncCallbackInfoOrderedCommonEvent *asyncCallbackInfo =
                static_cast<AsyncCallbackInfoOrderedCommonEvent *>(data);
            if (asyncCallbackInfo == nullptr) {
                EVENT_LOGE("asyncCallbackInfo is null");
                return;
            }
            napi_value result = nullptr;
            napi_get_boolean(env, asyncCallbackInfo->isOrdered, &result);
            ReturnCallbackPromise(env, asyncCallbackInfo->info, result);
            if (asyncCallbackInfo->info.callback != nullptr) {
                napi_delete_reference(env, asyncCallbackInfo->info.callback);
            }
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
            delete asyncCallbackInfo;
            asyncCallbackInfo = nullptr;
            EVENT_LOGD("asyncCallbackInfo is null");
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));

    if (asyncCallbackInfo->info.isCallback) {
        EVENT_LOGD("Delete IsOrderedCommonEvent callback reference.");
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value IsStickyCommonEvent(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("IsStickyCommonEvent start");

    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_ref callback = nullptr;
    if (ParseParametersByIsStickyCommonEvent(env, argv, argc, callback) == nullptr) {
        EVENT_LOGE("ParseParametersByIsStickyCommonEvent failed");
        return NapiGetNull(env);
    }

    AsyncCallbackInfoStickyCommonEvent *asyncCallbackInfo = new (std::nothrow)
        AsyncCallbackInfoStickyCommonEvent {.env = env, .asyncWork = nullptr};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGD("asyncCallbackInfo is fail.");
        return NapiGetNull(env);
    }

    asyncCallbackInfo->subscriber = GetSubscriber(env, thisVar);
    if (asyncCallbackInfo->subscriber == nullptr) {
        EVENT_LOGE("subscriber is nullptr");
        delete asyncCallbackInfo;
        return NapiGetNull(env);
    }

    napi_value promise = nullptr;
    PaddingAsyncCallbackInfoIsStickyCommonEvent(env, argc, asyncCallbackInfo, callback, promise);

    EVENT_LOGD("Create isStickyCommonEvent string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "isStickyCommonEvent", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("isStickyCommonEvent napi_create_async_work start");
            AsyncCallbackInfoStickyCommonEvent *asyncCallbackInfo =
                static_cast<AsyncCallbackInfoStickyCommonEvent *>(data);
            if (asyncCallbackInfo == nullptr) {
                EVENT_LOGE("asyncCallbackInfo is null");
                return;
            }
            std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(asyncCallbackInfo->subscriber.get());
            if (asyncResult) {
                asyncCallbackInfo->isSticky = asyncResult->IsStickyCommonEvent();
            } else {
                asyncCallbackInfo->isSticky = asyncCallbackInfo->subscriber->IsStickyCommonEvent();
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("isStickyCommonEvent napi_create_async_work end");
            AsyncCallbackInfoStickyCommonEvent *asyncCallbackInfo =
                static_cast<AsyncCallbackInfoStickyCommonEvent *>(data);
            if (asyncCallbackInfo == nullptr) {
                EVENT_LOGE("asyncCallbackInfo is null");
                return;
            }
            napi_value result = nullptr;
            napi_get_boolean(env, asyncCallbackInfo->isSticky, &result);
            ReturnCallbackPromise(env, asyncCallbackInfo->info, result);
            if (asyncCallbackInfo->info.callback != nullptr) {
                napi_delete_reference(env, asyncCallbackInfo->info.callback);
            }
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
            delete asyncCallbackInfo;
            asyncCallbackInfo = nullptr;
            EVENT_LOGD("asyncCallbackInfo is nullptr");
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));

    if (asyncCallbackInfo->info.isCallback) {
        EVENT_LOGD("Delete isStickyCommonEvent callback reference.");
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value GetCode(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("GetCode start");
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_ref callback = nullptr;
    if (ParseParametersByGetCode(env, argv, argc, callback) == nullptr) {
        EVENT_LOGE("ParseParametersByGetCode failed");
        return NapiGetNull(env);
    }

    AsyncCallbackInfoGetCode *asyncCallbackInfo =
        new (std::nothrow) AsyncCallbackInfoGetCode {.env = env, .asyncWork = nullptr};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGE("Failed to create asyncCallbackInfo.");
        return NapiGetNull(env);
    }

    asyncCallbackInfo->subscriber = GetSubscriber(env, thisVar);
    if (asyncCallbackInfo->subscriber == nullptr) {
        EVENT_LOGE("subscriber is nullptr");
        delete asyncCallbackInfo;
        return NapiGetNull(env);
    }

    napi_value promise = nullptr;
    PaddingAsyncCallbackInfoGetCode(env, argc, asyncCallbackInfo, callback, promise);

    EVENT_LOGD("Create getCode string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getCode", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("GetCode napi_create_async_work start");
            AsyncCallbackInfoGetCode *asyncCallbackInfo = static_cast<AsyncCallbackInfoGetCode *>(data);
            if (asyncCallbackInfo == nullptr) {
                EVENT_LOGE("asyncCallbackInfo is null");
                return;
            }
            std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(asyncCallbackInfo->subscriber.get());
            if (asyncResult) {
                asyncCallbackInfo->code = asyncResult->GetCode();
            } else {
                asyncCallbackInfo->code = 0;
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("GetCode napi_create_async_work end");
            AsyncCallbackInfoGetCode *asyncCallbackInfo = static_cast<AsyncCallbackInfoGetCode *>(data);
            if (asyncCallbackInfo) {
                napi_value result = nullptr;
                napi_create_int32(env, asyncCallbackInfo->code, &result);
                ReturnCallbackPromise(env, asyncCallbackInfo->info, result);
                if (asyncCallbackInfo->info.callback != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->info.callback);
                    EVENT_LOGD("Delete GetCode callback reference.");
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
            EVENT_LOGD("GetCode work complete end.");
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));

    if (asyncCallbackInfo->info.isCallback) {
        EVENT_LOGD("Delete GetCode callback reference.");
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value GetData(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("GetData start");
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_ref callback = nullptr;
    if (ParseParametersByGetData(env, argv, argc, callback) == nullptr) {
        EVENT_LOGE("ParseParametersByGetData failed");
        return NapiGetNull(env);
    }

    AsyncCallbackInfoGetData *asyncCallbackInfo =
        new (std::nothrow) AsyncCallbackInfoGetData {.env = env, .asyncWork = nullptr};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGE("asyncCallbackInfo is null");
        return NapiGetNull(env);
    }

    asyncCallbackInfo->subscriber = GetSubscriber(env, thisVar);
    if (asyncCallbackInfo->subscriber == nullptr) {
        EVENT_LOGD("subscriber is defeat.");
        delete asyncCallbackInfo;
        return NapiGetNull(env);
    }

    napi_value promise = nullptr;
    PaddingAsyncCallbackInfoGetData(env, argc, asyncCallbackInfo, callback, promise);

    EVENT_LOGD("Create getData string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getData", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("GetData napi_create_async_work start");
            AsyncCallbackInfoGetData *asyncCallbackInfo = static_cast<AsyncCallbackInfoGetData *>(data);
            if (asyncCallbackInfo == nullptr) {
                EVENT_LOGE("asyncCallbackInfo is null");
                return;
            }
            std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(asyncCallbackInfo->subscriber.get());
            if (asyncResult) {
                asyncCallbackInfo->data = asyncResult->GetData();
            } else {
                asyncCallbackInfo->data = std::string();
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("GetData work complete.");
            AsyncCallbackInfoGetData *asyncCallbackInfo = static_cast<AsyncCallbackInfoGetData *>(data);
            if (asyncCallbackInfo) {
                napi_value result = nullptr;
                napi_create_string_utf8(env, asyncCallbackInfo->data.c_str(), NAPI_AUTO_LENGTH, &result);
                ReturnCallbackPromise(env, asyncCallbackInfo->info, result);
                if (asyncCallbackInfo->info.callback != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->info.callback);
                    EVENT_LOGD("Delete GetData callback reference.");
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
            EVENT_LOGD("GetData work complete end.");
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));

    if (asyncCallbackInfo->info.isCallback) {
        EVENT_LOGD("Delete GetData callback reference.");
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value AbortCommonEvent(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("Abort start");
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_ref callback = nullptr;
    if (ParseParametersByAbort(env, argv, argc, callback) == nullptr) {
        EVENT_LOGE("ParseParametersByAbort failed");
        return NapiGetNull(env);
    }

    AsyncCallbackInfoAbort *asyncCallbackInfo =
        new (std::nothrow) AsyncCallbackInfoAbort {.env = env, .asyncWork = nullptr};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGE("AsyncCallbackInfo failed.");
        return NapiGetNull(env);
    }

    asyncCallbackInfo->subscriber = GetSubscriber(env, thisVar);
    if (asyncCallbackInfo->subscriber == nullptr) {
        EVENT_LOGD("subscriber is unsuccessful");
        delete asyncCallbackInfo;
        return NapiGetNull(env);
    }
    napi_value promise = nullptr;
    PaddingAsyncCallbackInfoAbort(env, argc, asyncCallbackInfo, callback, promise);

    EVENT_LOGD("Create abort string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "abort", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("Abort napi_create_async_work start");
            AsyncCallbackInfoAbort *asyncCallbackInfo = static_cast<AsyncCallbackInfoAbort *>(data);
            if (asyncCallbackInfo == nullptr) {
                EVENT_LOGE("asyncCallbackInfo is null");
                return;
            }
            std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(asyncCallbackInfo->subscriber.get());
            if (asyncResult) {
                asyncCallbackInfo->info.errorCode = asyncResult->AbortCommonEvent() ? NO_ERROR : ERR_CES_FAILED;
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("Abort napi_create_async_work end");
            AsyncCallbackInfoAbort *asyncCallbackInfo = static_cast<AsyncCallbackInfoAbort *>(data);
            if (asyncCallbackInfo) {
                ReturnCallbackPromise(env, asyncCallbackInfo->info, NapiGetNull(env));
                if (asyncCallbackInfo->info.callback != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->info.callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
            EVENT_LOGD("Abort work complete end");
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));

    if (asyncCallbackInfo->info.isCallback) {
        EVENT_LOGD("Delete Abort callback reference.");
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value ClearAbortCommonEvent(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("enter");
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_ref callback = nullptr;
    if (ParseParametersByClearAbort(env, argv, argc, callback) == nullptr) {
        EVENT_LOGE("ParseParametersByClearAbort failed");
        return NapiGetNull(env);
    }

    AsyncCallbackInfoClearAbort *asyncCallbackInfo =
        new (std::nothrow) AsyncCallbackInfoClearAbort {.env = env, .asyncWork = nullptr};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGD("asyncCallbackInfo is nullptr.");
        return NapiGetNull(env);
    }

    asyncCallbackInfo->subscriber = GetSubscriber(env, thisVar);
    if (asyncCallbackInfo->subscriber == nullptr) {
        EVENT_LOGE("subscriber is nullptr");
        delete asyncCallbackInfo;
        return NapiGetNull(env);
    }

    napi_value promise = nullptr;
    PaddingAsyncCallbackInfoClearAbort(env, argc, asyncCallbackInfo, callback, promise);

    EVENT_LOGD("Create clearAbort string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "clearAbort", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("Excute create async ClearAbort");
            AsyncCallbackInfoClearAbort *asyncCallbackInfo = static_cast<AsyncCallbackInfoClearAbort *>(data);
            if (asyncCallbackInfo == nullptr) {
                EVENT_LOGE("asyncCallbackInfo is null");
                return;
            }
            std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(asyncCallbackInfo->subscriber.get());
            if (asyncResult) {
                asyncCallbackInfo->info.errorCode = asyncResult->ClearAbortCommonEvent() ? NO_ERROR : ERR_CES_FAILED;
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("ClearAbort napi_create_async_work end");
            AsyncCallbackInfoClearAbort *asyncCallbackInfo = static_cast<AsyncCallbackInfoClearAbort *>(data);
            if (asyncCallbackInfo) {
                ReturnCallbackPromise(env, asyncCallbackInfo->info, NapiGetNull(env));
                if (asyncCallbackInfo->info.callback != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->info.callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
            EVENT_LOGD("ClearAbort work complete end");
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));

    if (asyncCallbackInfo->info.isCallback) {
        EVENT_LOGD("Delete ClearAbort callback reference.");
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value GetAbortCommonEvent(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("GetAbort start");
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_ref callback = nullptr;
    if (ParseParametersByGetAbort(env, argv, argc, callback) == nullptr) {
        EVENT_LOGE("ParseParametersByGetAbort failed");
        return NapiGetNull(env);
    }

    AsyncCallbackInfoGetAbort *asyncCallbackInfo =
        new (std::nothrow) AsyncCallbackInfoGetAbort {.env = env, .asyncWork = nullptr};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGD("Create asyncCallbackInfo is failed");
        return NapiGetNull(env);
    }

    asyncCallbackInfo->subscriber = GetSubscriber(env, thisVar);
    if (asyncCallbackInfo->subscriber == nullptr) {
        EVENT_LOGE("subscriber is nullptr");
        delete asyncCallbackInfo;
        return NapiGetNull(env);
    }

    napi_value promise = nullptr;
    PaddingAsyncCallbackInfoGetAbort(env, argc, asyncCallbackInfo, callback, promise);

    EVENT_LOGD("Create getAbort string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getAbort", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("GetAbort napi_create_async_work start");
            AsyncCallbackInfoGetAbort *asyncCallbackInfo = static_cast<AsyncCallbackInfoGetAbort *>(data);
            if (asyncCallbackInfo == nullptr) {
                EVENT_LOGE("asyncCallbackInfo is null");
                return;
            }
            std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(asyncCallbackInfo->subscriber.get());
            if (asyncResult) {
                asyncCallbackInfo->abortEvent = asyncResult->GetAbortCommonEvent();
            } else {
                asyncCallbackInfo->abortEvent = false;
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("GetAbort napi_create_async_work end");
            AsyncCallbackInfoGetAbort *asyncCallbackInfo = static_cast<AsyncCallbackInfoGetAbort *>(data);
            if (asyncCallbackInfo) {
                napi_value result = nullptr;
                napi_get_boolean(env, asyncCallbackInfo->abortEvent, &result);
                ReturnCallbackPromise(env, asyncCallbackInfo->info, result);
                if (asyncCallbackInfo->info.callback != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->info.callback);
                    EVENT_LOGD("Delete GetAbort callback reference.");
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
            EVENT_LOGD("GetAbort work complete end.");
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));

    if (asyncCallbackInfo->info.isCallback) {
        EVENT_LOGD("Delete GetAbort callback reference.");
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value FinishCommonEvent(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("Finish start");
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_ref callback = nullptr;
    if (ParseParametersByFinish(env, argv, argc, callback) == nullptr) {
        EVENT_LOGE("ParseParametersByFinish failed");
        return NapiGetNull(env);
    }

    AsyncCallbackInfoFinish *asyncCallbackInfo =
        new (std::nothrow) AsyncCallbackInfoFinish {.env = env, .asyncWork = nullptr};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGE("asyncCallbackInfo is null");
        return NapiGetNull(env);
    }

    asyncCallbackInfo->subscriber = GetSubscriber(env, thisVar);
    if (asyncCallbackInfo->subscriber == nullptr) {
        EVENT_LOGE("subscriber is nullptr");
        delete asyncCallbackInfo;
        return NapiGetNull(env);
    }

    napi_value promise = nullptr;
    PaddingAsyncCallbackInfoFinish(env, argc, asyncCallbackInfo, callback, promise);

    EVENT_LOGD("Create finish string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "finish", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("Finish napi_create_async_work start");
            AsyncCallbackInfoFinish *asyncCallbackInfo = static_cast<AsyncCallbackInfoFinish *>(data);
            if (asyncCallbackInfo == nullptr) {
                EVENT_LOGE("asyncCallbackInfo is null");
                return;
            }
            std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(asyncCallbackInfo->subscriber.get());
            if (asyncResult) {
                asyncCallbackInfo->info.errorCode = asyncResult->FinishCommonEvent() ? NO_ERROR : ERR_CES_FAILED;
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("Finish work complete");
            AsyncCallbackInfoFinish *asyncCallbackInfo = static_cast<AsyncCallbackInfoFinish *>(data);
            if (asyncCallbackInfo) {
                ReturnCallbackPromise(env, asyncCallbackInfo->info, NapiGetNull(env));
                if (asyncCallbackInfo->info.callback != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->info.callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
            EVENT_LOGD("Finish work complete end");
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));

    if (asyncCallbackInfo->info.isCallback) {
        EVENT_LOGD("Delete Finish callback reference.");
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

std::shared_ptr<SubscriberInstance> GetSubscriber(const napi_env &env, const napi_value &value)
{
    EVENT_LOGD("GetSubscriber start");

    SubscriberInstanceWrapper *wrapper = nullptr;
    napi_unwrap(env, value, (void **)&wrapper);
    if (wrapper == nullptr) {
        EVENT_LOGW("GetSubscriber wrapper is nullptr");
        return nullptr;
    }

    return wrapper->GetSubscriber();
}

napi_value GetSubscriberByUnsubscribe(
    const napi_env &env, const napi_value &value, std::shared_ptr<SubscriberInstance> &subscriber, bool &isFind)
{
    EVENT_LOGD("GetSubscriberByUnsubscribe start");

    isFind = false;
    subscriber = GetSubscriber(env, value);
    if (subscriber == nullptr) {
        EVENT_LOGE("subscriber is nullptr");
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(subscriberInsMutex);
    for (auto subscriberInstance : subscriberInstances) {
        if (subscriberInstance.first.get() == subscriber.get()) {
            isFind = true;
            subscriber = subscriberInstance.first;
            break;
        }
    }

    return NapiGetNull(env);
}

void NapiDeleteSubscribe(const napi_env &env, std::shared_ptr<SubscriberInstance> &subscriber)
{
    EVENT_LOGD("NapiDeleteSubscribe start");
    std::lock_guard<std::mutex> lock(subscriberInsMutex);
    auto subscribe = subscriberInstances.find(subscriber);
    if (subscribe != subscriberInstances.end()) {
        for (auto asyncCallbackInfoSubscribe : subscribe->second.asyncCallbackInfo) {
            if (asyncCallbackInfoSubscribe->callback != nullptr) {
                napi_delete_reference(env, asyncCallbackInfoSubscribe->callback);
            }
            delete asyncCallbackInfoSubscribe;
            asyncCallbackInfoSubscribe = nullptr;
        }
        subscriber->SetCallbackRef(nullptr);
        subscriberInstances.erase(subscribe);
    }
}

napi_value CommonEventSubscriberConstructor(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("CommonEventSubscriberConstructor start");
    napi_value thisVar = nullptr;
    CommonEventSubscribeInfo subscribeInfo;
    if (!ParseParametersConstructor(env, info, thisVar, subscribeInfo)) {
        EVENT_LOGE("ParseParametersConstructor failed");
        return NapiGetNull(env);
    }

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
                            EVENT_LOGD("Delete CommonEventSubscriberConstructor work reference.");
                            napi_delete_reference(env, asyncCallbackInfo->callback);
                        }
                        delete asyncCallbackInfo;
                        asyncCallbackInfo = nullptr;
                    }
                    wrapper->GetSubscriber()->SetCallbackRef(nullptr);
                    CommonEventManager::UnSubscribeCommonEvent(subscriberInstance.first);
                    subscriberInstances.erase(subscriberInstance.first);
                    break;
                    EVENT_LOGD("Execution complete");
                }
            }
            delete wrapper;
            wrapper = nullptr;
        },
        nullptr,
        nullptr);

    EVENT_LOGD("End");
    return thisVar;
}

napi_value PublishAsUser(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("Publish start");

    size_t argc = PUBLISH_MAX_PARA_BY_USERID;
    napi_value argv[PUBLISH_MAX_PARA_BY_USERID] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < PUBLISH_MAX_PARA_AS_USER) {
        EVENT_LOGE("Wrong number of arguments.");
        return NapiGetNull(env);
    }

    std::string event;
    int32_t userId = UNDEFINED_USER;
    CommonEventPublishDataByjs commonEventPublishDatajs;
    napi_ref callback = nullptr;

    if (ParseParametersByPublishAsUser(env, argv, argc, event, userId, commonEventPublishDatajs, callback) == nullptr) {
        EVENT_LOGE("ParseParametersByPublishAsUser failed");
        return NapiGetNull(env);
    }

    AsyncCallbackInfoPublish *asyncCallbackInfo =
        new (std::nothrow) AsyncCallbackInfoPublish {.env = env, .asyncWork = nullptr};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGE("asyncCallbackInfo is null");
        return NapiGetNull(env);
    }
    asyncCallbackInfo->callback = callback;

    // CommonEventData::want->action
    Want want;
    want.SetAction(event);
    if (argc == PUBLISH_MAX_PARA_BY_USERID) {
        EVENT_LOGD("argc is PUBLISH_MAX_PARA_BY_USERID.");
        PaddingCallbackInfoPublish(want, asyncCallbackInfo, commonEventPublishDatajs);
    }
    asyncCallbackInfo->commonEventData.SetWant(want);
    asyncCallbackInfo->userId = userId;

    EVENT_LOGD("Create publish string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "Publish", NAPI_AUTO_LENGTH, &resourceName);

    // Calling Asynchronous functions
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("Publish napi_create_async_work start");
            AsyncCallbackInfoPublish *asyncCallbackInfo = static_cast<AsyncCallbackInfoPublish *>(data);
            if (asyncCallbackInfo == nullptr) {
                EVENT_LOGE("asyncCallbackInfo is nullptr");
                return;
            }
            asyncCallbackInfo->errorCode = CommonEventManager::PublishCommonEventAsUser(
                asyncCallbackInfo->commonEventData, asyncCallbackInfo->commonEventPublishInfo,
                asyncCallbackInfo->userId) ? NO_ERROR : ERR_CES_FAILED;
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("PublishAsUser work complete.");
            AsyncCallbackInfoPublish *asyncCallbackInfo = static_cast<AsyncCallbackInfoPublish *>(data);
            if (asyncCallbackInfo) {
                SetCallback(env, asyncCallbackInfo->callback, asyncCallbackInfo->errorCode, NapiGetNull(env));
                if (asyncCallbackInfo->callback != nullptr) {
                    EVENT_LOGD("Delete PublishAsUser callback reference.");
                    napi_delete_reference(env, asyncCallbackInfo->callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
            EVENT_LOGD("PublishAsUser work complete end.");
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));

    return NapiGetNull(env);
}

napi_value CreateSubscriber(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("CreateSubscriber start");

    size_t argc = CREATE_MAX_PARA;
    napi_value argv[CREATE_MAX_PARA] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) {
        EVENT_LOGE("Wrong number of arguments");
        return NapiGetNull(env);
    }

    napi_ref callback = nullptr;
    if (ParseParametersByCreateSubscriber(env, argv, argc, callback) == nullptr) {
        EVENT_LOGE("ParseParametersByCreateSubscriber failed");
        return NapiGetNull(env);
    }

    AsyncCallbackInfoCreate *asyncCallbackInfo =
        new (std::nothrow) AsyncCallbackInfoCreate {.env = env, .asyncWork = nullptr, .subscribeInfo = nullptr};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGD("asyncCallbackInfo is failed.");
        return NapiGetNull(env);
    }
    napi_value promise = nullptr;

    PaddingAsyncCallbackInfoCreateSubscriber(env, asyncCallbackInfo, callback, promise);

    napi_create_reference(env, argv[0], 1, &asyncCallbackInfo->subscribeInfo);

    EVENT_LOGD("Create createSubscriber string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "CreateSubscriber", NAPI_AUTO_LENGTH, &resourceName);

    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("CreateSubscriber napi_create_async_work start");
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("CreateSubscriber napi_create_async_work end");
            AsyncCallbackInfoCreate *asyncCallbackInfo = static_cast<AsyncCallbackInfoCreate *>(data);
            if (asyncCallbackInfo == nullptr) {
                EVENT_LOGE("asyncCallbackInfo is null");
                return;
            }
            napi_value constructor = nullptr;
            napi_value subscribeInfoRefValue = nullptr;
            napi_get_reference_value(env, asyncCallbackInfo->subscribeInfo, &subscribeInfoRefValue);
            napi_get_reference_value(env, g_CommonEventSubscriber, &constructor);
            napi_new_instance(env, constructor, 1, &subscribeInfoRefValue, &asyncCallbackInfo->result);

            if (asyncCallbackInfo->result == nullptr) {
                EVENT_LOGE("Failed to create subscriber instance.");
                asyncCallbackInfo->info.errorCode = ERR_CES_FAILED;
            }
            ReturnCallbackPromise(env, asyncCallbackInfo->info, asyncCallbackInfo->result);
            if (asyncCallbackInfo->info.callback != nullptr) {
                EVENT_LOGD("Delete CreateSubscriber callback reference.");
                napi_delete_reference(env, asyncCallbackInfo->info.callback);
            }
            if (asyncCallbackInfo->subscribeInfo != nullptr) {
                napi_delete_reference(env, asyncCallbackInfo->subscribeInfo);
            }
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
            delete asyncCallbackInfo;
            asyncCallbackInfo = nullptr;
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));

    if (asyncCallbackInfo->info.isCallback) {
        EVENT_LOGD("Delete create callback reference.");
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value Subscribe(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("Subscribe start");

    // Argument parsing
    size_t argc = SUBSCRIBE_MAX_PARA;
    napi_value argv[SUBSCRIBE_MAX_PARA] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < SUBSCRIBE_MAX_PARA) {
        EVENT_LOGE("Wrong number of arguments.");
        return NapiGetNull(env);
    }

    napi_ref callback = nullptr;
    std::shared_ptr<SubscriberInstance> subscriber = nullptr;

    if (ParseParametersBySubscribe(env, argv, subscriber, callback) == nullptr) {
        EVENT_LOGE("ParseParametersBySubscribe failed");
        return NapiGetNull(env);
    }

    AsyncCallbackInfoSubscribe *asyncCallbackInfo =
        new (std::nothrow) AsyncCallbackInfoSubscribe {.env = env, .asyncWork = nullptr, .subscriber = nullptr};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGE("asyncCallbackInfo is null");
        return NapiGetNull(env);
    }
    asyncCallbackInfo->subscriber = subscriber;
    asyncCallbackInfo->callback = callback;

    EVENT_LOGD("Create subscribe string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "Subscribe", NAPI_AUTO_LENGTH, &resourceName);

    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("Subscribe napi_create_async_work start");
            AsyncCallbackInfoSubscribe *asyncCallbackInfo = static_cast<AsyncCallbackInfoSubscribe *>(data);
            if (asyncCallbackInfo == nullptr) {
                EVENT_LOGE("asyncCallbackInfo is null");
                return;
            }
            asyncCallbackInfo->subscriber->SetEnv(env);
            asyncCallbackInfo->subscriber->SetCallbackRef(asyncCallbackInfo->callback);
            asyncCallbackInfo->errorCode = CommonEventManager::SubscribeCommonEvent(asyncCallbackInfo->subscriber) ?
                NO_ERROR : ERR_CES_FAILED;
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("Subscribe work complete");
            AsyncCallbackInfoSubscribe *asyncCallbackInfo = static_cast<AsyncCallbackInfoSubscribe *>(data);
            if (asyncCallbackInfo == nullptr) {
                EVENT_LOGE("asyncCallbackInfo is null");
                return;
            }
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
            if (asyncCallbackInfo->errorCode == NO_ERROR) {
                std::lock_guard<std::mutex> lock(subscriberInsMutex);
                subscriberInstances[asyncCallbackInfo->subscriber].asyncCallbackInfo.emplace_back(asyncCallbackInfo);
            } else {
                SetCallback(env, asyncCallbackInfo->callback, asyncCallbackInfo->errorCode, NapiGetNull(env));

                if (asyncCallbackInfo->callback != nullptr) {
                    EVENT_LOGD("Delete subscribe callback reference.");
                    napi_delete_reference(env, asyncCallbackInfo->callback);
                }

                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
            EVENT_LOGD("Subscribe work complete end");
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));
    return NapiGetNull(env);
}

napi_value Unsubscribe(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("Unsubscribe start");

    // Argument parsing
    size_t argc = UNSUBSCRIBE_MAX_PARA;
    napi_value argv[UNSUBSCRIBE_MAX_PARA] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) {
        EVENT_LOGE("Wrong number of arguments");
        return NapiGetNull(env);
    }

    napi_ref callback = nullptr;
    std::shared_ptr<SubscriberInstance> subscriber = nullptr;
    napi_value result = nullptr;
    result = ParseParametersByUnsubscribe(env, argc, argv, subscriber, callback);
    if (result == nullptr) {
        EVENT_LOGE("ParseParametersByUnsubscribe failed");
        return NapiGetNull(env);
    }
    bool isFind = false;
    napi_get_value_bool(env, result, &isFind);
    if (!isFind) {
        EVENT_LOGE("Unsubscribe failed. The current subscriber does not exist");
        return NapiGetNull(env);
    }

    AsyncCallbackInfoUnsubscribe *asynccallback = new (std::nothrow) AsyncCallbackInfoUnsubscribe();
    if (asynccallback == nullptr) {
        EVENT_LOGE("asynccallback is null");
        return NapiGetNull(env);
    }
    asynccallback->env = env;
    asynccallback->subscriber = subscriber;
    asynccallback->argc = argc;
    if (argc >= UNSUBSCRIBE_MAX_PARA) {
        asynccallback->callback = callback;
    }

    EVENT_LOGD("Create unsubscribe string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "Unsubscribe", NAPI_AUTO_LENGTH, &resourceName);

    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("Excute create async Unsubscribe");
            AsyncCallbackInfoUnsubscribe *asyncCallbackInfo = static_cast<AsyncCallbackInfoUnsubscribe *>(data);
            if (asyncCallbackInfo == nullptr) {
                EVENT_LOGE("asyncCallbackInfo is null");
                return;
            }
            asyncCallbackInfo->errorCode = CommonEventManager::UnSubscribeCommonEvent(asyncCallbackInfo->subscriber) ?
                NO_ERROR : ERR_CES_FAILED;
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("Unsubscribe napi_create_async_work end");
            AsyncCallbackInfoUnsubscribe *asyncCallbackInfo = static_cast<AsyncCallbackInfoUnsubscribe *>(data);
            if (asyncCallbackInfo) {
                if (asyncCallbackInfo->argc >= UNSUBSCRIBE_MAX_PARA) {
                    napi_value result = nullptr;
                    napi_get_null(env, &result);
                    SetCallback(env, asyncCallbackInfo->callback, asyncCallbackInfo->errorCode, result);
                }
                if (asyncCallbackInfo->callback != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                NapiDeleteSubscribe(env, asyncCallbackInfo->subscriber);
                EVENT_LOGD("delete asyncCallbackInfo");
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
        },
        (void *)asynccallback,
        &asynccallback->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asynccallback->asyncWork, napi_qos_user_initiated));
    return NapiGetNull(env);
}

napi_value Publish(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("Publish start");

    size_t argc = PUBLISH_MAX_PARA_BY_PUBLISHDATA;
    napi_value argv[PUBLISH_MAX_PARA_BY_PUBLISHDATA] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < PUBLISH_MAX_PARA) {
        EVENT_LOGE("Error number of arguments.");
        return NapiGetNull(env);
    }

    std::string event;
    CommonEventPublishDataByjs commonEventPublishDatajs;
    napi_ref callback = nullptr;

    if (ParseParametersByPublish(env, argv, argc, event, commonEventPublishDatajs, callback) == nullptr) {
        EVENT_LOGE("ParseParametersByPublish failed");
        return NapiGetNull(env);
    }

    AsyncCallbackInfoPublish *asyncCallbackInfo =
        new (std::nothrow) AsyncCallbackInfoPublish {.env = env, .asyncWork = nullptr};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGE("asyncCallbackInfo failed.");
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

    EVENT_LOGD("Create publish string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "Publish", NAPI_AUTO_LENGTH, &resourceName);

    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("Publish napi_create_async_work start");
            AsyncCallbackInfoPublish *asyncCallbackInfo = static_cast<AsyncCallbackInfoPublish *>(data);
            if (asyncCallbackInfo == nullptr) {
                EVENT_LOGE("asyncCallbackInfo is null");
                return;
            }
            bool ret = CommonEventManager::PublishCommonEvent(
                asyncCallbackInfo->commonEventData, asyncCallbackInfo->commonEventPublishInfo);
            asyncCallbackInfo->errorCode = ret ? NO_ERROR : ERR_CES_FAILED;
        },
        [](napi_env env, napi_status status, void *data) {
            AsyncCallbackInfoPublish *asyncCallbackInfo = static_cast<AsyncCallbackInfoPublish *>(data);
            if (asyncCallbackInfo) {
                SetCallback(env, asyncCallbackInfo->callback, asyncCallbackInfo->errorCode, NapiGetNull(env));
                if (asyncCallbackInfo->callback != nullptr) {
                    EVENT_LOGD("Delete cancel callback reference");
                    napi_delete_reference(env, asyncCallbackInfo->callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
            EVENT_LOGD("Publish work complete end.");
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));

    return NapiGetNull(env);
}

napi_value CommonEventInit(napi_env env, napi_value exports)
{
    EVENT_LOGD("enter");

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("publish", Publish),
        DECLARE_NAPI_FUNCTION("publishAsUser", PublishAsUser),
        DECLARE_NAPI_FUNCTION("createSubscriber", CreateSubscriber),
        DECLARE_NAPI_FUNCTION("subscribe", Subscribe),
        DECLARE_NAPI_FUNCTION("unsubscribe", Unsubscribe),
    };

    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));

    OHOS::EventFwkNapi::SupportInit(env, exports);
    return exports;
}

napi_value CommonEventSubscriberInit(napi_env env, napi_value exports)
{
    EVENT_LOGD("enter");
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("getSubscribeInfo", GetSubscribeInfo),
        DECLARE_NAPI_FUNCTION("isOrderedCommonEvent", IsOrderedCommonEvent),
        DECLARE_NAPI_FUNCTION("isStickyCommonEvent", IsStickyCommonEvent),
        DECLARE_NAPI_FUNCTION("getCode", GetCode),
        DECLARE_NAPI_FUNCTION("setCode", SetCode),
        DECLARE_NAPI_FUNCTION("getData", GetData),
        DECLARE_NAPI_FUNCTION("setData", SetData),
        DECLARE_NAPI_FUNCTION("setCodeAndData", SetCodeAndData),
        DECLARE_NAPI_FUNCTION("abortCommonEvent", AbortCommonEvent),
        DECLARE_NAPI_FUNCTION("clearAbortCommonEvent", ClearAbortCommonEvent),
        DECLARE_NAPI_FUNCTION("getAbortCommonEvent", GetAbortCommonEvent),
        DECLARE_NAPI_FUNCTION("finishCommonEvent", FinishCommonEvent),
    };
    napi_value constructor = nullptr;

    NAPI_CALL(env,
        napi_define_class(env,
            "commonEventSubscriber",
            NAPI_AUTO_LENGTH,
            CommonEventSubscriberConstructor,
            nullptr,
            sizeof(properties) / sizeof(*properties),
            properties,
            &constructor));

    EVENT_LOGD("Create commonEventSubscriber reference.");
    napi_create_reference(env, constructor, 1, &g_CommonEventSubscriber);
    napi_set_named_property(env, exports, "commonEventSubscriber", constructor);
    return exports;
}

}  // namespace EventFwkNapi
}  // namespace OHOS
