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

static const int32_t SET_CODE_MAX_PARA = 2;
static const int32_t SET_DATA_MAX_PARA = 2;
static const int32_t SET_CODE_AND_DATA_MAX_PARA = 3;
static const int32_t ARGS_TWO_EVENT = 2;
static const int32_t PARAM0_EVENT = 0;
static const int32_t PARAM1_EVENT = 1;

void SetPublisherPermissionResult(
    const napi_env &env, const std::string &permission, napi_value &commonEventSubscribeInfo)
{
    EVENT_LOGD("SetPublisherPermissionResult start");

    napi_value value = nullptr;
    napi_create_string_utf8(env, permission.c_str(), NAPI_AUTO_LENGTH, &value);

    napi_set_named_property(env, commonEventSubscribeInfo, "publisherPermission", value);
}

void SetPublisherDeviceIdResult(const napi_env &env, const std::string &deviceId, napi_value &commonEventSubscribeInfo)
{
    EVENT_LOGD("SetPublisherDeviceIdResult start");

    napi_value value = nullptr;
    napi_create_string_utf8(env, deviceId.c_str(), NAPI_AUTO_LENGTH, &value);

    napi_set_named_property(env, commonEventSubscribeInfo, "publisherDeviceId", value);
}

void SetPublisherUserIdResult(const napi_env &env, const int32_t &userId, napi_value &commonEventSubscribeInfo)
{
    EVENT_LOGD("SetPublisherUserIdResult start");

    napi_value value = nullptr;
    napi_create_int32(env, userId, &value);

    napi_set_named_property(env, commonEventSubscribeInfo, "userId", value);
}

void SetPublisherPriorityResult(const napi_env &env, const int32_t &priority, napi_value &commonEventSubscribeInfo)
{
    EVENT_LOGD("SetPublisherPriorityResult start");

    napi_value value = nullptr;
    napi_create_int32(env, priority, &value);

    napi_set_named_property(env, commonEventSubscribeInfo, "priority", value);
}

void SetNapiResult(const napi_env &env, const AsyncCallbackInfoSubscribeInfo *asyncCallbackInfo, napi_value &result)
{
    EVENT_LOGD("SetNapiResult start");

    SetEventsResult(env, asyncCallbackInfo->events, result);
    SetPublisherPermissionResult(env, asyncCallbackInfo->permission, result);
    SetPublisherDeviceIdResult(env, asyncCallbackInfo->deviceId, result);
    SetPublisherUserIdResult(env, asyncCallbackInfo->userId, result);
    SetPublisherPriorityResult(env, asyncCallbackInfo->priority, result);
}

napi_value SetCode(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("SetCode start");
    size_t argc = SET_CODE_MAX_PARA;
    napi_value argv[SET_CODE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_ref callback = nullptr;
    int32_t code = 0;
    if (ParseParametersBySetCode(env, argv, argc, code, callback) == nullptr) {
        EVENT_LOGE("ParseParametersBySetCode failed");
        return NapiGetNull(env);
    }

    AsyncCallbackInfoSetCode *asyncCallbackInfo = new (std::nothrow)
        AsyncCallbackInfoSetCode {.env = env, .asyncWork = nullptr, .code = code};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGD("Create asyncCallbackInfo is defeat.");
        return NapiGetNull(env);
    }

    asyncCallbackInfo->subscriber = GetSubscriber(env, thisVar);
    if (asyncCallbackInfo->subscriber == nullptr) {
        EVENT_LOGE("subscriber is nullptr");
        delete asyncCallbackInfo;
        return NapiGetNull(env);
    }

    napi_value promise = nullptr;
    PaddingAsyncCallbackInfoSetCode(env, argc, asyncCallbackInfo, callback, promise);

    EVENT_LOGD("Create setCode string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setCode", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("SetCode napi_create_async_work start");
            AsyncCallbackInfoSetCode *asyncCallbackInfo = static_cast<AsyncCallbackInfoSetCode *>(data);
            if (asyncCallbackInfo == nullptr) {
                EVENT_LOGE("asyncCallbackInfo is null");
                return;
            }
            std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(asyncCallbackInfo->subscriber.get());
            if (asyncResult) {
                asyncCallbackInfo->info.errorCode = asyncResult->SetCode(asyncCallbackInfo->code) ?
                    NO_ERROR : ERR_CES_FAILED;
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("SetCode napi_create_async_work end");
            AsyncCallbackInfoSetCode *asyncCallbackInfo = static_cast<AsyncCallbackInfoSetCode *>(data);
            if (asyncCallbackInfo) {
                ReturnCallbackPromise(env, asyncCallbackInfo->info, NapiGetNull(env));
                if (asyncCallbackInfo->info.callback != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->info.callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
            EVENT_LOGD("SetCode work complete end.");
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));

    if (asyncCallbackInfo->info.isCallback) {
        EVENT_LOGD("Delete SetCode callback reference.");
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value SetData(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("SetData start");
    size_t argc = SET_DATA_MAX_PARA;
    napi_value argv[SET_DATA_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_ref callback = nullptr;
    std::string data;
    if (ParseParametersBySetData(env, argv, argc, data, callback) == nullptr) {
        EVENT_LOGE("ParseParametersBySetData failed");
        return NapiGetNull(env);
    }

    AsyncCallbackInfoSetData *asyncCallbackInfo = new (std::nothrow)
        AsyncCallbackInfoSetData {.env = env, .asyncWork = nullptr, .data = data};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGE("asyncCallbackInfo is null");
        return NapiGetNull(env);
    }

    asyncCallbackInfo->subscriber = GetSubscriber(env, thisVar);
    if (asyncCallbackInfo->subscriber == nullptr) {
        EVENT_LOGD("subscriber is failed");
        delete asyncCallbackInfo;
        return NapiGetNull(env);
    }

    napi_value promise = nullptr;
    PaddingAsyncCallbackInfoSetData(env, argc, asyncCallbackInfo, callback, promise);

    EVENT_LOGD("Create setData string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setData", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("SetData napi_create_async_work start");
            AsyncCallbackInfoSetData *asyncCallbackInfo = static_cast<AsyncCallbackInfoSetData *>(data);
            if (asyncCallbackInfo == nullptr) {
                EVENT_LOGE("asyncCallbackInfo is null");
                return;
            }
            std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(asyncCallbackInfo->subscriber.get());
            if (asyncResult) {
                asyncCallbackInfo->info.errorCode = asyncResult->SetData(asyncCallbackInfo->data) ?
                    NO_ERROR : ERR_CES_FAILED;
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("SetData napi_create_async_work end");
            AsyncCallbackInfoSetData *asyncCallbackInfo = static_cast<AsyncCallbackInfoSetData *>(data);
            if (asyncCallbackInfo) {
                ReturnCallbackPromise(env, asyncCallbackInfo->info, NapiGetNull(env));
                if (asyncCallbackInfo->info.callback != nullptr) {
                    EVENT_LOGD("Delete setData work reference.");
                    napi_delete_reference(env, asyncCallbackInfo->info.callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
            EVENT_LOGD("SetData work complete end.");
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));

    if (asyncCallbackInfo->info.isCallback) {
        EVENT_LOGD("Delete SetData callback reference.");
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value SetCodeAndData(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("SetCodeAndData start");
    size_t argc = SET_CODE_AND_DATA_MAX_PARA;
    napi_value argv[SET_CODE_AND_DATA_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_ref callback = nullptr;
    int32_t code = 0;
    std::string data;
    if (ParseParametersBySetCodeAndData(env, argv, argc, code, data, callback) == nullptr) {
        EVENT_LOGE("ParseParametersBySetData failed");
        return NapiGetNull(env);
    }

    AsyncCallbackInfoSetCodeAndData *asyncCallbackInfo = new (std::nothrow) AsyncCallbackInfoSetCodeAndData {
        .env = env, .asyncWork = nullptr, .code = code, .data = data};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGE("asyncCallbackInfo is null");
        return NapiGetNull(env);
    }

    asyncCallbackInfo->subscriber = GetSubscriber(env, thisVar);
    if (asyncCallbackInfo->subscriber == nullptr) {
        EVENT_LOGD("subscriber is fail");
        delete asyncCallbackInfo;
        return NapiGetNull(env);
    }

    napi_value promise = nullptr;
    PaddingAsyncCallbackInfoSetCodeAndData(env, argc, asyncCallbackInfo, callback, promise);

    EVENT_LOGD("Create setCodeAndData string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setCodeAndData", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("SetCodeAndData work excute.");
            AsyncCallbackInfoSetCodeAndData *asyncCallbackInfo = static_cast<AsyncCallbackInfoSetCodeAndData *>(data);
            if (asyncCallbackInfo == nullptr) {
                EVENT_LOGE("asyncCallbackInfo is null");
                return;
            }
            std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(asyncCallbackInfo->subscriber.get());
            if (asyncResult) {
                asyncCallbackInfo->info.errorCode = asyncResult->SetCodeAndData(
                    asyncCallbackInfo->code, asyncCallbackInfo->data) ? NO_ERROR : ERR_CES_FAILED;
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("SetCodeAndData napi_create_async_work end");
            AsyncCallbackInfoSetCodeAndData *asyncCallbackInfo = static_cast<AsyncCallbackInfoSetCodeAndData *>(data);
            if (asyncCallbackInfo) {
                ReturnCallbackPromise(env, asyncCallbackInfo->info, NapiGetNull(env));
                if (asyncCallbackInfo->info.callback != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->info.callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
            EVENT_LOGD("SetCodeAndData work complete end.");
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));

    if (asyncCallbackInfo->info.isCallback) {
        EVENT_LOGD("Delete SetCodeAndData callback reference.");
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

void SetEventsResult(const napi_env &env, const std::vector<std::string> &events, napi_value &commonEventSubscribeInfo)
{
    EVENT_LOGD("enter");

    napi_value value = nullptr;

    if (events.size() > 0) {
        napi_value nEvents = nullptr;
        if (napi_create_array(env, &nEvents) != napi_ok) {
            EVENT_LOGE("failed to create array");
            return;
        }
        size_t index = 0;
        for (auto event : events) {
            napi_create_string_utf8(env, event.c_str(), NAPI_AUTO_LENGTH, &value);
            napi_set_element(env, nEvents, index, value);
            index++;
        }

        napi_set_named_property(env, commonEventSubscribeInfo, "events", nEvents);
    }
}

void SubscriberInstance::SetEnv(const napi_env &env)
{
    env_ = env;
}

void SubscriberInstance::SetCallbackRef(const napi_ref &ref)
{
    EVENT_LOGD("enter");
    ref_ = ref;
    *valid_ = ref_ != nullptr ? true : false;
}

void SetCallback(const napi_env &env, const napi_ref &callbackIn, const int8_t &errorCode, const napi_value &result)
{
    napi_value undefined = nullptr;
    napi_get_undefined(env, &undefined);

    napi_value callback = nullptr;
    napi_value resultout = nullptr;
    napi_get_reference_value(env, callbackIn, &callback);

    napi_value results[ARGS_TWO_EVENT] = {nullptr};
    results[PARAM0_EVENT] = GetCallbackErrorValue(env, errorCode);
    results[PARAM1_EVENT] = result;

    NAPI_CALL_RETURN_VOID(env,
        napi_call_function(env, undefined, callback, ARGS_TWO_EVENT, &results[PARAM0_EVENT], &resultout));
}

void SetCallback(const napi_env &env, const napi_ref &callbackIn, const napi_value &result)
{
    napi_value undefined = nullptr;
    napi_get_undefined(env, &undefined);

    napi_value callback = nullptr;
    napi_value resultout = nullptr;
    napi_get_reference_value(env, callbackIn, &callback);

    napi_value results[ARGS_TWO_EVENT] = {nullptr};
    results[PARAM0_EVENT] = GetCallbackErrorValue(env, NO_ERROR);
    results[PARAM1_EVENT] = result;

    NAPI_CALL_RETURN_VOID(env,
        napi_call_function(env, undefined, callback, ARGS_TWO_EVENT, &results[PARAM0_EVENT], &resultout));
}

void SetPromise(const napi_env &env, const napi_deferred &deferred, const int8_t &errorCode, const napi_value &result)
{
    if (errorCode == NO_ERROR) {
        napi_resolve_deferred(env, deferred, result);
    } else {
        napi_reject_deferred(env, deferred, GetCallbackErrorValue(env, errorCode));
    }
}

void ReturnCallbackPromise(const napi_env &env, const CallbackPromiseInfo &info, const napi_value &result)
{
    EVENT_LOGD("ReturnCallbackPromise start");

    if (info.isCallback) {
        SetCallback(env, info.callback, info.errorCode, result);
    } else {
        SetPromise(env, info.deferred, info.errorCode, result);
    }
}

}  // namespace EventFwkNapi
}  // namespace OHOS
