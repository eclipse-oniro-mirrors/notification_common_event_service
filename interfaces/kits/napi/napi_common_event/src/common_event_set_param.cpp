/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "event_log_wrapper.h"
#include "ces_inner_error_code.h"
#include "napi_common_util.h"

namespace OHOS {
namespace EventManagerFwkNapi {
using namespace OHOS::EventFwk;
using namespace OHOS::Notification;

static const int32_t SET_CODE_MAX_PARA = 2;
static const int32_t SET_DATA_MAX_PARA = 2;
static const int32_t SET_CODE_AND_DATA_MAX_PARA = 3;
static const int32_t ARGS_TWO_EVENT = 2;
static const int32_t INDEX_ZERO = 0;
static const uint32_t INDEX_ONE = 1;
static const int32_t ARGC_ONE = 1;
static const int32_t ARGC_TWO = 2;

void AsyncCompleteCallbackRemoveStickyCommonEvent(napi_env env, napi_status status, void *data)
{
    EVENT_LOGD("enter");
    if (!data) {
        EVENT_LOGE("Invalid async callback data");
        return;
    }
    AsyncCallbackRemoveSticky *asyncCallbackInfo = static_cast<AsyncCallbackRemoveSticky *>(data);
    ReturnCallbackPromise(env, asyncCallbackInfo->info, NapiGetNull(env));
    if (asyncCallbackInfo->info.callback != nullptr) {
        napi_delete_reference(env, asyncCallbackInfo->info.callback);
    }

    napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
    delete asyncCallbackInfo;
    asyncCallbackInfo = nullptr;
}

void SetPublisherPermissionResult(
    const napi_env &env, const std::string &permission, napi_value &commonEventSubscribeInfo)
{
    EVENT_LOGD("SetPublisherPermissionResult excute");

    napi_value value = nullptr;
    napi_create_string_utf8(env, permission.c_str(), NAPI_AUTO_LENGTH, &value);

    napi_set_named_property(env, commonEventSubscribeInfo, "publisherPermission", value);
}

void SetPublisherDeviceIdResult(const napi_env &env, const std::string &deviceId, napi_value &commonEventSubscribeInfo)
{
    EVENT_LOGD("SetPublisherDeviceIdResult excute");

    napi_value value = nullptr;
    napi_create_string_utf8(env, deviceId.c_str(), NAPI_AUTO_LENGTH, &value);

    napi_set_named_property(env, commonEventSubscribeInfo, "publisherDeviceId", value);
}

void SetPublisherUserIdResult(const napi_env &env, const int32_t &userId, napi_value &commonEventSubscribeInfo)
{
    EVENT_LOGD("SetPublisherUserIdResult excute");

    napi_value value = nullptr;
    napi_create_int32(env, userId, &value);

    napi_set_named_property(env, commonEventSubscribeInfo, "userId", value);
}

void SetPublisherPriorityResult(const napi_env &env, const int32_t &priority, napi_value &commonEventSubscribeInfo)
{
    EVENT_LOGD("SetPublisherPriorityResult excute");

    napi_value value = nullptr;
    napi_create_int32(env, priority, &value);

    napi_set_named_property(env, commonEventSubscribeInfo, "priority", value);
}

void SetPublisherBundleNameResult(
    const napi_env &env, const std::string &publisherBundleName, napi_value &commonEventSubscribeInfo)
{
    EVENT_LOGD("Called.");
    napi_value value = nullptr;
    napi_create_string_utf8(env, publisherBundleName.c_str(), NAPI_AUTO_LENGTH, &value);

    napi_set_named_property(env, commonEventSubscribeInfo, "publisherBundleName", value);
}

void SetNapiResult(const napi_env &env, const AsyncCallbackInfoSubscribeInfo *asyncCallbackInfo, napi_value &result)
{
    EVENT_LOGD("SetNapiResult excute");

    SetEventsResult(env, asyncCallbackInfo->events, result);
    SetPublisherPermissionResult(env, asyncCallbackInfo->permission, result);
    SetPublisherDeviceIdResult(env, asyncCallbackInfo->deviceId, result);
    SetPublisherUserIdResult(env, asyncCallbackInfo->userId, result);
    SetPublisherPriorityResult(env, asyncCallbackInfo->priority, result);
    SetPublisherBundleNameResult(env, asyncCallbackInfo->publisherBundleName, result);
}

napi_value SetCode(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("SetCode excute");
    size_t argc = SET_CODE_MAX_PARA;
    napi_value argv[SET_CODE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_ref callback = nullptr;
    int32_t code = 0;
    if (ParseParametersBySetCode(env, argv, argc, code, callback) == nullptr) {
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID);
        return NapiGetNull(env);
    }

    AsyncCallbackInfoSetCode *asyncCallbackInfo = new (std::nothrow)
        AsyncCallbackInfoSetCode {.env = env, .asyncWork = nullptr, .code = code};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGE("Create asyncCallbackInfo is defeat.");
        return NapiGetNull(env);
    }

    asyncCallbackInfo->subscriber = GetSubscriber(env, thisVar);
    if (asyncCallbackInfo->subscriber == nullptr) {
        EVENT_LOGE("subscriber is null");
        delete asyncCallbackInfo;
        return NapiGetNull(env);
    }

    napi_value promise = nullptr;
    PaddingAsyncCallbackInfoSetCode(env, argc, asyncCallbackInfo, callback, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setCode", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("SetCode napi_create_async_work excute");
            AsyncCallbackInfoSetCode *asyncCallbackInfo = static_cast<AsyncCallbackInfoSetCode *>(data);
            if (asyncCallbackInfo) {
                std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(
                    asyncCallbackInfo->subscriber.get());
                if (asyncResult) {
                    asyncCallbackInfo->info.errorCode = asyncResult->SetCode(asyncCallbackInfo->code) ?
                        NO_ERROR : ERR_CES_FAILED;
                }
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("SetCode napi_create_async_work complete");
            AsyncCallbackInfoSetCode *asyncCallbackInfo = static_cast<AsyncCallbackInfoSetCode *>(data);
            if (asyncCallbackInfo) {
                ReturnCallbackPromise(env, asyncCallbackInfo->info, NapiGetNull(env));
                if (asyncCallbackInfo->info.callback != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->info.callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
                EVENT_LOGD("NapiSetCode work complete end.");
            }
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));

    if (asyncCallbackInfo->info.isCallback) {
        EVENT_LOGD("Delete napiSetCode callback reference.");
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value SetData(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("SetData excute");
    size_t argc = SET_DATA_MAX_PARA;
    napi_value argv[SET_DATA_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_ref callback = nullptr;
    std::string data;
    if (ParseParametersBySetData(env, argv, argc, data, callback) == nullptr) {
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID);
        return NapiGetNull(env);
    }

    AsyncCallbackInfoSetData *asyncCallbackInfo = new (std::nothrow)
        AsyncCallbackInfoSetData {.env = env, .asyncWork = nullptr, .data = data};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGE("asyncCallbackInfo is defeat");
        return NapiGetNull(env);
    }

    asyncCallbackInfo->subscriber = GetSubscriber(env, thisVar);
    if (asyncCallbackInfo->subscriber == nullptr) {
        EVENT_LOGE("subscriber is null");
        delete asyncCallbackInfo;
        return NapiGetNull(env);
    }

    napi_value promise = nullptr;
    PaddingAsyncCallbackInfoSetData(env, argc, asyncCallbackInfo, callback, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setData", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("SetData work excute");
            AsyncCallbackInfoSetData *asyncCallbackInfo = static_cast<AsyncCallbackInfoSetData *>(data);
            if (asyncCallbackInfo) {
                std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(
                    asyncCallbackInfo->subscriber.get());
                if (asyncResult) {
                    asyncCallbackInfo->info.errorCode = asyncResult->SetData(asyncCallbackInfo->data) ?
                        NO_ERROR : ERR_CES_FAILED;
                }
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("SetData work complete");
            AsyncCallbackInfoSetData *asyncCallbackInfo = static_cast<AsyncCallbackInfoSetData *>(data);
            if (asyncCallbackInfo) {
                ReturnCallbackPromise(env, asyncCallbackInfo->info, NapiGetNull(env));
                if (asyncCallbackInfo->info.callback != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->info.callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
            EVENT_LOGD("NapiSetData work complete end.");
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));

    if (asyncCallbackInfo->info.isCallback) {
        EVENT_LOGD("Delete napiSetData callback reference.");
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value SetCodeAndData(napi_env env, napi_callback_info info)
{
    EVENT_LOGD("SetCodeAndData excute");
    size_t argc = SET_CODE_AND_DATA_MAX_PARA;
    napi_value argv[SET_CODE_AND_DATA_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_ref callback = nullptr;
    int32_t code = 0;
    std::string data;
    if (ParseParametersBySetCodeAndData(env, argv, argc, code, data, callback) == nullptr) {
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID);
        return NapiGetNull(env);
    }

    AsyncCallbackInfoSetCodeAndData *asyncCallbackInfo = new (std::nothrow) AsyncCallbackInfoSetCodeAndData {
        .env = env, .asyncWork = nullptr, .code = code, .data = data};
    if (asyncCallbackInfo == nullptr) {
        EVENT_LOGE("asyncCallbackInfo is nullptr");
        return NapiGetNull(env);
    }

    asyncCallbackInfo->subscriber = GetSubscriber(env, thisVar);
    if (asyncCallbackInfo->subscriber == nullptr) {
        EVENT_LOGE("subscriber is defeat");
        delete asyncCallbackInfo;
        return NapiGetNull(env);
    }

    napi_value promise = nullptr;
    PaddingAsyncCallbackInfoSetCodeAndData(env, argc, asyncCallbackInfo, callback, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setCodeAndData", NAPI_AUTO_LENGTH, &resourceName);
    // Calling Asynchronous functions
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGD("SetCodeAndData napi_create_async_work start");
            AsyncCallbackInfoSetCodeAndData *asyncCallbackInfo = static_cast<AsyncCallbackInfoSetCodeAndData *>(data);
            if (asyncCallbackInfo) {
                std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(
                    asyncCallbackInfo->subscriber.get());
                if (asyncResult) {
                    asyncCallbackInfo->info.errorCode = asyncResult->SetCodeAndData(
                        asyncCallbackInfo->code, asyncCallbackInfo->data) ? NO_ERROR : ERR_CES_FAILED;
                }
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGD("SetCodeAndData napi_create_async_work complete");
            AsyncCallbackInfoSetCodeAndData *asyncCallbackInfo = static_cast<AsyncCallbackInfoSetCodeAndData *>(data);
            if (asyncCallbackInfo) {
                ReturnCallbackPromise(env, asyncCallbackInfo->info, NapiGetNull(env));
                if (asyncCallbackInfo->info.callback != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->info.callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
                EVENT_LOGD("asyncCallbackInfo is null");
            }
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated));

    if (asyncCallbackInfo->info.isCallback) {
        EVENT_LOGD("Delete napiSetCodeAndData callback reference.");
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value NapiStaticSubscribe::SetStaticSubscriberState(napi_env env, napi_callback_info info)
{
    NapiStaticSubscribe *me = AbilityRuntime::CheckParamsAndGetThis<NapiStaticSubscribe>(env, info);
    return (me != nullptr) ? me->OnSetStaticSubscriberState(env, info) : nullptr;
}

void SetEventsResult(const napi_env &env, const std::vector<std::string> &events, napi_value &commonEventSubscribeInfo)
{
    EVENT_LOGD("SetEventsResult start");

    napi_value value = nullptr;

    if (events.size() > 0) {
        napi_value nEvents = nullptr;
        if (napi_create_array(env, &nEvents) != napi_ok) {
            return;
        }
        size_t index = 0;
        for (auto event : events) {
            EVENT_LOGD("SetEventsResult event: %{public}s", event.c_str());
            napi_create_string_utf8(env, event.c_str(), NAPI_AUTO_LENGTH, &value);
            napi_set_element(env, nEvents, index, value);
            index++;
        }

        napi_set_named_property(env, commonEventSubscribeInfo, "events", nEvents);
    }

    EVENT_LOGD("SetEventsResult end");
}


void SubscriberInstance::SetEnv(const napi_env &env)
{
    env_ = env;
}

void SubscriberInstance::SetCallbackRef(const napi_ref &ref)
{
    ref_ = ref;
    *valid_ = ref_ != nullptr ? true : false;
}

void SetCallback(const napi_env &env, const napi_ref &callbackIn, const int32_t &errorCode, const napi_value &result)
{
    EVENT_LOGD("Return error: %{public}d", errorCode);
    napi_value undefined = nullptr;
    napi_get_undefined(env, &undefined);

    napi_value callback = nullptr;
    napi_value resultout = nullptr;
    napi_get_reference_value(env, callbackIn, &callback);

    napi_value results[ARGS_TWO_EVENT] = {nullptr};
    results[INDEX_ZERO] = GetCallbackErrorValue(env, errorCode);
    results[INDEX_ONE] = result;

    NAPI_CALL_RETURN_VOID(env,
        napi_call_function(env, undefined, callback, ARGS_TWO_EVENT, &results[INDEX_ZERO], &resultout));
}

void SetCallback(const napi_env &env, const napi_ref &callbackIn, const napi_value &result)
{
    napi_value undefined = nullptr;
    napi_get_undefined(env, &undefined);

    napi_value callback = nullptr;
    napi_value resultout = nullptr;
    napi_get_reference_value(env, callbackIn, &callback);

    napi_value results[ARGS_TWO_EVENT] = {nullptr};
    results[INDEX_ZERO] = GetCallbackErrorValue(env, NO_ERROR);
    results[INDEX_ONE] = result;

    NAPI_CALL_RETURN_VOID(env,
        napi_call_function(env, undefined, callback, ARGS_TWO_EVENT, &results[INDEX_ZERO], &resultout));
}

void SetPromise(const napi_env &env, const napi_deferred &deferred, const int32_t &errorCode, const napi_value &result)
{
    if (errorCode == NO_ERROR) {
        napi_resolve_deferred(env, deferred, result);
    } else {
        napi_reject_deferred(env, deferred, GetCallbackErrorValue(env, errorCode));
    }
}

void ReturnCallbackPromise(const napi_env &env, const CallbackPromiseInfo &info, const napi_value &result)
{
    EVENT_LOGD("ReturnCallbackPromise excute");

    if (info.isCallback) {
        SetCallback(env, info.callback, info.errorCode, result);
    } else {
        SetPromise(env, info.deferred, info.errorCode, result);
    }
}

bool ParseSetStaticSubscriberStateParam(napi_env env, const napi_callback_info info, std::vector<std::string> &events,
    bool &fromBundle, napi_value &lastParam)
{
    EVENT_LOGD("Called.");
    napi_value thisVar = nullptr;
    size_t argc = ARGC_TWO;
    napi_value argv[ARGC_TWO] = { nullptr };
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL), false);
    if (argc == ARGC_ONE) {
        return true;
    }
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, argv[INDEX_ONE], &valueType), false);
    if (valueType == napi_function) {
        lastParam = argv[INDEX_ONE];
        return true;
    }
    fromBundle = true;
    uint32_t arraySize = 0;
    NAPI_CALL_BASE(env, napi_get_array_length(env, argv[INDEX_ONE], &arraySize), false);
    napi_value jsValue = nullptr;
    for (uint32_t index = 0; index < arraySize; index++) {
        if (napi_get_element(env, argv[INDEX_ONE], index, &jsValue) != napi_ok) {
            EVENT_LOGE("Get element failed.");
            std::string msg = "Mandatory parameters are left unspecified.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return false;
        }
        std::string event;
        if (!AppExecFwk::UnwrapStringFromJS2(env, jsValue, event)) {
            EVENT_LOGE("Failed to convert value to string.");
            std::string msg = "Incorrect parameter types.The type of param must be string.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return false;
        }
        events.push_back(event);
    }
    return true;
}

napi_value NapiStaticSubscribe::OnSetStaticSubscriberState(napi_env env, const napi_callback_info info)
{
    EVENT_LOGD("Called.");
    napi_value argv[ARGC_TWO] = { nullptr };
    napi_value result = nullptr;
    size_t argc = ARGC_TWO;
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < ARGC_ONE) {
        EVENT_LOGE("The param is invalid.");
        std::string msg = "Mandatory parameters are left unspecified.";
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
        napi_get_undefined(env, &result);
        return result;
    }
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[INDEX_ZERO], &valueType));
    if (valueType != napi_boolean) {
        EVENT_LOGE("Parse type failed.");
        std::string msg = "Incorrect parameter types.The type of param must be boolean.";
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
        napi_get_undefined(env, &result);
        return result;
    }
    bool enable;
    NAPI_CALL(env, napi_get_value_bool(env, argv[INDEX_ZERO], &enable));
    napi_value lastParam = nullptr;
    std::vector<std::string> events;
    bool fromBundle = false;
    if (!ParseSetStaticSubscriberStateParam(env, info, events, fromBundle, lastParam)) {
        EVENT_LOGE("Parameter judgment error.");
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID);
        napi_get_undefined(env, &result);
        return result;
    }
    auto complete = [enable, events, fromBundle](napi_env env, AbilityRuntime::NapiAsyncTask &task, int32_t status) {
        auto ret = fromBundle ? CommonEventManager::SetStaticSubscriberState(events, enable)
                              : CommonEventManager::SetStaticSubscriberState(enable);
        if (ret == ERR_OK) {
            napi_value result = nullptr;
            napi_get_undefined(env, &result);
            task.Resolve(env, result);
        } else {
            if (ret != ERR_NOTIFICATION_CES_COMMON_NOT_SYSTEM_APP && ret != ERR_NOTIFICATION_SEND_ERROR) {
                ret = ERR_NOTIFICATION_CESM_ERROR;
            }
            task.Reject(env, AbilityRuntime::CreateJsError(env, ret, "SetStaticSubscriberState failed"));
        }
    };
    AbilityRuntime::NapiAsyncTask::Schedule("NapiStaticSubscribe::OnSetStaticSubscriberState", env,
        AbilityRuntime::CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
    return result;
}
}
}
