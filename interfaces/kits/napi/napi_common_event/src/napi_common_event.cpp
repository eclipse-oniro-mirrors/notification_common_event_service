/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "event_log_wrapper.h"
#include "napi_common.h"
#include "ces_inner_error_code.h"

namespace OHOS {
namespace EventManagerFwkNapi {
using namespace OHOS::EventFwk;
using namespace OHOS::Notification;

namespace {
static const int32_t GETSUBSCREBEINFO_MAX_PARA = 1;
static const int32_t ISORDEREDCOMMONEVENT_MAX_PARA = 1;
static const int32_t ISSTICKYCOMMONEVENT_MAX_PARA = 1;
static const int32_t GET_CODE_MAX_PARA = 1;
static const int32_t SET_CODE_MAX_PARA = 2;
static const int32_t GET_DATA_MAX_PARA = 1;
static const int32_t SET_DATA_MAX_PARA = 2;
static const int32_t SET_CODE_AND_DATA_MAX_PARA = 3;
static const int32_t ABORT_MAX_PARA = 1;
static const int32_t CLEAR_ABORT_MAX_PARA = 1;
static const int32_t GET_ABORT_MAX_PARA = 1;
static const int32_t FINISH_MAX_PARA = 1;
static const int32_t ARGS_TWO_EVENT = 2;
static const int32_t PARAM0_EVENT = 0;
static const int32_t PARAM1_EVENT = 1;
}
std::atomic_ullong SubscriberInstance::subscriberID_ = 0;

static const std::unordered_map<int32_t, std::string> ErrorCodeToMsg {
    {ERR_NOTIFICATION_CES_COMMON_PERMISSION_DENIED, "Permission denied"},
    {ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, "Invalid parameter"},
    {ERR_NOTIFICATION_CES_COMMON_SYSTEMCAP_NOT_SUPPORT, "SystemCapability not found"},
    {ERR_NOTIFICATION_CES_WANT_ACTION_IS_NULL, "Want action is null"},
    {ERR_NOTIFICATION_CES_SANDBOX_NOT_SUPPORT, "sandbox application can not send common event"},
    {ERR_NOTIFICATION_CES_EVENT_FREQ_TOO_HIGH, "common event send frequency too high"},
    {ERR_NOTIFICATION_CES_NOT_SA_SYSTEM_APP, "not SA app or System app"},
    {ERR_NOTIFICATION_CES_NO_SUBSCRIBER, "subscriber can not found"},
    {ERR_NOTIFICATION_CES_USERID_INVALID, "usreId is invalid"},
    {ERR_NOTIFICATION_CES_PARCLE_REEOR, "parcle not written correctly"},
    {ERR_NOTIFICATION_SEND_ERROR, "message send error"},
    {ERR_NOTIFICATION_CESM_ERROR, "CEMS is not read"},
    {ERR_NOTIFICATION_SYS_ERROR, "system error"}
};

AsyncCallbackInfoUnsubscribe::AsyncCallbackInfoUnsubscribe()
{
    EVENT_LOGI("constructor AsyncCallbackInfoUnsubscribe: %{private}p", this);
}

AsyncCallbackInfoUnsubscribe::~AsyncCallbackInfoUnsubscribe()
{
    EVENT_LOGI("destructor AsyncCallbackInfoUnsubscribe: %{private}p - subscriber[%{public}llu](%{private}p)",
               this, subscriber->GetID(), subscriber.get());
}

SubscriberInstance::SubscriberInstance(const CommonEventSubscribeInfo &sp) : CommonEventSubscriber(sp)
{
    id_ = ++subscriberID_;
    EVENT_LOGI("constructor SubscriberInstance[%{public}llu]: %{private}p", id_.load(), this);
    valid_ = std::make_shared<bool>(false);
}

SubscriberInstance::~SubscriberInstance()
{
    EVENT_LOGI("destructor SubscriberInstance[%{public}llu]: %{private}p", id_.load(), this);
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
        EVENT_LOGE("objectInfo is nullptr");
        return;
    }

    EVENT_LOGI("Constructor objectInfo = %{private}p", objectInfo);
    subscriber = std::shared_ptr<SubscriberInstance>(objectInfo);
}

std::shared_ptr<SubscriberInstance> SubscriberInstanceWrapper::GetSubscriber()
{
    return subscriber;
}

void UvQueueWorkOnReceiveEvent(uv_work_t *work, int status)
{
    EVENT_LOGI("OnReceiveEvent uv_work_t start");
    if (work == nullptr) {
        return;
    }
    CommonEventDataWorker *commonEventDataWorkerData = (CommonEventDataWorker *)work->data;
    if (commonEventDataWorkerData == nullptr || commonEventDataWorkerData->ref == nullptr) {
        EVENT_LOGE("OnReceiveEvent commonEventDataWorkerData or ref is null");
        delete work;
        work = nullptr;
        return;
    }
    if ((commonEventDataWorkerData->valid == nullptr) || *(commonEventDataWorkerData->valid) == false) {
        EVENT_LOGE("OnReceiveEvent commonEventDataWorkerData or ref is invalid which may be freed before");
        delete work;
        work = nullptr;
        return;
    }
    napi_handle_scope scope;
    napi_open_handle_scope(commonEventDataWorkerData->env, &scope);

    napi_value result = nullptr;
    napi_create_object(commonEventDataWorkerData->env, &result);

    napi_value undefined = nullptr;
    napi_get_undefined(commonEventDataWorkerData->env, &undefined);

    napi_value callback = nullptr;
    napi_value resultout = nullptr;
    EVENT_LOGI("OnReceiveEvent ref = %{private}p", commonEventDataWorkerData->ref);
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
    EVENT_LOGI("OnReceiveEvent start");
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
    EVENT_LOGI("OnReceiveEvent() action = %{public}s", data.GetWant().GetAction().c_str());
    commonEventDataWorker->code = data.GetCode();
    commonEventDataWorker->data = data.GetData();
    commonEventDataWorker->env = env_;
    commonEventDataWorker->ref = ref_;
    commonEventDataWorker->valid = valid_;

    work->data = (void *)commonEventDataWorker;

    EVENT_LOGI("OnReceiveEvent this = %{private}p", this);

    if (this->IsOrderedCommonEvent()) {
        std::lock_guard<std::mutex> lock(subscriberInsMutex);
        for (auto subscriberInstance : subscriberInstances) {
            EVENT_LOGI("OnReceiveEvent get = %{private}p", subscriberInstance.first.get());
            if (subscriberInstance.first.get() == this) {
                subscriberInstances[subscriberInstance.first].commonEventResult = GoAsyncCommonEvent();
                break;
            }
        }
    }

    int ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, UvQueueWorkOnReceiveEvent);
    if (ret != 0) {
        delete commonEventDataWorker;
        commonEventDataWorker = nullptr;
        delete work;
        work = nullptr;
    }
    EVENT_LOGI("OnReceiveEvent end");
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

napi_value NapiGetNull(napi_env env)
{
    napi_value result = nullptr;
    napi_get_null(env, &result);

    return result;
}

napi_value GetCallbackErrorValue(napi_env env, int8_t errorCode)
{
    napi_value result = nullptr;
    napi_value eCode = nullptr;
    NAPI_CALL(env, napi_create_int32(env, errorCode, &eCode));
    NAPI_CALL(env, napi_create_object(env, &result));
    NAPI_CALL(env, napi_set_named_property(env, result, "code", eCode));
    return result;
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

void ReturnCallbackPromise(const napi_env &env, const CallbackPromiseInfo &info, const napi_value &result)
{
    EVENT_LOGI("ReturnCallbackPromise start");

    if (info.isCallback) {
        SetCallback(env, info.callback, info.errorCode, result);
    }
}

void SetEventsResult(const napi_env &env, const std::vector<std::string> &events, napi_value &commonEventSubscribeInfo)
{
    EVENT_LOGI("SetEventsResult start");

    napi_value value = nullptr;

    if (events.size() > 0) {
        napi_value nEvents = nullptr;
        if (napi_create_array(env, &nEvents) != napi_ok) {
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

    EVENT_LOGI("SetEventsResult end");
}

void SetPublisherPermissionResult(
    const napi_env &env, const std::string &permission, napi_value &commonEventSubscribeInfo)
{
    EVENT_LOGI("SetPublisherPermissionResult start");

    napi_value value = nullptr;
    napi_create_string_utf8(env, permission.c_str(), NAPI_AUTO_LENGTH, &value);

    napi_set_named_property(env, commonEventSubscribeInfo, "publisherPermission", value);
}

void SetPublisherDeviceIdResult(const napi_env &env, const std::string &deviceId, napi_value &commonEventSubscribeInfo)
{
    EVENT_LOGI("SetPublisherDeviceIdResult start");

    napi_value value = nullptr;
    napi_create_string_utf8(env, deviceId.c_str(), NAPI_AUTO_LENGTH, &value);

    napi_set_named_property(env, commonEventSubscribeInfo, "publisherDeviceId", value);
}

void SetPublisherUserIdResult(const napi_env &env, const int32_t &userId, napi_value &commonEventSubscribeInfo)
{
    EVENT_LOGI("SetPublisherUserIdResult start");

    napi_value value = nullptr;
    napi_create_int32(env, userId, &value);

    napi_set_named_property(env, commonEventSubscribeInfo, "userId", value);
}

void SetPublisherPriorityResult(const napi_env &env, const int32_t &priority, napi_value &commonEventSubscribeInfo)
{
    EVENT_LOGI("SetPublisherPriorityResult start");

    napi_value value = nullptr;
    napi_create_int32(env, priority, &value);

    napi_set_named_property(env, commonEventSubscribeInfo, "priority", value);
}

void PaddingAsyncCallbackInfoGetSubscribeInfo(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoSubscribeInfo *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGI("PaddingAsyncCallbackInfoGetSubscribeInfo start");

    if (argc >= GETSUBSCREBEINFO_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }
}

void PaddingNapiCreateAsyncWorkCallbackInfo(AsyncCallbackInfoSubscribeInfo *&asyncCallbackInfo)
{
    EVENT_LOGI("PaddingNapiCreateAsyncWorkCallbackInfo start");

    asyncCallbackInfo->events = asyncCallbackInfo->subscriber->GetSubscribeInfo().GetMatchingSkills().GetEvents();
    asyncCallbackInfo->permission = asyncCallbackInfo->subscriber->GetSubscribeInfo().GetPermission();
    asyncCallbackInfo->deviceId = asyncCallbackInfo->subscriber->GetSubscribeInfo().GetDeviceId();
    asyncCallbackInfo->userId = asyncCallbackInfo->subscriber->GetSubscribeInfo().GetUserId();
    asyncCallbackInfo->priority = asyncCallbackInfo->subscriber->GetSubscribeInfo().GetPriority();
}

void SetNapiResult(const napi_env &env, const AsyncCallbackInfoSubscribeInfo *asyncCallbackInfo, napi_value &result)
{
    EVENT_LOGI("SetNapiResult start");

    SetEventsResult(env, asyncCallbackInfo->events, result);
    SetPublisherPermissionResult(env, asyncCallbackInfo->permission, result);
    SetPublisherDeviceIdResult(env, asyncCallbackInfo->deviceId, result);
    SetPublisherUserIdResult(env, asyncCallbackInfo->userId, result);
    SetPublisherPriorityResult(env, asyncCallbackInfo->priority, result);
}

void PaddingAsyncCallbackInfoIsOrderedCommonEvent(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoOrderedCommonEvent *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGI("PaddingAsyncCallbackInfoIsOrderedCommonEvent start");

    if (argc >= ISORDEREDCOMMONEVENT_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }
}

std::shared_ptr<AsyncCommonEventResult> GetAsyncResult(const SubscriberInstance *objectInfo)
{
    EVENT_LOGI("GetAsyncResult start");
    if (!objectInfo) {
        EVENT_LOGE("Invalid objectInfo");
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(subscriberInsMutex);
    for (auto subscriberInstance : subscriberInstances) {
        EVENT_LOGI("SubscriberInstance = %{private}p", subscriberInstance.first.get());
        if (subscriberInstance.first.get() == objectInfo) {
            EVENT_LOGI("Result = %{private}p", subscriberInstance.second.commonEventResult.get());
            return subscriberInstance.second.commonEventResult;
        }
    }
    EVENT_LOGI("No found objectInfo");
    return nullptr;
}

void PaddingAsyncCallbackInfoIsStickyCommonEvent(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoStickyCommonEvent *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGI("PaddingAsyncCallbackInfoIsStickyCommonEvent start");

    if (argc >= ISSTICKYCOMMONEVENT_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }

    EVENT_LOGI("PaddingAsyncCallbackInfoIsStickyCommonEvent end");
}

void PaddingAsyncCallbackInfoGetCode(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoGetCode *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGI("PaddingAsyncCallbackInfoGetCode start");

    if (argc >= GET_CODE_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }

    EVENT_LOGI("PaddingAsyncCallbackInfoGetCode end");
}

void PaddingAsyncCallbackInfoSetCode(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoSetCode *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGI("PaddingAsyncCallbackInfoSetCode start");

    if (argc >= SET_CODE_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }

    EVENT_LOGI("PaddingAsyncCallbackInfoSetCode end");
}

napi_value SetCode(napi_env env, napi_callback_info info)
{
    EVENT_LOGI("SetCode start");
    size_t argc = SET_CODE_MAX_PARA;
    napi_value argv[SET_CODE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_ref callback = nullptr;
    int32_t code = 0;

    AsyncCallbackInfoSetCode *asyncCallbackInfo = new (std::nothrow)
        AsyncCallbackInfoSetCode {.env = env, .asyncWork = nullptr, .code = code};
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
    PaddingAsyncCallbackInfoSetCode(env, argc, asyncCallbackInfo, callback, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setCode", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGI("SetCode napi_create_async_work start");
            AsyncCallbackInfoSetCode *asyncCallbackInfo = (AsyncCallbackInfoSetCode *)data;
            std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(asyncCallbackInfo->subscriber.get());
            EVENT_LOGI("SetCode get = %{private}p", asyncResult.get());
            if (asyncResult) {
                EVENT_LOGI("SetCode get2 = %{private}p", asyncResult.get());
                asyncCallbackInfo->info.errorCode = asyncResult->SetCode(asyncCallbackInfo->code) ?
                    NO_ERROR : ERR_CES_FAILED;
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGI("SetCode napi_create_async_work end");
            AsyncCallbackInfoSetCode *asyncCallbackInfo = (AsyncCallbackInfoSetCode *)data;
            if (asyncCallbackInfo) {
                ReturnCallbackPromise(env, asyncCallbackInfo->info, NapiGetNull(env));
                if (asyncCallbackInfo->info.callback != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->info.callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));

    if (asyncCallbackInfo->info.isCallback) {
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

void PaddingAsyncCallbackInfoGetData(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoGetData *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGI("PaddingAsyncCallbackInfoGetData start");

    if (argc >= GET_DATA_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }

    EVENT_LOGI("PaddingAsyncCallbackInfoGetData end");
}

napi_value GetData(napi_env env, napi_callback_info info)
{
    EVENT_LOGI("GetData start");
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_ref callback = nullptr;

    AsyncCallbackInfoGetData *asyncCallbackInfo =
        new (std::nothrow) AsyncCallbackInfoGetData {.env = env, .asyncWork = nullptr};
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
    PaddingAsyncCallbackInfoGetData(env, argc, asyncCallbackInfo, callback, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getData", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGI("GetData napi_create_async_work start");
            AsyncCallbackInfoGetData *asyncCallbackInfo = (AsyncCallbackInfoGetData *)data;
            std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(asyncCallbackInfo->subscriber.get());
            if (asyncResult) {
                asyncCallbackInfo->data = asyncResult->GetData();
            } else {
                asyncCallbackInfo->data = std::string();
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGI("GetData napi_create_async_work end");
            AsyncCallbackInfoGetData *asyncCallbackInfo = (AsyncCallbackInfoGetData *)data;
            if (asyncCallbackInfo) {
                napi_value result = nullptr;
                napi_create_string_utf8(env, asyncCallbackInfo->data.c_str(), NAPI_AUTO_LENGTH, &result);
                ReturnCallbackPromise(env, asyncCallbackInfo->info, result);
                if (asyncCallbackInfo->info.callback != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->info.callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));

    if (asyncCallbackInfo->info.isCallback) {
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

void PaddingAsyncCallbackInfoSetData(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoSetData *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGI("PaddingAsyncCallbackInfoSetData start");

    if (argc >= SET_DATA_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }

    EVENT_LOGI("PaddingAsyncCallbackInfoSetData end");
}

napi_value SetData(napi_env env, napi_callback_info info)
{
    EVENT_LOGI("SetData start");
    size_t argc = SET_DATA_MAX_PARA;
    napi_value argv[SET_DATA_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_ref callback = nullptr;
    std::string data;

    AsyncCallbackInfoSetData *asyncCallbackInfo = new (std::nothrow)
        AsyncCallbackInfoSetData {.env = env, .asyncWork = nullptr, .data = data};
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
    PaddingAsyncCallbackInfoSetData(env, argc, asyncCallbackInfo, callback, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setData", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGI("SetData napi_create_async_work start");
            AsyncCallbackInfoSetData *asyncCallbackInfo = (AsyncCallbackInfoSetData *)data;
            std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(asyncCallbackInfo->subscriber.get());
            EVENT_LOGI("SetData get = %{private}p", asyncResult.get());
            if (asyncResult) {
                EVENT_LOGI("SetData get2 = %{private}p", asyncResult.get());
                asyncCallbackInfo->info.errorCode = asyncResult->SetData(asyncCallbackInfo->data) ?
                    NO_ERROR : ERR_CES_FAILED;
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGI("SetData napi_create_async_work end");
            AsyncCallbackInfoSetData *asyncCallbackInfo = (AsyncCallbackInfoSetData *)data;
            if (asyncCallbackInfo) {
                ReturnCallbackPromise(env, asyncCallbackInfo->info, NapiGetNull(env));
                if (asyncCallbackInfo->info.callback != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->info.callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));

    if (asyncCallbackInfo->info.isCallback) {
        return NapiGetNull(env);
    } else {
        return promise;
    }
}


void PaddingAsyncCallbackInfoSetCodeAndData(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoSetCodeAndData *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGI("PaddingAsyncCallbackInfoSetCodeAndData start");

    if (argc >= SET_CODE_AND_DATA_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }

    EVENT_LOGI("PaddingAsyncCallbackInfoSetCodeAndData end");
}

napi_value SetCodeAndData(napi_env env, napi_callback_info info)
{
    EVENT_LOGI("SetCodeAndData start");
    size_t argc = SET_CODE_AND_DATA_MAX_PARA;
    napi_value argv[SET_CODE_AND_DATA_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_ref callback = nullptr;
    int32_t code = 0;
    std::string data;

    AsyncCallbackInfoSetCodeAndData *asyncCallbackInfo = new (std::nothrow) AsyncCallbackInfoSetCodeAndData {
        .env = env, .asyncWork = nullptr, .code = code, .data = data};
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
    PaddingAsyncCallbackInfoSetCodeAndData(env, argc, asyncCallbackInfo, callback, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setCodeAndData", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGI("SetCodeAndData napi_create_async_work start");
            AsyncCallbackInfoSetCodeAndData *asyncCallbackInfo = (AsyncCallbackInfoSetCodeAndData *)data;
            std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(asyncCallbackInfo->subscriber.get());
            if (asyncResult) {
                asyncCallbackInfo->info.errorCode = asyncResult->SetCodeAndData(
                    asyncCallbackInfo->code, asyncCallbackInfo->data) ? NO_ERROR : ERR_CES_FAILED;
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGI("SetCodeAndData napi_create_async_work end");
            AsyncCallbackInfoSetCodeAndData *asyncCallbackInfo = (AsyncCallbackInfoSetCodeAndData *)data;
            if (asyncCallbackInfo) {
                ReturnCallbackPromise(env, asyncCallbackInfo->info, NapiGetNull(env));
                if (asyncCallbackInfo->info.callback != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->info.callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));

    if (asyncCallbackInfo->info.isCallback) {
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value ParseParametersByAbort(const napi_env &env, const napi_value (&argv)[1], size_t argc, napi_ref &callback)
{
    napi_valuetype valuetype;

    // argv[0]:callback
    if (argc >= ABORT_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Wrong argument type. Function expected.");
            return nullptr;
        }
        napi_create_reference(env, argv[0], 1, &callback);
    }

    return NapiGetNull(env);
}

void PaddingAsyncCallbackInfoAbort(const napi_env &env, const size_t &argc, AsyncCallbackInfoAbort *&asyncCallbackInfo,
    const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGI("PaddingAsyncCallbackInfoAbort start");

    if (argc >= ABORT_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }

    EVENT_LOGI("PaddingAsyncCallbackInfoAbort end");
}

napi_value AbortCommonEvent(napi_env env, napi_callback_info info)
{
    EVENT_LOGI("Abort start");
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
        EVENT_LOGE("subscriber is nullptr");
        delete asyncCallbackInfo;
        return NapiGetNull(env);
    }
    napi_value promise = nullptr;
    PaddingAsyncCallbackInfoAbort(env, argc, asyncCallbackInfo, callback, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "abort", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGI("Abort napi_create_async_work start");
            AsyncCallbackInfoAbort *asyncCallbackInfo = (AsyncCallbackInfoAbort *)data;
            std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(asyncCallbackInfo->subscriber.get());
            if (asyncResult) {
                asyncCallbackInfo->info.errorCode = asyncResult->AbortCommonEvent() ? NO_ERROR : ERR_CES_FAILED;
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGI("Abort napi_create_async_work end");
            AsyncCallbackInfoAbort *asyncCallbackInfo = (AsyncCallbackInfoAbort *)data;
            if (asyncCallbackInfo) {
                ReturnCallbackPromise(env, asyncCallbackInfo->info, NapiGetNull(env));
                if (asyncCallbackInfo->info.callback != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->info.callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));

    if (asyncCallbackInfo->info.isCallback) {
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

void PaddingAsyncCallbackInfoClearAbort(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoClearAbort *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGI("PaddingAsyncCallbackInfoClearAbort start");

    if (argc >= CLEAR_ABORT_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }

    EVENT_LOGI("PaddingAsyncCallbackInfoClearAbort end");
}

napi_value ClearAbortCommonEvent(napi_env env, napi_callback_info info)
{
    EVENT_LOGI("ClearAbort start");
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_ref callback = nullptr;

    AsyncCallbackInfoClearAbort *asyncCallbackInfo =
        new (std::nothrow) AsyncCallbackInfoClearAbort {.env = env, .asyncWork = nullptr};
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
    PaddingAsyncCallbackInfoClearAbort(env, argc, asyncCallbackInfo, callback, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "clearAbort", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGI("ClearAbort napi_create_async_work start");
            AsyncCallbackInfoClearAbort *asyncCallbackInfo = (AsyncCallbackInfoClearAbort *)data;
            std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(asyncCallbackInfo->subscriber.get());
            if (asyncResult) {
                asyncCallbackInfo->info.errorCode = asyncResult->ClearAbortCommonEvent() ? NO_ERROR : ERR_CES_FAILED;
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGI("ClearAbort napi_create_async_work end");
            AsyncCallbackInfoClearAbort *asyncCallbackInfo = (AsyncCallbackInfoClearAbort *)data;
            if (asyncCallbackInfo) {
                ReturnCallbackPromise(env, asyncCallbackInfo->info, NapiGetNull(env));
                if (asyncCallbackInfo->info.callback != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->info.callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));

    if (asyncCallbackInfo->info.isCallback) {
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

void PaddingAsyncCallbackInfoGetAbort(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoGetAbort *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGI("PaddingAsyncCallbackInfoGetAbort start");

    if (argc >= GET_ABORT_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }

    EVENT_LOGI("PaddingAsyncCallbackInfoGetAbort end");
}

napi_value GetAbortCommonEvent(napi_env env, napi_callback_info info)
{
    EVENT_LOGI("GetAbort start");
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_ref callback = nullptr;

    AsyncCallbackInfoGetAbort *asyncCallbackInfo =
        new (std::nothrow) AsyncCallbackInfoGetAbort {.env = env, .asyncWork = nullptr};
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
    PaddingAsyncCallbackInfoGetAbort(env, argc, asyncCallbackInfo, callback, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getAbort", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGI("GetAbort napi_create_async_work start");
            AsyncCallbackInfoGetAbort *asyncCallbackInfo = (AsyncCallbackInfoGetAbort *)data;
            std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(asyncCallbackInfo->subscriber.get());
            if (asyncResult) {
                asyncCallbackInfo->abortEvent = asyncResult->GetAbortCommonEvent();
            } else {
                asyncCallbackInfo->abortEvent = false;
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGI("GetAbort napi_create_async_work end");
            AsyncCallbackInfoGetAbort *asyncCallbackInfo = (AsyncCallbackInfoGetAbort *)data;
            if (asyncCallbackInfo) {
                napi_value result = nullptr;
                napi_get_boolean(env, asyncCallbackInfo->abortEvent, &result);
                ReturnCallbackPromise(env, asyncCallbackInfo->info, result);
                if (asyncCallbackInfo->info.callback != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->info.callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));

    if (asyncCallbackInfo->info.isCallback) {
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

void PaddingAsyncCallbackInfoFinish(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoFinish *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGI("PaddingAsyncCallbackInfoFinish start");

    if (argc >= FINISH_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }

    EVENT_LOGI("PaddingAsyncCallbackInfoFinish end");
}

napi_value FinishCommonEvent(napi_env env, napi_callback_info info)
{
    EVENT_LOGI("Finish start");
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_ref callback = nullptr;

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

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "finish", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            EVENT_LOGI("Finish napi_create_async_work start");
            AsyncCallbackInfoFinish *asyncCallbackInfo = (AsyncCallbackInfoFinish *)data;
            std::shared_ptr<AsyncCommonEventResult> asyncResult = GetAsyncResult(asyncCallbackInfo->subscriber.get());
            if (asyncResult) {
                asyncCallbackInfo->info.errorCode = asyncResult->FinishCommonEvent() ? NO_ERROR : ERR_CES_FAILED;
            }
        },
        [](napi_env env, napi_status status, void *data) {
            EVENT_LOGI("Finish napi_create_async_work end");
            AsyncCallbackInfoFinish *asyncCallbackInfo = (AsyncCallbackInfoFinish *)data;
            if (asyncCallbackInfo) {
                ReturnCallbackPromise(env, asyncCallbackInfo->info, NapiGetNull(env));
                if (asyncCallbackInfo->info.callback != nullptr) {
                    napi_delete_reference(env, asyncCallbackInfo->info.callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
                asyncCallbackInfo = nullptr;
            }
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));

    if (asyncCallbackInfo->info.isCallback) {
        return NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value CommonEventSubscriberConstructor(napi_env env, napi_callback_info info)
{
    EVENT_LOGI("enter");
    napi_value thisVar = nullptr;
    CommonEventSubscribeInfo subscribeInfo;

    auto wrapper = new (std::nothrow) SubscriberInstanceWrapper(subscribeInfo);
    if (wrapper == nullptr) {
        EVENT_LOGE("wrapper is null");
        return NapiGetNull(env);
    }
    EVENT_LOGI("Constructor wrapper = %{private}p", wrapper);

    napi_wrap(env, thisVar, wrapper,
        [](napi_env env, void *data, void *hint) {
            auto *wrapper = reinterpret_cast<SubscriberInstanceWrapper *>(data);
            EVENT_LOGI("Constructor destroy %{private}p", wrapper);
            std::lock_guard<std::mutex> lock(subscriberInsMutex);
            for (auto subscriberInstance : subscriberInstances) {
                EVENT_LOGI("Constructor get = %{private}p", subscriberInstance.first.get());
                if (subscriberInstance.first.get() == wrapper->GetSubscriber().get()) {
                    for (auto asyncCallbackInfo : subscriberInstance.second.asyncCallbackInfo) {
                        EVENT_LOGI("Constructor ptr = %{private}p", asyncCallbackInfo);
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

    EVENT_LOGI("end");
    return thisVar;
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

    EVENT_LOGI("GetSubscriber wrapper = %{private}p", wrapper);
    return wrapper->GetSubscriber();
}

void NapiThrow(napi_env env, int32_t errCode)
{
    EVENT_LOGI("enter");

    napi_value code = nullptr;
    napi_create_int32(env, errCode, &code);
    
    auto iter = ErrorCodeToMsg.find(errCode);
    std::string errMsg = iter != ErrorCodeToMsg.end() ? iter->second : "";
    napi_value message = nullptr;
    napi_create_string_utf8(env, errMsg.c_str(), NAPI_AUTO_LENGTH, &message);

    napi_value error = nullptr;
    napi_create_error(env, nullptr, message, &error);
    napi_set_named_property(env, error, "code", code);
    napi_throw(env, error);
}

napi_value CommonEventSubscriberInit(napi_env env, napi_value exports)
{
    EVENT_LOGI("enter");
    napi_value constructor = nullptr;
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("setCode", SetCode),
        DECLARE_NAPI_FUNCTION("getData", GetData),
        DECLARE_NAPI_FUNCTION("setData", SetData),
        DECLARE_NAPI_FUNCTION("setCodeAndData", SetCodeAndData),
        DECLARE_NAPI_FUNCTION("abortCommonEvent", AbortCommonEvent),
        DECLARE_NAPI_FUNCTION("clearAbortCommonEvent", ClearAbortCommonEvent),
        DECLARE_NAPI_FUNCTION("getAbortCommonEvent", GetAbortCommonEvent),
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

napi_value CommonEventManagerInit(napi_env env, napi_value exports)
{
    EVENT_LOGI("enter");

    napi_property_descriptor desc[] = {
        
    };

    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));

    return exports;
}
}  // namespace EventManagerFwkNapi
}  // namespace OHOS
