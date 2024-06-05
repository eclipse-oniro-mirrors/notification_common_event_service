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
#include "ces_inner_error_code.h"
#include "event_log_wrapper.h"
#include "napi_common.h"
namespace OHOS {
namespace EventManagerFwkNapi {
using namespace OHOS::Notification;

static const std::unordered_map<int32_t, std::string> ErrorCodeToMsg {
    {ERR_NOTIFICATION_CES_COMMON_PERMISSION_DENIED,
        "Permission verification failed, usually the result returned by VerifyAccessToken."},
    {ERR_NOTIFICATION_CES_COMMON_NOT_SYSTEM_APP, "The application isn't system application."},
    {ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, "Parameter error."},
    {ERR_NOTIFICATION_CES_COMMON_SYSTEMCAP_NOT_SUPPORT, "Capability not supported."},
    {ERR_NOTIFICATION_CES_WANT_ACTION_IS_NULL, "The action field in the want parameter is null."},
    {ERR_NOTIFICATION_CES_SANDBOX_NOT_SUPPORT, "A sandbox application cannot send common events."},
    {ERR_NOTIFICATION_CES_EVENT_FREQ_TOO_HIGH, "Too many common events are sent in a short period of time."},
    {ERR_NOTIFICATION_CES_NOT_SA_SYSTEM_APP, "A third-party application cannot send system common events."},
    {ERR_NOTIFICATION_CES_NO_SUBSCRIBER, "The subscriber is not found."},
    {ERR_NOTIFICATION_CES_USERID_INVALID, "Invalid userId."},
    {ERR_NOTIFICATION_SEND_ERROR, "Failed to send the message."},
    {ERR_NOTIFICATION_CESM_ERROR, "Failed to read the data."},
    {ERR_NOTIFICATION_SYS_ERROR, "System error."}
};

static const int32_t STR_MAX_SIZE = 256;
static const int32_t STR_DATA_MAX_SIZE = 64 * 1024;  // 64KB
static const int32_t PUBLISH_MAX_PARA = 2;
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
static const int32_t PUBLISH_MAX_PARA_AS_USER = 3;
static const int32_t ARGS_DATA_TWO = 2;

void NapiThrow(napi_env env, int32_t errCode)
{
    EVENT_LOGD("enter");

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

void NapiThrow(napi_env env, int32_t errCode, std::string &msg)
{
    EVENT_LOGD("enter");

    napi_value code = nullptr;
    napi_create_int32(env, errCode, &code);
    
    auto iter = ErrorCodeToMsg.find(errCode);
    std::string errMsg = iter != ErrorCodeToMsg.end() ? iter->second : "";
    napi_value message = nullptr;
    napi_create_string_utf8(env, errMsg.append(" ").append(msg).c_str(), NAPI_AUTO_LENGTH, &message);

    napi_value error = nullptr;
    napi_create_error(env, nullptr, message, &error);
    napi_set_named_property(env, error, "code", code);
    napi_throw(env, error);
}

napi_value NapiGetNull(napi_env env)
{
    napi_value result = nullptr;
    napi_get_null(env, &result);

    return result;
}

napi_value GetCallbackErrorValue(napi_env env, int32_t errorCode)
{
    napi_value result = NapiGetNull(env);
    napi_value eCode = NapiGetNull(env);
    if (errorCode == ERR_OK) {
        return result;
    }
    NAPI_CALL(env, napi_create_int32(env, errorCode, &eCode));
    NAPI_CALL(env, napi_create_object(env, &result));
    NAPI_CALL(env, napi_set_named_property(env, result, "code", eCode));

    auto iter = ErrorCodeToMsg.find(errorCode);
    std::string errMsg = iter != ErrorCodeToMsg.end() ? iter->second : "";
    napi_value message = nullptr;
    napi_create_string_utf8(env, errMsg.c_str(), NAPI_AUTO_LENGTH, &message);
    napi_set_named_property(env, result, "message", message);
    return result;
}

napi_value ParseParametersByCreateSubscriber(
    const napi_env &env, const napi_value (&argv)[CREATE_MAX_PARA], const size_t &argc, napi_ref &callback)
{
    napi_valuetype valuetype;

    // argv[0]:CommonEventSubscribeInfo
    NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
    if (valuetype != napi_object) {
        EVENT_LOGE("Parameter type error. object expected.");
        std::string msg = "Incorrect parameter types.The type of param must be object.";
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
        return nullptr;
    }

    // argv[1]:callback
    if (argc >= CREATE_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[1], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Callback is not function. Execute promise.");
            return NapiGetNull(env);
        }
        napi_create_reference(env, argv[1], 1, &callback);
    }

    return NapiGetNull(env);
}

void PaddingAsyncCallbackInfoCreateSubscriber(const napi_env &env,
    AsyncCallbackInfoCreate *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGD("PaddingAsyncCallbackInfoCreateSubscriber excute");

    if (callback) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        napi_create_promise(env, &deferred, &promise);
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }
}

void PaddingCallbackPromiseInfo(const napi_env &env, const napi_ref &callback,
    CallbackPromiseInfo &callbackInfo, napi_value &promise)
{
    EVENT_LOGD("PaddingCallbackPromiseInfo start");

    if (callback) {
        callbackInfo.callback = callback;
        callbackInfo.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        napi_create_promise(env, &deferred, &promise);
        callbackInfo.deferred = deferred;
        callbackInfo.isCallback = false;
    }
}

napi_value ParseParametersByGetSubscribeInfo(
    const napi_env &env, const size_t &argc, const napi_value (&argv)[1], napi_ref &callback)
{
    napi_valuetype valuetype;

    // argv[0]:callback
    if (argc >= GETSUBSCREBEINFO_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Parameter type error. Function expected.");
            std::string msg = "Incorrect parameter types.The type of param must be function.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }

        napi_create_reference(env, argv[0], 1, &callback);
    }

    return NapiGetNull(env);
}

void PaddingAsyncCallbackInfoGetSubscribeInfo(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoSubscribeInfo *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGD("PaddingAsyncCallbackInfoGetSubscribeInfo excute");

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

napi_value ParseParametersByIsOrderedCommonEvent(
    const napi_env &env, const napi_value (&argv)[1], size_t argc, napi_ref &callback)
{
    napi_valuetype valuetype;

    // argv[0]:callback
    if (argc >= ISORDEREDCOMMONEVENT_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Wrong Parameter type. Function expected.");
            std::string msg = "Incorrect parameter types.The type of param must be function.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_create_reference(env, argv[0], 1, &callback);
    }

    return NapiGetNull(env);
}

void PaddingAsyncCallbackInfoIsOrderedCommonEvent(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoOrderedCommonEvent *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGD("PaddingAsyncCallbackInfoIsOrderedCommonEvent excute");

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

napi_value ParseParametersByIsStickyCommonEvent(
    const napi_env &env, const napi_value (&argv)[1], size_t argc, napi_ref &callback)
{
    napi_valuetype valuetype;

    // argv[0]:callback
    if (argc >= ISSTICKYCOMMONEVENT_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Parameter type error. Function expected.");
            std::string msg = "Incorrect parameter types.The type of param must be function.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_create_reference(env, argv[0], 1, &callback);
    }

    return NapiGetNull(env);
}

void PaddingAsyncCallbackInfoIsStickyCommonEvent(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoStickyCommonEvent *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGD("PaddingAsyncCallbackInfoIsStickyCommonEvent excute");

    if (argc >= ISSTICKYCOMMONEVENT_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }

    EVENT_LOGD("PaddingAsyncCallbackInfoIsStickyCommonEvent complete");
}

napi_value ParseParametersByGetCode(const napi_env &env, const napi_value (&argv)[1], size_t argc, napi_ref &callback)
{
    napi_valuetype valuetype;

    // argv[0]:callback
    if (argc >= GET_CODE_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Parameter type error. Function expected.");
            std::string msg = "Incorrect parameter types.The type of param must be function.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_create_reference(env, argv[0], 1, &callback);
    }

    return NapiGetNull(env);
}

void PaddingAsyncCallbackInfoGetCode(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoGetCode *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGD("PaddingAsyncCallbackInfoGetCode excute");

    if (argc >= GET_CODE_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }

    EVENT_LOGD("PaddingAsyncCallbackInfoGetCode complete");
}

napi_value ParseParametersBySetCode(
    const napi_env &env, const napi_value (&argv)[SET_CODE_MAX_PARA], size_t argc, int32_t &code, napi_ref &callback)
{
    napi_valuetype valuetype;

    // argv[0]:code
    NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
    if (valuetype != napi_number) {
        EVENT_LOGE("Parameter type error. Number expected.");
        std::string msg = "Incorrect parameter types.The type of param must be number.";
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_int32(env, argv[0], &code));

    // argv[1]:callback
    if (argc >= SET_CODE_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[1], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Parameter type is error. Function expected.");
            std::string msg = "Incorrect parameter types.The type of param must be function.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_create_reference(env, argv[1], 1, &callback);
    }
    return NapiGetNull(env);
}

void PaddingAsyncCallbackInfoSetCode(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoSetCode *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGD("PaddingAsyncCallbackInfoSetCode excute");

    if (argc >= SET_CODE_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }

    EVENT_LOGD("PaddingAsyncCallbackInfoSetCode complete");
}

void PaddingAsyncCallbackInfoSetData(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoSetData *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGD("PaddingAsyncCallbackInfoSetData excute");

    if (argc >= SET_DATA_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }

    EVENT_LOGD("PaddingAsyncCallbackInfoSetData complete");
}

void PaddingAsyncCallbackInfoSetCodeAndData(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoSetCodeAndData *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGD("PaddingAsyncCallbackInfoSetCodeAndData excute");

    if (argc >= SET_CODE_AND_DATA_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }

    EVENT_LOGD("PaddingAsyncCallbackInfoSetCodeAndData complete");
}

void PaddingNapiCreateAsyncWorkCallbackInfo(AsyncCallbackInfoSubscribeInfo *&asyncCallbackInfo)
{
    EVENT_LOGD("PaddingNapiCreateAsyncWorkCallbackInfo excute");

    asyncCallbackInfo->events = asyncCallbackInfo->subscriber->GetSubscribeInfo().GetMatchingSkills().GetEvents();
    asyncCallbackInfo->permission = asyncCallbackInfo->subscriber->GetSubscribeInfo().GetPermission();
    asyncCallbackInfo->deviceId = asyncCallbackInfo->subscriber->GetSubscribeInfo().GetDeviceId();
    asyncCallbackInfo->userId = asyncCallbackInfo->subscriber->GetSubscribeInfo().GetUserId();
    asyncCallbackInfo->priority = asyncCallbackInfo->subscriber->GetSubscribeInfo().GetPriority();
    asyncCallbackInfo->publisherBundleName = asyncCallbackInfo->subscriber->GetSubscribeInfo().GetPublisherBundleName();
}

napi_value ParseParametersByGetData(const napi_env &env, const napi_value (&argv)[1], size_t argc, napi_ref &callback)
{
    napi_valuetype valuetype;

    // argv[0]:callback
    if (argc >= GET_DATA_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Parameter type error. Function expected.");
            std::string msg = "Incorrect parameter types.The type of param must be function.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_create_reference(env, argv[0], 1, &callback);
    }

    return NapiGetNull(env);
}

void PaddingAsyncCallbackInfoGetData(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoGetData *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGD("PaddingAsyncCallbackInfoGetData excute");

    if (argc >= GET_DATA_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }

    EVENT_LOGD("PaddingAsyncCallbackInfoGetData complete");
}

napi_value ParseParametersBySetData(
    const napi_env &env, const napi_value (&argv)[SET_DATA_MAX_PARA], size_t argc,
    std::string &data, napi_ref &callback)
{
    napi_valuetype valuetype;
    size_t strLen = 0;
    char str[STR_DATA_MAX_SIZE] = {0};
    // argv[0]:data
    NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
    if (valuetype != napi_string) {
        EVENT_LOGE("Wrong argument type. String expected.");
        std::string msg = "Incorrect parameter types.The type of param must be string.";
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_string_utf8(env, argv[0], str, STR_DATA_MAX_SIZE, &strLen));

    if (strLen > STR_DATA_MAX_SIZE - 1) {
        EVENT_LOGE("data over size");
        std::string msg = "Parameter verification failed. cannot exceed ";
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID,
            msg.append(std::to_string(STR_DATA_MAX_SIZE - 1)).append(" characters"));
        return nullptr;
    }

    data = str;

    // argv[1]:callback
    if (argc >= SET_CODE_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[1], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Parameter type error. Function expected.");
            std::string msg = "Incorrect parameter types.The type of param must be function.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_create_reference(env, argv[1], 1, &callback);
    }
    return NapiGetNull(env);
}

napi_value ParseParametersBySetCodeAndData(
    const napi_env &env, const napi_value (&argv)[SET_CODE_AND_DATA_MAX_PARA],
    size_t argc, int32_t &code, std::string &data, napi_ref &callback)
{
    napi_valuetype valuetype;
    size_t strLen = 0;
    char str[STR_DATA_MAX_SIZE] = {0};

    // argv[0]:code
    NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
    if (valuetype != napi_number) {
        EVENT_LOGE("Parameter type error. Number expected.");
        std::string msg = "Incorrect parameter types.The type of param must be function.";
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_int32(env, argv[0], &code));

    // argv[1]:data
    NAPI_CALL(env, napi_typeof(env, argv[1], &valuetype));
    if (valuetype != napi_string) {
        EVENT_LOGE("Parameter type error. String expected.");
        std::string msg = "Incorrect parameter types.The type of param must be string.";
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_string_utf8(env, argv[1], str, STR_DATA_MAX_SIZE, &strLen));

    if (strLen > STR_DATA_MAX_SIZE - 1) {
        EVENT_LOGE("data exceed size");
        std::string msg = "Parameter verification failed. cannot exceed ";
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID,
            msg.append(std::to_string(STR_DATA_MAX_SIZE - 1)).append(" characters"));
        return nullptr;
    }

    data = str;

    // argv[2]:callback
    if (argc >= SET_CODE_AND_DATA_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[SET_CODE_AND_DATA_MAX_PARA - 1], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Parameter type error. Function expected.");
            std::string msg = "Incorrect parameter types.The type of param must be function.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_create_reference(env, argv[SET_CODE_AND_DATA_MAX_PARA - 1], 1, &callback);
    }
    return NapiGetNull(env);
}

napi_value ParseParametersByClearAbort(
    const napi_env &env, const napi_value (&argv)[1], size_t argc, napi_ref &callback)
{
    napi_valuetype valuetype;

    // argv[0]:callback
    if (argc >= CLEAR_ABORT_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Wrong argument type. Function expected.");
            std::string msg = "Incorrect parameter types.The type of param must be function.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_create_reference(env, argv[0], 1, &callback);
    }

    return NapiGetNull(env);
}

void PaddingAsyncCallbackInfoClearAbort(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoClearAbort *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGD("PaddingAsyncCallbackInfoClearAbort start");

    if (argc >= CLEAR_ABORT_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }

    EVENT_LOGD("PaddingAsyncCallbackInfoClearAbort end");
}

napi_value ParseParametersByAbort(const napi_env &env, const napi_value (&argv)[1], size_t argc, napi_ref &callback)
{
    napi_valuetype valuetype;

    // argv[0]:callback
    if (argc >= ABORT_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Function expected. Wrong argument type.");
            std::string msg = "Incorrect parameter types.The type of param must be function.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_create_reference(env, argv[0], 1, &callback);
    }

    return NapiGetNull(env);
}

void PaddingAsyncCallbackInfoAbort(const napi_env &env, const size_t &argc, AsyncCallbackInfoAbort *&asyncCallbackInfo,
    const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGD("PaddingAsyncCallbackInfoAbort excute");

    if (argc >= ABORT_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }

    EVENT_LOGD("PaddingAsyncCallbackInfoAbort complete");
}

napi_value ParseParametersByGetAbort(const napi_env &env, const napi_value (&argv)[1], size_t argc, napi_ref &callback)
{
    napi_valuetype valuetype;

    // argv[0]:callback
    if (argc >= GET_ABORT_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Parameter type error. Function expected.");
            std::string msg = "Incorrect parameter types.The type of param must be function.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_create_reference(env, argv[0], 1, &callback);
    }

    return NapiGetNull(env);
}

void PaddingAsyncCallbackInfoGetAbort(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoGetAbort *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGD("PaddingAsyncCallbackInfoGetAbort excute");

    if (argc >= GET_ABORT_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }

    EVENT_LOGD("PaddingAsyncCallbackInfoGetAbort complete");
}

napi_value ParseParametersByFinish(const napi_env &env, const napi_value (&argv)[1], size_t argc, napi_ref &callback)
{
    napi_valuetype valuetype;

    // argv[0]:callback
    if (argc >= FINISH_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Wrong parameter type. Function expected.");
            std::string msg = "Incorrect parameter types.The type of param must be function.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_create_reference(env, argv[0], 1, &callback);
    }

    return NapiGetNull(env);
}

void PaddingAsyncCallbackInfoFinish(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoFinish *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGD("PaddingAsyncCallbackInfoFinish excute");

    if (argc >= FINISH_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }

    EVENT_LOGD("PaddingAsyncCallbackInfoFinish complete");
}

napi_value ParseParametersBySubscribe(const napi_env &env, const napi_value (&argv)[SUBSCRIBE_MAX_PARA],
    std::shared_ptr<SubscriberInstance> &subscriber, napi_ref &callback)
{
    EVENT_LOGD("ParseParametersBySubscribe excute");

    napi_valuetype valuetype;
    // argv[0]:subscriber
    NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
    if (valuetype != napi_object) {
        EVENT_LOGE("Subscribe expected. Wrong argument type for arg0.");
        std::string msg = "Incorrect parameter types.The type of param must be object.";
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
        return nullptr;
    }
    subscriber = GetSubscriber(env, argv[0]);
    if (subscriber == nullptr) {
        EVENT_LOGE("subscriber is null");
        std::string msg = "Mandatory parameters are left unspecified.";
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
        return nullptr;
    }

    // argv[1]:callback
    NAPI_CALL(env, napi_typeof(env, argv[1], &valuetype));
    if (valuetype != napi_function) {
        EVENT_LOGE("Parameter type error. Function expected.");
        std::string msg = "Incorrect parameter types.The type of param must be function.";
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
        return nullptr;
    }
    napi_create_reference(env, argv[1], 1, &callback);

    return NapiGetNull(env);
}

napi_value GetBundlenameByPublish(const napi_env &env, const napi_value &value, std::string &bundleName)
{
    EVENT_LOGD("GetBundlenameByPublish excute");

    napi_valuetype valuetype;
    napi_value result = nullptr;
    char str[STR_MAX_SIZE] = {0};
    bool hasProperty = false;
    size_t strLen = 0;

    NAPI_CALL(env, napi_has_named_property(env, value, "bundleName", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "bundleName", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_string) {
            EVENT_LOGE("Parameter type error. String expected.");
            std::string msg = "Incorrect parameter types.The type of param must be string.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }
        NAPI_CALL(env, napi_get_value_string_utf8(env, result, str, STR_MAX_SIZE - 1, &strLen));
        bundleName = str;
    }

    return NapiGetNull(env);
}

napi_value GetDataByPublish(const napi_env &env, const napi_value &value, std::string &data)
{
    EVENT_LOGD("GetDataByPublish excute");

    napi_valuetype valuetype;
    napi_value result = nullptr;
    char str[STR_DATA_MAX_SIZE] = {0};
    bool hasProperty = false;
    size_t strLen = 0;

    NAPI_CALL(env, napi_has_named_property(env, value, "data", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "data", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_string) {
            EVENT_LOGE("Parameter type error. String expected.");
            std::string msg = "Incorrect parameter types.The type of param must be string.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }
        NAPI_CALL(env, napi_get_value_string_utf8(env, result, str, STR_DATA_MAX_SIZE, &strLen));

        if (strLen > STR_DATA_MAX_SIZE - 1) {
            EVENT_LOGE("data exceed size");
            std::string msg = "Parameter verification failed. cannot exceed ";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID,
                msg.append(std::to_string(STR_DATA_MAX_SIZE - 1)).append(" characters"));
            return nullptr;
        }

        data = str;
    }

    return NapiGetNull(env);
}

napi_value GetCodeByPublish(const napi_env &env, const napi_value &value, int32_t &code)
{
    EVENT_LOGD("GetCodeByPublish excute");

    napi_valuetype valuetype;
    napi_value result = nullptr;
    bool hasProperty = false;

    NAPI_CALL(env, napi_has_named_property(env, value, "code", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "code", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_number) {
            EVENT_LOGE("Parameter type error. Number expected.");
            std::string msg = "Incorrect parameter types.The type of param must be number.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_int32(env, result, &code);
    }

    return NapiGetNull(env);
}

napi_value GetSubscriberPermissionsByPublish(
    const napi_env &env, const napi_value &value, std::vector<std::string> &subscriberPermissions)
{
    EVENT_LOGD("GetSubscriberPermissionsByPublish excute");

    napi_valuetype valuetype;
    napi_value result = nullptr;
    bool isArray = false;
    size_t strLen = 0;
    bool hasProperty = false;
    char str[STR_MAX_SIZE] = {0};

    NAPI_CALL(env, napi_has_named_property(env, value, "subscriberPermissions", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "subscriberPermissions", &result);
        napi_is_array(env, result, &isArray);
        if (isArray) {
            uint32_t length = 0;
            napi_get_array_length(env, result, &length);
            if (length > 0) {
                for (uint32_t i = 0; i < length; ++i) {
                    napi_value nSubscriberPermission = nullptr;
                    napi_get_element(env, result, i, &nSubscriberPermission);
                    NAPI_CALL(env, napi_typeof(env, nSubscriberPermission, &valuetype));
                    if (valuetype != napi_string) {
                        EVENT_LOGE("Parameter type error. String expected.");
                        std::string msg = "Incorrect parameter types.The type of param must be string.";
                        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
                        return nullptr;
                    }
                    if (memset_s(str, STR_MAX_SIZE, 0, STR_MAX_SIZE) != 0) {
                        EVENT_LOGE("memset_s failed");
                        std::string msg = "Parameter verification failed.";
                        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
                        return nullptr;
                    }
                    NAPI_CALL(
                        env, napi_get_value_string_utf8(env, nSubscriberPermission, str, STR_MAX_SIZE - 1, &strLen));
                    subscriberPermissions.emplace_back(str);
                }
            }
        }
    }

    return NapiGetNull(env);
}

napi_value GetIsOrderedByPublish(const napi_env &env, const napi_value &value, bool &isOrdered)
{
    EVENT_LOGD("GetIsOrderedByPublish excute");

    napi_valuetype valuetype;
    napi_value result = nullptr;
    bool hasProperty = false;

    NAPI_CALL(env, napi_has_named_property(env, value, "isOrdered", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "isOrdered", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_boolean) {
            EVENT_LOGE("Parameter type error. Boolean expected.");
            std::string msg = "Incorrect parameter types.The type of param must be boolean.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_bool(env, result, &isOrdered);
    }

    return NapiGetNull(env);
}

napi_value GetIsStickyByPublish(const napi_env &env, const napi_value &value, bool &isSticky)
{
    EVENT_LOGD("GetIsStickyByPublish excute");

    napi_valuetype valuetype;
    napi_value result = nullptr;
    bool hasProperty = false;

    NAPI_CALL(env, napi_has_named_property(env, value, "isSticky", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "isSticky", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_boolean) {
            EVENT_LOGE("Parameter type error. Boolean expected.");
            std::string msg = "Incorrect parameter types.The type of param must be boolean.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_bool(env, result, &isSticky);
    }

    return NapiGetNull(env);
}

napi_value GetParametersByPublish(const napi_env &env, const napi_value &value, AAFwk::WantParams &wantParams)
{
    EVENT_LOGD("GetParametersByPublish excute");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;

    NAPI_CALL(env, napi_has_named_property(env, value, "parameters", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "parameters", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_object) {
            EVENT_LOGE("Parameter type error. Object expected.");
            std::string msg = "Incorrect parameter types.The type of param must be object.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }
        if (!OHOS::AppExecFwk::UnwrapWantParams(env, result, wantParams)) {
            std::string msg = "Parameter verification failed.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }
    }

    return NapiGetNull(env);
}

napi_value ParseParametersByPublish(const napi_env &env, const napi_value (&argv)[PUBLISH_MAX_PARA_BY_PUBLISHDATA],
    const size_t &argc, std::string &event, CommonEventPublishDataByjs &commonEventPublishData, napi_ref &callback)
{
    EVENT_LOGD("ParseParametersByPublish excute");

    napi_valuetype valuetype;
    // argv[0]: event
    NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
    if (valuetype != napi_string) {
        EVENT_LOGE("Parameter type error. String expected.");
        std::string msg = "Incorrect parameter types.The type of param must be string.";
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
        return nullptr;
    }

    char str[STR_MAX_SIZE] = {0};
    size_t strLen = 0;
    napi_get_value_string_utf8(env, argv[0], str, STR_MAX_SIZE - 1, &strLen);
    event = str;
    EVENT_LOGD("ParseParametersByPublish event: %{public}s", str);

    if (argc == PUBLISH_MAX_PARA_BY_PUBLISHDATA) {
        // argv[1]: CommonEventPublishData
        NAPI_CALL(env, napi_typeof(env, argv[1], &valuetype));
        if (valuetype != napi_object) {
            EVENT_LOGE("Wrong argument type. Object expected.");
            std::string msg = "Incorrect parameter types.The type of param must be object.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }

        // argv[1]: CommonEventPublishData:bundlename
        if (GetBundlenameByPublish(env, argv[1], commonEventPublishData.bundleName) == nullptr) {
            return nullptr;
        }
        // argv[1]: CommonEventPublishData:data
        if (GetDataByPublish(env, argv[1], commonEventPublishData.data) == nullptr) {
            return nullptr;
        }
        // argv[1]: CommonEventPublishData:code
        if (GetCodeByPublish(env, argv[1], commonEventPublishData.code) == nullptr) {
            return nullptr;
        }
        // argv[1]: CommonEventPublishData:permissions
        if (GetSubscriberPermissionsByPublish(env, argv[1], commonEventPublishData.subscriberPermissions) == nullptr) {
            return nullptr;
        }
        // argv[1]: CommonEventPublishData:isOrdered
        if (GetIsOrderedByPublish(env, argv[1], commonEventPublishData.isOrdered) == nullptr) {
            return nullptr;
        }
        // argv[1]: CommonEventPublishData:isSticky
        if (GetIsStickyByPublish(env, argv[1], commonEventPublishData.isSticky) == nullptr) {
            return nullptr;
        }
        // argv[1]: CommonEventPublishData:parameters
        if (GetParametersByPublish(env, argv[1], commonEventPublishData.wantParams) == nullptr) {
            return nullptr;
        }

        // argv[2]: callback
        NAPI_CALL(env, napi_typeof(env, argv[PUBLISH_MAX_PARA], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Wrong argument type. Function expected.");
            std::string msg = "Incorrect parameter types.The type of param must be function.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_create_reference(env, argv[PUBLISH_MAX_PARA], 1, &callback);
    } else {
        NAPI_CALL(env, napi_typeof(env, argv[1], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Wrong argument type. Function expected.");
            std::string msg = "Incorrect parameter types.The type of param must be function.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_create_reference(env, argv[1], 1, &callback);
    }

    return NapiGetNull(env);
}

void PaddingCallbackInfoPublish(Want &want, AsyncCallbackInfoPublish *&asyncCallbackInfo,
    const CommonEventPublishDataByjs &commonEventPublishDatajs)
{
    EVENT_LOGD("NapiPaddingCallbackInfoPublish start");
    want.SetParams(commonEventPublishDatajs.wantParams);
    asyncCallbackInfo->commonEventData.SetCode(commonEventPublishDatajs.code);
    asyncCallbackInfo->commonEventData.SetData(commonEventPublishDatajs.data);
    asyncCallbackInfo->commonEventPublishInfo.SetSubscriberPermissions(commonEventPublishDatajs.subscriberPermissions);
    asyncCallbackInfo->commonEventPublishInfo.SetOrdered(commonEventPublishDatajs.isOrdered);
    asyncCallbackInfo->commonEventPublishInfo.SetSticky(commonEventPublishDatajs.isSticky);
    asyncCallbackInfo->commonEventPublishInfo.SetBundleName(commonEventPublishDatajs.bundleName);
}

napi_value ParseParametersByPublishAsUser(const napi_env &env, const napi_value (&argv)[PUBLISH_MAX_PARA_BY_USERID],
    const size_t &argc, std::string &event, int32_t &userId, CommonEventPublishDataByjs &commonEventPublishData,
    napi_ref &callback)
{
    EVENT_LOGD("ParseParametersByPublishAsUser start");

    napi_valuetype valuetype;
    // argv[0]: event
    NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
    if (valuetype != napi_string) {
        EVENT_LOGE("Wrong Parameter type. String expected.");
        std::string msg = "Incorrect parameter types.The type of param must be string.";
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
        return nullptr;
    }

    char str[STR_MAX_SIZE] = {0};
    size_t strLen = 0;
    napi_get_value_string_utf8(env, argv[0], str, STR_MAX_SIZE - 1, &strLen);
    event = str;
    EVENT_LOGD("ParseParametersByPublishAsUser event = %{public}s", str);

    // argv[1]: userId
    NAPI_CALL(env, napi_typeof(env, argv[1], &valuetype));
    if (valuetype != napi_number) {
        EVENT_LOGE("Wrong Parameter type. Number expected.");
        std::string msg = "Incorrect parameter types.The type of param must be number.";
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
        return nullptr;
    }
    napi_get_value_int32(env, argv[1], &userId);
    EVENT_LOGD("ParseParametersByPublishAsUser userId = %{public}d", userId);

    if (argc == PUBLISH_MAX_PARA_BY_USERID) {
        // argv[2]: CommonEventPublishData
        NAPI_CALL(env, napi_typeof(env, argv[ARGS_DATA_TWO], &valuetype));
        if (valuetype != napi_object) {
            EVENT_LOGE("Wrong argument type. Object expected.");
            std::string msg = "Incorrect parameter types.The type of param must be object.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }

        // argv[2]: CommonEventPublishData:bundlename
        if (GetBundlenameByPublish(env, argv[ARGS_DATA_TWO], commonEventPublishData.bundleName) == nullptr) {
            return nullptr;
        }
        // argv[2]: CommonEventPublishData:data
        if (GetDataByPublish(env, argv[ARGS_DATA_TWO], commonEventPublishData.data) == nullptr) {
            return nullptr;
        }
        // argv[2]: CommonEventPublishData:code
        if (GetCodeByPublish(env, argv[ARGS_DATA_TWO], commonEventPublishData.code) == nullptr) {
            return nullptr;
        }
        // argv[2]: CommonEventPublishData:permissions
        if (GetSubscriberPermissionsByPublish(env, argv[ARGS_DATA_TWO],
            commonEventPublishData.subscriberPermissions) == nullptr) {
            return nullptr;
        }
        // argv[2]: CommonEventPublishData:isOrdered
        if (GetIsOrderedByPublish(env, argv[ARGS_DATA_TWO], commonEventPublishData.isOrdered) == nullptr) {
            return nullptr;
        }
        // argv[2]: CommonEventPublishData:isSticky
        if (GetIsStickyByPublish(env, argv[ARGS_DATA_TWO], commonEventPublishData.isSticky) == nullptr) {
            return nullptr;
        }
        // argv[2]: CommonEventPublishData:parameters
        if (GetParametersByPublish(env, argv[ARGS_DATA_TWO], commonEventPublishData.wantParams) == nullptr) {
            return nullptr;
        }

        // argv[3]: callback
        NAPI_CALL(env, napi_typeof(env, argv[PUBLISH_MAX_PARA_AS_USER], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Wrong argument type. Function expected.");
            std::string msg = "Incorrect parameter types.The type of param must be function.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_create_reference(env, argv[PUBLISH_MAX_PARA_AS_USER], 1, &callback);
    } else {
        NAPI_CALL(env, napi_typeof(env, argv[ARGS_DATA_TWO], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Wrong argument type. Function expected.");
            std::string msg = "Incorrect parameter types.The type of param must be function.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_create_reference(env, argv[ARGS_DATA_TWO], 1, &callback);
    }

    return NapiGetNull(env);
}

napi_value ParseParametersByUnsubscribe(const napi_env &env, const size_t &argc,
    const napi_value (&argv)[UNSUBSCRIBE_MAX_PARA], std::shared_ptr<SubscriberInstance> &subscriber, napi_ref &callback)
{
    EVENT_LOGD("ParseParametersByUnsubscribe excute");

    napi_valuetype valuetype;
    napi_value result = nullptr;
    // argv[0]:subscriber
    NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
    if (valuetype != napi_object) {
        EVENT_LOGE("Parameter type error for arg0. Subscribe expected.");
        std::string msg = "Incorrect parameter types.The type of param must be subscribe.";
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
        return nullptr;
    }

    bool isFind = false;
    if (GetSubscriberByUnsubscribe(env, argv[0], subscriber, isFind) == nullptr) {
        return nullptr;
    }

    // argv[1]:callback
    if (argc >= UNSUBSCRIBE_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[1], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Parameter type error. Function expected.");
            std::string msg = "Incorrect parameter types.The type of param must be function.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_create_reference(env, argv[1], 1, &callback);
    }

    napi_get_boolean(env, isFind, &result);

    return result;
}

napi_value ParseParametersByRemoveSticky(const napi_env &env,
    const napi_callback_info &info, std::string &event, CallbackPromiseInfo &params)
{
    EVENT_LOGD("ParseParametersByRemoveSticky start");

    size_t argc = REMOVE_STICKY_MAX_PARA;
    napi_value argv[REMOVE_STICKY_MAX_PARA] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < REMOVE_STICKY_MAX_PARA - 1) {
        EVENT_LOGE("Wrong number of arguments.");
        std::string msg = "Incorrect parameter types.The type of param must be number.";
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
        return nullptr;
    }

    // argv[0]: event
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_string && valuetype != napi_number && valuetype != napi_boolean) {
        EVENT_LOGE("Wrong argument type. String expected.");
        std::string msg = "Incorrect parameter types.The type of param must be string.";
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
        return nullptr;
    }
    if (valuetype == napi_string) {
        size_t strLen = 0;
        char str[STR_MAX_SIZE] = {0};
        NAPI_CALL(env, napi_get_value_string_utf8(env, argv[PARAM0], str, STR_MAX_SIZE - 1, &strLen));
        event = str;
    } else if (valuetype == napi_number) {
        int64_t number = 0;
        NAPI_CALL(env, napi_get_value_int64(env, argv[PARAM0], &number));
        event = std::to_string(number);
    } else {
        bool result = false;
        NAPI_CALL(env, napi_get_value_bool(env, argv[PARAM0], &result));
        event = std::to_string(result);
    }

    // argv[1]:callback
    if (argc >= REMOVE_STICKY_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Callback is not function excute promise.");
            return NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM1], 1, &params.callback);
    }

    return NapiGetNull(env);
}

napi_value GetEventsByCreateSubscriber(const napi_env &env, const napi_value &argv, std::vector<std::string> &events)
{
    EVENT_LOGD("GetEventsByCreateSubscriber start");
    napi_valuetype valuetype;
    bool hasProperty = false;
    bool isArray = false;
    napi_value eventsNapi = nullptr;
    size_t strLen = 0;
    uint32_t length = 0;
    // get events
    NAPI_CALL(env, napi_has_named_property(env, argv, "events", &hasProperty));
    if (!hasProperty) {
        EVENT_LOGE("Property events expected");
        std::string msg = "Incorrect parameter types.The type of param must be events.";
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
        return nullptr;
    }
    napi_get_named_property(env, argv, "events", &eventsNapi);
    napi_is_array(env, eventsNapi, &isArray);
    if (!isArray) {
        EVENT_LOGE("Parameter type error . Array expected.");
        std::string msg = "Incorrect parameter types.The type of param must be array.";
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
        return nullptr;
    }
    napi_get_array_length(env, eventsNapi, &length);
    if (length == 0) {
        EVENT_LOGE("The array is empty.");
        std::string msg = "Parameter verification failed.The array is empty.";
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
        return nullptr;
    }
    for (size_t i = 0; i < length; i++) {
        napi_value event = nullptr;
        napi_get_element(env, eventsNapi, i, &event);
        NAPI_CALL(env, napi_typeof(env, event, &valuetype));
        if (valuetype != napi_string) {
            EVENT_LOGE("Wrong argument type. String expected.");
            std::string msg = "Incorrect parameter types.The type of param must be string.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }
        char str[STR_MAX_SIZE] = {0};
        NAPI_CALL(env, napi_get_value_string_utf8(env, event, str, STR_MAX_SIZE - 1, &strLen));
        EVENT_LOGD("event = %{public}s", str);
        events.emplace_back(str);
    }

    return NapiGetNull(env);
}

napi_value GetPublisherPermissionByCreateSubscriber(
    const napi_env &env, const napi_value &argv, CommonEventSubscribeInfo &info)
{
    EVENT_LOGD("enter");

    bool hasProperty = false;
    napi_value result = nullptr;
    napi_valuetype valuetype = napi_undefined;
    size_t strLen = 0;
    char str[STR_MAX_SIZE] = {0};

    // publisherPermission
    NAPI_CALL(env, napi_has_named_property(env, argv, "publisherPermission", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, argv, "publisherPermission", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_string) {
            EVENT_LOGE("Wrong argument type. String expected.");
            std::string msg = "Incorrect parameter types.The type of param must be string.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }
        NAPI_CALL(env, napi_get_value_string_utf8(env, result, str, STR_MAX_SIZE - 1, &strLen));
        info.SetPermission(str);
    }

    return NapiGetNull(env);
}

napi_value GetPublisherDeviceIdByCreateSubscriber(
    const napi_env &env, const napi_value &argv, CommonEventSubscribeInfo &info)
{
    EVENT_LOGD("enter");

    bool hasProperty = false;
    napi_value result = nullptr;
    napi_valuetype valuetype = napi_undefined;
    size_t strLen = 0;
    char str[STR_MAX_SIZE] = {0};

    // publisherDeviceId
    NAPI_CALL(env, napi_has_named_property(env, argv, "publisherDeviceId", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, argv, "publisherDeviceId", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_string) {
            EVENT_LOGE("Wrong argument type. String expected.");
            std::string msg = "Incorrect parameter types.The type of param must be string.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }
        NAPI_CALL(env, napi_get_value_string_utf8(env, result, str, STR_MAX_SIZE - 1, &strLen));
        info.SetDeviceId(str);
    }

    return NapiGetNull(env);
}

napi_value GetUserIdByCreateSubscriber(const napi_env &env, const napi_value &argv, CommonEventSubscribeInfo &info)
{
    EVENT_LOGD("enter");

    bool hasUserId = false;
    napi_value result = nullptr;
    napi_valuetype valuetype = napi_undefined;
    int32_t value = 0;

    // userId
    NAPI_CALL(env, napi_has_named_property(env, argv, "userId", &hasUserId));
    if (hasUserId) {
        napi_get_named_property(env, argv, "userId", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_number) {
            EVENT_LOGE("Wrong argument type. Number expected.");
            std::string msg = "Incorrect parameter types.The type of param must be number.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }
        NAPI_CALL(env, napi_get_value_int32(env, result, &value));
        info.SetUserId(value);
    }

    return NapiGetNull(env);
}

napi_value GetPriorityByCreateSubscriber(const napi_env &env, const napi_value &argv, CommonEventSubscribeInfo &info)
{
    EVENT_LOGD("enter");

    bool hasProperty = false;
    napi_value result = nullptr;
    napi_valuetype valuetype = napi_undefined;
    int32_t value = 0;

    // priority
    NAPI_CALL(env, napi_has_named_property(env, argv, "priority", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, argv, "priority", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_number) {
            EVENT_LOGE("Wrong argument type. Number expected.");
            std::string msg = "Incorrect parameter types.The type of param must be number.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }
        NAPI_CALL(env, napi_get_value_int32(env, result, &value));
        info.SetPriority(value);
    }

    return NapiGetNull(env);
}

napi_value GetPublisherBundleNameByCreateSubscriber(
    const napi_env &env, const napi_value &argv, CommonEventSubscribeInfo &info)
{
    EVENT_LOGD("Called.");
    bool hasPublisherBundleName = false;
    napi_value result = nullptr;
    napi_valuetype valuetype = napi_undefined;
    size_t strLen = 0;
    char str[STR_MAX_SIZE] = {0};

    // publisherBundleName
    NAPI_CALL(env, napi_has_named_property(env, argv, "publisherBundleName", &hasPublisherBundleName));
    if (hasPublisherBundleName) {
        napi_get_named_property(env, argv, "publisherBundleName", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_string) {
            EVENT_LOGE("Wrong argument type. String expected.");
            std::string msg = "Incorrect parameter types.The type of param must be string.";
            NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
            return nullptr;
        }
        NAPI_CALL(env, napi_get_value_string_utf8(env, result, str, STR_MAX_SIZE - 1, &strLen));
        info.SetPublisherBundleName(str);
    }

    return NapiGetNull(env);
}

napi_value ParseParametersConstructor(
    const napi_env &env, const napi_callback_info &info, napi_value &thisVar, CommonEventSubscribeInfo &params)
{
    EVENT_LOGD("enter");
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    if (argc < 1) {
        EVENT_LOGE("Wrong number of arguments");
        std::string msg = "Incorrect parameter types.The type of param must be number.";
        NapiThrow(env, ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, msg);
        return nullptr;
    }

    // events: Array<string>
    std::vector<std::string> events;
    if (!GetEventsByCreateSubscriber(env, argv[0], events)) {
        return nullptr;
    }
    MatchingSkills matchingSkills;
    for (const auto &event : events) {
        matchingSkills.AddEvent(event);
    }
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    // publisherPermission?: string
    if (!GetPublisherPermissionByCreateSubscriber(env, argv[0], subscribeInfo)) {
        return nullptr;
    }

    // publisherDeviceId?: string
    if (!GetPublisherDeviceIdByCreateSubscriber(env, argv[0], subscribeInfo)) {
        return nullptr;
    }

    // userId?: number
    if (!GetUserIdByCreateSubscriber(env, argv[0], subscribeInfo)) {
        return nullptr;
    }

    // priority?: number
    if (!GetPriorityByCreateSubscriber(env, argv[0], subscribeInfo)) {
        return nullptr;
    }

    // publisherBundleName?: string
    if (!GetPublisherBundleNameByCreateSubscriber(env, argv[0], subscribeInfo)) {
        return nullptr;
    }

    params = subscribeInfo;
    return NapiGetNull(env);
}

}
}
