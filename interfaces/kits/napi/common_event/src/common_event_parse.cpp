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

static const int32_t STR_MAX_SIZE = 256;
static const int32_t STR_DATA_MAX_SIZE = 64 * 1024;  // 64KB
static const int32_t PUBLISH_MAX_PARA = 2;
static const int32_t PUBLISH_MAX_PARA_AS_USER = 3;
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
static const int32_t SUBSCRIBE_EVENT_MAX_NUM = 512;
static const int32_t COMMON_EVENT_PUBLISH_PARAM = 2;

napi_value NapiGetNull(napi_env env)
{
    EVENT_LOGD("enter");
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

napi_value ParseParametersByCreateSubscriber(
    const napi_env &env, const napi_value (&argv)[CREATE_MAX_PARA], const size_t &argc, napi_ref &callback)
{
    napi_valuetype valuetype;

    // argv[0]:CommonEventSubscribeInfo
    NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
    if (valuetype != napi_object) {
        EVENT_LOGE("Wrong argument type. object expected.");
        return nullptr;
    }

    // argv[1]:callback
    if (argc >= CREATE_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[1], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Callback does not work. Execute promise.");
            return NapiGetNull(env);
        }
        napi_create_reference(env, argv[1], 1, &callback);
    }

    return NapiGetNull(env);
}

void PaddingAsyncCallbackInfoCreateSubscriber(const napi_env &env,
    AsyncCallbackInfoCreate *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGD("PaddingAsyncCallbackInfoCreateSubscriber start");

    if (callback) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        EVENT_LOGD("callback is nullptr.");
        napi_deferred deferred = nullptr;
        napi_create_promise(env, &deferred, &promise);
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }
}

void PaddingAsyncCallbackInfoGetSubscribeInfo(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoSubscribeInfo *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGD("PaddingAsyncCallbackInfoGetSubscribeInfo start");

    if (argc >= GETSUBSCREBEINFO_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        EVENT_LOGD("argc less than GETSUBSCREBEINFO_MAX_PARA.");
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
            EVENT_LOGE("Wrong argument type. Function expected.");
            return nullptr;
        }
        napi_create_reference(env, argv[0], 1, &callback);
    }

    return NapiGetNull(env);
}

void PaddingAsyncCallbackInfoIsOrderedCommonEvent(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoOrderedCommonEvent *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGD("PaddingAsyncCallbackInfoIsOrderedCommonEvent start");

    if (argc >= ISORDEREDCOMMONEVENT_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        EVENT_LOGD("argc less than ISORDEREDCOMMONEVENT_MAX_PARA");
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
            EVENT_LOGE("Wrong argument type. Function expected.");
            return nullptr;
        }
        napi_create_reference(env, argv[0], 1, &callback);
    }

    return NapiGetNull(env);
}

void PaddingAsyncCallbackInfoIsStickyCommonEvent(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoStickyCommonEvent *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGD("PaddingAsyncCallbackInfoIsStickyCommonEvent start");

    if (argc >= ISSTICKYCOMMONEVENT_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }

    EVENT_LOGD("PaddingAsyncCallbackInfoIsStickyCommonEvent end");
}

napi_value ParseParametersByGetCode(const napi_env &env, const napi_value (&argv)[1], size_t argc, napi_ref &callback)
{
    napi_valuetype valuetype;

    // argv[0]:callback
    if (argc >= GET_CODE_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Wrong argument type. Function expected.");
            return nullptr;
        }
        napi_create_reference(env, argv[0], 1, &callback);
    }

    return NapiGetNull(env);
}

void PaddingAsyncCallbackInfoGetCode(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoGetCode *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGD("PaddingAsyncCallbackInfoGetCode start");

    if (argc >= GET_CODE_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }

    EVENT_LOGD("PaddingAsyncCallbackInfoGetCode end");
}

napi_value ParseParametersBySetCode(
    const napi_env &env, const napi_value (&argv)[SET_CODE_MAX_PARA], size_t argc, int32_t &code, napi_ref &callback)
{
    napi_valuetype valuetype;

    // argv[0]:code
    NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
    if (valuetype != napi_number) {
        EVENT_LOGE("Wrong argument type. Number expected.");
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_int32(env, argv[0], &code));

    // argv[1]:callback
    if (argc >= SET_CODE_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[1], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Wrong Parameter type. Function expected.");
            return nullptr;
        }
        napi_create_reference(env, argv[1], 1, &callback);
    }
    return NapiGetNull(env);
}

void PaddingAsyncCallbackInfoSetCode(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoSetCode *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGD("PaddingAsyncCallbackInfoSetCode start");

    if (argc >= SET_CODE_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }

    EVENT_LOGD("PaddingAsyncCallbackInfoSetCode end");
}

napi_value ParseParametersBySetData(
    const napi_env &env, const napi_value (&argv)[SET_DATA_MAX_PARA], size_t argc,
    std::string &data, napi_ref &callback)
{
    size_t strLen = 0;
    napi_valuetype valuetype;
    char str[STR_DATA_MAX_SIZE] = {0};
    // argv[0]:data
    NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
    if (valuetype != napi_string) {
        EVENT_LOGE("Argument type is error. String expected.");
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_string_utf8(env, argv[0], str, STR_DATA_MAX_SIZE, &strLen));

    if (strLen > STR_DATA_MAX_SIZE - 1) {
        EVENT_LOGE("data exceed size");
        return nullptr;
    }

    data = str;

    // argv[1]:callback
    if (argc >= SET_CODE_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[1], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Wrong argument type. Function expected.");
            return nullptr;
        }
        napi_create_reference(env, argv[1], 1, &callback);
    }
    return NapiGetNull(env);
}

void PaddingAsyncCallbackInfoSetData(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoSetData *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGD("PaddingAsyncCallbackInfoSetData start");

    if (argc >= SET_DATA_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }

    EVENT_LOGD("PaddingAsyncCallbackInfoSetData end");
}

napi_value ParseParametersBySetCodeAndData(
    const napi_env &env, const napi_value (&argv)[SET_CODE_AND_DATA_MAX_PARA],
    size_t argc, int32_t &code, std::string &data, napi_ref &callback)
{
    EVENT_LOGD("enter");
    napi_valuetype valuetype;
    size_t strLen = 0;
    char str[STR_DATA_MAX_SIZE] = {0};

    // argv[0]:code
    NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
    if (valuetype != napi_number) {
        EVENT_LOGE("Wrong argument type. Number expected.");
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_int32(env, argv[0], &code));

    // argv[1]:data
    NAPI_CALL(env, napi_typeof(env, argv[1], &valuetype));
    if (valuetype != napi_string) {
        EVENT_LOGE("Wrong argument type. String expected.");
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_string_utf8(env, argv[1], str, STR_DATA_MAX_SIZE, &strLen));

    if (strLen > STR_DATA_MAX_SIZE - 1) {
        EVENT_LOGE("data over size");
        return nullptr;
    }

    data = str;

    // argv[2]:callback
    if (argc >= SET_CODE_AND_DATA_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[SET_CODE_AND_DATA_MAX_PARA - 1], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Wrong argument type. Function expected.");
            return nullptr;
        }
        napi_create_reference(env, argv[SET_CODE_AND_DATA_MAX_PARA - 1], 1, &callback);
    }
    return NapiGetNull(env);
}

void PaddingAsyncCallbackInfoSetCodeAndData(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoSetCodeAndData *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGD("PaddingAsyncCallbackInfoSetCodeAndData start");

    if (argc >= SET_CODE_AND_DATA_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }

    EVENT_LOGD("PaddingAsyncCallbackInfoSetCodeAndData end");
}

void PaddingNapiCreateAsyncWorkCallbackInfo(AsyncCallbackInfoSubscribeInfo *&asyncCallbackInfo)
{
    EVENT_LOGD("PaddingNapiCreateAsyncWorkCallbackInfo start");

    asyncCallbackInfo->events = asyncCallbackInfo->subscriber->GetSubscribeInfo().GetMatchingSkills().GetEvents();
    asyncCallbackInfo->permission = asyncCallbackInfo->subscriber->GetSubscribeInfo().GetPermission();
    asyncCallbackInfo->deviceId = asyncCallbackInfo->subscriber->GetSubscribeInfo().GetDeviceId();
    asyncCallbackInfo->userId = asyncCallbackInfo->subscriber->GetSubscribeInfo().GetUserId();
    asyncCallbackInfo->priority = asyncCallbackInfo->subscriber->GetSubscribeInfo().GetPriority();
}

napi_value ParseParametersByGetData(const napi_env &env, const napi_value (&argv)[1], size_t argc, napi_ref &callback)
{
    napi_valuetype valuetype;

    // argv[0]:callback
    if (argc >= GET_DATA_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Wrong argument type. Function expected.");
            return nullptr;
        }
        napi_create_reference(env, argv[0], 1, &callback);
    }

    return NapiGetNull(env);
}

void PaddingAsyncCallbackInfoGetData(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoGetData *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGD("PaddingAsyncCallbackInfoGetData start");

    if (argc >= GET_DATA_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }

    EVENT_LOGD("PaddingAsyncCallbackInfoGetData end");
}

napi_value ParseParametersByClearAbort(
    const napi_env &env, const napi_value (&argv)[1], size_t argc, napi_ref &callback)
{
    napi_valuetype valuetype;

    // argv[0]:callback
    if (argc >= CLEAR_ABORT_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Argument type is error. Function expected.");
            return nullptr;
        }
        napi_create_reference(env, argv[0], 1, &callback);
    }

    return NapiGetNull(env);
}

void PaddingAsyncCallbackInfoClearAbort(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoClearAbort *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGD("enter");

    if (argc >= CLEAR_ABORT_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }

    EVENT_LOGD("Padding async callback info clear abort end");
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
    EVENT_LOGD("PaddingAsyncCallbackInfoAbort start");

    if (argc >= ABORT_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }

    EVENT_LOGD("PaddingAsyncCallbackInfoAbort end");
}

napi_value ParseParametersByGetAbort(const napi_env &env, const napi_value (&argv)[1], size_t argc, napi_ref &callback)
{
    napi_valuetype valuetype;

    // argv[0]:callback
    if (argc >= GET_ABORT_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Wrong argument type. Function expected.");
            return nullptr;
        }
        napi_create_reference(env, argv[0], 1, &callback);
    }

    return NapiGetNull(env);
}

void PaddingAsyncCallbackInfoGetAbort(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoGetAbort *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGD("PaddingAsyncCallbackInfoGetAbort start");

    if (argc >= GET_ABORT_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }

    EVENT_LOGD("PaddingAsyncCallbackInfoGetAbort end");
}

napi_value ParseParametersByFinish(const napi_env &env, const napi_value (&argv)[1], size_t argc, napi_ref &callback)
{
    napi_valuetype valuetype;

    // argv[0]:callback
    if (argc >= FINISH_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Wrong argument type. Function expected.");
            return nullptr;
        }
        napi_create_reference(env, argv[0], 1, &callback);
    }

    return NapiGetNull(env);
}

void PaddingAsyncCallbackInfoFinish(const napi_env &env, const size_t &argc,
    AsyncCallbackInfoFinish *&asyncCallbackInfo, const napi_ref &callback, napi_value &promise)
{
    EVENT_LOGD("PaddingAsyncCallbackInfoFinish start");

    if (argc >= FINISH_MAX_PARA) {
        asyncCallbackInfo->info.callback = callback;
        asyncCallbackInfo->info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->info.deferred = deferred;
        asyncCallbackInfo->info.isCallback = false;
    }

    EVENT_LOGD("PaddingAsyncCallbackInfoFinish end");
}

napi_value ParseParametersBySubscribe(const napi_env &env, const napi_value (&argv)[SUBSCRIBE_MAX_PARA],
    std::shared_ptr<SubscriberInstance> &subscriber, napi_ref &callback)
{
    EVENT_LOGD("ParseParametersBySubscribe start");

    napi_valuetype valuetype;
    // argv[0]:subscriber
    NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
    if (valuetype != napi_object) {
        EVENT_LOGE("Wrong argument type for arg0. Subscribe expected.");
        return nullptr;
    }
    subscriber = GetSubscriber(env, argv[0]);
    if (subscriber == nullptr) {
        EVENT_LOGE("subscriber is nullptr");
        return nullptr;
    }

    // argv[1]:callback
    NAPI_CALL(env, napi_typeof(env, argv[1], &valuetype));
    if (valuetype != napi_function) {
        EVENT_LOGE("Wrong argument type. Function expected.");
        return nullptr;
    }
    napi_create_reference(env, argv[1], 1, &callback);

    return NapiGetNull(env);
}

napi_value GetBundlenameByPublish(const napi_env &env, const napi_value &value, std::string &bundleName)
{
    EVENT_LOGD("GetBundlenameByPublish start");

    napi_valuetype valuetype;
    napi_value result = nullptr;
    char str[STR_MAX_SIZE] = {0};
    size_t strLen = 0;
    bool hasProperty = false;

    NAPI_CALL(env, napi_has_named_property(env, value, "bundleName", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "bundleName", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_string) {
            EVENT_LOGE("Wrong argument type. String expected.");
            return nullptr;
        }
        NAPI_CALL(env, napi_get_value_string_utf8(env, result, str, STR_MAX_SIZE - 1, &strLen));
        bundleName = str;
    }

    return NapiGetNull(env);
}

napi_value GetDataByPublish(const napi_env &env, const napi_value &value, std::string &data)
{
    EVENT_LOGD("GetDataByPublish start");

    napi_valuetype valuetype;
    napi_value result = nullptr;
    char str[STR_DATA_MAX_SIZE] = {0};
    size_t strLen = 0;
    bool hasProperty = false;

    NAPI_CALL(env, napi_has_named_property(env, value, "data", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "data", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_string) {
            EVENT_LOGE("Wrong argument type. String expected.");
            return nullptr;
        }
        NAPI_CALL(env, napi_get_value_string_utf8(env, result, str, STR_DATA_MAX_SIZE, &strLen));

        if (strLen > STR_DATA_MAX_SIZE - 1) {
            EVENT_LOGE("data over size");
            return nullptr;
        }

        data = str;
    }

    return NapiGetNull(env);
}

napi_value GetCodeByPublish(const napi_env &env, const napi_value &value, int32_t &code)
{
    EVENT_LOGD("GetCodeByPublish start");

    napi_valuetype valuetype;
    napi_value result = nullptr;
    bool hasProperty = false;

    NAPI_CALL(env, napi_has_named_property(env, value, "code", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "code", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_number) {
            EVENT_LOGE("Wrong argument type. Number expected.");
            return nullptr;
        }
        napi_get_value_int32(env, result, &code);
    }

    return NapiGetNull(env);
}

napi_value GetSubscriberPermissionsByPublish(
    const napi_env &env, const napi_value &value, std::vector<std::string> &subscriberPermissions)
{
    EVENT_LOGD("GetSubscriberPermissionsByPublish start");

    napi_valuetype valuetype;
    napi_value result = nullptr;
    bool isArray = false;
    char str[STR_MAX_SIZE] = {0};
    size_t strLen = 0;
    bool hasProperty = false;

    NAPI_CALL(env, napi_has_named_property(env, value, "subscriberPermissions", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "subscriberPermissions", &result);
        napi_is_array(env, result, &isArray);
        if (isArray) {
            EVENT_LOGD("isArray is true.");
            uint32_t length = 0;
            napi_get_array_length(env, result, &length);
            if (length > 0) {
                for (uint32_t i = 0; i < length; ++i) {
                    napi_value nSubscriberPermission = nullptr;
                    napi_get_element(env, result, i, &nSubscriberPermission);
                    NAPI_CALL(env, napi_typeof(env, nSubscriberPermission, &valuetype));
                    if (valuetype != napi_string) {
                        EVENT_LOGE("Wrong argument type. String expected.");
                        return nullptr;
                    }
                    if (memset_s(str, STR_MAX_SIZE, 0, STR_MAX_SIZE) != 0) {
                        EVENT_LOGE("memset_s failed.");
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
    EVENT_LOGD("GetIsOrderedByPublish start");

    napi_valuetype valuetype;
    napi_value result = nullptr;
    bool hasProperty = false;

    NAPI_CALL(env, napi_has_named_property(env, value, "isOrdered", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "isOrdered", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_boolean) {
            EVENT_LOGE("Wrong argument type. Boolean expected.");
            return nullptr;
        }
        napi_get_value_bool(env, result, &isOrdered);
    }

    return NapiGetNull(env);
}

napi_value GetIsStickyByPublish(const napi_env &env, const napi_value &value, bool &isSticky)
{
    EVENT_LOGD("GetIsStickyByPublish start");

    napi_valuetype valuetype;
    napi_value result = nullptr;
    bool hasProperty = false;

    NAPI_CALL(env, napi_has_named_property(env, value, "isSticky", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "isSticky", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_boolean) {
            EVENT_LOGE("Wrong argument type. Boolean expected.");
            return nullptr;
        }
        napi_get_value_bool(env, result, &isSticky);
    }

    return NapiGetNull(env);
}

napi_value GetParametersByPublish(const napi_env &env, const napi_value &value, AAFwk::WantParams &wantParams)
{
    EVENT_LOGD("GetParametersByPublish start");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;

    NAPI_CALL(env, napi_has_named_property(env, value, "parameters", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "parameters", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_object) {
            EVENT_LOGE("Wrong argument type. Object expected.");
            return nullptr;
        }
        if (!OHOS::AppExecFwk::UnwrapWantParams(env, result, wantParams)) {
            EVENT_LOGD("UnwrapWantParams is false.");
            return nullptr;
        }
    }

    return NapiGetNull(env);
}

napi_value ParseParametersByPublish(const napi_env &env, const napi_value (&argv)[PUBLISH_MAX_PARA_BY_PUBLISHDATA],
    const size_t &argc, std::string &event, CommonEventPublishDataByjs &commonEventPublishData, napi_ref &callback)
{
    EVENT_LOGD("ParseParametersByPublish start");

    napi_valuetype valuetype;
    // argv[0]: event
    NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
    if (valuetype != napi_string) {
        EVENT_LOGE("Argument type error. String expected.");
        return nullptr;
    }

    char str[STR_MAX_SIZE] = {0};
    size_t strLen = 0;
    napi_get_value_string_utf8(env, argv[0], str, STR_MAX_SIZE - 1, &strLen);
    event = str;
    EVENT_LOGD("ParseParametersByPublish event = %{public}s", str);
    // argv[1]: CommonEventPublishData
    if (argc == PUBLISH_MAX_PARA_BY_PUBLISHDATA) {
        NAPI_CALL(env, napi_typeof(env, argv[1], &valuetype));
        if (valuetype != napi_object) {
            EVENT_LOGE("Wrong argument type. Object expected.");
            return nullptr;
        }

        // argv[1]: CommonEventPublishData:bundlename
        if (GetBundlenameByPublish(env, argv[1], commonEventPublishData.bundleName) == nullptr) {
            EVENT_LOGD("GetBundlenameByPublish is nullptr.");
            return nullptr;
        }
        // argv[1]: CommonEventPublishData:data
        if (GetDataByPublish(env, argv[1], commonEventPublishData.data) == nullptr) {
            EVENT_LOGD("GetDataByPublish is nullptr.");
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
            EVENT_LOGD("GetIsOrderedByPublish is nullptr.");
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
    }

    // argv[2]: callback
    if (argc == PUBLISH_MAX_PARA_BY_PUBLISHDATA) {
        NAPI_CALL(env, napi_typeof(env, argv[PUBLISH_MAX_PARA], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Argument type error. Function expected.");
            return nullptr;
        }
        napi_create_reference(env, argv[PUBLISH_MAX_PARA], 1, &callback);
    } else {
        NAPI_CALL(env, napi_typeof(env, argv[1], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Argument type error. Function expected.");
            return nullptr;
        }
        napi_create_reference(env, argv[1], 1, &callback);
    }

    return NapiGetNull(env);
}

void PaddingCallbackInfoPublish(Want &want, AsyncCallbackInfoPublish *&asyncCallbackInfo,
    const CommonEventPublishDataByjs &commonEventPublishDatajs)
{
    EVENT_LOGD("PaddingCallbackInfoPublish start");
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
        EVENT_LOGE("Wrong argument type. String expected.");
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
        EVENT_LOGE("Wrong argument type. Number expected.");
        return nullptr;
    }
    napi_get_value_int32(env, argv[1], &userId);
    EVENT_LOGD("ParseParametersByPublishAsUser userId = %{public}d", userId);

    // argv[2]: CommonEventPublishData
    if (argc == PUBLISH_MAX_PARA_BY_USERID) {
        NAPI_CALL(env, napi_typeof(env, argv[COMMON_EVENT_PUBLISH_PARAM], &valuetype));
        if (valuetype != napi_object) {
            EVENT_LOGE("Wrong argument type. Object expected.");
            return nullptr;
        }

        // argv[2]: CommonEventPublishData:bundlename
        if (GetBundlenameByPublish(env, argv[COMMON_EVENT_PUBLISH_PARAM], commonEventPublishData.bundleName)
            == nullptr) {
            return nullptr;
        }
        // argv[2]: CommonEventPublishData:data
        if (GetDataByPublish(env, argv[COMMON_EVENT_PUBLISH_PARAM], commonEventPublishData.data) == nullptr) {
            return nullptr;
        }
        // argv[2]: CommonEventPublishData:code
        if (GetCodeByPublish(env, argv[COMMON_EVENT_PUBLISH_PARAM], commonEventPublishData.code) == nullptr) {
            return nullptr;
        }
        // argv[2]: CommonEventPublishData:permissions
        if (GetSubscriberPermissionsByPublish(env, argv[COMMON_EVENT_PUBLISH_PARAM],
            commonEventPublishData.subscriberPermissions) == nullptr) {
            return nullptr;
        }
        // argv[2]: CommonEventPublishData:isOrdered
        if (GetIsOrderedByPublish(env, argv[COMMON_EVENT_PUBLISH_PARAM], commonEventPublishData.isOrdered) == nullptr) {
            return nullptr;
        }
        // argv[2]: CommonEventPublishData:isSticky
        if (GetIsStickyByPublish(env, argv[COMMON_EVENT_PUBLISH_PARAM], commonEventPublishData.isSticky) == nullptr) {
            return nullptr;
        }
        // argv[2]: CommonEventPublishData:parameters
        if (GetParametersByPublish(env, argv[COMMON_EVENT_PUBLISH_PARAM], commonEventPublishData.wantParams)
            == nullptr) {
            return nullptr;
        }
    }

    // argv[3]: callback
    if (argc == PUBLISH_MAX_PARA_BY_USERID) {
        NAPI_CALL(env, napi_typeof(env, argv[PUBLISH_MAX_PARA_AS_USER], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Wrong argument type. Function expected.");
            return nullptr;
        }
        napi_create_reference(env, argv[PUBLISH_MAX_PARA_AS_USER], 1, &callback);
    } else {
        NAPI_CALL(env, napi_typeof(env, argv[COMMON_EVENT_PUBLISH_PARAM], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Wrong argument type. Function expected.");
            return nullptr;
        }
        napi_create_reference(env, argv[COMMON_EVENT_PUBLISH_PARAM], 1, &callback);
    }

    return NapiGetNull(env);
}

napi_value ParseParametersByUnsubscribe(const napi_env &env, const size_t &argc,
    const napi_value (&argv)[UNSUBSCRIBE_MAX_PARA], std::shared_ptr<SubscriberInstance> &subscriber, napi_ref &callback)
{
    EVENT_LOGD("ParseParametersByUnsubscribe start");

    napi_valuetype valuetype;
    napi_value result = nullptr;
    // argv[0]:subscriber
    NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
    if (valuetype != napi_object) {
        EVENT_LOGE("Wrong argument type for arg0. Subscribe expected.");
        return nullptr;
    }

    bool isFind = false;
    if (GetSubscriberByUnsubscribe(env, argv[0], subscriber, isFind) == nullptr) {
        EVENT_LOGE("GetSubscriberByUnsubscribe failed");
        return nullptr;
    }

    // argv[1]:callback
    if (argc >= UNSUBSCRIBE_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[1], &valuetype));
        if (valuetype != napi_function) {
            EVENT_LOGE("Wrong argument type. Function expected.");
            return nullptr;
        }
        napi_create_reference(env, argv[1], 1, &callback);
    }

    napi_get_boolean(env, isFind, &result);

    return result;
}

napi_value GetEventsByCreateSubscriber(const napi_env &env, const napi_value &argv, std::vector<std::string> &events)
{
    EVENT_LOGD("enter");
    napi_valuetype valuetype;
    bool hasProperty = false;
    bool isArray = false;
    napi_value eventsNapi = nullptr;
    size_t strLen = 0;
    uint32_t length = 0;
    // events
    NAPI_CALL(env, napi_has_named_property(env, argv, "events", &hasProperty));
    if (!hasProperty) {
        EVENT_LOGE("Property events expected.");
        return nullptr;
    }
    napi_get_named_property(env, argv, "events", &eventsNapi);
    napi_is_array(env, eventsNapi, &isArray);
    if (!isArray) {
        EVENT_LOGE("Wrong argument type. Array expected.");
        return nullptr;
    }
    napi_get_array_length(env, eventsNapi, &length);
    if (length == 0 || length > SUBSCRIBE_EVENT_MAX_NUM) {
        EVENT_LOGE("The array size is error.");
        return nullptr;
    }
    for (size_t i = 0; i < length; i++) {
        napi_value event = nullptr;
        napi_get_element(env, eventsNapi, i, &event);
        NAPI_CALL(env, napi_typeof(env, event, &valuetype));
        if (valuetype != napi_string) {
            EVENT_LOGE("Wrong parameter type. String expected.");
            return nullptr;
        }
        char str[STR_MAX_SIZE] = {0};
        NAPI_CALL(env, napi_get_value_string_utf8(env, event, str, STR_MAX_SIZE - 1, &strLen));
        EVENT_LOGD("event: %{public}s", str);
        events.emplace_back(str);
    }

    return NapiGetNull(env);
}

napi_value GetPublisherPermissionByCreateSubscriber(
    const napi_env &env, const napi_value &argv, CommonEventSubscribeInfo &info)
{
    EVENT_LOGD("GetPublisherPermissionByCreateSubscriber start");

    napi_value result = nullptr;
    bool hasProperty = false;
    napi_valuetype valuetype = napi_undefined;
    size_t strLen = 0;
    char str[STR_MAX_SIZE] = {0};

    // publisherPermission
    NAPI_CALL(env, napi_has_named_property(env, argv, "publisherPermission", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, argv, "publisherPermission", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_string) {
            EVENT_LOGE("Wrong parameter type. String expected.");
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
    EVENT_LOGD("GetPublisherDeviceIdByCreateSubscriber start");

    bool hasProperty = false;
    napi_value result = nullptr;
    size_t strLen = 0;
    napi_valuetype valuetype = napi_undefined;
    char str[STR_MAX_SIZE] = {0};

    // publisherDeviceId
    NAPI_CALL(env, napi_has_named_property(env, argv, "publisherDeviceId", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, argv, "publisherDeviceId", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_string) {
            EVENT_LOGE("Wrong parameter type. String expected.");
            return nullptr;
        }
        NAPI_CALL(env, napi_get_value_string_utf8(env, result, str, STR_MAX_SIZE - 1, &strLen));
        info.SetDeviceId(str);
    }

    return NapiGetNull(env);
}

napi_value GetUserIdByCreateSubscriber(const napi_env &env, const napi_value &argv, CommonEventSubscribeInfo &info)
{
    EVENT_LOGD("GetUserIdByCreateSubscriber start");

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
            EVENT_LOGE("Wrong parameter type. Number expected.");
            return nullptr;
        }
        NAPI_CALL(env, napi_get_value_int32(env, result, &value));
        info.SetUserId(value);
    }

    return NapiGetNull(env);
}

napi_value GetPriorityByCreateSubscriber(const napi_env &env, const napi_value &argv, CommonEventSubscribeInfo &info)
{
    EVENT_LOGD("GetPriorityByCreateSubscriber start");

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
            EVENT_LOGE("Wrong parameter type. Number expected.");
            return nullptr;
        }
        NAPI_CALL(env, napi_get_value_int32(env, result, &value));
        info.SetPriority(value);
    }

    return NapiGetNull(env);
}

napi_value ParseParametersConstructor(
    const napi_env &env, const napi_callback_info &info, napi_value &thisVar, CommonEventSubscribeInfo &params)
{
    EVENT_LOGD("ParseParametersConstructor start");
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    if (argc < 1) {
        EVENT_LOGE("Wrong number of parameters");
        return nullptr;
    }

    // events: Array<string>
    std::vector<std::string> events;
    if (!GetEventsByCreateSubscriber(env, argv[0], events)) {
        EVENT_LOGE("GetEventsByCreateSubscriber failed");
        return nullptr;
    }
    MatchingSkills matchingSkills;
    for (const auto &event : events) {
        matchingSkills.AddEvent(event);
    }
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    // publisherPermission?: string
    if (!GetPublisherPermissionByCreateSubscriber(env, argv[0], subscribeInfo)) {
        EVENT_LOGE("GetPublisherPermissionByCreateSubscriber failed");
        return nullptr;
    }

    // publisherDeviceId?: string
    if (!GetPublisherDeviceIdByCreateSubscriber(env, argv[0], subscribeInfo)) {
        EVENT_LOGE("GetPublisherDeviceIdByCreateSubscriber failed");
        return nullptr;
    }

    // userId?: number
    if (!GetUserIdByCreateSubscriber(env, argv[0], subscribeInfo)) {
        EVENT_LOGE("GetUserIdByCreateSubscriber failed");
        return nullptr;
    }

    // priority?: number
    if (!GetPriorityByCreateSubscriber(env, argv[0], subscribeInfo)) {
        EVENT_LOGE("GetPriorityByCreateSubscriber failed");
        return nullptr;
    }

    params = subscribeInfo;
    return NapiGetNull(env);
}

}  // namespace EventFwkNapi
}  // namespace OHOS
