/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <new>

#include "array_wrapper.h"
#include "bool_wrapper.h"
#include "common_event_constant.h"
#include "common_event_manager.h"
#include "double_wrapper.h"
#include "event_log_wrapper.h"
#include "int_wrapper.h"
#include "long_wrapper.h"
#include "oh_commonevent.h"
#include "oh_commonevent_parameters_parse.h"
#include "oh_commonevent_wrapper.h"
#include "securec.h"
#include "string_wrapper.h"
#include "want_params_wrapper.h"
#include "zchar_wrapper.h"

#ifdef __cplusplus
extern "C" {
#endif

CommonEvent_SubscribeInfo* OH_CommonEvent_CreateSubscribeInfo(const char* events[], int32_t eventsNum)
{
    if (eventsNum == 0) {
        EVENT_LOGE("Events is empty");
        return nullptr;
    }
    CommonEvent_SubscribeInfo* subscribeInfo = new (std::nothrow) CommonEvent_SubscribeInfo();
    if (subscribeInfo == nullptr) {
        EVENT_LOGE("Failed to create subscribeInfo");
        return nullptr;
    }
    for (int i = 0; i < eventsNum; i++) {
        if (events[i] != nullptr) {
            subscribeInfo->events.emplace_back(events[i]);
        }
    }
    return subscribeInfo;
}

CommonEvent_ErrCode OH_CommonEvent_SetPublisherPermission(CommonEvent_SubscribeInfo* info, const char* permission)
{
    if (info == nullptr) {
        EVENT_LOGE("Invalid para");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }
    info->permission = permission == nullptr? std::string(): permission;
    return COMMONEVENT_ERR_OK;
}

CommonEvent_ErrCode OH_CommonEvent_SetPublisherBundleName(CommonEvent_SubscribeInfo* info, const char* bundleName)
{
    if (info == nullptr) {
        EVENT_LOGE("Invalid para");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }
    info->bundleName = bundleName == nullptr? std::string(): bundleName;
    return COMMONEVENT_ERR_OK;
}

void OH_CommonEvent_DestroySubscribeInfo(CommonEvent_SubscribeInfo* info)
{
    if (info != nullptr) {
        delete info;
    }
}

CommonEvent_Subscriber* OH_CommonEvent_CreateSubscriber(const CommonEvent_SubscribeInfo* info,
    CommonEvent_ReceiveCallback callback)
{
    return SubscriberManager::GetInstance()->CreateSubscriber(info, callback);
}

void OH_CommonEvent_DestroySubscriber(CommonEvent_Subscriber* subscriber)
{
    SubscriberManager::GetInstance()->DestroySubscriber(subscriber);
}

CommonEvent_ErrCode OH_CommonEvent_Subscribe(const CommonEvent_Subscriber* subscriber)
{
    return SubscriberManager::GetInstance()->Subscribe(subscriber);
}

CommonEvent_ErrCode OH_CommonEvent_UnSubscribe(const CommonEvent_Subscriber* subscriber)
{
    return SubscriberManager::GetInstance()->UnSubscribe(subscriber);
}

const char* OH_CommonEvent_GetEventFromRcvData(const CommonEvent_RcvData* rcvData)
{
    return rcvData == nullptr ? nullptr : rcvData->event.c_str();
}

int32_t OH_CommonEvent_GetCodeFromRcvData(const CommonEvent_RcvData* rcvData)
{
    return rcvData == nullptr ? 0 : rcvData->code;
}

const char* OH_CommonEvent_GetDataStrFromRcvData(const CommonEvent_RcvData* rcvData)
{
    return rcvData == nullptr ? nullptr : rcvData->data.c_str();
}

const char* OH_CommonEvent_GetBundleNameFromRcvData(const CommonEvent_RcvData* rcvData)
{
    return rcvData == nullptr ? nullptr : rcvData->bundleName.c_str();
}

const CommonEvent_Parameters* OH_CommonEvent_GetParametersFromRcvData(const CommonEvent_RcvData* rcvData)
{
    return rcvData == nullptr ? nullptr : rcvData->parameters;
}

CommonEvent_PublishInfo* OH_CommonEvent_CreatePublishInfo(const bool ordered)
{
    CommonEvent_PublishInfo* publishInfo = new (std::nothrow) CommonEvent_PublishInfo();
    if (publishInfo == nullptr) {
        EVENT_LOGE("Failed to create PublishInfo");
    }
    publishInfo->ordered = ordered;
    return publishInfo;
}

void OH_CommonEvent_DestroyPublishInfo(CommonEvent_PublishInfo* info)
{
    if (info != nullptr) {
        delete info;
    }
}

CommonEvent_ErrCode OH_CommonEvent_SetPublishInfoBundleName(CommonEvent_PublishInfo* info, const char* bundleName)
{
    if (info == nullptr) {
        EVENT_LOGE("Invalid info");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }
    info->bundleName = bundleName == nullptr ? std::string() : bundleName;
    return COMMONEVENT_ERR_OK;
}

CommonEvent_ErrCode OH_CommonEvent_SetPublishInfoPermissions(
    CommonEvent_PublishInfo* info, const char* permissions[], const int32_t num)
{
    if (info == nullptr) {
        EVENT_LOGE("Invalid info");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }

    info->subscriberPermissions.clear();
    for (int32_t i = 0; i < num; ++i) {
        if (permissions[i] != nullptr) {
            info->subscriberPermissions.emplace_back(permissions[i]);
        }
    }

    return COMMONEVENT_ERR_OK;
}

CommonEvent_ErrCode OH_CommonEvent_SetPublishInfoCode(CommonEvent_PublishInfo* info, const int32_t code)
{
    if (info == nullptr) {
        EVENT_LOGE("Invalid info");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }

    info->code = code;
    return COMMONEVENT_ERR_OK;
}

CommonEvent_ErrCode OH_CommonEvent_SetPublishInfoData(
    CommonEvent_PublishInfo* info, const char* data, const size_t length)
{
    if (info == nullptr) {
        EVENT_LOGE("Invalid info");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }
    if (data == nullptr) {
        info->data.clear();
    } else {
        info->data = std::string(data, std::min(std::strlen(data), length));
    }
    return COMMONEVENT_ERR_OK;
}

CommonEvent_ErrCode OH_CommonEvent_SetPublishInfoParameters(
    CommonEvent_PublishInfo* info, CommonEvent_Parameters* param)
{
    if (info == nullptr) {
        EVENT_LOGE("Invalid info");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }

    info->parameters = reinterpret_cast<CArrParameters*>(param);
    return COMMONEVENT_ERR_OK;
}

CommonEvent_Parameters* OH_CommonEvent_CreateParameters()
{
    auto obj = new (std::nothrow) CArrParameters();
    return obj;
}

void OH_CommonEvent_DestroyParameters(CommonEvent_Parameters* param)
{
    auto parameters = reinterpret_cast<CArrParameters*>(param);
    if (parameters != nullptr) {
        for (void* ptr : parameters->allocatedPointers) {
            if (ptr == nullptr) {
                continue;
            }
            free(ptr);
        }
        parameters->allocatedPointers.clear();
        delete parameters;
        parameters = nullptr;
    }
}

bool OH_CommonEvent_HasKeyInParameters(const CommonEvent_Parameters* para, const char* key)
{
    if (para == nullptr || key == nullptr) {
        EVENT_LOGE("Invalid para");
        return false;
    }
    auto parameters = reinterpret_cast<const CArrParameters*>(para);
    if (parameters == nullptr) {
        EVENT_LOGE("Invalid para");
        return false;
    }
    return parameters->wantParams.HasParam(key);
}

int OH_CommonEvent_GetIntFromParameters(const CommonEvent_Parameters* para, const char* key, const int defaultValue)
{
    if (para == nullptr || key == nullptr) {
        EVENT_LOGE("Invalid para");
        return defaultValue;
    }
    auto parameters = reinterpret_cast<const CArrParameters*>(para);
    if (parameters == nullptr) {
        EVENT_LOGE("Invalid para");
        return defaultValue;
    }
    return OHOS::EventFwk::GetDataFromParams<OHOS::AAFwk::IInteger, OHOS::AAFwk::Integer, int>(
        *parameters, key, defaultValue);
}

CommonEvent_ErrCode OH_CommonEvent_SetIntToParameters(CommonEvent_Parameters* param, const char* key, const int value)
{
    if (param == nullptr || key == nullptr) {
        EVENT_LOGE("Invalid param");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }

    auto parameters = reinterpret_cast<CArrParameters*>(param);
    if (parameters == nullptr) {
        EVENT_LOGE("Invalid param");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }
    return OHOS::EventFwk::SetDataToParams<OHOS::AAFwk::Integer, int>(*parameters, key, value);
}

int OH_CommonEvent_GetIntArrayFromParameters(const CommonEvent_Parameters* para, const char* key, int** array)
{
    if (para == nullptr || key == nullptr || array == nullptr) {
        EVENT_LOGE("Invalid para");
        return 0;
    }
    auto parameters = reinterpret_cast<const CArrParameters*>(para);
    if (parameters == nullptr) {
        EVENT_LOGE("Invalid para");
        return 0;
    }
    return OHOS::EventFwk::GetDataArrayFromParams<OHOS::AAFwk::IInteger, OHOS::AAFwk::Integer, int>(
        *parameters, key, array);
}

CommonEvent_ErrCode OH_CommonEvent_SetIntArrayToParameters(
    CommonEvent_Parameters* param, const char* key, const int* value, const size_t num)
{
    if (param == nullptr || key == nullptr || (value == nullptr && num > 0)) {
        EVENT_LOGE("Invalid param");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }

    auto parameters = reinterpret_cast<CArrParameters*>(param);
    if (parameters == nullptr) {
        EVENT_LOGE("Invalid param");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }
    return OHOS::EventFwk::SetDataArrayToParams<OHOS::AAFwk::Integer, int>(
        *parameters, key, value, num, OHOS::AAFwk::g_IID_IInteger);
}

long OH_CommonEvent_GetLongFromParameters(const CommonEvent_Parameters* para, const char* key,
    const long defaultValue)
{
    if (para == nullptr || key == nullptr) {
        EVENT_LOGE("Invalid para");
        return defaultValue;
    }
    auto parameters = reinterpret_cast<const CArrParameters*>(para);
    if (parameters == nullptr) {
        EVENT_LOGE("Invalid para");
        return defaultValue;
    }
    return OHOS::EventFwk::GetDataFromParams<OHOS::AAFwk::ILong, OHOS::AAFwk::Long, long>(
        *parameters, key, defaultValue);
}

CommonEvent_ErrCode OH_CommonEvent_SetLongToParameters(CommonEvent_Parameters* param, const char* key, const long value)
{
    if (param == nullptr || key == nullptr) {
        EVENT_LOGE("Invalid param");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }

    auto parameters = reinterpret_cast<CArrParameters*>(param);
    if (parameters == nullptr) {
        EVENT_LOGE("Invalid param");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }
    return OHOS::EventFwk::SetDataToParams<OHOS::AAFwk::Long, long>(*parameters, key, value);
}

int32_t OH_CommonEvent_GetLongArrayFromParameters(const CommonEvent_Parameters* para, const char* key, long** array)
{
    if (para == nullptr || key == nullptr || array == nullptr) {
        EVENT_LOGE("Invalid para");
        return 0;
    }
    auto parameters = reinterpret_cast<const CArrParameters*>(para);
    if (parameters == nullptr) {
        EVENT_LOGE("Invalid para");
        return 0;
    }
    return OHOS::EventFwk::GetDataArrayFromParams<OHOS::AAFwk::ILong, OHOS::AAFwk::Long, long>(
        *parameters, key, array);
}

CommonEvent_ErrCode OH_CommonEvent_SetLongArrayToParameters(CommonEvent_Parameters* param, const char* key,
    const long* value, const size_t num)
{
    if (param == nullptr || key == nullptr || (value == nullptr && num > 0)) {
        EVENT_LOGE("Invalid param");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }

    auto parameters = reinterpret_cast<CArrParameters*>(param);
    if (parameters == nullptr) {
        EVENT_LOGE("Invalid param");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }
    return OHOS::EventFwk::SetDataArrayToParams<OHOS::AAFwk::Long, long>(
        *parameters, key, value, num, OHOS::AAFwk::g_IID_ILong);
}

bool OH_CommonEvent_GetBoolFromParameters(const CommonEvent_Parameters* para, const char* key,
    const bool defaultValue)
{
    if (para == nullptr || key == nullptr) {
        EVENT_LOGE("Invalid para");
        return defaultValue;
    }
    auto parameters = reinterpret_cast<const CArrParameters*>(para);
    if (parameters == nullptr) {
        EVENT_LOGE("Invalid para");
        return defaultValue;
    }
    return OHOS::EventFwk::GetDataFromParams<OHOS::AAFwk::IBoolean, OHOS::AAFwk::Boolean, bool>(
        *parameters, key, defaultValue);
}

CommonEvent_ErrCode OH_CommonEvent_SetBoolToParameters(CommonEvent_Parameters* param, const char* key, const bool value)
{
    if (param == nullptr || key == nullptr) {
        EVENT_LOGE("Invalid param");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }

    auto parameters = reinterpret_cast<CArrParameters*>(param);
    if (parameters == nullptr) {
        EVENT_LOGE("Invalid param");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }
    return OHOS::EventFwk::SetDataToParams<OHOS::AAFwk::Boolean, bool>(*parameters, key, value);
}

int32_t OH_CommonEvent_GetBoolArrayFromParameters(const CommonEvent_Parameters* para, const char* key, bool** array)
{
    if (para == nullptr || key == nullptr || array == nullptr) {
        EVENT_LOGE("Invalid para");
        return 0;
    }
    auto parameters = reinterpret_cast<const CArrParameters*>(para);
    if (parameters == nullptr) {
        EVENT_LOGE("Invalid para");
        return 0;
    }
    return OHOS::EventFwk::GetDataArrayFromParams<OHOS::AAFwk::IBoolean, OHOS::AAFwk::Boolean, bool>(
        *parameters, key, array);
}

CommonEvent_ErrCode OH_CommonEvent_SetBoolArrayToParameters(
    CommonEvent_Parameters* param, const char* key, const bool* value, const size_t num)
{
    if (param == nullptr || key == nullptr || (value == nullptr && num > 0)) {
        EVENT_LOGE("Invalid param");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }

    auto parameters = reinterpret_cast<CArrParameters*>(param);
    if (parameters == nullptr) {
        EVENT_LOGE("Invalid param");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }
    return OHOS::EventFwk::SetDataArrayToParams<OHOS::AAFwk::Boolean, bool>(
        *parameters, key, value, num, OHOS::AAFwk::g_IID_IBoolean);
}

char OH_CommonEvent_GetCharFromParameters(const CommonEvent_Parameters* para, const char* key,
    const char defaultValue)
{
    if (para == nullptr || key == nullptr) {
        EVENT_LOGE("Invalid para");
        return defaultValue;
    }
    auto parameters = reinterpret_cast<const CArrParameters*>(para);
    if (parameters == nullptr) {
        EVENT_LOGE("Invalid para");
        return defaultValue;
    }
    return OHOS::EventFwk::GetDataFromParams<OHOS::AAFwk::IChar, OHOS::AAFwk::Char, char>(
        *parameters, key, defaultValue);
}

CommonEvent_ErrCode OH_CommonEvent_SetCharToParameters(CommonEvent_Parameters* param, const char* key, const char value)
{
    if (param == nullptr || key == nullptr) {
        EVENT_LOGE("Invalid param");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }

    auto parameters = reinterpret_cast<CArrParameters*>(param);
    if (parameters == nullptr) {
        EVENT_LOGE("Invalid param");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }
    return OHOS::EventFwk::SetDataToParams<OHOS::AAFwk::Char, char>(*parameters, key, value);
}

int32_t OH_CommonEvent_GetCharArrayFromParameters(const CommonEvent_Parameters* para, const char* key, char** array)
{
    if (para == nullptr || key == nullptr || array == nullptr) {
        EVENT_LOGE("Invalid para");
        return 0;
    }
    auto parameters = reinterpret_cast<const CArrParameters*>(para);
    if (parameters == nullptr) {
        EVENT_LOGE("Invalid para");
        return 0;
    }
    return OHOS::EventFwk::GetStringFromParams(*parameters, key, array);
}

CommonEvent_ErrCode OH_CommonEvent_SetCharArrayToParameters(
    CommonEvent_Parameters* param, const char* key, const char* value, const size_t num)
{
    if (param == nullptr || key == nullptr || (value == nullptr && num > 0)) {
        EVENT_LOGE("Invalid param");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }

    auto parameters = reinterpret_cast<CArrParameters*>(param);
    if (parameters == nullptr) {
        EVENT_LOGE("Invalid param");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }
    const std::string str(value, std::min(std::strlen(value), num));
    return OHOS::EventFwk::SetDataToParams<OHOS::AAFwk::String, std::string>(*parameters, key, str);
}

double OH_CommonEvent_GetDoubleFromParameters(const CommonEvent_Parameters* para, const char* key,
    const double defaultValue)
{
    if (para == nullptr || key == nullptr) {
        EVENT_LOGE("Invalid para");
        return defaultValue;
    }
    auto parameters = reinterpret_cast<const CArrParameters*>(para);
    if (parameters == nullptr) {
        EVENT_LOGE("Invalid para");
        return defaultValue;
    }
    return OHOS::EventFwk::GetDataFromParams<OHOS::AAFwk::IDouble, OHOS::AAFwk::Double, double>(
        *parameters, key, defaultValue);
}

CommonEvent_ErrCode OH_CommonEvent_SetDoubleToParameters(
    CommonEvent_Parameters* param, const char* key, const double value)
{
    if (param == nullptr || key == nullptr) {
        EVENT_LOGE("Invalid param");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }

    auto parameters = reinterpret_cast<CArrParameters*>(param);
    if (parameters == nullptr) {
        EVENT_LOGE("Invalid param");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }
    return OHOS::EventFwk::SetDataToParams<OHOS::AAFwk::Double, double>(*parameters, key, value);
}

int32_t OH_CommonEvent_GetDoubleArrayFromParameters(const CommonEvent_Parameters* para, const char* key,
    double** array)
{
    if (para == nullptr || key == nullptr || array == nullptr) {
        EVENT_LOGE("Invalid para");
        return 0;
    }
    auto parameters = reinterpret_cast<const CArrParameters*>(para);
    if (parameters == nullptr) {
        EVENT_LOGE("Invalid para");
        return 0;
    }
    return OHOS::EventFwk::GetDataArrayFromParams<OHOS::AAFwk::IDouble, OHOS::AAFwk::Double, double>(
        *parameters, key, array);
}

CommonEvent_ErrCode OH_CommonEvent_SetDoubleArrayToParameters(
    CommonEvent_Parameters* param, const char* key, const double* value, const size_t num)
{
    if (param == nullptr || key == nullptr || (value == nullptr && num > 0)) {
        EVENT_LOGE("Invalid param");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }

    auto parameters = reinterpret_cast<CArrParameters*>(param);
    if (parameters == nullptr) {
        EVENT_LOGE("Invalid param");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }
    return OHOS::EventFwk::SetDataArrayToParams<OHOS::AAFwk::Double, double>(
        *parameters, key, value, num, OHOS::AAFwk::g_IID_IDouble);
}

CommonEvent_ErrCode OH_CommonEvent_Publish(const char* event)
{
    if (event == nullptr) {
        EVENT_LOGE("Invalid event");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }

    OHOS::AAFwk::Want want;
    want.SetAction(event);
    OHOS::EventFwk::CommonEventData data;
    OHOS::EventFwk::CommonEventPublishInfo publishInfo;
    data.SetWant(want);

    auto ret = OHOS::EventFwk::CommonEventManager::NewPublishCommonEvent(data, publishInfo);
    return static_cast<CommonEvent_ErrCode>(ret);
}

CommonEvent_ErrCode OH_CommonEvent_PublishWithInfo(const char* event, const CommonEvent_PublishInfo* info)
{
    if (event == nullptr) {
        EVENT_LOGE("Invalid event");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }
    if (info == nullptr) {
        EVENT_LOGE("Invalid info");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }

    OHOS::AAFwk::Want want;
    want.SetAction(event);
    OHOS::EventFwk::CommonEventData data;
    OHOS::EventFwk::CommonEventPublishInfo publishInfo;
    if (info->parameters != nullptr) {
        want.SetParams(info->parameters->wantParams);
    }
    data.SetCode(info->code);
    data.SetData(info->data);
    publishInfo.SetSubscriberPermissions(info->subscriberPermissions);
    publishInfo.SetOrdered(info->ordered);
    publishInfo.SetBundleName(info->bundleName);
    data.SetWant(want);

    auto ret = OHOS::EventFwk::CommonEventManager::NewPublishCommonEvent(data, publishInfo);
    return static_cast<CommonEvent_ErrCode>(ret);
}

bool OH_CommonEvent_IsOrderedCommonEvent(const CommonEvent_Subscriber* subscriber)
{
    if (subscriber == nullptr) {
        EVENT_LOGE("Invalid subscriber");
        return false;
    }
    auto observer = *(reinterpret_cast<const std::shared_ptr<SubscriberObserver>*>(subscriber));
    auto item = SubscriberManager::GetInstance()->GetAsyncResult(observer.get());
    return (item == nullptr || item->result == nullptr) ? observer->IsOrderedCommonEvent()
                                                        : item->result->IsOrderedCommonEvent();
}

bool OH_CommonEvent_FinishCommonEvent(CommonEvent_Subscriber* subscriber)
{
    if (subscriber == nullptr) {
        EVENT_LOGE("Invalid subscriber");
        return false;
    }
    auto observer = *(reinterpret_cast<const std::shared_ptr<SubscriberObserver>*>(subscriber));
    auto item = SubscriberManager::GetInstance()->GetAsyncResult(observer.get());
    return (item == nullptr || item->result == nullptr) ? false : item->result->FinishCommonEvent();
}

bool OH_CommonEvent_GetAbortCommonEvent(const CommonEvent_Subscriber* subscriber)
{
    if (subscriber == nullptr) {
        EVENT_LOGE("Invalid subscriber");
        return false;
    }
    auto observer = *(reinterpret_cast<const std::shared_ptr<SubscriberObserver>*>(subscriber));
    auto item = SubscriberManager::GetInstance()->GetAsyncResult(observer.get());
    return (item == nullptr || item->result == nullptr) ? false : item->result->GetAbortCommonEvent();
}

bool OH_CommonEvent_AbortCommonEvent(CommonEvent_Subscriber* subscriber)
{
    if (subscriber == nullptr) {
        EVENT_LOGE("Invalid subscriber");
        return false;
    }
    auto observer = *(reinterpret_cast<const std::shared_ptr<SubscriberObserver>*>(subscriber));
    auto item = SubscriberManager::GetInstance()->GetAsyncResult(observer.get());
    return (item == nullptr || item->result == nullptr) ? false : item->result->AbortCommonEvent();
}

bool OH_CommonEvent_ClearAbortCommonEvent(CommonEvent_Subscriber* subscriber)
{
    if (subscriber == nullptr) {
        EVENT_LOGE("Invalid subscriber");
        return false;
    }
    auto observer = *(reinterpret_cast<const std::shared_ptr<SubscriberObserver>*>(subscriber));
    auto item = SubscriberManager::GetInstance()->GetAsyncResult(observer.get());
    return (item == nullptr || item->result == nullptr) ? false : item->result->ClearAbortCommonEvent();
}

int32_t OH_CommonEvent_GetCodeFromSubscriber(const CommonEvent_Subscriber* subscriber)
{
    if (subscriber == nullptr) {
        EVENT_LOGE("Invalid subscriber");
        return 0;
    }
    auto observer = *(reinterpret_cast<const std::shared_ptr<SubscriberObserver>*>(subscriber));
    auto item = SubscriberManager::GetInstance()->GetAsyncResult(observer.get());
    return (item == nullptr || item->result == nullptr) ? 0 : item->result->GetCode();
}

bool OH_CommonEvent_SetCodeToSubscriber(CommonEvent_Subscriber* subscriber, const int32_t code)
{
    if (subscriber == nullptr) {
        EVENT_LOGE("Invalid subscriber");
        return false;
    }
    auto observer = *(reinterpret_cast<const std::shared_ptr<SubscriberObserver>*>(subscriber));
    auto item = SubscriberManager::GetInstance()->GetAsyncResult(observer.get());
    return (item == nullptr || item->result == nullptr) ? false : item->result->SetCode(code);
}

const char* OH_CommonEvent_GetDataFromSubscriber(const CommonEvent_Subscriber* subscriber)
{
    if (subscriber == nullptr) {
        EVENT_LOGE("Invalid subscriber");
        return nullptr;
    }
    auto observer = *(reinterpret_cast<const std::shared_ptr<SubscriberObserver>*>(subscriber));
    auto item = SubscriberManager::GetInstance()->GetAsyncResult(observer.get());
    if (item == nullptr || item->result == nullptr) {
        return nullptr;
    }
    item->data = item->result->GetData();
    return item->data.c_str();
}

bool OH_CommonEvent_SetDataToSubscriber(CommonEvent_Subscriber* subscriber, const char* data, const size_t length)
{
    if (subscriber == nullptr) {
        EVENT_LOGE("Invalid subscriber");
        return false;
    }
    auto observer = *(reinterpret_cast<const std::shared_ptr<SubscriberObserver>*>(subscriber));
    auto item = SubscriberManager::GetInstance()->GetAsyncResult(observer.get());
    if (item == nullptr || item->result == nullptr) {
        return false;
    }
    const std::string strData(data, std::min(std::strlen(data), length));
    if (item->result->SetData(strData)) {
        return true;
    }
    return false;
}
#ifdef __cplusplus
}
#endif