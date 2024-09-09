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

#include "common_event_constant.h"
#include "event_log_wrapper.h"
#include "oh_commonevent.h"
#include "oh_commonevent_parameters_parse.h"
#include "oh_commonevent_wrapper.h"
#include "securec.h"
#include <cstdlib>

#ifdef __cplusplus
extern "C" {
#endif

CommonEvent_SubscribeInfo* OH_CommonEvent_CreateSubscribeInfo(const char* events[], int32_t eventsNum)
{
    if (eventsNum == 0) {
        EVENT_LOGE("Events is empty");
        return nullptr;
    }
    CommonEvent_SubscribeInfo *subscribeInfo = new CommonEvent_SubscribeInfo();
    if (subscribeInfo == nullptr) {
        EVENT_LOGE("Failed to create subscribeInfo");
        return nullptr;
    }
    int count = 0;
    for (int i = 0; i < eventsNum; i++) {
        if (events + i != nullptr) {
            count++;
        }
    }
    subscribeInfo->events = new char* [count];
    for (int i = 0; i < eventsNum; i++) {
        if (events + i != nullptr) {
            subscribeInfo->events[subscribeInfo->eventLength] = OHOS::EventFwk::MallocCString(events[i]);
            subscribeInfo->eventLength++;
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
    info->permission = OHOS::EventFwk::MallocCString(permission);
    return COMMONEVENT_ERR_OK;
}

CommonEvent_ErrCode OH_CommonEvent_SetPublisherBundleName(CommonEvent_SubscribeInfo* info, const char* bundleName)
{
    if (info == nullptr) {
        EVENT_LOGE("Invalid para");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }
    info->bundleName = OHOS::EventFwk::MallocCString(bundleName);
    return COMMONEVENT_ERR_OK;
}

void OH_CommonEvent_DestroySubscribeInfo(CommonEvent_SubscribeInfo* info)
{
    if (info != nullptr) {
        for (uint32_t i = 0; i < info->eventLength; i++) {
            free(info->events[i]);
            info->events[i] = nullptr;
        }
        delete[] info->events;
        info->events = nullptr;
        free(info->permission);
        info->permission = nullptr;
        free(info->bundleName);
        info->bundleName = nullptr;
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
    return rcvData->event;
}

int32_t OH_CommonEvent_GetCodeFromRcvData(const CommonEvent_RcvData* rcvData)
{
    return rcvData->code;
}

const char* OH_CommonEvent_GetDataStrFromRcvData(const CommonEvent_RcvData* rcvData)
{
    return rcvData->data;
}

const char* OH_CommonEvent_GetBundleNameFromRcvData(const CommonEvent_RcvData* rcvData)
{
    return rcvData->bundleName;
}

const CommonEvent_Parameters* OH_CommonEvent_GetParametersFromRcvData(const CommonEvent_RcvData* rcvData)
{
    return rcvData->parameters;
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
    return OHOS::EventFwk::HasKeyFromParameters(parameters, key);
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
    return OHOS::EventFwk::GetDataFromParams<int>(parameters, key, OHOS::EventFwk::I32_TYPE, defaultValue);
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
    return OHOS::EventFwk::GetDataArrayFromParams<int>(parameters, key, OHOS::EventFwk::I32_PTR_TYPE, array);
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
    return OHOS::EventFwk::GetDataFromParams<long>(parameters, key, OHOS::EventFwk::I64_TYPE, defaultValue);
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
    return OHOS::EventFwk::GetDataArrayFromParams<long>(parameters, key, OHOS::EventFwk::I64_PTR_TYPE, array);
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
    return OHOS::EventFwk::GetDataFromParams<bool>(parameters, key, OHOS::EventFwk::BOOL_TYPE, defaultValue);
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
    return OHOS::EventFwk::GetDataArrayFromParams<bool>(parameters, key, OHOS::EventFwk::BOOL_PTR_TYPE, array);
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
    return OHOS::EventFwk::GetDataFromParams<char>(parameters, key, OHOS::EventFwk::CHAR_TYPE, defaultValue);
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
    return OHOS::EventFwk::GetDataArrayFromParams<char>(parameters, key, OHOS::EventFwk::STR_TYPE, array);
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
    return OHOS::EventFwk::GetDataFromParams<double>(parameters, key, OHOS::EventFwk::DOUBLE_TYPE, defaultValue);
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
    return OHOS::EventFwk::GetDataArrayFromParams<double>(parameters, key, OHOS::EventFwk::DOUBLE_PTR_TYPE, array);
}
#ifdef __cplusplus
}
#endif