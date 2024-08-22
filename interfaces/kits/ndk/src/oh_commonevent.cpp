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


template <class T>
int32_t GetWantParamsArrayT(std::vector<T> list, T** ret)
{
    int32_t size = list.size();
    if (size <= 0) {
        ret = nullptr;
        return 0;
    }
    T *arrP = static_cast<T *>(malloc(sizeof(T) * size));
    if (arrP == nullptr) {
        ret = nullptr;
        return 0;
    }
    for (long i = 0; i < size; i++) {
        arrP[i] = list[i];
    }
    *ret = arrP;
    return size;
}

#ifdef __cplusplus
extern "C" {
#endif

CommonEventSubscribeInfo* OH_CommonEvent_CreateSubscribeInfo(const char* events[], int32_t eventsNum)
{
    CommonEventSubscribeInfo *subscribeInfo = new CommonEventSubscribeInfo();
    if (subscribeInfo == nullptr) {
        EVENT_LOGE("Failed to create subscribeInfo");
        return nullptr;
    }
    subscribeInfo->events = events;
    subscribeInfo->eventLength = eventsNum;
    return subscribeInfo;
}

CommonEvent_ErrCode OH_CommonEvent_SetPublisherPermission(CommonEventSubscribeInfo* info, const char* permission)
{
    if (info == nullptr) {
        EVENT_LOGE("Invalid para");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }
    info->permission = permission;
    return COMMONEVENT_ERR_OK;
}

CommonEvent_ErrCode OH_CommonEvent_SetPublisherBundleName(CommonEventSubscribeInfo* info, const char* bundleName)
{
    if (info == nullptr) {
        EVENT_LOGE("Invalid para");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }
    info->bundleName = bundleName;
    return COMMONEVENT_ERR_OK;
}

void OH_CommonEvent_DestroySubscribeInfo(CommonEventSubscribeInfo* info)
{
    if (info != nullptr) {
        delete info;
        info = nullptr;
    }
}

CommonEventSubscriber* OH_CommonEvent_CreateSubscriber(const CommonEventSubscribeInfo* info, CommonEventReceiveCallback callback)
{
    return SubscriberManager::GetInstance()->CreateSubscriber(info, callback);
}

void OH_CommonEvent_DestroySubscriber(CommonEventSubscriber* subscriber)
{
    SubscriberManager::GetInstance()->DestroySubscriber(subscriber);
}

CommonEvent_ErrCode OH_CommonEvent_Subscribe(const CommonEventSubscriber* subscriber)
{
    return SubscriberManager::GetInstance()->Subscribe(subscriber);
}

CommonEvent_ErrCode OH_CommonEvent_UnSubscribe(const CommonEventSubscriber* subscriber)
{
    return SubscriberManager::GetInstance()->UnSubscribe(subscriber);
}

const char* OH_CommonEvent_GetEventFromRcvData(const CommonEventRcvData* rcvData)
{
    return rcvData->event;
}

int32_t OH_CommonEvent_GetCodeFromRcvData(const CommonEventRcvData* rcvData)
{
    return rcvData->code;
}

const char* OH_CommonEvent_GetDataStrFromRcvData(const CommonEventRcvData* rcvData)
{
    return rcvData->data;
}

const char* OH_CommonEvent_GetBundleNameFromRcvData(const CommonEventRcvData* rcvData)
{
    return rcvData->bundleName;
}

const CommonEventParameters* OH_CommonEvent_GetParametersFromRcvData(const CommonEventRcvData* rcvData)
{
    return rcvData->want;
}
bool OH_CommonEvent_HasKeyInParameters(const CommonEventParameters* para, const char* key)
{
    if (para == nullptr || key == nullptr) {
        EVENT_LOGE("Invalid para");
        return false;
    }
    auto want = *(reinterpret_cast<const std::shared_ptr<OHOS::AAFwk::Want>*>(para));
    if (want == nullptr) {
        EVENT_LOGE("Invalid para");
        return false;
    }
    return want->HasParameter(key);
}

int OH_CommonEvent_GetIntFromParameters(const CommonEventParameters* para, const char* key, const int defaultValue)
{
    if (para == nullptr || key == nullptr) {
        EVENT_LOGE("Invalid para");
        return defaultValue;
    }
    auto want = *(reinterpret_cast<const std::shared_ptr<OHOS::AAFwk::Want>*>(para));
    if (want == nullptr) {
        EVENT_LOGE("Invalid para");
        return defaultValue;
    }
    return want->GetIntParam(key, defaultValue);
}

int OH_CommonEvent_GetIntArrayFromParameters(const CommonEventParameters* para, const char* key, int** array)
{
    if (para == nullptr || key == nullptr || array == nullptr) {
        EVENT_LOGE("Invalid para");
        array = nullptr;
        return 0;
    }
    auto want = *(reinterpret_cast<const std::shared_ptr<OHOS::AAFwk::Want>*>(para));
    if (want == nullptr) {
        EVENT_LOGE("Invalid para");
        array = nullptr;
        return 0;
    }
    return GetWantParamsArrayT<int>(want->GetIntArrayParam(key), array);
}

long OH_CommonEvent_GetLongFromParameters(const CommonEventParameters* para, const char* key, const long defaultValue)
{
    if (para == nullptr || key == nullptr) {
        EVENT_LOGE("Invalid para");
        return defaultValue;
    }
    auto want = *(reinterpret_cast<const std::shared_ptr<OHOS::AAFwk::Want>*>(para));
    if (want == nullptr) {
        EVENT_LOGE("Invalid para");
        return defaultValue;
    }
    return want->GetLongParam(key, defaultValue);
}

int32_t OH_CommonEvent_GetLongArrayFromParameters(const CommonEventParameters* para, const char* key, long** array)
{
    if (para == nullptr || key == nullptr || array == nullptr) {
        EVENT_LOGE("Invalid para");
        array = nullptr;
        return 0;
    }
    auto want = *(reinterpret_cast<const std::shared_ptr<OHOS::AAFwk::Want>*>(para));
    if (want == nullptr) {
        EVENT_LOGE("Invalid para");
        array = nullptr;
        return 0;
    }
    return GetWantParamsArrayT<long>(want->GetLongArrayParam(key), array);
}

bool OH_CommonEvent_GetBoolFromParameters(const CommonEventParameters* para, const char* key, const bool defaultValue)
{
    if (para == nullptr || key == nullptr) {
        EVENT_LOGE("Invalid para");
        return defaultValue;
    }
    auto want = *(reinterpret_cast<const std::shared_ptr<OHOS::AAFwk::Want>*>(para));
    if (want == nullptr) {
        EVENT_LOGE("Invalid para");
        return defaultValue;
    }
    return want->GetBoolParam(key, defaultValue);
}

int32_t OH_CommonEvent_GetBoolArrayFromParameters(const CommonEventParameters* para, const char* key, bool** array)
{
    if (para == nullptr || key == nullptr || array == nullptr) {
        EVENT_LOGE("Invalid para");
        array = nullptr;
        return 0;
    }
    auto want = *(reinterpret_cast<const std::shared_ptr<OHOS::AAFwk::Want>*>(para));
    if (want == nullptr) {
        EVENT_LOGE("Invalid para");
        array = nullptr;
        return 0;
    }
    return GetWantParamsArrayT<bool>(want->GetBoolArrayParam(key), array);
}

char OH_CommonEvent_GetCharFromParameters(const CommonEventParameters* para, const char* key, const char defaultValue)
{
    if (para == nullptr || key == nullptr) {
        EVENT_LOGE("Invalid para");
        return defaultValue;
    }
    auto want = *(reinterpret_cast<const std::shared_ptr<OHOS::AAFwk::Want>*>(para));
    if (want == nullptr) {
        EVENT_LOGE("Invalid para");
        return defaultValue;
    }
    return want->GetCharParam(key, defaultValue);
}

int32_t OH_CommonEvent_GetCharArrayFromParameters(const CommonEventParameters* para, const char* key, char** array)
{
    if (para == nullptr || key == nullptr || array == nullptr) {
        EVENT_LOGE("Invalid para");
        array = nullptr;
        return 0;
    }
    auto want = *(reinterpret_cast<const std::shared_ptr<OHOS::AAFwk::Want>*>(para));
    if (want == nullptr) {
        EVENT_LOGE("Invalid para");
        array = nullptr;
        return 0;
    }
    std::string str = want->GetStringParam(key);
    *array = MallocCString(str);
    return str.length();
}

double OH_CommonEvent_GetDoubleFromParameters(const CommonEventParameters* para, const char* key,
    const char defaultValue)
{
    if (para == nullptr || key == nullptr) {
        EVENT_LOGE("Invalid para");
        return defaultValue;
    }
    auto want = *(reinterpret_cast<const std::shared_ptr<OHOS::AAFwk::Want>*>(para));
    if (want == nullptr) {
        EVENT_LOGE("Invalid para");
        return defaultValue;
    }
    return want->GetDoubleParam(key, defaultValue);
}

int32_t OH_CommonEvent_GetDoubleArrayFromParameters(const CommonEventParameters* para, const char* key, double** array)
{
    if (para == nullptr || key == nullptr || array == nullptr) {
        EVENT_LOGE("Invalid para");
        array = nullptr;
        return 0;
    }
    auto want = *(reinterpret_cast<const std::shared_ptr<OHOS::AAFwk::Want>*>(para));
    if (want == nullptr) {
        EVENT_LOGE("Invalid para");
        array = nullptr;
        return 0;
    }
    return GetWantParamsArrayT<double>(want->GetDoubleArrayParam(key), array);
}
#ifdef __cplusplus
}
#endif