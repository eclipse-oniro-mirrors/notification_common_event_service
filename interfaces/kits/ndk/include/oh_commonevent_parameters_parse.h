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
#ifndef OH_COMMONEVENT_PARAMETERS_PARSE_H
#define OH_COMMONEVENT_PARAMETERS_PARSE_H

#include <cstring>
#include <string>

#include "array_wrapper.h"
#include "bool_wrapper.h"
#include "double_wrapper.h"
#include "event_log_wrapper.h"
#include "int_wrapper.h"
#include "long_wrapper.h"
#include "oh_commonevent_wrapper.h"
#include "stdlib.h"
#include "string_wrapper.h"
#include "want_params_wrapper.h"
#include "zchar_wrapper.h"
namespace OHOS {
namespace EventFwk {

const int8_t I32_TYPE = 0;
const int8_t DOUBLE_TYPE = 1;
const int8_t STR_TYPE = 2;
const int8_t BOOL_TYPE = 3;
const int8_t I64_TYPE = 4;
const int8_t CHAR_TYPE = 5;
const int8_t I32_PTR_TYPE = 6;
const int8_t I64_PTR_TYPE = 7;
const int8_t BOOL_PTR_TYPE = 8;
const int8_t DOUBLE_PTR_TYPE = 9;
const int8_t STR_PTR_TYPE = 10;

template<class TBase, class T, class NativeT>
NativeT GetDataFromParams(const CArrParameters& parameters, const std::string& key, const NativeT defaultVal)
{
    TBase* ao = TBase::Query(parameters.wantParams.GetParam(key));
    if (ao == nullptr) {
        EVENT_LOGE(LOG_TAG_CES_CAPI, "No value");
        return defaultVal;
    }
    return T::Unbox(ao);
}

template<class T, class NativeT>
CommonEvent_ErrCode SetDataToParams(CArrParameters& parameters, const std::string& key, const NativeT value)
{
    parameters.wantParams.SetParam(key, T::Box(value));
    return COMMONEVENT_ERR_OK;
}

template<class TBase, class T, class NativeT>
int32_t GetDataArrayFromParams(const CArrParameters& parameters, const std::string& key, NativeT** array)
{
    AAFwk::IArray* ao = AAFwk::IArray::Query(parameters.wantParams.GetParam(key));
    if (ao == nullptr) {
        EVENT_LOGE(LOG_TAG_CES_CAPI, "No value");
        return 0;
    }

    long size = 0;
    if (ao->GetLength(size) != COMMONEVENT_ERR_OK) {
        EVENT_LOGD(LOG_TAG_CES_CAPI, "fail to get length");
        return 0;
    }
    *array = static_cast<NativeT*>(malloc(sizeof(NativeT) * size));
    if (*array == nullptr) {
        EVENT_LOGE(LOG_TAG_CES_CAPI, "malloc fail");
        return 0;
    }
    parameters.allocatedPointers.push_back(*array);
    for (long i = 0; i < size; i++) {
        sptr<AAFwk::IInterface> interface = nullptr;
        if (ao->Get(i, interface) == COMMONEVENT_ERR_OK) {
            TBase* iValue = TBase::Query(interface);
            if (iValue != nullptr) {
                (*array)[i] = T::Unbox(iValue);
            }
        }
    }
    return size;
}

template<class T, class NativeT>
CommonEvent_ErrCode SetDataArrayToParams(CArrParameters& parameters, const std::string& key, const NativeT* array,
    const size_t count, const AAFwk::InterfaceID iid)
{
    sptr<AAFwk::IArray> ao = new (std::nothrow) AAFwk::Array(count, iid);
    if (ao == nullptr) {
        return COMMONEVENT_ERR_ALLOC_MEMORY_FAILED;
    } else {
        for (size_t i = 0; i < count; ++i) {
            ao->Set(i, T::Box(array[i]));
        }
        parameters.wantParams.SetParam(key, ao);
        return COMMONEVENT_ERR_OK;
    }
}

int32_t GetStringFromParams(const CArrParameters& parameters, const std::string& key, char** str);
}  // namespace EventFwk
}  // namespace OHOS
#endif