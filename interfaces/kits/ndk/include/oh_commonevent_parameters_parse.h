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

#include "oh_commonevent_wrapper.h"
#include "securec.h"
#include "stdlib.h"
#include <string>
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

char *MallocCString(const std::string &origin);
int32_t GetCommonEventData(const CommonEventData &data, CommonEvent_RcvData* cData);
void FreeCCommonEventDataCharPtr(CommonEvent_RcvData* cData);
void FreeCCommonEventData(CommonEvent_RcvData* cData);
bool HasKeyFromParameters(const CArrParameters* parameters, const char* key);

template <class T>
T GetDataFromParams(const CArrParameters* parameters, const char* key, int8_t type, T defaultVal)
{
    if (parameters->head == nullptr) {
        return defaultVal;
    }
    for (int i = 0; i < parameters->size; i++) {
        CParameters *it = parameters->head + i;
        if (it->valueType == type && std::strcmp(it->key, key) == 0) {
            return *(static_cast<T *>(it->value));
        }
    }
    return defaultVal;
}

template <class T>
int32_t GetDataArrayFromParams(const CArrParameters* parameters, const char* key, int8_t type, T** array)
{
    if (parameters->head == nullptr) {
        return 0;
    }
    for (int i = 0; i < parameters->size; i++) {
        CParameters *it = parameters->head + i;
        if (it->valueType == type && std::strcmp(it->key, key) == 0) {
            *array = static_cast<T *>(it->value);
            return it->size;
        }
    }
    return 0;
}
}  // namespace EventFwk
}  // namespace OHOS
#endif