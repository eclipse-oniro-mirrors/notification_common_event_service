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

#include "event_log_wrapper.h"
#include "oh_commonevent_parameters_parse.h"
#include "oh_commonevent.h"
#include "want.h"
#include "int_wrapper.h"
#include "double_wrapper.h"
#include "string_wrapper.h"
#include "bool_wrapper.h"
#include "zchar_wrapper.h"
#include "long_wrapper.h"
#include "array_wrapper.h"
#include "want_params_wrapper.h"
#include "securec.h"
#include <memory>
#include <new>

// WantParameters -> CArrParameters
void InnerWrapWantParamsString(OHOS::AAFwk::WantParams &wantParams, CParameters *p)
{
    auto value = wantParams.GetParam(p->key);
    OHOS::AAFwk::IString *ao = OHOS::AAFwk::IString::Query(value);
    if (ao == nullptr) {
        EVENT_LOGE("No value");
        return;
    }
    std::string natValue = OHOS::AAFwk::String::Unbox(ao);
    p->value = MallocCString(natValue);
    p->size = static_cast<int64_t>(natValue.length()) + 1;
    p->valueType = STR_TYPE;
}

template <class TBase, class T, class NativeT>
void InnerWrapWantParamsT(OHOS::AAFwk::WantParams &wantParams, CParameters *p)
{
    auto value = wantParams.GetParam(p->key);
    TBase *ao = TBase::Query(value);
    if (ao == nullptr) {
        EVENT_LOGE("No value");
        return;
    }
    NativeT natValue = T::Unbox(ao);
    NativeT *ptr = static_cast<NativeT *>(malloc(sizeof(NativeT)));
    if (ptr == nullptr) {
        return;
    }
    *ptr = natValue;
    p->value = static_cast<void*>(ptr);
    p->size = sizeof(NativeT);
}

void InnerWrapWantParamsArrayString(OHOS::sptr<OHOS::AAFwk::IArray> &ao, CParameters *p)
{
    long size = 0;
    if (ao->GetLength(size) != COMMONEVENT_ERR_OK) {
        EVENT_LOGD("fail to get length");
        return;
    }
    char **arrP = static_cast<char **>(malloc(sizeof(char *) * size));
    if (arrP == nullptr) {
        return;
    }
    for (long i = 0; i < size; i++) {
        OHOS::sptr<OHOS::AAFwk::IInterface> iface = nullptr;
        if (ao->Get(i, iface) == COMMONEVENT_ERR_OK) {
            OHOS::AAFwk::IString *iValue = OHOS::AAFwk::IString::Query(iface);
            if (iValue != nullptr) {
                auto val = OHOS::AAFwk::String::Unbox(iValue);
                arrP[i] = MallocCString(val);
            }
        }
    }
    p->size = size;
    p->value = static_cast<void *>(arrP);
}

void ClearParametersPtr(CParameters **ptr, int count, bool isKey)
{
    CParameters *p = *ptr;
    for (int i = 0; i < count; i++) {
        free(p[i].key);
        free(p[i].value);
        p[i].key = nullptr;
        p[i].value = nullptr;
    }
    if (!isKey) {
        free(p[count].key);
        p[count].key = nullptr;
    }
    free(*ptr);
    *ptr = nullptr;
}

template <class TBase, class T, class NativeT>
void InnerWrapWantParamsArrayT(OHOS::sptr<OHOS::AAFwk::IArray> &ao, CParameters *p)
{
    long size = 0;
    if (ao->GetLength(size) != COMMONEVENT_ERR_OK) {
        EVENT_LOGD("fail to get length");
        return;
    }
    NativeT *arrP = static_cast<NativeT *>(malloc(sizeof(NativeT) * size));
    if (arrP == nullptr) {
        return;
    }
    for (long i = 0; i < size; i++) {
        OHOS::sptr<OHOS::AAFwk::IInterface> iface = nullptr;
        if (ao->Get(i, iface) == COMMONEVENT_ERR_OK) {
            TBase *iValue = TBase::Query(iface);
            if (iValue != nullptr) {
                arrP[i] = T::Unbox(iValue);
            }
        }
    }
    p->size = size;
    p->value = static_cast<void *>(arrP);
}

void InnerWrapWantParamsArray(OHOS::AAFwk::WantParams &wantParams, OHOS::sptr<OHOS::AAFwk::IArray> &ao, CParameters *p)
{
    if (OHOS::AAFwk::Array::IsBooleanArray(ao)) {
        p->valueType = BOOL_PTR_TYPE;
        return InnerWrapWantParamsArrayT<OHOS::AAFwk::IBoolean, OHOS::AAFwk::Boolean, bool>(ao, p);
    } else if (OHOS::AAFwk::Array::IsIntegerArray(ao)) {
        p->valueType = I32_PTR_TYPE;
        return InnerWrapWantParamsArrayT<OHOS::AAFwk::IInteger, OHOS::AAFwk::Integer, int>(ao, p);
    } else if (OHOS::AAFwk::Array::IsLongArray(ao)) {
        p->valueType = I64_PTR_TYPE;
        return InnerWrapWantParamsArrayT<OHOS::AAFwk::ILong, OHOS::AAFwk::Long, int64_t>(ao, p);
    } else if (OHOS::AAFwk::Array::IsDoubleArray(ao)) {
        p->valueType = DOUBLE_PTR_TYPE;
        return InnerWrapWantParamsArrayT<OHOS::AAFwk::IDouble, OHOS::AAFwk::Double, double>(ao, p);
    } else {
        return;
    }
}

void ParseParameters(OHOS::AAFwk::Want &want, CArrParameters* parameters, int32_t &code)
{
    if (code != COMMONEVENT_ERR_OK || parameters == nullptr) {
        return;
    }
    OHOS::AAFwk::WantParams wantP = want.GetParams();
    std::map<std::string, OHOS::sptr<OHOS::AAFwk::IInterface>> paramsMap = wantP.GetParams();
    int count = 0;
    auto size = static_cast<int64_t>(paramsMap.size());
    
    parameters->head = static_cast<CParameters *>(malloc(sizeof(CParameters) * size));
    if (parameters->head == nullptr) {
        return;
    }
    parameters->size = size;
    for (auto iter = paramsMap.begin(); iter != paramsMap.end(); iter++) {
        auto ptr = parameters->head + count;
        ptr->key = MallocCString(iter->first);
        if (ptr->key == nullptr) {
            code = COMMONEVENT_ERR_SYSTEM;
            parameters->size = 0;
            return ClearParametersPtr(&parameters->head, count, true);
        }
        ptr->value = nullptr;
        if (OHOS::AAFwk::IString::Query(iter->second) != nullptr) {
            InnerWrapWantParamsString(wantP, ptr);
        } else if (OHOS::AAFwk::IBoolean::Query(iter->second) != nullptr) {
            ptr->valueType = BOOL_TYPE;
            InnerWrapWantParamsT<OHOS::AAFwk::IBoolean, OHOS::AAFwk::Boolean, bool>(wantP, ptr);
        } else if (OHOS::AAFwk::IChar::Query(iter->second) != nullptr) {
            ptr->valueType = CHAR_TYPE;
            InnerWrapWantParamsT<OHOS::AAFwk::IChar, OHOS::AAFwk::Char, char>(wantP, ptr);
        } else if (OHOS::AAFwk::IInteger::Query(iter->second) != nullptr) {
            ptr->valueType = I32_TYPE;
            InnerWrapWantParamsT<OHOS::AAFwk::IInteger, OHOS::AAFwk::Integer, int>(wantP, ptr);
        } else if (OHOS::AAFwk::IDouble::Query(iter->second) != nullptr) {
            ptr->valueType = DOUBLE_TYPE;
            InnerWrapWantParamsT<OHOS::AAFwk::IDouble, OHOS::AAFwk::Double, double>(wantP, ptr);
        } else if (OHOS::AAFwk::ILong::Query(iter->second) != nullptr) {
            ptr->valueType = I64_TYPE;
            InnerWrapWantParamsT<OHOS::AAFwk::ILong, OHOS::AAFwk::Long, int64_t>(wantP, ptr);
        } else if (OHOS::AAFwk::IArray::Query(iter->second) != nullptr) {
            OHOS::AAFwk::IArray *ao = OHOS::AAFwk::IArray::Query(iter->second);
            OHOS::sptr<OHOS::AAFwk::IArray> array(ao);
            InnerWrapWantParamsArray(wantP, array, ptr);
        }
        count++;
    }
}

char *MallocCString(const std::string &origin)
{
    if (origin.empty()) {
        return nullptr;
    }
    auto len = origin.length() + 1;
    char *res = static_cast<char *>(malloc(sizeof(char) * len));
    if (res == nullptr) {
        return nullptr;
    }
    return std::char_traits<char>::copy(res, origin.c_str(), len);
}

char *MallocCString(const std::string &origin, int32_t &code)
{
    if (origin.empty() || code != COMMONEVENT_ERR_OK) {
        return nullptr;
    }
    auto len = origin.length() + 1;
    char *res = static_cast<char *>(malloc(sizeof(char) * len));
    if (res == nullptr) {
        code = COMMONEVENT_ERR_SYSTEM;
        return nullptr;
    }
    return std::char_traits<char>::copy(res, origin.c_str(), len);
}

void FreeCCommonEventDataCharPtr(CommonEvent_RcvData *cData)
{
    free(cData->data);
    free(cData->event);
    free(cData->bundleName);
    cData->data = nullptr;
    cData->event = nullptr;
    cData->bundleName = nullptr;
}

int32_t GetCommonEventData(const OHOS::EventFwk::CommonEventData &data, CommonEvent_RcvData *cData)
{
    auto want = data.GetWant();
    cData->code = data.GetCode();
    int32_t code = COMMONEVENT_ERR_OK;
    cData->data = MallocCString(data.GetData(), code);
    cData->event = MallocCString(want.GetAction(), code);
    cData->bundleName = MallocCString(want.GetBundle(), code);
    cData->parameters = new (std::nothrow) CArrParameters();
    ParseParameters(want, cData->parameters, code);
    return code;
}

void FreeCCommonEventData(CommonEvent_RcvData *cData)
{
    EVENT_LOGD("free commonEventData");
    FreeCCommonEventDataCharPtr(cData);
    auto parameters = cData->parameters;
    if (parameters != nullptr && parameters->head != nullptr) {
        for (int i = 0; i < parameters->size; i++) {
            auto ptr = parameters->head[i];
            free(ptr.key);
            ptr.key = nullptr;
            free(ptr.value);
            ptr.value = nullptr;
        }
        free(parameters->head);
        parameters->head = nullptr;
        parameters->size = 0;
    }
    cData->parameters = nullptr;
    free(cData);
}

bool HasKeyFromParameters(const CArrParameters* parameters, const char* key)
{
    if (parameters->head == nullptr) {
        EVENT_LOGI("head is null");
        return false;
    }
    for (int i = 0; i < parameters->size; i++) {
        CParameters *it = parameters->head + i;
        if (std::strcmp(it->key, key) == 0) {
            return true;
        }
    }
    return false;
}