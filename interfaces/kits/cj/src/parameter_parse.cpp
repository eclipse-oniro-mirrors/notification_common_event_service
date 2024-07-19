/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License")
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

#include "parameter_parse.h"

#include "native_log.h"
#include "int_wrapper.h"
#include "double_wrapper.h"
#include "string_wrapper.h"
#include "bool_wrapper.h"
#include "long_wrapper.h"
#include "array_wrapper.h"
#include "want_params_wrapper.h"
#include "securec.h"
#include <cinttypes>

namespace OHOS::CommonEventManager {
    const char *FD = "FD";
    const char *REMOTE_OBJECT = "RemoteObject";
    const char *TYPE_PROPERTY = "type";
    const char *VALUE_PROPERTY = "value";
    const int8_t I32_TYPE = 0;
    const int8_t DOUBLE_TYPE = 1;
    const int8_t STR_TYPE = 2;
    const int8_t BOOL_TYPE = 3;
    const int8_t FD_TYPE = 4;
    const int8_t STR_PTR_TYPE = 5;
    const int8_t I32_PTR_TYPE = 6;
    const int8_t I64_PTR_TYPE = 7;
    const int8_t BOOL_PTR_TYPE = 8;
    const int8_t DOUBLE_PTR_TYPE = 9;
    const int8_t FD_PTR_TYPE = 10;
    const int SUCCESS = 0;
    const int NONE_VALUE = 1;
    using Want = OHOS::AAFwk::Want;
    using WantParams = OHOS::AAFwk::WantParams;

    void charPtrToVector(char **charPtr, int size, std::vector<std::string> &result)
    {
        for (int i = 0; i < size; i++) {
            result.push_back(std::string(charPtr[i]));
        }
    }

    void SetFdData(std::string key, int *value, WantParams &wantP)
    {
        WantParams wp;
        wp.SetParam(TYPE_PROPERTY, OHOS::AAFwk::String::Box(FD));
        wp.SetParam(VALUE_PROPERTY, OHOS::AAFwk::Integer::Box(*value));
        sptr<OHOS::AAFwk::IWantParams> pWantParams = OHOS::AAFwk::WantParamWrapper::Box(wp);
        wantP.SetParam(key, pWantParams);
    }

    bool InnerSetWantParamsArrayString(
        const std::string &key, const std::vector<std::string> &value, AAFwk::WantParams &wantParams)
    {
        size_t size = value.size();
        sptr<AAFwk::IArray> ao = new (std::nothrow) AAFwk::Array(size, AAFwk::g_IID_IString);
        if (ao != nullptr) {
            for (size_t i = 0; i < size; i++) {
                ao->Set(i, AAFwk::String::Box(value[i]));
            }
            wantParams.SetParam(key, ao);
            return true;
        } else {
            return false;
        }
    }

    bool InnerSetWantParamsArrayInt(const std::string &key, const std::vector<int> &value,
        AAFwk::WantParams &wantParams)
    {
        size_t size = value.size();
        sptr<AAFwk::IArray> ao = new (std::nothrow) AAFwk::Array(size, AAFwk::g_IID_IInteger);
        if (ao != nullptr) {
            for (size_t i = 0; i < size; i++) {
                ao->Set(i, AAFwk::Integer::Box(value[i]));
            }
            wantParams.SetParam(key, ao);
            return true;
        } else {
            return false;
        }
    }

    bool InnerSetWantParamsArrayLong(const std::string &key, const std::vector<long> &value,
        AAFwk::WantParams &wantParams)
    {
        size_t size = value.size();
        sptr<AAFwk::IArray> ao = new (std::nothrow) AAFwk::Array(size, AAFwk::g_IID_ILong);
        if (ao != nullptr) {
            for (size_t i = 0; i < size; i++) {
                ao->Set(i, AAFwk::Long::Box(value[i]));
            }
            wantParams.SetParam(key, ao);
            return true;
        } else {
            return false;
        }
    }

    bool InnerSetWantParamsArrayBool(const std::string &key, const std::vector<bool> &value,
        AAFwk::WantParams &wantParams)
    {
        size_t size = value.size();
        sptr<AAFwk::IArray> ao = new (std::nothrow) AAFwk::Array(size, AAFwk::g_IID_IBoolean);
        if (ao != nullptr) {
            for (size_t i = 0; i < size; i++) {
                ao->Set(i, AAFwk::Boolean::Box(value[i]));
            }
            wantParams.SetParam(key, ao);
            return true;
        } else {
            return false;
        }
    }

    bool InnerSetWantParamsArrayDouble(
        const std::string &key, const std::vector<double> &value, AAFwk::WantParams &wantParams)
    {
        size_t size = value.size();
        sptr<AAFwk::IArray> ao = new (std::nothrow) AAFwk::Array(size, AAFwk::g_IID_IDouble);
        if (ao != nullptr) {
            for (size_t i = 0; i < size; i++) {
                ao->Set(i, AAFwk::Double::Box(value[i]));
            }
            wantParams.SetParam(key, ao);
            return true;
        } else {
            return false;
        }
    }

    void InnerSetWantParamsArrayFD(CParameters* head, int64_t size, AAFwk::WantParams &wantParams)
    {
        sptr<AAFwk::IArray> ao = new (std::nothrow) AAFwk::Array(size, AAFwk::g_IID_IWantParams);
        if (ao != nullptr) {
            for (size_t i = 0; i < static_cast<size_t>(size); i++) {
                WantParams wp;
                SetFdData(std::string(head->key), static_cast<int *>(head->value) + i, wp);
                wp.DumpInfo(0);
                ao->Set(i, OHOS::AAFwk::WantParamWrapper::Box(wp));
            }
            wantParams.SetParam(std::string(head->key), ao);
        }
        return;
    }

    void SetDataParameters(CArrParameters parameters, WantParams &wantP)
    {
        for (int i = 0; i < parameters.size; i++) {
            auto head = parameters.head + i;
            auto key = std::string(head->key);
            if (head->valueType == I32_TYPE) { // int32_t
                wantP.SetParam(key, OHOS::AAFwk::Integer::Box(*static_cast<int32_t *>(head->value)));
            } else if (head->valueType == DOUBLE_TYPE) { // double
                wantP.SetParam(key, OHOS::AAFwk::Double::Box(*static_cast<double *>(head->value)));
            } else if (head->valueType == STR_TYPE) { // std::string
                wantP.SetParam(key, OHOS::AAFwk::String::Box(std::string(static_cast<char *>(head->value))));
            } else if (head->valueType == BOOL_TYPE) { // bool
                wantP.SetParam(key, OHOS::AAFwk::Boolean::Box(*static_cast<bool *>(head->value)));
            } else if (head->valueType == FD_TYPE) { // "FD"
                SetFdData(key, static_cast<int *>(head->value), wantP);
            } else if (head->valueType == STR_PTR_TYPE) { // char**
                char **strPtr = static_cast<char **>(head->value);
                std::vector<std::string> strVec;
                charPtrToVector(strPtr, head->size, strVec);
                InnerSetWantParamsArrayString(key, strVec, wantP);
            } else if (head->valueType == I32_PTR_TYPE) { // int32_t*
                int *intArr = static_cast<int *>(head->value);
                std::vector<int> intVec(intArr, intArr + head->size);
                InnerSetWantParamsArrayInt(key, intVec, wantP);
            } else if (head->valueType == I64_PTR_TYPE) { // int64_t*
                long *longArr = static_cast<long *>(head->value);
                std::vector<long> longVec(longArr, longArr + head->size);
                InnerSetWantParamsArrayLong(key, longVec, wantP);
            } else if (head->valueType == BOOL_PTR_TYPE) { // bool*
                bool *boolArr = static_cast<bool *>(head->value);
                std::vector<bool> boolVec(boolArr, boolArr + head->size);
                InnerSetWantParamsArrayBool(key, boolVec, wantP);
            } else if (head->valueType == DOUBLE_PTR_TYPE) { // double*
                double *doubleArr = static_cast<double *>(head->value);
                std::vector<double> doubleVec(doubleArr, doubleArr + head->size);
                InnerSetWantParamsArrayDouble(key, doubleVec, wantP);
            } else if (head->valueType == FD_PTR_TYPE) { // FD*
                InnerSetWantParamsArrayFD(head, head->size, wantP);
            } else {
                LOGE("Wrong type!");
            }
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
        if (origin.empty() || code != NO_ERROR) {
            return nullptr;
        }
        auto len = origin.length() + 1;
        char *res = static_cast<char *>(malloc(sizeof(char) * len));
        if (res == nullptr) {
            code = ERR_NO_MEMORY;
            return nullptr;
        }
        return std::char_traits<char>::copy(res, origin.c_str(), len);
    }

    // WantParameters -> CArrParameters
    void InnerWrapWantParamsString(WantParams &wantParams, CParameters *p)
    {
        auto value = wantParams.GetParam(p->key);
        AAFwk::IString *ao = AAFwk::IString::Query(value);
        if (ao == nullptr) {
            LOGE("No value");
            return;
        }
        std::string natValue = OHOS::AAFwk::String::Unbox(ao);
        p->value = MallocCString(natValue);
        p->size = static_cast<int64_t>(natValue.length()) + 1;
        p->valueType = STR_TYPE;
    }

    template <class TBase, class T, class NativeT>
    void InnerWrapWantParamsT(WantParams &wantParams, CParameters *p)
    {
        auto value = wantParams.GetParam(p->key);
        TBase *ao = TBase::Query(value);
        if (ao == nullptr) {
            LOGE("No value");
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

    void InnerWrapWantParamsArrayString(sptr<AAFwk::IArray> &ao, CParameters *p)
    {
        long size = 0;
        if (ao->GetLength(size) != ERR_OK) {
            LOGE("fail to get length");
            return;
        }
        char **arrP = static_cast<char **>(malloc(sizeof(char *) * size));
        if (arrP == nullptr) {
            return;
        }
        for (long i = 0; i < size; i++) {
            sptr<AAFwk::IInterface> iface = nullptr;
            if (ao->Get(i, iface) == ERR_OK) {
                AAFwk::IString *iValue = AAFwk::IString::Query(iface);
                if (iValue != nullptr) {
                    auto val = AAFwk::String::Unbox(iValue);
                    arrP[i] = MallocCString(val);
                }
            }
        }
        p->size = size;
        p->value = static_cast<void *>(arrP);
    }

    void ClearParametersPtr(CParameters *p, int count, bool isKey)
    {
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
        free(p);
        p = nullptr;
    }

    template <class TBase, class T, class NativeT>
    void InnerWrapWantParamsArrayT(sptr<AAFwk::IArray> &ao, CParameters *p)
    {
        long size = 0;
        if (ao->GetLength(size) != ERR_OK) {
            LOGE("fail to get length");
            return;
        }
        NativeT *arrP = static_cast<NativeT *>(malloc(sizeof(NativeT) * size));
        if (arrP == nullptr) {
            return;
        }
        for (long i = 0; i < size; i++) {
            sptr<AAFwk::IInterface> iface = nullptr;
            if (ao->Get(i, iface) == ERR_OK) {
                TBase *iValue = TBase::Query(iface);
                if (iValue != nullptr) {
                    arrP[i] = T::Unbox(iValue);
                }
            }
        }
        p->size = size;
        p->value = static_cast<void *>(arrP);
    }

    int GetFDValue(WantParams &wantParams, std::string key, int *ptr)
    {
        auto value = wantParams.GetParam(key);
        AAFwk::IWantParams *o = AAFwk::IWantParams::Query(value);
        if (o == nullptr) {
            return NONE_VALUE;
        }
        AAFwk::WantParams wp = AAFwk::WantParamWrapper::Unbox(o);
        value = wp.GetParam(VALUE_PROPERTY);
        AAFwk::IInteger *ao = AAFwk::IInteger::Query(value);
        if (ao == nullptr) {
            LOGE("No value");
            return NONE_VALUE;
        }
        *ptr = OHOS::AAFwk::Integer::Unbox(ao);
        return SUCCESS;
    }

    void InnerWrapWantParamsFd(WantParams &wantParams, CParameters *p)
    {
        int *ptr = static_cast<int *>(malloc(sizeof(int)));
        if (ptr == nullptr) {
            return;
        }
        int error = GetFDValue(wantParams, std::string(p->key), ptr);
        if (error != SUCCESS) {
            free(ptr);
            return;
        }
        p->value = static_cast<void*>(ptr);
        p->size = sizeof(int32_t);
        p->valueType = FD_TYPE;
    }

    int InnerWrapWantParamsArrayFd(sptr<AAFwk::IArray> &ao, CParameters *p)
    {
        long size = 0;
        if (ao->GetLength(size) != ERR_OK) {
            LOGE("fail to get length");
            return NONE_VALUE;
        }
        int *arrP = static_cast<int *>(malloc(sizeof(int) * size));
        if (arrP == nullptr) {
            return NONE_VALUE;
        }
        for (long i = 0; i < size; i++) {
            sptr<AAFwk::IInterface> iface = nullptr;
            if (ao->Get(i, iface) == ERR_OK) {
                AAFwk::IWantParams *iValue = AAFwk::IWantParams::Query(iface);
                if (iValue == nullptr) {
                    free(arrP);
                    return NONE_VALUE;
                }
                WantParams wantP = AAFwk::WantParamWrapper::Unbox(iValue);
                int ret = GetFDValue(wantP, std::string(p->key), arrP + i);
                if (ret != SUCCESS) {
                    free(arrP);
                    return ret;
                }
            }
        }
        p->size = size;
        p->value = arrP;
        p->valueType = FD_PTR_TYPE;
        return SUCCESS;
    }

    void InnerWrapWantParamsArray(WantParams &wantParams, sptr<AAFwk::IArray> &ao, CParameters *p)
    {
        LOGI("%{public}s called. key=%{public}s", __func__, p->key);
        if (AAFwk::Array::IsStringArray(ao)) {
            p->valueType = STR_PTR_TYPE;
            InnerWrapWantParamsArrayString(ao, p);
            return;
        } else if (AAFwk::Array::IsBooleanArray(ao)) {
            p->valueType = BOOL_PTR_TYPE;
            return InnerWrapWantParamsArrayT<AAFwk::IBoolean, AAFwk::Boolean, bool>(ao, p);
        } else if (AAFwk::Array::IsIntegerArray(ao)) {
            p->valueType = I32_PTR_TYPE;
            return InnerWrapWantParamsArrayT<AAFwk::IInteger, AAFwk::Integer, int>(ao, p);
        } else if (AAFwk::Array::IsLongArray(ao)) {
            p->valueType = I64_PTR_TYPE;
            return InnerWrapWantParamsArrayT<AAFwk::ILong, AAFwk::Long, int64_t>(ao, p);
        } else if (AAFwk::Array::IsDoubleArray(ao)) {
            p->valueType = DOUBLE_PTR_TYPE;
            return InnerWrapWantParamsArrayT<AAFwk::IDouble, AAFwk::Double, double>(ao, p);
        } else if (AAFwk::Array::IsWantParamsArray(ao)) {
            p->valueType = FD_PTR_TYPE;
            InnerWrapWantParamsArrayFd(ao, p);
            return;
        } else {
            return;
        }
    }

    void ParseParameters(Want &want, CCommonEventData &cData, int32_t &code)
    {
        if (code != NO_ERROR) {
            return;
        }
        WantParams wantP = want.GetParams();
        std::map<std::string, sptr<OHOS::AAFwk::IInterface>> paramsMap = wantP.GetParams();
        int count = 0;
        auto size = static_cast<int64_t>(paramsMap.size());
        LOGI("paramsMap size = %{public}" PRId64, size);
        cData.parameters.head = static_cast<CParameters *>(malloc(sizeof(CParameters) * size));
        if (cData.parameters.head == nullptr) {
            return;
        }
        cData.parameters.size = size;
        for (auto iter = paramsMap.begin(); iter != paramsMap.end(); iter++) {
            auto ptr = cData.parameters.head + count;
            ptr->key = MallocCString(iter->first);
            if (ptr->key == nullptr) {
                code = ERR_NO_MEMORY;
                return ClearParametersPtr(cData.parameters.head, count, true);
            }
            ptr->value = nullptr;
            if (AAFwk::IString::Query(iter->second) != nullptr) {
                InnerWrapWantParamsString(wantP, ptr);
            } else if (AAFwk::IBoolean::Query(iter->second) != nullptr) {
                ptr->valueType = BOOL_TYPE;
                InnerWrapWantParamsT<AAFwk::IBoolean, AAFwk::Boolean, bool>(wantP, ptr);
            } else if (AAFwk::IInteger::Query(iter->second) != nullptr) {
                ptr->valueType = I32_TYPE;
                InnerWrapWantParamsT<AAFwk::IInteger, AAFwk::Integer, int>(wantP, ptr);
            } else if (AAFwk::IDouble::Query(iter->second) != nullptr) {
                ptr->valueType = DOUBLE_TYPE;
                InnerWrapWantParamsT<AAFwk::IDouble, AAFwk::Double, double>(wantP, ptr);
            } else if (AAFwk::IWantParams::Query(iter->second) != nullptr) {
                InnerWrapWantParamsFd(wantP, ptr);
            } else if (AAFwk::IArray::Query(iter->second) != nullptr) {
                AAFwk::IArray *ao = AAFwk::IArray::Query(iter->second);
                sptr<AAFwk::IArray> array(ao);
                InnerWrapWantParamsArray(wantP, array, ptr);
            }
            if (ptr->value == nullptr) {
                code = ERR_NO_MEMORY;
                return ClearParametersPtr(cData.parameters.head, count, false);
            }
            count++;
        }
    }

    void FreeCCommonEventDataCharPtr(CCommonEventData &cData)
    {
        free(cData.data);
        free(cData.event);
        free(cData.bundleName);
        cData.data = nullptr;
        cData.event = nullptr;
        cData.bundleName = nullptr;
    }

    int32_t GetCommonEventData(const CommonEventData &data, CCommonEventData &cData)
    {
        auto want = data.GetWant();
        cData.code = data.GetCode();
        int32_t code = NO_ERROR;
        cData.data = MallocCString(data.GetData(), code);
        cData.event = MallocCString(want.GetAction(), code);
        cData.bundleName = MallocCString(want.GetBundle(), code);
        ParseParameters(want, cData, code);
        if (code != NO_ERROR) {
            FreeCCommonEventDataCharPtr(cData);
        }
        return code;
    }
}