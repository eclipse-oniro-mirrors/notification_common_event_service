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

#include "common_event_manager_ffi.h"
#include "common_event_constant.h"
#include "common_event_manager_impl.h"
#include "common_event.h"

#include "native_log.h"
#include "cj_lambda.h"
#include "securec.h"
using namespace OHOS::FFI;
using CommonEventManagerImpl = OHOS::CommonEventManager::CommonEventManagerImpl;

namespace OHOS::CommonEventManager {
    template<typename T, int version>
    sptr<T> ConvertInstance(int64_t id)
    {
        if constexpr (version == 0) {
            return FFIData::GetData<T>(id);
        } else {
            return *reinterpret_cast<sptr<T>*>(id);
        }
    }

    template<int version>
    int64_t CreateSubscriber(int64_t id, int64_t (*createSubscribeManager)(sptr<CommonEventSubscribeInfoImpl>, int64_t))
    {
        bool haveId = false;
        int64_t managerId = GetManagerId(id, haveId);
        if (haveId) {
            return managerId;
        }
        auto instance = ConvertInstance<CommonEventSubscribeInfoImpl, version>(id);
        if (!instance) {
            LOGE("CommonEventSubscribeInfoImpl instance not exist %{public}" PRId64, id);
            return static_cast<int64_t>(ERR_INVALID_INSTANCE_ID);
        }
        return createSubscribeManager(instance, id);
    }

    template<int version>
    int32_t Subscribe(int64_t id, void (*callbackRef)(const CCommonEventData data))
    {
        auto instance = ConvertInstance<SubscriberManager, version>(id);
        if (!instance) {
            LOGE("SubscriberManager instance not exist %{public}" PRId64, id);
            return ERR_INVALID_INSTANCE_CODE;
        }
        auto subscriber = instance->GetSubscriber();
        if (!subscriber) {
            return ERR_INVALID_INSTANCE_CODE;
        }
        auto onChange = [lambda = CJLambda::Create(callbackRef)](const CCommonEventData data) -> void {
            lambda(data);
        };
        return CommonEventManagerImpl::Subscribe(subscriber, onChange);
    }

    template<int version>
    int32_t Unsubscribe(int64_t id)
    {
        auto instance = ConvertInstance<SubscriberManager, version>(id);
        if (!instance) {
            LOGE("SubscriberManager instance not exist %{public}" PRId64, id);
            return ERR_INVALID_INSTANCE_CODE;
        }
        auto subscriber = instance->GetSubscriber();
        if (!subscriber) {
            return ERR_INVALID_INSTANCE_CODE;
        }
        return CommonEventManagerImpl::Unsubscribe(subscriber);
    }

    template<int version>
    RetDataI32 GetCode(int64_t id)
    {
        RetDataI32 ret = {.code = ERR_INVALID_INSTANCE_CODE, .data = 0};
        auto instance = ConvertInstance<SubscriberManager, version>(id);
        if (!instance) {
            LOGE("SubscriberManager instance not exist %{public}" PRId64, id);
            return ret;
        }
        auto subscriber = instance->GetSubscriber();
        if (!subscriber) {
            return ret;
        }
        GetSubscriberCode(subscriber, ret.data);
        ret.code = NO_ERROR;
        return ret;
    }

    template<int version>
    int32_t SetCode(int64_t id, int32_t code)
    {
        auto instance = ConvertInstance<SubscriberManager, version>(id);
        if (!instance) {
            LOGE("SubscriberManager instance not exist %{public}" PRId64, id);
            return ERR_INVALID_INSTANCE_CODE;
        }
        auto subscriber = instance->GetSubscriber();
        if (!subscriber) {
            return ERR_INVALID_INSTANCE_CODE;
        }
        return SetSubscriberCode(subscriber, code);
    }

    template<int version>
    RetDataCString GetData(int64_t id)
    {
        RetDataCString ret = {.code = ERR_INVALID_INSTANCE_CODE, .data = nullptr};
        auto instance = ConvertInstance<SubscriberManager, version>(id);
        if (!instance) {
            LOGE("SubscriberManager instance not exist %{public}" PRId64, id);
            return ret;
        }
        auto subscriber = instance->GetSubscriber();
        if (!subscriber) {
            return ret;
        }
        int32_t code = NO_ERROR;
        ret.data = MallocCString(GetSubscriberData(subscriber), code);
        ret.code = code;
        return ret;
    }

    template<int version>
    int32_t SetData(int64_t id, char *data)
    {
        auto instance = ConvertInstance<SubscriberManager, version>(id);
        if (!instance) {
            LOGE("SubscriberManager instance not exist %{public}" PRId64, id);
            return ERR_INVALID_INSTANCE_CODE;
        }
        auto subscriber = instance->GetSubscriber();
        if (!subscriber) {
            return ERR_INVALID_INSTANCE_CODE;
        }
        return SetSubscriberData(subscriber, data);
    }

    template<int version>
    int32_t SetCodeAndData(int64_t id, int32_t code, char *data)
    {
        auto instance = ConvertInstance<SubscriberManager, version>(id);
        if (!instance) {
            LOGE("SubscriberManager instance not exist %{public}" PRId64, id);
            return ERR_INVALID_INSTANCE_CODE;
        }
        auto subscriber = instance->GetSubscriber();
        if (!subscriber) {
            return ERR_INVALID_INSTANCE_CODE;
        }
        return SetSubscriberCodeAndData(subscriber, code, data);
    }

    template<int version>
    RetDataBool IsOrderedCommonEvent(int64_t id)
    {
        RetDataBool ret = {.code = ERR_INVALID_INSTANCE_CODE, .data = false};
        auto instance = ConvertInstance<SubscriberManager, version>(id);
        if (!instance) {
            LOGE("SubscriberManager instance not exist %{public}" PRId64, id);
            return ret;
        }
        auto subscriber = instance->GetSubscriber();
        if (!subscriber) {
            return ret;
        }
        IsCommonEventOrdered(subscriber, ret.data);
        ret.code = NO_ERROR;
        return ret;
    }

    template<int version>
    RetDataBool IsStickyCommonEvent(int64_t id)
    {
        RetDataBool ret = {.code = ERR_INVALID_INSTANCE_CODE, .data = false};
        auto instance = ConvertInstance<SubscriberManager, version>(id);
        if (!instance) {
            LOGE("SubscriberManager instance not exist %{public}" PRId64, id);
            return ret;
        }
        auto subscriber = instance->GetSubscriber();
        if (!subscriber) {
            return ret;
        }
        IsCommonEventSticky(subscriber, ret.data);
        ret.code = NO_ERROR;
        return ret;
    }

    template<int version>
    int32_t AbortCommonEvent(int64_t id)
    {
        auto instance = ConvertInstance<SubscriberManager, version>(id);
        if (!instance) {
            LOGE("SubscriberManager instance not exist %{public}" PRId64, id);
            return ERR_INVALID_INSTANCE_CODE;
        }

        auto subscriber = instance->GetSubscriber();
        if (!subscriber) {
            return ERR_INVALID_INSTANCE_CODE;
        }
        std::shared_ptr<AsyncCommonEventResult> result = GetAsyncResult(subscriber.get());
        if (!result) {
            LOGE("SubscriberManager result not exist %{public}" PRId64, id);
            return ERR_CES_FAILED;
        }

        return result->AbortCommonEvent() ? SUCCESS_CODE : ERR_CES_FAILED;
    }

    template<int version>
    int32_t ClearAbortCommonEvent(int64_t id)
    {
        auto instance = ConvertInstance<SubscriberManager, version>(id);
        if (!instance) {
            LOGE("SubscriberManager instance not exist %{public}" PRId64, id);
            return ERR_INVALID_INSTANCE_CODE;
        }

        auto subscriber = instance->GetSubscriber();
        if (!subscriber) {
            return ERR_INVALID_INSTANCE_CODE;
        }
        std::shared_ptr<AsyncCommonEventResult> result = GetAsyncResult(subscriber.get());
        if (!result) {
            LOGE("SubscriberManager result not exist %{public}" PRId64, id);
            return ERR_CES_FAILED;
        }

        return result->ClearAbortCommonEvent() ? SUCCESS_CODE : ERR_CES_FAILED;
    }

    template<int version>
    RetDataBool GetAbortCommonEvent(int64_t id)
    {
        RetDataBool ret = {.code = ERR_INVALID_INSTANCE_CODE, .data = false};
        auto instance = ConvertInstance<SubscriberManager, version>(id);
        if (!instance) {
            LOGE("SubscriberManager instance not exist %{public}" PRId64, id);
            return ret;
        }

        auto subscriber = instance->GetSubscriber();
        if (!subscriber) {
            return ret;
        }
        std::shared_ptr<AsyncCommonEventResult> result = GetAsyncResult(subscriber.get());
        if (!result) {
            LOGE("SubscriberManager result not exist %{public}" PRId64, id);
            ret.code = ERR_CES_FAILED;
            return ret;
        }

        ret.data = result->GetAbortCommonEvent();
        ret.code = SUCCESS_CODE;
        return ret;
    }

    template<int version>
    RetDataI64 GetSubscribeInfo(int64_t id)
    {
        RetDataI64 ret = {.code = ERR_INVALID_INSTANCE_ID, .data = 0};
        auto instance = ConvertInstance<SubscriberManager, version>(id);
        if (!instance) {
            LOGE("SubscriberManager instance not exist %{public}" PRId64, id);
            return ret;
        }
        ret.code = instance->GetSubscribeInfoId(ret.data);
        return ret;
    }

    template<int version>
    int32_t FinishCommonEvent(int64_t id)
    {
        int32_t errorCode = NO_ERROR;
        auto instance = ConvertInstance<SubscriberManager, version>(id);
        if (!instance) {
            LOGE("SubscriberManager instance not exist %{public}" PRId64, id);
            return ERR_INVALID_INSTANCE_ID;
        }
        auto subscriber = instance->GetSubscriber();
        if (!subscriber) {
            return ERR_INVALID_INSTANCE_ID;
        }
        std::shared_ptr<AsyncCommonEventResult> result = GetAsyncResult(subscriber.get());
        if (result) {
            errorCode = result->FinishCommonEvent() ? NO_ERROR : ERR_CES_FAILED;
        }
        return errorCode;
    }

    std::shared_ptr<CommonEventSubscribeInfo> CreateCommonEventSubscribeInfo(CSubscribeInfo *info)
    {
        OHOS::EventFwk::MatchingSkills matchingSkills;
        for (int64_t i = 0; i < info->events.size; ++i) {
            std::string event(info->events.head[i]);
            matchingSkills.AddEvent(event);
        }
        auto infoPtr = std::make_shared<CommonEventSubscribeInfo>(matchingSkills);
        if (info->publisherPermission) {
            std::string permission(info->publisherPermission);
            infoPtr->SetPermission(permission);
        }
        if (info->publisherDeviceId) {
            std::string deviceId(info->publisherDeviceId);
            infoPtr->SetDeviceId(deviceId);
        }
        if (info->publisherBundleName) {
            std::string bundleName(info->publisherBundleName);
            infoPtr->SetPublisherBundleName(bundleName);
        }
        infoPtr->SetUserId(info->userId);
        infoPtr->SetPriority(info->priority);
        return infoPtr;
    }

    template<int version>
    void SetPermission(int64_t id, char *value)
    {
        auto instance = ConvertInstance<CommonEventSubscribeInfoImpl, version>(id);
        if (!instance) {
            LOGE("CommonEventSubscribeInfoImpl instance not exist %{public}" PRId64, id);
            return;
        }

        return instance->SetPermission(std::string(value));
    }

    template<int version>
    void SetDeviceId(int64_t id, const char *value)
    {
        auto instance = ConvertInstance<CommonEventSubscribeInfoImpl, version>(id);
        if (!instance) {
            LOGE("CommonEventSubscribeInfoImpl instance not exist %{public}" PRId64, id);
            return;
        }
        return instance->SetDeviceId(std::string(value));
    }

    template<int version>
    void SetUserId(int64_t id, int32_t value)
    {
        auto instance = ConvertInstance<CommonEventSubscribeInfoImpl, version>(id);
        if (!instance) {
            LOGE("CommonEventSubscribeInfoImpl instance not exist %{public}" PRId64, id);
            return;
        }
        return instance->SetUserId(value);
    }

    template<int version>
    void SetPriority(int64_t id, int32_t value)
    {
        auto instance = ConvertInstance<CommonEventSubscribeInfoImpl, version>(id);
        if (!instance) {
            LOGE("CommonEventSubscribeInfoImpl instance not exist %{public}" PRId64, id);
            return;
        }
        return instance->SetPriority(value);
    }

    template<int version>
    void SetBundleName(int64_t id, const char *value)
    {
        auto instance = ConvertInstance<CommonEventSubscribeInfoImpl, version>(id);
        if (!instance) {
            LOGE("CommonEventSubscribeInfoImpl instance not exist %{public}" PRId64, id);
            return;
        }
        return instance->SetPublisherBundleName(std::string(value));
    }

    template<int version>
    const char *GetPermission(int64_t id)
    {
        auto instance = ConvertInstance<CommonEventSubscribeInfoImpl, version>(id);
        if (!instance) {
            LOGE("CommonEventSubscribeInfoImpl instance not exist %{public}" PRId64, id);
            return nullptr;
        }
        auto str = instance->GetPermission();
        auto ret = MallocCString(str);
        return ret;
    }

    template<int version>
    const char *GetDeviceId(int64_t id)
    {
        auto instance = ConvertInstance<CommonEventSubscribeInfoImpl, version>(id);
        if (!instance) {
            LOGE("CJ_GetDeviceId instance not exist %{public}" PRId64, id);
            return nullptr;
        }
        auto str = instance->GetDeviceId();
        auto ret = MallocCString(str);
        return ret;
    }

    template<int version>
    int32_t GetUserId(int64_t id)
    {
        auto instance = ConvertInstance<CommonEventSubscribeInfoImpl, version>(id);
        if (!instance) {
            LOGE("CommonEventSubscribeInfoImpl instance not exist %{public}" PRId64, id);
            return 0;
        }
        return instance->GetUserId();
    }

    template<int version>
    int32_t GetPriority(int64_t id)
    {
        auto instance = ConvertInstance<CommonEventSubscribeInfoImpl, version>(id);
        if (!instance) {
            LOGE("CommonEventSubscribeInfoImpl instance not exist %{public}" PRId64, id);
            return 0;
        }
        return instance->GetPriority();
    }

    template<int version>
    const char *GetBundleName(int64_t id)
    {
        auto instance = ConvertInstance<CommonEventSubscribeInfoImpl, version>(id);
        if (!instance) {
            LOGE("CJ_GetBundleName instance not exist %{public}" PRId64, id);
            return nullptr;
        }
        auto str = instance->GetPublisherBundleName();
        auto ret = MallocCString(str);
        return ret;
    }

    void ClearCharPointer(char** ptr, int count)
    {
        for (int i = 0; i < count; i++) {
            free(ptr[i]);
            ptr[i] = nullptr;
        }
    }

    char **VectorToCharPointer(std::vector<std::string> &vec)
    {
        char** result = static_cast<char**>(malloc(sizeof(char*) * vec.size()));
        if (result == nullptr) {
            return nullptr;
        }
        for (size_t i = 0; i < vec.size(); i++) {
            result[i] = MallocCString(vec[i]);
            if (result[i] == nullptr) {
                ClearCharPointer(result, i);
                free(result);
                return nullptr;
            }
        }
        return result;
    }

    template<int version>
    CArrString GetEvents(int64_t id)
    {
        auto instance = ConvertInstance<CommonEventSubscribeInfoImpl, version>(id);
        CArrString ret = {.head = nullptr, .size = 0};
        if (!instance) {
            LOGE("CJ_GetEvents instance not exist %{public}" PRId64, id);
            return ret;
        }
        auto vStr = instance->GetEvents();
        if (vStr.size() == 0) {
            return ret;
        }
        ret.head = VectorToCharPointer(vStr);
        ret.size = static_cast<int64_t>(vStr.size());
        if (ret.head == nullptr) {
            LOGE("Failed to malloc.");
            ret.size = 0;
        }
        return ret;
    }

    extern "C"
    {
        int32_t CJ_PublishEvent(char *event, int32_t userId)
        {
            return CommonEventManagerImpl::PublishEvent(event, userId);
        }

        int32_t CJ_PublishEventWithData(char *event, int32_t userId, CommonEventPublishDataBycj options)
        {
            return CommonEventManagerImpl::PublishEventWithData(event, userId, options);
        }

        int32_t CJ_SetStaticSubscriberState(bool enable)
        {
            return CommonEventManagerImpl::SetStaticSubscriberState(enable);
        }

        int32_t CJ_RemoveStickyCommonEvent(char *event)
        {
            return CommonEventManagerImpl::RemoveStickyCommonEvent(event);
        }

        int64_t CJ_CreateCommonEventSubscribeInfo(CArrString events)
        {
            auto infoPtr = CommonEventManagerImpl::CreateCommonEventSubscribeInfo(events.head, events.size);
            auto ptr = FFIData::Create<CommonEventSubscribeInfoImpl>(infoPtr);
            if (!ptr) {
                return static_cast<int64_t>(ERR_INVALID_INSTANCE_ID);
            }
            return ptr->GetID();
        }

        FFI_EXPORT int64_t FfiOHOSCreateCommonEventSubscribeInfo(CArrString events)
        {
            auto infoPtr = CommonEventManagerImpl::CreateCommonEventSubscribeInfo(events.head, events.size);
            sptr<CommonEventSubscribeInfoImpl> info = new CommonEventSubscribeInfoImpl(infoPtr);
            auto* ptr = new sptr<CommonEventSubscribeInfoImpl>(info);
            return reinterpret_cast<int64_t>(ptr);
        }

        int64_t CreateSubscribeManager(sptr<CommonEventSubscribeInfoImpl> info, int64_t infoID)
        {
            auto infoPtr = info->GetInfoPtr();
            auto ptr = SubscriberManager::Create(infoPtr, infoID);
            if (!ptr) {
                return static_cast<int64_t>(ERR_INVALID_INSTANCE_ID);
            }
            return ptr->GetID();
        }

        int64_t CreateSubscribeManagerV2(sptr<CommonEventSubscribeInfoImpl> info, int64_t infoID)
        {
            auto infoPtr = info->GetInfoPtr();
            auto mgrAddr = SubscriberManager::CreateID(infoPtr, infoID);
            return mgrAddr;
        }

        int64_t CJ_CreateSubscriber(int64_t id)
        {
            return CreateSubscriber<0>(id, CreateSubscribeManager);
        }

        FFI_EXPORT int64_t FfiOHOSCreateSubscriber(int64_t id)
        {
            return CreateSubscriber<1>(id, CreateSubscribeManagerV2);
        }

        int64_t FfiCommonEventManagerCreateSubscriber(CSubscribeInfo *info, int32_t *errorCode)
        {
            auto infoPtr = CreateCommonEventSubscribeInfo(info);
            auto mgrPtr = SubscriberManager::Create(infoPtr);
            if (!mgrPtr) {
                *errorCode = ERR_INVALID_INSTANCE_ID;
                return 0;
            }
            return mgrPtr->GetID();
        }

        FFI_EXPORT int64_t FfiCommonEventManagerCreateSubscriberV2(CSubscribeInfo *info)
        {
            auto infoPtr = CreateCommonEventSubscribeInfo(info);
            auto mgrAddr = SubscriberManager::CreateID(infoPtr);
            return mgrAddr;
        }

        int32_t CJ_Subscribe(int64_t id, void (*callbackRef)(const CCommonEventData data))
        {
            return Subscribe<0>(id, callbackRef);
        }

        FFI_EXPORT int32_t FfiOHOSSubscribe(int64_t id, void (*callbackRef)(const CCommonEventData data))
        {
            return Subscribe<1>(id, callbackRef);
        }

        int32_t CJ_Unsubscribe(int64_t id)
        {
            return Unsubscribe<0>(id);
        }

        FFI_EXPORT int32_t FfiOHOSUnsubscribe(int64_t id)
        {
            return Unsubscribe<1>(id);
        }

        RetDataI32 CJ_GetCode(int64_t id)
        {
            return GetCode<0>(id);
        }

        FFI_EXPORT RetDataI32 FfiOHOSGetCode(int64_t id)
        {
            return GetCode<1>(id);
        }

        int32_t CJ_SetCode(int64_t id, int32_t code)
        {
            return SetCode<0>(id, code);
        }

        int32_t FfiOHOSSetCode(int64_t id, int32_t code)
        {
            return SetCode<1>(id, code);
        }

        RetDataCString CJ_GetData(int64_t id)
        {
            return GetData<0>(id);
        }

        FFI_EXPORT RetDataCString FfiOHOSGetData(int64_t id)
        {
            return GetData<1>(id);
        }

        int32_t CJ_SetData(int64_t id, char *data)
        {
            return SetData<0>(id, data);
        }

        FFI_EXPORT int32_t FfiOHOSSetData(int64_t id, char *data)
        {
            return SetData<1>(id, data);
        }

        int32_t CJ_SetCodeAndData(int64_t id, int32_t code, char *data)
        {
            return SetCodeAndData<0>(id, code, data);
        }

        FFI_EXPORT int32_t FfiOHOSSetCodeAndData(int64_t id, int32_t code, char *data)
        {
            return SetCodeAndData<1>(id, code, data);
        }

        RetDataBool CJ_IsOrderedCommonEvent(int64_t id)
        {
            return IsOrderedCommonEvent<0>(id);
        }

        FFI_EXPORT RetDataBool FfiOHOSIsOrderedCommonEvent(int64_t id)
        {
            return IsOrderedCommonEvent<1>(id);
        }

        RetDataBool CJ_IsStickyCommonEvent(int64_t id)
        {
            return IsStickyCommonEvent<0>(id);
        }

        FFI_EXPORT RetDataBool FfiOHOSIsStickyCommonEvent(int64_t id)
        {
            return IsStickyCommonEvent<1>(id);
        }

        int32_t CJ_AbortCommonEvent(int64_t id)
        {
            return AbortCommonEvent<0>(id);
        }

        FFI_EXPORT int32_t FfiOHOSAbortCommonEvent(int64_t id)
        {
            return AbortCommonEvent<1>(id);
        }

        int32_t CJ_ClearAbortCommonEvent(int64_t id)
        {
            return ClearAbortCommonEvent<0>(id);
        }

        FFI_EXPORT int32_t FfiOHOSClearAbortCommonEvent(int64_t id)
        {
            return ClearAbortCommonEvent<1>(id);
        }

        RetDataBool CJ_GetAbortCommonEvent(int64_t id)
        {
            return GetAbortCommonEvent<0>(id);
        }

        FFI_EXPORT RetDataBool FfiOHOSGetAbortCommonEvent(int64_t id)
        {
            return GetAbortCommonEvent<1>(id);
        }

        RetDataI64 CJ_GetSubscribeInfo(int64_t id)
        {
            return GetSubscribeInfo<0>(id);
        }

        FFI_EXPORT RetDataI64 FfiOHOSGetSubscribeInfo(int64_t id)
        {
            return GetSubscribeInfo<1>(id);
        }

        int32_t CJ_FinishCommonEvent(int64_t id)
        {
            return FinishCommonEvent<0>(id);
        }

        FFI_EXPORT int32_t FfiOHOSFinishCommonEvent(int64_t id)
        {
            return FinishCommonEvent<1>(id);
        }

        void CJ_SetPermission(int64_t id, char *value)
        {
            SetPermission<0>(id, value);
        }

        FFI_EXPORT void FfiOHOSSetPermission(int64_t id, char *value)
        {
            SetPermission<1>(id, value);
        }

        void CJ_SetDeviceId(int64_t id, const char *value)
        {
            SetDeviceId<0>(id, value);
        }

        FFI_EXPORT void FfiOHOSSetDeviceId(int64_t id, const char *value)
        {
            SetDeviceId<1>(id, value);
        }

        void CJ_SetUserId(int64_t id, int32_t value)
        {
            SetUserId<0>(id, value);
        }

        FFI_EXPORT void FfiOHOSSetUserId(int64_t id, int32_t value)
        {
            SetUserId<1>(id, value);
        }

        void CJ_SetPriority(int64_t id, int32_t value)
        {
            SetPriority<0>(id, value);
        }

        FFI_EXPORT void FfiOHOSSetPriority(int64_t id, int32_t value)
        {
            SetPriority<1>(id, value);
        }

        void CJ_SetBundleName(int64_t id, const char *value)
        {
            SetBundleName<0>(id, value);
        }

        FFI_EXPORT void FfiOHOSSetBundleName(int64_t id, const char *value)
        {
            SetBundleName<1>(id, value);
        }

        const char *CJ_GetPermission(int64_t id)
        {
            return GetPermission<0>(id);
        }

        FFI_EXPORT const char *FfiOHOSGetPermission(int64_t id)
        {
            return GetPermission<1>(id);
        }

        const char *CJ_GetDeviceId(int64_t id)
        {
            return GetDeviceId<0>(id);
        }

        FFI_EXPORT const char *FfiOHOSGetDeviceId(int64_t id)
        {
            return GetDeviceId<1>(id);
        }

        int32_t CJ_GetUserId(int64_t id)
        {
            return GetUserId<0>(id);
        }

        FFI_EXPORT int32_t FfiOHOSGetUserId(int64_t id)
        {
            return GetUserId<1>(id);
        }

        int32_t CJ_GetPriority(int64_t id)
        {
            return GetPriority<0>(id);
        }

        FFI_EXPORT int32_t FfiOHOSGetPriority(int64_t id)
        {
            return GetPriority<1>(id);
        }

        const char *CJ_GetBundleName(int64_t id)
        {
            return GetBundleName<0>(id);
        }

        FFI_EXPORT const char *FfiOHOSGetBundleName(int64_t id)
        {
            return GetBundleName<1>(id);
        }

        CArrString CJ_GetEvents(int64_t id)
        {
            return GetEvents<0>(id);
        }

        FFI_EXPORT CArrString FfiOHOSGetEvents(int64_t id)
        {
            return GetEvents<1>(id);
        }

        FFI_EXPORT void FfiOHOSCommonEventManagerReleaseSubscribeInfo(int64_t id)
        {
            auto* instance = reinterpret_cast<std::shared_ptr<CommonEventSubscribeInfoImpl> *>(id);
            delete instance;
        }

        FFI_EXPORT void FfiOHOSCommonEventManagerReleaseSubscribeManager(int64_t id)
        {
            auto* instance = reinterpret_cast<std::shared_ptr<SubscriberManager> *>(id);
            delete instance;
        }
    }
}