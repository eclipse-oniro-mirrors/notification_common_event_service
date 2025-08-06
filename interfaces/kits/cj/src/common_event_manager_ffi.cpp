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

        int64_t CJ_CreateSubscriber(int64_t id)
        {
            bool haveId = false;
            int64_t managerId = GetManagerId(id, haveId);
            if (haveId) {
                return managerId;
            }
            auto instance = FFIData::GetData<CommonEventSubscribeInfoImpl>(id);
            if (!instance) {
                LOGE("CommonEventSubscribeInfoImpl instance not exist %{public}" PRId64, id);
                return static_cast<int64_t>(ERR_INVALID_INSTANCE_ID);
            }
            auto info = instance->GetInfoPtr();
            auto ptr = FFIData::Create<SubscriberManager>(info, id);
            if (!ptr) {
                return static_cast<int64_t>(ERR_INVALID_INSTANCE_ID);
            }
            auto subscriber = ptr->GetSubscriber();
            if (!subscriber) {
                return ERR_INVALID_INSTANCE_CODE;
            }
            subscriber->SetSubscriberManagerId(ptr->GetID());
            return ptr->GetID();
        }

        int32_t CJ_Subscribe(int64_t id, void (*callbackRef)(const CCommonEventData data))
        {
            auto instance = FFIData::GetData<SubscriberManager>(id);
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

        int32_t CJ_Unsubscribe(int64_t id)
        {
            auto instance = FFIData::GetData<SubscriberManager>(id);
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

        RetDataI32 CJ_GetCode(int64_t id)
        {
            RetDataI32 ret = {.code = ERR_INVALID_INSTANCE_CODE, .data = 0};
            auto instance = FFIData::GetData<SubscriberManager>(id);
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

        int32_t CJ_SetCode(int64_t id, int32_t code)
        {
            auto instance = FFIData::GetData<SubscriberManager>(id);
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

        RetDataCString CJ_GetData(int64_t id)
        {
            RetDataCString ret = {.code = ERR_INVALID_INSTANCE_CODE, .data = nullptr};
            auto instance = FFIData::GetData<SubscriberManager>(id);
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

        int32_t CJ_SetData(int64_t id, char *data)
        {
            auto instance = FFIData::GetData<SubscriberManager>(id);
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

        int32_t CJ_SetCodeAndData(int64_t id, int32_t code, char *data)
        {
            auto instance = FFIData::GetData<SubscriberManager>(id);
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

        RetDataBool CJ_IsOrderedCommonEvent(int64_t id)
        {
            RetDataBool ret = {.code = ERR_INVALID_INSTANCE_CODE, .data = false};
            auto instance = FFIData::GetData<SubscriberManager>(id);
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

        RetDataBool CJ_IsStickyCommonEvent(int64_t id)
        {
            RetDataBool ret = {.code = ERR_INVALID_INSTANCE_CODE, .data = false};
            auto instance = FFIData::GetData<SubscriberManager>(id);
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

        int32_t CJ_AbortCommonEvent(int64_t id)
        {
            auto instance = FFIData::GetData<SubscriberManager>(id);
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

        int32_t CJ_ClearAbortCommonEvent(int64_t id)
        {
            auto instance = FFIData::GetData<SubscriberManager>(id);
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

        RetDataBool CJ_GetAbortCommonEvent(int64_t id)
        {
            RetDataBool ret = {.code = ERR_INVALID_INSTANCE_CODE, .data = false};
            auto instance = FFIData::GetData<SubscriberManager>(id);
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

        RetDataI64 CJ_GetSubscribeInfo(int64_t id)
        {
            RetDataI64 ret = {.code = ERR_INVALID_INSTANCE_ID, .data = 0};
            auto instance = FFIData::GetData<SubscriberManager>(id);
            if (!instance) {
                LOGE("SubscriberManager instance not exist %{public}" PRId64, id);
                return ret;
            }
            ret.code = instance->GetSubscribeInfoId(ret.data);
            return ret;
        }

        int32_t CJ_FinishCommonEvent(int64_t id)
        {
            int32_t errorCode = NO_ERROR;
            auto instance = FFIData::GetData<SubscriberManager>(id);
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

        void CJ_SetPermission(int64_t id, char *value)
        {
            auto instance = FFIData::GetData<CommonEventSubscribeInfoImpl>(id);
            if (!instance) {
                LOGE("CommonEventSubscribeInfoImpl instance not exist %{public}" PRId64, id);
                return;
            }

            return instance->SetPermission(std::string(value));
        }

        void CJ_SetDeviceId(int64_t id, const char *value)
        {
            auto instance = FFIData::GetData<CommonEventSubscribeInfoImpl>(id);
            if (!instance) {
                LOGE("CommonEventSubscribeInfoImpl instance not exist %{public}" PRId64, id);
                return;
            }
            return instance->SetDeviceId(std::string(value));
        }

        void CJ_SetUserId(int64_t id, int32_t value)
        {
            auto instance = FFIData::GetData<CommonEventSubscribeInfoImpl>(id);
            if (!instance) {
                LOGE("CommonEventSubscribeInfoImpl instance not exist %{public}" PRId64, id);
                return;
            }
            return instance->SetUserId(value);
        }

        void CJ_SetPriority(int64_t id, int32_t value)
        {
            auto instance = FFIData::GetData<CommonEventSubscribeInfoImpl>(id);
            if (!instance) {
                LOGE("CommonEventSubscribeInfoImpl instance not exist %{public}" PRId64, id);
                return;
            }
            return instance->SetPriority(value);
        }

        void CJ_SetBundleName(int64_t id, const char *value)
        {
            auto instance = FFIData::GetData<CommonEventSubscribeInfoImpl>(id);
            if (!instance) {
                LOGE("CommonEventSubscribeInfoImpl instance not exist %{public}" PRId64, id);
                return;
            }
            return instance->SetPublisherBundleName(std::string(value));
        }

        const char *CJ_GetPermission(int64_t id)
        {
            auto instance = FFIData::GetData<CommonEventSubscribeInfoImpl>(id);
            if (!instance) {
                LOGE("CJ_GetPermission instance not exist %{public}" PRId64, id);
                return nullptr;
            }
            auto str = instance->GetPermission();
            auto ret = MallocCString(str);
            return ret;
        }

        const char *CJ_GetDeviceId(int64_t id)
        {
            auto instance = FFIData::GetData<CommonEventSubscribeInfoImpl>(id);
            if (!instance) {
                LOGE("CJ_GetDeviceId instance not exist %{public}" PRId64, id);
                return nullptr;
            }
            auto str = instance->GetDeviceId();
            auto ret = MallocCString(str);
            return ret;
        }

        int32_t CJ_GetUserId(int64_t id)
        {
            auto instance = FFIData::GetData<CommonEventSubscribeInfoImpl>(id);
            if (!instance) {
                LOGE("CJ_GetUserId instance not exist %{public}" PRId64, id);
                return 0;
            }
            return instance->GetUserId();
        }

        int32_t CJ_GetPriority(int64_t id)
        {
            auto instance = FFIData::GetData<CommonEventSubscribeInfoImpl>(id);
            if (!instance) {
                LOGE("CJ_GetPriority instance not exist %{public}" PRId64, id);
                return 0;
            }
            return instance->GetPriority();
        }

        const char *CJ_GetBundleName(int64_t id)
        {
            auto instance = FFIData::GetData<CommonEventSubscribeInfoImpl>(id);
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

        CArrString CJ_GetEvents(int64_t id)
        {
            auto instance = FFIData::GetData<CommonEventSubscribeInfoImpl>(id);
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
    }
}