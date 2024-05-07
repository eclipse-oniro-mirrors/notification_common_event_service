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

#ifndef COMMON_EVENT_MANAGER_FFI_H
#define COMMON_EVENT_MANAGER_FFI_H

#include "ffi_remote_data.h"
#include "cj_common_ffi.h"
#include "common_event_defination.h"

#include <cstdint>

extern "C"
{
    // CommonEventManager ffi apis
    FFI_EXPORT int32_t CJ_PublishEvent(char *event, int32_t userId);
    FFI_EXPORT int32_t CJ_PublishEventWithData(char *event, int32_t userId, CommonEventPublishDataBycj options);
    FFI_EXPORT int32_t CJ_SetStaticSubscriberState(bool enable);
    FFI_EXPORT int32_t CJ_RemoveStickyCommonEvent(char *event);
    FFI_EXPORT int64_t CJ_CreateCommonEventSubscribeInfo(CArrString events);
    FFI_EXPORT int64_t CJ_CreateSubscriber(int64_t id);
    FFI_EXPORT int32_t CJ_Subscribe(int64_t id, void (*callbackRef)(const CCommonEventData data));
    FFI_EXPORT int32_t CJ_Unsubscribe(int64_t id);

    FFI_EXPORT RetDataI64 CJ_GetCode(int64_t id);
    FFI_EXPORT int32_t CJ_SetCode(int64_t id, int32_t code);
    FFI_EXPORT RetDataCString CJ_GetData(int64_t id);
    FFI_EXPORT int32_t CJ_SetData(int64_t id, char *data);
    FFI_EXPORT int32_t CJ_SetCodeAndData(int64_t id, int32_t code, char *data);

    // subscriber properties
    FFI_EXPORT RetDataI64 CJ_GetCode(int64_t id);
    FFI_EXPORT int32_t CJ_SetCode(int64_t id, int32_t code);
    FFI_EXPORT RetDataCString CJ_GetData(int64_t id);
    FFI_EXPORT int32_t CJ_SetData(int64_t id, char *data);
    FFI_EXPORT int32_t CJ_SetCodeAndData(int64_t id, int32_t code, char *data);
    FFI_EXPORT RetDataBool CJ_IsOrderedCommonEvent(int64_t id);
    FFI_EXPORT RetDataBool CJ_IsStickyCommonEvent(int64_t id);
    FFI_EXPORT int32_t CJ_AbortCommonEvent(int64_t id);
    FFI_EXPORT int32_t CJ_ClearAbortCommonEvent(int64_t id);
    FFI_EXPORT RetDataBool CJ_GetAbortCommonEvent(int64_t id);
    FFI_EXPORT RetDataI64 CJ_GetSubscribeInfo(int64_t id);
    FFI_EXPORT int32_t CJ_FinishCommonEvent(int64_t id);

    // CommonEventSubscribeInfo properties
    FFI_EXPORT void CJ_SetPermission(int64_t id, char *value);
    FFI_EXPORT void CJ_SetDeviceId(int64_t id, const char *value);
    FFI_EXPORT void CJ_SetUserId(int64_t id, int32_t value);
    FFI_EXPORT void CJ_SetPriority(int64_t id, int32_t value);
    FFI_EXPORT void CJ_SetBundleName(int64_t id, const char *value);
    FFI_EXPORT const char *CJ_GetPermission(int64_t id);
    FFI_EXPORT const char *CJ_GetDeviceId(int64_t id);
    FFI_EXPORT int32_t CJ_GetUserId(int64_t id);
    FFI_EXPORT int32_t CJ_GetPriority(int64_t id);
    FFI_EXPORT const char *CJ_GetBundleName(int64_t id);
    FFI_EXPORT CArrString CJ_GetEvents(int64_t id);
}

#endif