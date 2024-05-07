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

#include "cj_ffi/cj_common_ffi.h"

extern "C"
{
    FFI_EXPORT int CJ_PublishEvent = 0;
    FFI_EXPORT int CJ_PublishEventWithData;
    FFI_EXPORT int CJ_SetStaticSubscriberState = 0;
    FFI_EXPORT int CJ_RemoveStickyCommonEvent = 0;
    FFI_EXPORT int CJ_CreateCommonEventSubscribeInfo = 0;
    FFI_EXPORT int CJ_CreateSubscriber = 0;
    FFI_EXPORT int CJ_Subscribe;
    FFI_EXPORT int CJ_Unsubscribe;
    FFI_EXPORT int CJ_GetCode = 0;
    FFI_EXPORT int CJ_SetCode = 0;
    FFI_EXPORT int CJ_GetData = 0;
    FFI_EXPORT int CJ_SetData = 0;
    FFI_EXPORT int CJ_SetCodeAndData = 0;
    FFI_EXPORT int CJ_IsOrderedCommonEvent = 0;
    FFI_EXPORT int CJ_IsStickyCommonEvent = 0;
    FFI_EXPORT int CJ_AbortCommonEvent = 0;
    FFI_EXPORT int CJ_ClearAbortCommonEvent = 0;
    FFI_EXPORT int CJ_GetAbortCommonEvent = 0;
    FFI_EXPORT int CJ_GetSubscribeInfo = 0;
    FFI_EXPORT int CJ_FinishCommonEvent = 0;
    FFI_EXPORT int CJ_SetPermission = 0;
    FFI_EXPORT int CJ_SetDeviceId = 0;
    FFI_EXPORT int CJ_SetUserId = 0;
    FFI_EXPORT int CJ_SetPriority = 0;
    FFI_EXPORT int CJ_SetBundleName = 0;
    FFI_EXPORT int CJ_GetPermission = 0;
    FFI_EXPORT int CJ_GetDeviceId = 0;
    FFI_EXPORT int CJ_GetUserId = 0;
    FFI_EXPORT int CJ_GetPriority = 0;
    FFI_EXPORT int CJ_GetBundleName = 0;
    FFI_EXPORT int CJ_GetEvents = 0;
}