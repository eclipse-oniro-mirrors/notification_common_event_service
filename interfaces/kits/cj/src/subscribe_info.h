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

#ifndef SUBSCRIBE_INFO_H
#define SUBSCRIBE_INFO_H

#include "ffi_remote_data.h"
#include "common_event_subscribe_info.h"

namespace OHOS::CommonEventManager {
    using CommonEventSubscribeInfo = OHOS::EventFwk::CommonEventSubscribeInfo;
    class CommonEventSubscribeInfoImpl : public OHOS::FFI::FFIData {
    public:
        OHOS::FFI::RuntimeType *GetRuntimeType() override
        {
            return GetClassType();
        }
        explicit CommonEventSubscribeInfoImpl(std::shared_ptr<CommonEventSubscribeInfo> info): info_(info){};
        void SetPriority(int32_t &priority);
        int32_t GetPriority();
        void SetUserId(int32_t &userId);
        int32_t GetUserId();
        void SetPermission(const std::string &permission);
        std::string GetPermission();
        void SetDeviceId(const std::string &deviceId);
        std::string GetDeviceId();
        void SetPublisherBundleName(const std::string &publisherBundleName);
        std::string GetPublisherBundleName();
        std::vector<std::string> GetEvents();
        std::shared_ptr<CommonEventSubscribeInfo> GetInfoPtr();

    private:
        friend class OHOS::FFI::RuntimeType;
        friend class OHOS::FFI::TypeBase;
        static OHOS::FFI::RuntimeType *GetClassType()
        {
            static OHOS::FFI::RuntimeType runtimeType =
                OHOS::FFI::RuntimeType::Create<OHOS::FFI::FFIData>("CommonEventSubscribeInfoImpl");
            return &runtimeType;
        }
        std::shared_ptr<CommonEventSubscribeInfo> info_;
    };
} // namespace OHOS::CommonEventManager

#endif // SUBSCRIBE_INFO_H
