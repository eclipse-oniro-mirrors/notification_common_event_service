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

#ifndef SUBSCRIBER_H
#define SUBSCRIBER_H

#include "ffi_remote_data.h"
#include "common_event_defination.h"

#include "common_event_subscribe_info.h"
#include "common_event_subscriber.h"

namespace OHOS::CommonEventManager {
    using CommonEventSubscribeInfo = OHOS::EventFwk::CommonEventSubscribeInfo;
    using CommonEventSubscriber = OHOS::EventFwk::CommonEventSubscriber;
    using CommonEventData = OHOS::EventFwk::CommonEventData;

    class SubscriberImpl : public CommonEventSubscriber {
    public:
        SubscriberImpl(std::shared_ptr<CommonEventSubscribeInfo> sp, int64_t infoId);
        ~SubscriberImpl() override;

        void OnReceiveEvent(const CommonEventData &data) override;

        unsigned long long GetID();

        int64_t GetSubscribeInfoId();

        void SetSubscriberManagerId(int64_t id);

        int64_t GetSubscriberManagerId();

        void SetCallback(const std::function<void(CCommonEventData)> &callback);

    private:
        std::function<void(CCommonEventData)> callback_;
        std::shared_ptr<bool> valid_;
        std::atomic_ullong id_;
        static std::atomic_ullong subscriberID_;
        int64_t infoId_;
        int64_t managerId_ = -1;
    };

    class SubscriberManager : public OHOS::FFI::FFIData {
    public:
        OHOS::FFI::RuntimeType *GetRuntimeType() override
        {
            return GetClassType();
        }
        SubscriberManager(std::shared_ptr<CommonEventSubscribeInfo> info, int64_t infoId);
        ~SubscriberManager() override;

        std::shared_ptr<SubscriberImpl> GetSubscriber();

        int64_t GetSubscribeInfoId();

    private:
        friend class OHOS::FFI::RuntimeType;
        friend class OHOS::FFI::TypeBase;
        static OHOS::FFI::RuntimeType *GetClassType()
        {
            static OHOS::FFI::RuntimeType runtimeType =
                OHOS::FFI::RuntimeType::Create<OHOS::FFI::FFIData>("SubscriberManager");
            return &runtimeType;
        }
        std::shared_ptr<SubscriberImpl> subscriber;
    };

} // namespace OHOS::CommonEventManager

#endif // SUBSCRIBER_H
