/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_COMMON_EVENT_MANAGER_INCLUDE_ANI_COMMON_EVENT_MANAGER_H
#define BASE_NOTIFICATION_COMMON_EVENT_MANAGER_INCLUDE_ANI_COMMON_EVENT_MANAGER_H

#include <ani.h>
#include <mutex>

#include "common_event_manager.h"
#include "ffrt.h"

namespace OHOS {
namespace EventManagerFwkAni {
class SubscriberInstance : public OHOS::EventFwk::CommonEventSubscriber {
public:
    SubscriberInstance(const OHOS::EventFwk::CommonEventSubscribeInfo& sp);
    virtual ~SubscriberInstance();

    void OnReceiveEvent(const OHOS::EventFwk::CommonEventData& data) override;
    unsigned long long GetID();
    void SetEnv(ani_env* env);
    void SetVm(ani_vm* etsVm);
    void SetCallback(const ani_object& callback);
    void ClearEnv();

private:
    ffrt::mutex envMutex_;
    ffrt::mutex callbackMutex_;
    ani_env* env_ = nullptr;
    ani_object callback_ = nullptr;
    std::atomic_ullong id_;
    static std::atomic_ullong subscriberID_;
    ani_vm* etsVm_ = nullptr;
};

class SubscriberInstanceWrapper {
public:
    SubscriberInstanceWrapper(const OHOS::EventFwk::CommonEventSubscribeInfo& info);
    std::shared_ptr<SubscriberInstance> GetSubscriber();

private:
    std::shared_ptr<SubscriberInstance> subscriber = nullptr;
};

struct subscriberInstanceInfo {
    std::vector<std::shared_ptr<SubscriberInstance>> asyncCallbackInfo;
    std::shared_ptr<OHOS::EventFwk::AsyncCommonEventResult> commonEventResult = nullptr;
};

std::shared_ptr<SubscriberInstance> GetSubscriberByWrapper(SubscriberInstanceWrapper* wrapper);

} // namespace EventManagerFwkAni
} // namespace OHOS
#endif // BASE_NOTIFICATION_COMMON_EVENT_MANAGER_INCLUDE_ANI_COMMON_EVENT_MANAGER_H

