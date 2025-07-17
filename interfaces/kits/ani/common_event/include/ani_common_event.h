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
#include "napi_common_event.h"

namespace OHOS {
namespace EventManagerFwkAni {
using namespace OHOS::EventFwk;

class SubscriberInstance : public OHOS::EventFwk::CommonEventSubscriber,
    public std::enable_shared_from_this<SubscriberInstance> {
public:
    SubscriberInstance(const OHOS::EventFwk::CommonEventSubscribeInfo& sp);
    virtual ~SubscriberInstance();

    void OnReceiveEvent(const OHOS::EventFwk::CommonEventData& data) override;
    unsigned long long GetID();
    void SetVm(ani_vm* etsVm);
    ani_vm* GetVm();
    void SetCallback(const ani_object& callback);
    ani_object GetCallback();
    void SetIsToEvent(bool isToEvent);
    bool GetIsToEvent();
    void ClearEnv();

private:
    ffrt::mutex envMutex_;
    ffrt::mutex callbackMutex_;
    ffrt::mutex isToEventMutex_;
    ani_env* env_ = nullptr;
    ani_object callback_ = nullptr;
    bool isToEvent_ = false;
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

struct SubscriberInstanceRelationship {
    std::vector<std::shared_ptr<SubscriberInstance>> aniSubscribers_;
    std::vector<std::shared_ptr<EventManagerFwkNapi::SubscriberInstance>> napiSubscribers_;
    std::shared_ptr<SubscriberInstance> aniSubscriber_;
    std::shared_ptr<EventManagerFwkNapi::SubscriberInstance> napiSubscriber_;
    ffrt::mutex relationMutex_;
};

std::shared_ptr<SubscriberInstance> GetSubscriber(ani_env* env, ani_ref subscribeRef);
std::shared_ptr<AsyncCommonEventResult> GetAsyncCommonEventResult(ani_env* env, ani_ref subscribeRef);
std::shared_ptr<AsyncCommonEventResult> GetAsyncCommonEventResult(std::shared_ptr<SubscriberInstance> subscriber);
std::shared_ptr<SubscriberInstance> GetSubscriberByWrapper(SubscriberInstanceWrapper* wrapper);
ani_ref CreateSubscriberRef(ani_env* env, SubscriberInstanceWrapper *subscriberWrapper);
void SetNapiSubscriberCallback(std::shared_ptr<EventManagerFwkNapi::SubscriberInstance> subscriberInstance);
int32_t UnsubscribeAndRemoveInstance(ani_env* env, const std::shared_ptr<SubscriberInstance> &subscriber);
std::shared_ptr<SubscriberInstanceRelationship> GetTransferRelation(std::shared_ptr<SubscriberInstance> aniSubscriber,
    std::shared_ptr<EventManagerFwkNapi::SubscriberInstance> napiSubscriber);
} // namespace EventManagerFwkAni
} // namespace OHOS
#endif // BASE_NOTIFICATION_COMMON_EVENT_MANAGER_INCLUDE_ANI_COMMON_EVENT_MANAGER_H

