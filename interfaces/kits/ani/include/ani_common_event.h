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

#include <mutex>

#include "common_event_manager.h"

class SubscriberInstance : public OHOS::EventFwk::CommonEventSubscriber {
public:
    SubscriberInstance(const OHOS::EventFwk::CommonEventSubscribeInfo& sp);
    virtual ~SubscriberInstance();

    void OnReceiveEvent(const OHOS::EventFwk::CommonEventData& data) override;

private:
    std::mutex refMutex_;
};

class SubscriberInstanceWrapper {
public:
    SubscriberInstanceWrapper(const OHOS::EventFwk::CommonEventSubscribeInfo& info);
    std::shared_ptr<SubscriberInstance> GetSubscriber();

private:
    std::shared_ptr<SubscriberInstance> subscriber = nullptr;
};
#endif // BASE_NOTIFICATION_COMMON_EVENT_MANAGER_INCLUDE_ANI_COMMON_EVENT_MANAGER_H
