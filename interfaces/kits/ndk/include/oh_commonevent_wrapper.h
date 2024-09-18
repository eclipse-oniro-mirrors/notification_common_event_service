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

#ifndef OH_COMMON_EVENT_WRAPPER_C_H
#define OH_COMMON_EVENT_WRAPPER_C_H

#include "common_event_subscriber.h"
#include "oh_commonevent.h"

struct CParameters {
    int8_t valueType;
    char *key;
    void *value;
    int64_t size;
};

struct CArrParameters {
    CParameters *head;
    int64_t size;
};

struct CommonEvent_SubscribeInfo {
    uint32_t eventLength = 0;
    char **events = nullptr;
    char *permission = nullptr;
    char *bundleName = nullptr;
};

struct CommonEvent_RcvData {
    char *event;
    char *bundleName;
    int32_t code;
    char *data;
    CArrParameters* parameters;
};

class SubscriberObserver : public OHOS::EventFwk::CommonEventSubscriber {
public:
    SubscriberObserver(const OHOS::EventFwk::CommonEventSubscribeInfo &subscribeInfo);
    ~SubscriberObserver();

    void OnReceiveEvent(const OHOS::EventFwk::CommonEventData &data) override;
    void SetCallback(CommonEvent_ReceiveCallback callback);
private:
    CommonEvent_ReceiveCallback callback_ = nullptr;
};

class SubscriberManager {
public:
    SubscriberManager() = default;
    ~SubscriberManager() = default;
    CommonEvent_Subscriber* CreateSubscriber(const CommonEvent_SubscribeInfo* subscribeInfo,
        CommonEvent_ReceiveCallback callback);
    void DestroySubscriber(CommonEvent_Subscriber* subscriber);
    CommonEvent_ErrCode Subscribe(const CommonEvent_Subscriber* subscriber);
    CommonEvent_ErrCode UnSubscribe(const CommonEvent_Subscriber* subscriber);
    static std::shared_ptr<SubscriberManager> GetInstance();
private:
    static std::mutex instanceMutex_;
    static std::shared_ptr<SubscriberManager> instance_;
};

#endif