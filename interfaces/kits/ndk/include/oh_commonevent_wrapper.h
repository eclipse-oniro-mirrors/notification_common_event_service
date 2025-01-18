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

#include <map>
#include <string>
#include <vector>

#include "common_event_subscriber.h"
#include "oh_commonevent.h"
#include "want_params.h"

struct CArrParameters {
    OHOS::AAFwk::WantParams wantParams;
    mutable std::vector<void*> allocatedPointers;
};

struct CommonEvent_SubscribeInfo {
    std::vector<std::string> events;
    std::string permission;
    std::string bundleName;
};

struct CommonEvent_PublishInfo {
    bool ordered = false;
    std::string bundleName;
    std::vector<std::string> subscriberPermissions;
    int32_t code = 0;
    std::string data;
    CArrParameters* parameters = nullptr;
};

struct CommonEvent_RcvData {
    std::string event;
    std::string bundleName;
    int32_t code;
    std::string data;
    CArrParameters* parameters = nullptr;
};

struct ResultCacheItem {
    std::shared_ptr<OHOS::EventFwk::AsyncCommonEventResult> result = nullptr;
    std::string data;
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
    void SetAsyncResult(SubscriberObserver* subscriber);
    ResultCacheItem* GetAsyncResult(const SubscriberObserver* subscriber);
    static std::shared_ptr<SubscriberManager> GetInstance();
private:
    static std::mutex instanceMutex_;
    static std::mutex resultCacheMutex_;
    static std::shared_ptr<SubscriberManager> instance_;
    static std::map<std::shared_ptr<SubscriberObserver>, ResultCacheItem> resultCache_;
};

#endif