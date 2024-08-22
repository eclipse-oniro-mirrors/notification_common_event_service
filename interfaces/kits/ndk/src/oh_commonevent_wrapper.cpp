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

#include "event_log_wrapper.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "oh_commonevent_parameters_parse.h"
#include "oh_commonevent_wrapper.h"
#include <cstdlib>
#include <memory>
#include <new>

SubscriberObserver::SubscriberObserver(const OHOS::EventFwk::CommonEventSubscribeInfo &subscribeInfo)
    :OHOS::EventFwk::CommonEventSubscriber(subscribeInfo)
{}

SubscriberObserver::~SubscriberObserver()
{}

void SubscriberObserver::OnReceiveEvent(const OHOS::EventFwk::CommonEventData &data)
{
    EVENT_LOGD("Receive CommonEvent action = %{public}s", data.GetWant().GetAction().c_str());
    CommonEventRcvData *cData = new CommonEventRcvData();
    if (cData == nullptr) {
        EVENT_LOGE("Failed to create CommonEventRcvData");
        return;
    }
    int32_t code = GetCommonEventData(data, cData);
    if (code != COMMONEVENT_ERR_OK) {
        EVENT_LOGE("Failed to insert GetCommonEventData");
        FreeCCommonEventData(cData);
        return;
    }
    if (callback_ != nullptr) {
        EVENT_LOGD("Subscribe callback start to run.");
        (*callback_)(cData);
    }
    FreeCCommonEventData(cData);
}

void SubscriberObserver::SetCallback(CommonEventReceiveCallback callback)
{
    callback_ = callback;
}

std::mutex SubscriberManager::instanceMutex_;
std::shared_ptr<SubscriberManager> SubscriberManager::instance_;

std::shared_ptr<SubscriberManager> SubscriberManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(instanceMutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<SubscriberManager>();
        }
    }
    return instance_;
}

CommonEventSubscriber* SubscriberManager::CreateSubscriber(const CommonEventSubscribeInfo* subscribeInfo,
    CommonEventReceiveCallback callback)
{
    if (subscribeInfo == nullptr) {
        EVENT_LOGE("SubscribeInfo is null");
        return nullptr;
    } 
    OHOS::EventFwk::MatchingSkills matchingSkills;
    for (uint32_t i = 0; i < subscribeInfo->eventLength; i++) {
        matchingSkills.AddEvent(subscribeInfo->events[i]);
    }
    OHOS::EventFwk::CommonEventSubscribeInfo commonEventSubscribeInfo(matchingSkills);
    if (subscribeInfo->permission != nullptr) {
        commonEventSubscribeInfo.SetPermission(subscribeInfo->permission);
    }
    if (subscribeInfo->bundleName != nullptr) {
        commonEventSubscribeInfo.SetPublisherBundleName(subscribeInfo->bundleName);
    }

    auto observer = std::make_shared<SubscriberObserver>(commonEventSubscribeInfo);
    observer->SetCallback(callback);
    return new (std::nothrow) std::shared_ptr<SubscriberObserver>(observer);
}

void SubscriberManager::DestroySubscriber(CommonEventSubscriber* subscriber)
{
    if (subscriber != nullptr) {
        auto subscriberPtr = reinterpret_cast<std::shared_ptr<SubscriberObserver>*>(subscriber);
        delete subscriberPtr;
        subscriberPtr = nullptr;
        subscriber = nullptr;
    }
}

CommonEvent_ErrCode SubscriberManager::Subscribe(const CommonEventSubscriber* subscriber)
{
    if (subscriber == nullptr) {
        EVENT_LOGE("subscriber is null");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }
    auto observer = *(reinterpret_cast<const std::shared_ptr<SubscriberObserver>*>(subscriber));
    int32_t ret = OHOS::EventFwk::CommonEventManager::NewSubscribeCommonEvent(observer);
    if (ret == OHOS::Notification::ERR_NOTIFICATION_CES_COMMON_SYSTEMCAP_NOT_SUPPORT) {
        return COMMONEVENT_ERR_SUBSCRIBER_NUM_EXCEEDED;
    }
    return static_cast<CommonEvent_ErrCode>(ret);
}

CommonEvent_ErrCode SubscriberManager::UnSubscribe(const CommonEventSubscriber* subscriber)
{
    if (subscriber == nullptr) {
        EVENT_LOGE("subscriber is null");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }
    auto observer = *(reinterpret_cast<const std::shared_ptr<SubscriberObserver>*>(subscriber));
    int32_t ret = OHOS::EventFwk::CommonEventManager::NewUnSubscribeCommonEvent(observer);
    return static_cast<CommonEvent_ErrCode>(ret);
}