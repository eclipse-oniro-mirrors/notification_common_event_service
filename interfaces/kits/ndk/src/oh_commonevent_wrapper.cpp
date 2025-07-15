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
#include "ces_inner_error_code.h"
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
    CommonEvent_RcvData *cData = new (std::nothrow) CommonEvent_RcvData();
    if (cData == nullptr) {
        EVENT_LOGE("Failed to create CommonEventRcvData");
        return;
    }
    if (IsOrderedCommonEvent()) {
        EVENT_LOGD("SetAsyncResult");
        SubscriberManager::GetInstance()->SetAsyncResult(this);
    }
    auto want = data.GetWant();
    cData->code = data.GetCode();
    cData->data = data.GetData();
    cData->event = want.GetAction();
    cData->bundleName = want.GetBundle();
    cData->parameters = new (std::nothrow) CArrParameters();
    if (cData->parameters == nullptr) {
        EVENT_LOGE("Failed to init cData parameters");
        delete cData;
        cData = nullptr;
        return;
    }
    cData->parameters->wantParams = want.GetParams();
    if (callback_ != nullptr) {
        (*callback_)(cData);
    }
    delete cData->parameters;
    cData->parameters = nullptr;
    delete cData;
    cData = nullptr;
}

void SubscriberObserver::SetCallback(CommonEvent_ReceiveCallback callback)
{
    callback_ = callback;
}

ffrt::mutex SubscriberManager::instanceMutex_;
ffrt::mutex SubscriberManager::resultCacheMutex_;
std::shared_ptr<SubscriberManager> SubscriberManager::instance_;
std::map<std::shared_ptr<SubscriberObserver>, ResultCacheItem> SubscriberManager::resultCache_;

std::shared_ptr<SubscriberManager> SubscriberManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<ffrt::mutex> lock(instanceMutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<SubscriberManager>();
        }
    }
    return instance_;
}

CommonEvent_Subscriber* SubscriberManager::CreateSubscriber(const CommonEvent_SubscribeInfo* subscribeInfo,
    CommonEvent_ReceiveCallback callback)
{
    if (subscribeInfo == nullptr) {
        EVENT_LOGE("SubscribeInfo is null");
        return nullptr;
    }
    OHOS::EventFwk::MatchingSkills matchingSkills;
    for (const auto& iter : subscribeInfo->events) {
        if (!iter.empty()) {
            matchingSkills.AddEvent(iter);
        }
    }
    OHOS::EventFwk::CommonEventSubscribeInfo commonEventSubscribeInfo(matchingSkills);
    if (!subscribeInfo->permission.empty()) {
        commonEventSubscribeInfo.SetPermission(subscribeInfo->permission);
    }
    if (!subscribeInfo->bundleName.empty()) {
        commonEventSubscribeInfo.SetPublisherBundleName(subscribeInfo->bundleName);
    }

    auto observer = std::make_shared<SubscriberObserver>(commonEventSubscribeInfo);
    observer->SetCallback(callback);
    return new (std::nothrow) std::shared_ptr<SubscriberObserver>(observer);
}

void SubscriberManager::DestroySubscriber(CommonEvent_Subscriber* subscriber)
{
    if (subscriber != nullptr) {
        auto subscriberPtr = reinterpret_cast<std::shared_ptr<SubscriberObserver>*>(subscriber);
        delete subscriberPtr;
        subscriberPtr = nullptr;
    }
}

CommonEvent_ErrCode SubscriberManager::Subscribe(const CommonEvent_Subscriber* subscriber)
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
    if (ret != OHOS::ERR_OK) {
        return static_cast<CommonEvent_ErrCode>(ret);
    }
    {
        std::lock_guard<ffrt::mutex> lock(resultCacheMutex_);
        resultCache_.emplace(observer, ResultCacheItem());
    }
    return static_cast<CommonEvent_ErrCode>(ret);
}

CommonEvent_ErrCode SubscriberManager::UnSubscribe(const CommonEvent_Subscriber* subscriber)
{
    if (subscriber == nullptr) {
        EVENT_LOGE("subscriber is null");
        return COMMONEVENT_ERR_INVALID_PARAMETER;
    }
    auto observer = *(reinterpret_cast<const std::shared_ptr<SubscriberObserver>*>(subscriber));
    int32_t ret = OHOS::EventFwk::CommonEventManager::NewUnSubscribeCommonEvent(observer);
    {
        std::lock_guard<ffrt::mutex> lock(resultCacheMutex_);
        resultCache_.erase(observer);
    }
    return static_cast<CommonEvent_ErrCode>(ret);
}

void SubscriberManager::SetAsyncResult(SubscriberObserver* subscriber)
{
    if (subscriber == nullptr) {
        EVENT_LOGE("subscriber is null");
        return;
    }
    {
        std::lock_guard<ffrt::mutex> lock(resultCacheMutex_);
        for (auto& iter : resultCache_) {
            if (iter.first.get() == subscriber) {
                iter.second.result = subscriber->GoAsyncCommonEvent();
                break;
            }
        }
    }
}

ResultCacheItem* SubscriberManager::GetAsyncResult(const SubscriberObserver* subscriber)
{
    if (subscriber == nullptr) {
        EVENT_LOGE("subscriber is null");
        return nullptr;
    }
    {
        std::lock_guard<ffrt::mutex> lock(resultCacheMutex_);
        for (auto& iter : resultCache_) {
            if (iter.first.get() == subscriber) {
                return &iter.second;
            }
        }
    }
    EVENT_LOGI("subscriber not found");
    return nullptr;
}