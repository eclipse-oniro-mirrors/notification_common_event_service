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

#include "common_event.h"
#include "native_log.h"
#include "parameter_parse.h"

namespace OHOS::CommonEventManager {

    std::atomic_ullong SubscriberImpl::subscriberID_ = 0;

    SubscriberImpl::SubscriberImpl(std::shared_ptr<CommonEventSubscribeInfo> sp, int64_t infoId)
        : CommonEventSubscriber(*sp)
    {
        id_ = ++subscriberID_;
        LOGI("constructor SubscriberImpl");
        valid_ = std::make_shared<bool>(false);
        infoId_ = infoId;
    }

    SubscriberImpl::~SubscriberImpl()
    {
        LOGI("destructor SubscriberImpl[%{public}llu]", id_.load());
        *valid_ = false;
    }

    void SubscriberImpl::OnReceiveEvent(const CommonEventData &data)
    {
        LOGI("Receive event.")
        if (valid_ == nullptr || *(valid_) == false) {
            LOGE("OnReceiveEvent commonEventDataWorkerData or ref is invalid which may be freed before");
            return;
        }
        if (this->IsOrderedCommonEvent()) {
            LOGI("IsOrderedCommonEvent is true");
            SetPublishResult(this);
        }
        LOGI("Subscribe callback start to run.")
        CCommonEventData cData;
        GetCommonEventData(data, cData);
        callback_(cData);
    }

    unsigned long long SubscriberImpl::GetID()
    {
        return id_.load();
    }

    int64_t SubscriberImpl::GetSubscribeInfoId()
    {
        return infoId_;
    }

    void SubscriberImpl::SetSubscriberManagerId(int64_t id)
    {
        managerId_ = id;
    }

    int64_t SubscriberImpl::GetSubscriberManagerId()
    {
        return managerId_;
    }

    void SubscriberImpl::SetCallback(const std::function<void(CCommonEventData)> &callback)
    {
        callback_ = callback;
        *valid_ = true;
    }

    SubscriberManager::SubscriberManager(std::shared_ptr<CommonEventSubscribeInfo> info, int64_t infoId)
    {
        auto objectInfo = new (std::nothrow) SubscriberImpl(info, infoId);
        subscriber = std::shared_ptr<SubscriberImpl>(objectInfo);
    }

    SubscriberManager::~SubscriberManager()
    {
    }

    std::shared_ptr<SubscriberImpl> SubscriberManager::GetSubscriber()
    {
        return subscriber;
    }

    int64_t SubscriberManager::GetSubscribeInfoId()
    {
        return subscriber->GetSubscribeInfoId();
    }
} // namespace OHOS::CommonEventManager