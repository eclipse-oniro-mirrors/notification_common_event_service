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
#include "common_event_manager.h"
#include "native_log.h"
#include "parameter_parse.h"

namespace OHOS::CommonEventManager {
    const int8_t STR_PTR_TYPE = 5;
    std::atomic_ullong SubscriberImpl::subscriberID_ = 0;

    SubscriberImpl::SubscriberImpl(std::shared_ptr<CommonEventSubscribeInfo> sp, int64_t infoId)
        : CommonEventSubscriber(*sp)
    {
        id_ = ++subscriberID_;
        LOGI("constructor SubscriberImpl");
        valid_ = std::make_shared<bool>(false);
        infoId_ = infoId;
    }

    SubscriberImpl::SubscriberImpl(std::shared_ptr<CommonEventSubscribeInfo> sp)
        : CommonEventSubscriber(*sp)
    {
        id_ = ++subscriberID_;
        LOGI("constructor SubscriberImpl");
        valid_ = std::make_shared<bool>(false);
    }

    SubscriberImpl::~SubscriberImpl()
    {
        LOGI("destructor SubscriberImpl[%{public}llu]", id_.load());
        *valid_ = false;
    }

    static void FreeCCommonEventData(CCommonEventData &cData)
    {
        FreeCCommonEventDataCharPtr(cData);
        for (int i = 0; i < cData.parameters.size; i++) {
            auto ptr = cData.parameters.head[i];
            free(ptr.key);
            ptr.key = nullptr;
            if (ptr.valueType == STR_PTR_TYPE) {
                char **value = reinterpret_cast<char **>(ptr.value);
                for (int j = 0; j < ptr.size; j++) {
                    free(value[j]);
                    value[j] = nullptr;
                }
            }
            free(ptr.value);
            ptr.value = nullptr;
        }
        free(cData.parameters.head);
        cData.parameters.head = nullptr;
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
        CCommonEventData cData = {};
        int32_t code = GetCommonEventData(data, cData);
        if (code == ERR_NO_MEMORY || code == ERR_CES_FAILED) {
            LOGE("Failed to excute callback: out of memory.");
            return;
        }
        callback_(cData);
        FreeCCommonEventData(cData);
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

    sptr<SubscriberManager> SubscriberManager::Create(std::shared_ptr<CommonEventSubscribeInfo> info)
    {
        auto ptr = FFIData::Create<SubscriberManager>();
        if (ptr != nullptr) {
            ptr->subscriber = std::make_shared<SubscriberImpl>(info);
            ptr->subscriber->SetSubscriberManagerId(ptr->GetID());
        }
        return ptr;
    }

    sptr<SubscriberManager> SubscriberManager::Create(std::shared_ptr<CommonEventSubscribeInfo> info, int64_t infoId)
    {
        auto ptr = FFIData::Create<SubscriberManager>();
        if (ptr != nullptr) {
            ptr->subscriber = std::make_shared<SubscriberImpl>(info, infoId);
            ptr->subscriber->SetSubscriberManagerId(ptr->GetID());
        }
        return ptr;
    }

    int64_t SubscriberManager::CreateID(std::shared_ptr<CommonEventSubscribeInfo> info)
    {
        auto manager = new SubscriberManager();
        manager->subscriber = std::make_shared<SubscriberImpl>(info);
        auto* ptr = new sptr<SubscriberManager>(manager);
        auto mgrAddr = reinterpret_cast<int64_t>(ptr);
        manager->subscriber->SetSubscriberManagerId(mgrAddr);
        return mgrAddr;
    }

    int64_t SubscriberManager::CreateID(std::shared_ptr<CommonEventSubscribeInfo> info, int64_t infoId)
    {
        auto manager = new SubscriberManager();
        manager->subscriber = std::make_shared<SubscriberImpl>(info, infoId);
        auto* ptr = new sptr<SubscriberManager>(manager);
        auto mgrAddr = reinterpret_cast<int64_t>(ptr);
        manager->subscriber->SetSubscriberManagerId(mgrAddr);
        return mgrAddr;
    }

    SubscriberManager::~SubscriberManager()
    {
        if (subscriber != nullptr) {
            OHOS::EventFwk::CommonEventManager::UnSubscribeCommonEvent(subscriber);
            DeleteSubscribe(subscriber);
        }
    }

    std::shared_ptr<SubscriberImpl> SubscriberManager::GetSubscriber()
    {
        return subscriber;
    }

    int32_t SubscriberManager::GetSubscribeInfoId(int64_t &id)
    {
        if (subscriber == nullptr) {
            return ERR_INVALID_INSTANCE_ID;
        }
        id = subscriber->GetSubscribeInfoId();
        return SUCCESS_CODE;
    }
} // namespace OHOS::CommonEventManager