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
#include "common_event_manager_impl.h"

#include "common_event_manager.h"
#include "securec.h"
using namespace OHOS::FFI;
using CommonEventManagerImpl = OHOS::CommonEventManager::CommonEventManagerImpl;

namespace OHOS::CommonEventManager {

    static std::map<std::shared_ptr<SubscriberImpl>, SubscriberInstanceInfo> subscriberImpls;
    static std::mutex subscriberImplMutex;

    void SetPublishResult(OHOS::CommonEventManager::SubscriberImpl *subImpl)
    {
        LOGI("SetPublishResult start");
        std::lock_guard<std::mutex> lock(subscriberImplMutex);
        for (auto subscriberImpl : subscriberImpls) {
            if (subscriberImpl.first.get() == subImpl) {
                LOGI("Get success.");
                subscriberImpls[subscriberImpl.first].commonEventResult = subImpl->GoAsyncCommonEvent();
                break;
            }
        }
    }

    std::shared_ptr<AsyncCommonEventResult> GetAsyncResult(const SubscriberImpl *objectInfo)
    {
        LOGI("GetAsyncResult start");
        if (!objectInfo) {
            LOGE("Invalidity objectInfo");
            return nullptr;
        }
        std::lock_guard<std::mutex> lock(subscriberImplMutex);
        for (auto subscriberImpl : subscriberImpls) {
            if (subscriberImpl.first.get() == objectInfo) {
                return subscriberImpl.second.commonEventResult;
            }
        }
        LOGI("No found objectInfo");
        return nullptr;
    }

    void SetSubscribeInfo(std::shared_ptr<SubscriberImpl> subscriber,
        const std::function<void(CCommonEventData)> &callback)
    {
        LOGI("Set subscriberImpls.")
        subscriber->SetCallback(callback);
        AsyncCallbackInfoSubscribe *asyncCallbackInfo = new (std::nothrow) AsyncCallbackInfoSubscribe{
            .callback = callback, .subscriber = subscriber};
        std::lock_guard<std::mutex> lock(subscriberImplMutex);
        subscriberImpls[asyncCallbackInfo->subscriber].asyncCallbackInfo.emplace_back(asyncCallbackInfo);
    }

    void DeleteCallBack(const std::vector<AsyncCallbackInfoSubscribe *> &asyncCallbackInfos)
    {
        for (auto asyncCallbackInfo : asyncCallbackInfos) {
            delete asyncCallbackInfo;
            asyncCallbackInfo = nullptr;
        }
    }

    int64_t GetManagerId(int64_t id, bool &haveId)
    {
        std::lock_guard<std::mutex> lock(subscriberImplMutex);
        for (auto subscriberImpl : subscriberImpls) {
            if (subscriberImpl.first->GetSubscribeInfoId() == id) {
                std::shared_ptr<OHOS::CommonEventManager::SubscriberImpl> newSubscriber = subscriberImpl.first;
                DeleteCallBack(subscriberImpl.second.asyncCallbackInfo);
                newSubscriber->SetCallback(nullptr);
                OHOS::EventFwk::CommonEventManager::UnSubscribeCommonEvent(newSubscriber);
                subscriberImpls.erase(newSubscriber);
                haveId = true;
                return newSubscriber->GetSubscriberManagerId();
            }
        }
        return 0;
    }

    void DeleteSubscribe(std::shared_ptr<SubscriberImpl> subscriber)
    {
        LOGI("DeleteSubscribe start");
        std::lock_guard<std::mutex> lock(subscriberImplMutex);
        auto subscribe = subscriberImpls.find(subscriber);
        if (subscribe != subscriberImpls.end()) {
            for (auto asyncCallbackInfoSubscribe : subscribe->second.asyncCallbackInfo) {
                delete asyncCallbackInfoSubscribe;
                asyncCallbackInfoSubscribe = nullptr;
            }
            subscriber->SetCallback(nullptr);
            subscriberImpls.erase(subscribe);
        }
    }

    void GetSubscriberCode(std::shared_ptr<SubscriberImpl> subscriber, int64_t &code)
    {
        std::shared_ptr<AsyncCommonEventResult> result = GetAsyncResult(subscriber.get());
        if (result) {
            code = result->GetCode();
        } else {
            code = 0;
        }
    }

    int32_t SetSubscriberCode(std::shared_ptr<SubscriberImpl> subscriber, int32_t code)
    {
        std::shared_ptr<AsyncCommonEventResult> result = GetAsyncResult(subscriber.get());
        if (result) {
            return result->SetCode(code) ? NO_ERROR : ERR_CES_FAILED;
        }
        return NO_ERROR;
    }

    std::string GetSubscriberData(std::shared_ptr<SubscriberImpl> subscriber)
    {
        std::shared_ptr<AsyncCommonEventResult> result = GetAsyncResult(subscriber.get());
        if (result) {
            return result->GetData();
        } else {
            return std::string();
        }
    }

    int32_t SetSubscriberData(std::shared_ptr<SubscriberImpl> subscriber, const char *data)
    {
        std::shared_ptr<AsyncCommonEventResult> result = GetAsyncResult(subscriber.get());
        if (result) {
            return result->SetData(std::string(data)) ? NO_ERROR : ERR_CES_FAILED;
        }
        return NO_ERROR;
    }

    int32_t SetSubscriberCodeAndData(std::shared_ptr<SubscriberImpl> subscriber, int32_t code, const char *data)
    {
        std::shared_ptr<AsyncCommonEventResult> result = GetAsyncResult(subscriber.get());
        if (result) {
            return result->SetCodeAndData(code, std::string(data)) ? NO_ERROR : ERR_CES_FAILED;
        }
        return NO_ERROR;
    }

    void IsCommonEventSticky(std::shared_ptr<SubscriberImpl> subscriber, bool &data)
    {
        std::shared_ptr<AsyncCommonEventResult> result = GetAsyncResult(subscriber.get());
        if (result) {
            data = result->IsStickyCommonEvent();
        } else {
            data = subscriber->IsStickyCommonEvent();
        }
    }

    void IsCommonEventOrdered(std::shared_ptr<SubscriberImpl> subscriber, bool &data)
    {
        std::shared_ptr<AsyncCommonEventResult> result = GetAsyncResult(subscriber.get());
        if (result) {
            data = result->IsOrderedCommonEvent();
        } else {
            data = subscriber->IsOrderedCommonEvent();
        }
    }
}