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

#ifndef COMMON_EVENT_H
#define COMMON_EVENT_H

#include "subscriber.h"

namespace OHOS::CommonEventManager {
    using AsyncCommonEventResult = OHOS::EventFwk::AsyncCommonEventResult;
    const int32_t ERR_INVALID_INSTANCE_ID = -1;
    
    struct AsyncCallbackInfoSubscribe {
        std::function<void(CCommonEventData)> callback;
        std::shared_ptr<SubscriberImpl> subscriber = nullptr;
        int8_t errorCode = NO_ERROR;
    };

    struct SubscriberInstanceInfo {
        std::vector<AsyncCallbackInfoSubscribe *> asyncCallbackInfo;
        std::shared_ptr<AsyncCommonEventResult> commonEventResult = nullptr;
    };

    void SetPublishResult(OHOS::CommonEventManager::SubscriberImpl *subImpl);

    std::shared_ptr<AsyncCommonEventResult> GetAsyncResult(const SubscriberImpl *objectInfo);

    void SetSubscribeInfo(std::shared_ptr<SubscriberImpl> subscriber,
        const std::function<void(CCommonEventData)> &callback);

    int64_t GetManagerId(int64_t id, bool &haveId);

    void DeleteSubscribe(std::shared_ptr<SubscriberImpl> subscriber);

    void GetSubscriberCode(std::shared_ptr<SubscriberImpl> subscriber, int32_t &code);

    int32_t SetSubscriberCode(std::shared_ptr<SubscriberImpl> subscriber, int32_t code);

    std::string GetSubscriberData(std::shared_ptr<SubscriberImpl> subscriber);

    int32_t SetSubscriberData(std::shared_ptr<SubscriberImpl> subscriber, const char *data);

    int32_t SetSubscriberCodeAndData(std::shared_ptr<SubscriberImpl> subscriber, int32_t code, const char *data);

    void IsCommonEventSticky(std::shared_ptr<SubscriberImpl> subscriber, bool &data);

    void IsCommonEventOrdered(std::shared_ptr<SubscriberImpl> subscriber, bool &data);
}

#endif