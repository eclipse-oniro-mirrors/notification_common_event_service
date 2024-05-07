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

#ifndef COMMON_EVENT_MANAGER_IMPL_H
#define COMMON_EVENT_MANAGER_IMPL_H

#include "subscribe_info.h"
#include "subscriber.h"

#include <cinttypes>

namespace OHOS::CommonEventManager {

    class CommonEventManagerImpl {
    public:
        static int32_t PublishEvent(char *event, int32_t userId);
        static int32_t PublishEventWithData(char *event, int32_t userId, CommonEventPublishDataBycj options);
        static int32_t SetStaticSubscriberState(bool enable);
        static int32_t RemoveStickyCommonEvent(char *event);
        static std::shared_ptr<CommonEventSubscribeInfo> CreateCommonEventSubscribeInfo(char **event, int64_t size);
        static int32_t Subscribe(std::shared_ptr<SubscriberImpl> subscriber,
                    const std::function<void(CCommonEventData)> &callback);
        static int32_t Unsubscribe(std::shared_ptr<SubscriberImpl> subscriber);
    };
}

#endif // COMMON_EVENT_MANAGER_IMPL