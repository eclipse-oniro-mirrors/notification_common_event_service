/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_EVENT_CESFWK_SERVICES_INCLUDE_HISTORY_EVENT_RECORD_H
#define FOUNDATION_EVENT_CESFWK_SERVICES_INCLUDE_HISTORY_EVENT_RECORD_H

#include "common_event_constant.h"
#include "want.h"

namespace OHOS {
namespace EventFwk {
struct HistorySubscriberRecord {
    struct tm recordTime {};
    bool isFreeze;
    int32_t priority;
    int32_t userId;
    int64_t freezeTime;
    std::string bundleName;
    std::string permission;
    std::string deviceId;
    HistorySubscriberRecord() :  isFreeze(false), priority(0), userId(UNDEFINED_USER), freezeTime(0)
    {}
};

struct HistoryEventRecord {
    enum EventState {
        IDLE = 0,
        RECEIVING,
        RECEIVED,
    };
    enum DeliveryState {
        PENDING = 0,
        DELIVERED,
        SKIPPED,
        TIMEOUT,
    };

    bool sticky;
    bool ordered;
    bool isSystemApp;
    bool isSystemEvent;
    bool hasLastSubscribe;
    bool resultAbort;
    int8_t state;
    pid_t pid;
    uid_t uid;

    int32_t userId;
    int32_t code;
    int64_t dispatchTime;
    int64_t receiverTime;
    struct tm recordTime {};
    std::vector<std::string> subscriberPermissions;
    std::vector<HistorySubscriberRecord> receivers;
    std::vector<int> deliveryState;
    std::string data;
    std::string bundleName;

    Want want;
    
    HistoryEventRecord()
        : sticky(false),
          ordered(false),
          isSystemApp(false),
          isSystemEvent(false),
          hasLastSubscribe(false),
          resultAbort(false),
          state(0),
          pid(0),
          uid(0),
          userId(UNDEFINED_USER),
          code(0),
          dispatchTime(0),
          receiverTime(0)
    {}
};
}  // namespace EventFwk
}  // namespace OHOS

#endif  // FOUNDATION_EVENT_CESFWK_SERVICES_INCLUDE_HISTORY_EVENT_RECORD_H