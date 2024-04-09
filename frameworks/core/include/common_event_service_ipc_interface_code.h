/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_EVENT_CESFWK_INNERKITS_INCLUDE_COMMON_EVENT_SERVICE_IPC_INTERFACE_H
#define FOUNDATION_EVENT_CESFWK_INNERKITS_INCLUDE_COMMON_EVENT_SERVICE_IPC_INTERFACE_H

/* SAID:3299 */
namespace OHOS {
namespace EventFwk {
enum class CommonEventInterfaceCode {
    CES_PUBLISH_COMMON_EVENT = 0,
    CES_PUBLISH_COMMON_EVENT2,
    CES_SUBSCRIBE_COMMON_EVENT,
    CES_UNSUBSCRIBE_COMMON_EVENT,
    CES_GET_STICKY_COMMON_EVENT,
    CES_FINISH_RECEIVER,
    CES_FREEZE,
    CES_UNFREEZE,
    CES_UNFREEZE_ALL,
    CES_REMOVE_STICKY_COMMON_EVENT,
    CES_SET_STATIC_SUBSCRIBER_STATE,
    CES_SET_STATIC_SUBSCRIBER_EVENTS_STATE,
    CES_NOTIFY_COMMON_EVENT,
    COMMAND_ON_RECEIVE_EVENT,
    // ipc id 2001-3000 for tools
    // ipc id for dumping Subscribe State (2001)
    CES_DUMP_STATE = 2001,
};
}  // namespace EventFwk
}  // namespace OHOS

#endif //FOUNDATION_EVENT_CESFWK_INNERKITS_INCLUDE_COMMON_EVENT_SERVICE_IPC_INTERFACE_H