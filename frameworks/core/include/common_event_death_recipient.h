/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_EVENT_CESFWK_INNERKITS_INCLUDE_COMMON_EVENT_DEATH_RECIPIENT_H
#define FOUNDATION_EVENT_CESFWK_INNERKITS_INCLUDE_COMMON_EVENT_DEATH_RECIPIENT_H

#include "ffrt.h"
#include <cstdint>
#include <memory>
#include <mutex>
#include <singleton.h>

#include "system_ability_status_change_stub.h"

namespace OHOS {
namespace EventFwk {
class CommonEventDeathRecipient : public DelayedSingleton<CommonEventDeathRecipient> {
public:
    CommonEventDeathRecipient() = default;
    ~CommonEventDeathRecipient();

    void SubscribeSAManager();
private:
    class SystemAbilityStatusChangeListener : public SystemAbilityStatusChangeStub {
    public:
        SystemAbilityStatusChangeListener();
        ~SystemAbilityStatusChangeListener() = default;
        void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
        void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    private:
        /**
         * Execute the pending reconnection on the internal queue.
         *
         * It never runs on the IPC thread which handles the status change notification, otherwise the next
         * async transaction of the same binder node would be delayed until the retry finishes.
         */
        void DoReconnect();

        bool isSAOffline_ = false;
        bool reconnecting_ = false;
        uint64_t offlineGeneration_ = 0;
        uint64_t reconnectRequestCount_ = 0;
        ffrt::mutex mutex_;
        std::shared_ptr<ffrt::queue> queue_ = nullptr;
    };

    ffrt::mutex listenerMutex_;
    sptr<ISystemAbilityStatusChange> statusChangeListener_ = nullptr;
};
}  // namespace EventFwk
}  // namespace OHOS

#endif  // FOUNDATION_EVENT_CESFWK_INNERKITS_INCLUDE_COMMON_EVENT_DEATH_RECIPIENT_H
