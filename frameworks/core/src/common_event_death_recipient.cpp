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

#include "common_event_death_recipient.h"

#include "common_event.h"
#include "iservice_registry.h"
#include "event_log_wrapper.h"
#include "refbase.h"
#include "system_ability_definition.h"
#include <memory>
#include <mutex>

namespace OHOS {
namespace EventFwk {
CommonEventDeathRecipient::~CommonEventDeathRecipient()
{
    if (statusChangeListener_ != nullptr) {
        auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgrProxy == nullptr) {
            EVENT_LOGE(LOG_TAG_CES, "GetSystemAbilityManager failed");
            return;
        }
        
        int32_t ret = samgrProxy->UnSubscribeSystemAbility(COMMON_EVENT_SERVICE_ID, statusChangeListener_);
        if (ret != ERR_OK) {
            EVENT_LOGE(LOG_TAG_CES, "SubscribeSystemAbility to sa manager failed");
            return;
        }
        statusChangeListener_ = nullptr;
    }
}

void CommonEventDeathRecipient::SubscribeSAManager()
{
    std::lock_guard<ffrt::mutex> lock(listenerMutex_);
    if (statusChangeListener_ == nullptr) {
        auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgrProxy == nullptr) {
            EVENT_LOGE(LOG_TAG_CES, "GetSystemAbilityManager failed");
            return;
        }
        sptr<SystemAbilityStatusChangeListener> listener =
            new (std::nothrow) CommonEventDeathRecipient::SystemAbilityStatusChangeListener();
        if (listener == nullptr) {
            EVENT_LOGE(LOG_TAG_CES, "new SystemAbilityStatusChangeListener failed");
            return;
        }
        int32_t ret = samgrProxy->SubscribeSystemAbilityInImage(COMMON_EVENT_SERVICE_ID, listener);
        if (ret != ERR_OK) {
            EVENT_LOGE(LOG_TAG_CES, "SubscribeSystemAbility to sa manager failed");
            return;
        }
        statusChangeListener_ = listener;
    }
}

CommonEventDeathRecipient::SystemAbilityStatusChangeListener::SystemAbilityStatusChangeListener()
{
    queue_ = std::make_shared<ffrt::queue>("cesResubMain");
}

void CommonEventDeathRecipient::SystemAbilityStatusChangeListener::OnAddSystemAbility(
    int32_t systemAbilityId, const std::string& deviceId)
{
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        if (!isSAOffline_) {
            return;
        }
        // Record the restart notification so that an in-flight reconnection task retries instead of
        // dropping it.
        reconnectRequestCount_++;
        if (reconnecting_) {
            return;
        }
        reconnecting_ = true;
    }
    // The reconnection must not run in this callback. samgr notifies the status change through a oneway
    // IPC, and the binder driver only releases the next async transaction of this node after the current
    // one is finished (that is, after this callback returns). A long retry here would therefore delay
    // OnRemoveSystemAbility for up to MAX_RETRY_TIME * SLEEP_TIME milliseconds.
    if (queue_ == nullptr) {
        EVENT_LOGE(LOG_TAG_CES, "Reconnect queue is null");
        std::lock_guard<ffrt::mutex> lock(mutex_);
        reconnecting_ = false;
        return;
    }
    wptr<SystemAbilityStatusChangeListener> wThis = this;
    queue_->submit([wThis] () {
        sptr<SystemAbilityStatusChangeListener> self = wThis.promote();
        if (self == nullptr) {
            EVENT_LOGW(LOG_TAG_CES, "Listener has been released, skip reconnect");
            return;
        }
        self->DoReconnect();
    });
}

void CommonEventDeathRecipient::SystemAbilityStatusChangeListener::DoReconnect()
{
    for (;;) {
        uint64_t attemptedRequestCount = 0;
        uint64_t attemptedGeneration = 0;
        {
            std::lock_guard<ffrt::mutex> lock(mutex_);
            if (!isSAOffline_) {
                reconnecting_ = false;
                return;
            }
            attemptedRequestCount = reconnectRequestCount_;
            attemptedGeneration = offlineGeneration_;
        }

        EVENT_LOGI(LOG_TAG_CES, "CES restarted, try to reconnect");
        bool reconnected = CommonEvent::GetInstance()->Reconnect();

        bool restartPending = false;
        {
            std::lock_guard<ffrt::mutex> lock(mutex_);
            // A newer restart notification, or a new offline event, means that the proxy just obtained may
            // already be stale, so the reconnection has to be retried instead of being treated as done.
            restartPending = isSAOffline_ && (reconnectRequestCount_ != attemptedRequestCount ||
                offlineGeneration_ != attemptedGeneration);
            if (!restartPending) {
                reconnecting_ = false;
                if (!reconnected) {
                    EVENT_LOGE(LOG_TAG_CES, "Reconnect CES failed, wait for next restart");
                    return;
                }
                isSAOffline_ = false;
            }
        }
        if (!restartPending) {
            EVENT_LOGI(LOG_TAG_CES, "Reconnect CES success, resubscribe events");
            CommonEvent::GetInstance()->Resubscribe();
            return;
        }
        EVENT_LOGW(LOG_TAG_CES, "CES restarted again during reconnection, retry");
    }
}

void CommonEventDeathRecipient::SystemAbilityStatusChangeListener::OnRemoveSystemAbility(
    int32_t systemAbilityId, const std::string& deviceId)
{
    EVENT_LOGW(LOG_TAG_CES, "CES died");
    std::lock_guard<ffrt::mutex> lock(mutex_);
    isSAOffline_ = true;
    offlineGeneration_++;
}
}  // namespace EventFwk
}  // namespace OHOS
