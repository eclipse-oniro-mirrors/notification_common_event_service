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
            EVENT_LOGE("GetSystemAbilityManager failed");
            return;
        }
        
        int32_t ret = samgrProxy->UnSubscribeSystemAbility(COMMON_EVENT_SERVICE_ID, statusChangeListener_);
        if (ret != ERR_OK) {
            EVENT_LOGE("SubscribeSystemAbility to sa manager failed");
            return;
        }
        statusChangeListener_ = nullptr;
    }
}

void CommonEventDeathRecipient::SubscribeSAManager()
{
    if (statusChangeListener_ == nullptr) {
        std::lock_guard<std::mutex> lock(listenerMutex_);
        if (statusChangeListener_ == nullptr) {
            auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
            if (samgrProxy == nullptr) {
                EVENT_LOGE("GetSystemAbilityManager failed");
                return;
            }
            
            sptr<SystemAbilityStatusChangeListener> listener =
                new (std::nothrow) CommonEventDeathRecipient::SystemAbilityStatusChangeListener();
            if (listener == nullptr) {
                EVENT_LOGE("new SystemAbilityStatusChangeListener failed");
                return;
            }
            int32_t ret = samgrProxy->SubscribeSystemAbility(COMMON_EVENT_SERVICE_ID, listener);
            if (ret != ERR_OK) {
                EVENT_LOGE("SubscribeSystemAbility to sa manager failed");
                return;
            }
            statusChangeListener_ = listener;
        }
    }
}

CommonEventDeathRecipient::SystemAbilityStatusChangeListener::SystemAbilityStatusChangeListener()
{
    queue_ = std::make_shared<ffrt::queue>("cesResubMain");
}

void CommonEventDeathRecipient::SystemAbilityStatusChangeListener::OnAddSystemAbility(
    int32_t systemAbilityId, const std::string& deviceId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (isSAOffline_) {
        return;
    }
    EVENT_LOGI("Common event service restore, try to reconnect");
    if (CommonEvent::GetInstance()->Reconnect()) {
        auto resubscrebeFund = [] () {
            CommonEvent::GetInstance()->Resubscribe();
        };
        queue_->submit(resubscrebeFund);
        isSAOffline_ = false;
    }
}

void CommonEventDeathRecipient::SystemAbilityStatusChangeListener::OnRemoveSystemAbility(
    int32_t systemAbilityId, const std::string& deviceId)
{
    EVENT_LOGI("Common event service died");
    std::lock_guard<std::mutex> lock(mutex_);
    isSAOffline_ = true;
}
}  // namespace EventFwk
}  // namespace OHOS
