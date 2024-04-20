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
#include "system_ability_definition.h"

namespace OHOS {
namespace EventFwk {
void CommonEventDeathRecipient::SubscribeSAManager()
{
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    statusChangeListener_ = new (std::nothrow) CommonEventDeathRecipient::SystemAbilityStatusChangeListener();
    if (samgrProxy == nullptr || statusChangeListener_ == nullptr) {
        EVENT_LOGI("GetSystemAbilityManager failed or new SystemAbilityStatusChangeListener failed");
        statusChangeListener_ = nullptr;
        return;
    }
    int32_t ret = samgrProxy->SubscribeSystemAbility(COMMON_EVENT_SERVICE_ID, statusChangeListener_);
    if (ret != ERR_OK) {
        EVENT_LOGI("SubscribeSystemAbility to sa manager failed");
        statusChangeListener_ = nullptr;
    }
}

bool CommonEventDeathRecipient::GetIsSubscribeSAManager()
{
    return statusChangeListener_ != nullptr;
}

void CommonEventDeathRecipient::SystemAbilityStatusChangeListener::OnAddSystemAbility(
    int32_t systemAbilityId, const std::string& deviceId)
{
    if (!isSAOffline) {
        return;
    }
    EVENT_LOGI("Common event service restore, try to reconnect");
    auto commonEvent = DelayedSingleton<CommonEvent>::GetInstance();
    if (commonEvent->Reconnect()) {
        commonEvent->Resubscribe();
        isSAOffline = false;
    }
}

void CommonEventDeathRecipient::SystemAbilityStatusChangeListener::OnRemoveSystemAbility(
    int32_t systemAbilityId, const std::string& deviceId)
{
    EVENT_LOGI("Common event service died");
    isSAOffline = true;
    auto commonEvent = DelayedSingleton<CommonEvent>::GetInstance();
    commonEvent->ResetCommonEventProxy();
}
}  // namespace EventFwk
}  // namespace OHOS
