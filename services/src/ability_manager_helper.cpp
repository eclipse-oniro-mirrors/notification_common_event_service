/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "ability_manager_helper.h"

#include "event_log_wrapper.h"
#include "hitrace_meter_adapter.h"
#include "in_process_call_wrapper.h"
#include "iservice_registry.h"
#include "static_subscriber_connection.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace EventFwk {
namespace {
constexpr int32_t DISCONNECT_DELAY_TIME = 15000; // ms
constexpr int32_t TIME_UNIT_SIZE = 1000;
}

int AbilityManagerHelper::ConnectAbility(
    const Want &want, const CommonEventData &event, const sptr<IRemoteObject> &callerToken, const int32_t &userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    EVENT_LOGI("enter, target bundle = %{public}s", want.GetBundle().c_str());
    std::lock_guard<std::mutex> lock(mutex_);

    if (!GetAbilityMgrProxy()) {
        EVENT_LOGE("failed to get ability manager proxy!");
        return -1;
    }

    sptr<StaticSubscriberConnection> connection = new (std::nothrow) StaticSubscriberConnection(event);
    if (connection == nullptr) {
        EVENT_LOGE("failed to create obj!");
        return -1;
    }
    int32_t result = abilityMgr_->ConnectAbility(want, connection, callerToken, userId);
    if (result == ERR_OK) {
        subscriberConnection_.emplace(connection);
    }
    return result;
}

bool AbilityManagerHelper::GetAbilityMgrProxy()
{
    EVENT_LOGI_LIMIT("GetAbilityMgrProxy enter");
    if (abilityMgr_ == nullptr) {
        sptr<ISystemAbilityManager> systemAbilityManager =
            SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (systemAbilityManager == nullptr) {
            EVENT_LOGE("Failed to get system ability mgr.");
            return false;
        }

        sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(ABILITY_MGR_SERVICE_ID);
        if (remoteObject == nullptr) {
            EVENT_LOGE("Failed to get ability manager service.");
            return false;
        }

        abilityMgr_ = iface_cast<AAFwk::IAbilityManager>(remoteObject);
        if ((abilityMgr_ == nullptr) || (abilityMgr_->AsObject() == nullptr)) {
            EVENT_LOGE("Failed to get system ability manager services ability");
            return false;
        }

        deathRecipient_ = new (std::nothrow) AbilityManagerDeathRecipient();
        if (deathRecipient_ == nullptr) {
            EVENT_LOGE("Failed to create AbilityManagerDeathRecipient");
            return false;
        }
        if (!abilityMgr_->AsObject()->AddDeathRecipient(deathRecipient_)) {
            EVENT_LOGW("Failed to add AbilityManagerDeathRecipient");
        }
    }

    return true;
}

void AbilityManagerHelper::Clear()
{
    EVENT_LOGI("enter");
    std::lock_guard<std::mutex> lock(mutex_);

    if ((abilityMgr_ != nullptr) && (abilityMgr_->AsObject() != nullptr)) {
        abilityMgr_->AsObject()->RemoveDeathRecipient(deathRecipient_);
    }
    abilityMgr_ = nullptr;
}

void AbilityManagerHelper::DisconnectServiceAbilityDelay(const sptr<StaticSubscriberConnection> &connection)
{
    EVENT_LOGD("enter");
    if (connection == nullptr) {
        EVENT_LOGE("connection is nullptr");
        return;
    }

    if (!ffrt_) {
        EVENT_LOGD("ready to create ffrt");
        ffrt_ = std::make_shared<ffrt::queue>("AbilityManagerHelper");
    }

    std::function<void()> task = [connection]() {
        AbilityManagerHelper::GetInstance()->DisconnectAbility(connection);
    };
    ffrt_->submit(task, ffrt::task_attr().delay(DISCONNECT_DELAY_TIME * TIME_UNIT_SIZE));
}

void AbilityManagerHelper::DisconnectAbility(const sptr<StaticSubscriberConnection> &connection)
{
    EVENT_LOGD("enter");
    std::lock_guard<std::mutex> lock(mutex_);
    if (connection == nullptr) {
        EVENT_LOGE("connection is nullptr");
        return;
    }

    if (subscriberConnection_.find(connection) == subscriberConnection_.end()) {
        EVENT_LOGE("failed to find connection!");
        return;
    }

    if (!GetAbilityMgrProxy()) {
        EVENT_LOGE("failed to get ability manager proxy!");
        return;
    }
    IN_PROCESS_CALL_WITHOUT_RET(abilityMgr_->DisconnectAbility(connection));
    subscriberConnection_.erase(connection);
}
}  // namespace EventFwk
}  // namespace OHOS
