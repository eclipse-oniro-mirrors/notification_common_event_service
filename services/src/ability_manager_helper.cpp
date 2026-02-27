/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include "event_trace_wrapper.h"
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

AbilityManagerHelper::AbilityManagerHelper()
{
    ffrt_ = std::make_shared<ffrt::queue>("AbilityManagerHelper");
}

int AbilityManagerHelper::ConnectAbility(
    const Want &want, const CommonEventData &event, const sptr<IRemoteObject> &callerToken, const int32_t &userId)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    EVENT_LOGD(LOG_TAG_CES, "enter, target bundle = %{public}s", want.GetBundle().c_str());
    int result = -1;
    ffrt::task_handle handle = ffrt_->submit_h([&]() {
        std::string connectionKey =
            want.GetBundle() + "_" + want.GetElement().GetAbilityName() + "_" + std::to_string(userId);
        sptr<AAFwk::IAbilityManager> abilityMgr = GetAbilityMgrProxy();
        if (abilityMgr == nullptr) {
            EVENT_LOGE(LOG_TAG_CES, "Failed to get system ability manager services ability");
            return;
        }
        std::lock_guard<ffrt::mutex> lock(mutex_);
        auto it = subscriberConnection_.find(connectionKey);
        if (it != subscriberConnection_.end()) {
            it->second->NotifyEvent(event);
            EVENT_LOGD(LOG_TAG_CES, "Static cache sends events!");
            result = ERR_OK;
            return;
        }

        sptr<StaticSubscriberConnection> connection =
            new (std::nothrow) StaticSubscriberConnection(event, connectionKey);
        if (connection == nullptr) {
            EVENT_LOGE(LOG_TAG_CES, "failed to create obj!");
            result = -1;
            return;
        }
        result = abilityMgr->ConnectAbility(want, connection, callerToken, userId);
        if (result != ERR_OK) {
            EVENT_LOGE(LOG_TAG_CES, "Connect failed, result=%{public}d", result);
            return;
        }
        subscriberConnection_[connectionKey] = connection;
        DisconnectServiceAbilityDelay(connection, "");
        EVENT_LOGD(LOG_TAG_CES, "Connect success");
    });
    ffrt_->wait(handle);
    return result;
}

sptr<AAFwk::IAbilityManager> AbilityManagerHelper::GetAbilityMgrProxy()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        EVENT_LOGE(LOG_TAG_CES, "Failed to get system ability mgr.");
        return nullptr;
    }

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(ABILITY_MGR_SERVICE_ID);
    if (remoteObject == nullptr) {
        EVENT_LOGE(LOG_TAG_CES, "Failed to get ability manager service.");
        return nullptr;
    }

    auto abilityMgr = iface_cast<AAFwk::IAbilityManager>(remoteObject);
    
    return abilityMgr;
}

void AbilityManagerHelper::DisconnectServiceAbilityDelay(
    const sptr<StaticSubscriberConnection> &connection, const std::string &action)
{
    EVENT_LOGD(LOG_TAG_CES, "enter");
    if (connection == nullptr) {
        EVENT_LOGW(LOG_TAG_CES, "connection is nullptr");
        return;
    }
    std::function<void()> task = [connection, action, this]() {
        this->DisconnectAbility(connection, action);
    };
    ffrt_->submit(task, ffrt::task_attr().delay(DISCONNECT_DELAY_TIME * TIME_UNIT_SIZE));
}

void AbilityManagerHelper::DisconnectAbility(
    const sptr<StaticSubscriberConnection> &connection, const std::string &action)
{
    EVENT_LOGD(LOG_TAG_CES, "enter");
    if (connection == nullptr) {
        EVENT_LOGW(LOG_TAG_CES, "connection is nullptr");
        return;
    }

    std::lock_guard<ffrt::mutex> lock(mutex_);
    auto it = std::find_if(subscriberConnection_.begin(), subscriberConnection_.end(),
        [&connection](const auto &pair) { return pair.second == connection; });
    if (it == subscriberConnection_.end()) {
        EVENT_LOGW(LOG_TAG_CES, "failed to find connection!");
        return;
    }
    if (connection) {
        connection->RemoveEvent(action);
        if (!connection->IsEmptyAction()) {
            EVENT_LOGD(LOG_TAG_CES, "Event within 15 seconds!");
            return;
        }
    }
    sptr<AAFwk::IAbilityManager> abilityMgr = GetAbilityMgrProxy();
    if (abilityMgr) {
        IN_PROCESS_CALL_WITHOUT_RET(abilityMgr->DisconnectAbility(connection));
    }
    connection->Clear();
    subscriberConnection_.erase(it);
    EVENT_LOGD(LOG_TAG_CES, "erase connection!");
}

void AbilityManagerHelper::RemoveConnection(const sptr<StaticSubscriberConnection> &connection)
{
    EVENT_LOGD(LOG_TAG_CES, "enter");
    if (connection == nullptr) {
        EVENT_LOGW(LOG_TAG_CES, "connection is nullptr");
        return;
    }
    std::lock_guard<ffrt::mutex> lock(mutex_);
    auto it = std::find_if(subscriberConnection_.begin(), subscriberConnection_.end(),
        [&connection](const auto &pair) { return pair.second == connection; });
    if (it == subscriberConnection_.end()) {
        EVENT_LOGW(LOG_TAG_CES, "failed to find connection!");
        return;
    }
    sptr<AAFwk::IAbilityManager> abilityMgr = GetAbilityMgrProxy();
    if (abilityMgr) {
        IN_PROCESS_CALL_WITHOUT_RET(abilityMgr->DisconnectAbility(connection));
    }
    connection->Clear();
    subscriberConnection_.erase(it);
    EVENT_LOGD(LOG_TAG_CES, "erase connection!");
}
}  // namespace EventFwk
}  // namespace OHOS
