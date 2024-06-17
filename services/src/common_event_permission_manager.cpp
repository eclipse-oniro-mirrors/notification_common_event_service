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

#include "common_event_permission_manager.h"

#include <algorithm>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "common_event_support.h"
#include "event_log_wrapper.h"

namespace OHOS {
namespace EventFwk {
constexpr size_t REVERSE = 3;

static const std::unordered_map<std::string, std::pair<PermissionState, std::vector<std::string>>> COMMON_EVENT_MAP {
    {CommonEventSupport::COMMON_EVENT_BOOT_COMPLETED,
        {PermissionState::DEFAULT, {"ohos.permission.RECEIVER_STARTUP_COMPLETED"}}
    },
    {CommonEventSupport::COMMON_EVENT_LOCKED_BOOT_COMPLETED,
        {PermissionState::DEFAULT, {"ohos.permission.RECEIVER_STARTUP_COMPLETED"}}
    },
    {CommonEventSupport::COMMON_EVENT_USER_SWITCHED,
        {PermissionState::DEFAULT, {"ohos.permission.MANAGE_LOCAL_ACCOUNTS"}}
    },
    {CommonEventSupport::COMMON_EVENT_USER_STARTING,
        {PermissionState::DEFAULT, {"ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS"}}
    },
    {CommonEventSupport::COMMON_EVENT_USER_STOPPING,
        {PermissionState::DEFAULT, {"ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS"}}
    },
    {CommonEventSupport::COMMON_EVENT_WIFI_SCAN_FINISHED,
        {PermissionState::DEFAULT, {"ohos.permission.LOCATION"}}
    },
    {CommonEventSupport::COMMON_EVENT_WIFI_RSSI_VALUE,
        {PermissionState::DEFAULT, {"ohos.permission.GET_WIFI_INFO"}}
    },
    {CommonEventSupport::COMMON_EVENT_WIFI_AP_STA_JOIN,
        {PermissionState::DEFAULT, {"ohos.permission.GET_WIFI_INFO"}}
    },
    {CommonEventSupport::COMMON_EVENT_WIFI_AP_STA_LEAVE,
        {PermissionState::DEFAULT, {"ohos.permission.GET_WIFI_INFO"}}
    },
    {CommonEventSupport::COMMON_EVENT_WIFI_MPLINK_STATE_CHANGE,
        {PermissionState::DEFAULT, {"ohos.permission.MPLINK_CHANGE_STATE"}}
    },
    {CommonEventSupport::COMMON_EVENT_WIFI_P2P_CONN_STATE,
        {PermissionState::AND, {"ohos.permission.GET_WIFI_INFO", "ohos.permission.LOCATION"}}
    },
    {CommonEventSupport::COMMON_EVENT_WIFI_P2P_STATE_CHANGED,
        {PermissionState::DEFAULT, {"ohos.permission.GET_WIFI_INFO"}}
    },
    {CommonEventSupport::COMMON_EVENT_WIFI_P2P_PEERS_STATE_CHANGED,
        {PermissionState::DEFAULT, {"ohos.permission.GET_WIFI_INFO"}}
    },
    {CommonEventSupport::COMMON_EVENT_WIFI_P2P_PEERS_DISCOVERY_STATE_CHANGED,
        {PermissionState::DEFAULT, {"ohos.permission.GET_WIFI_INFO"}}
    },
    {CommonEventSupport::COMMON_EVENT_WIFI_P2P_CURRENT_DEVICE_STATE_CHANGED,
        {PermissionState::DEFAULT, {"ohos.permission.GET_WIFI_INFO"}}
    },
    {CommonEventSupport::COMMON_EVENT_WIFI_P2P_GROUP_STATE_CHANGED,
        {PermissionState::DEFAULT, {"ohos.permission.GET_WIFI_INFO"}}
    },
    {CommonEventSupport::COMMON_EVENT_NFC_ACTION_RF_FIELD_ON_DETECTED,
        {PermissionState::DEFAULT, {"ohos.permission.MANAGE_SECURE_SETTINGS"}}
    },
    {CommonEventSupport::COMMON_EVENT_NFC_ACTION_RF_FIELD_OFF_DETECTED,
        {PermissionState::DEFAULT, {"ohos.permission.MANAGE_SECURE_SETTINGS"}}
    },
    {CommonEventSupport::COMMON_EVENT_USER_ADDED,
        {PermissionState::DEFAULT, {"ohos.permission.MANAGE_LOCAL_ACCOUNTS"}}
    },
    {CommonEventSupport::COMMON_EVENT_USER_REMOVED,
        {PermissionState::DEFAULT, {"ohos.permission.MANAGE_LOCAL_ACCOUNTS"}}
    },
    {CommonEventSupport::COMMON_EVENT_ABILITY_ADDED,
        {PermissionState::DEFAULT, {"ohos.permission.LISTEN_BUNDLE_CHANGE"}}
    },
    {CommonEventSupport::COMMON_EVENT_ABILITY_REMOVED,
        {PermissionState::DEFAULT, {"ohos.permission.LISTEN_BUNDLE_CHANGE"}}
    },
    {CommonEventSupport::COMMON_EVENT_ABILITY_UPDATED,
        {PermissionState::DEFAULT, {"ohos.permission.LISTEN_BUNDLE_CHANGE"}}
    },
    {CommonEventSupport::COMMON_EVENT_DISK_REMOVED,
        {PermissionState::DEFAULT, {"ohos.permission.STORAGE_MANAGER"}}
    },
    {CommonEventSupport::COMMON_EVENT_DISK_UNMOUNTED,
        {PermissionState::DEFAULT, {"ohos.permission.STORAGE_MANAGER"}}
    },
    {CommonEventSupport::COMMON_EVENT_DISK_MOUNTED,
        {PermissionState::DEFAULT, {"ohos.permission.STORAGE_MANAGER"}}
    },
    {CommonEventSupport::COMMON_EVENT_DISK_BAD_REMOVAL,
        {PermissionState::DEFAULT, {"ohos.permission.STORAGE_MANAGER"}}
    },
    {CommonEventSupport::COMMON_EVENT_DISK_UNMOUNTABLE,
        {PermissionState::DEFAULT, {"ohos.permission.STORAGE_MANAGER"}}
    },
    {CommonEventSupport::COMMON_EVENT_DISK_EJECT,
        {PermissionState::DEFAULT, {"ohos.permission.STORAGE_MANAGER"}}
    },
    {CommonEventSupport::COMMON_EVENT_VOLUME_REMOVED,
        {PermissionState::DEFAULT, {"ohos.permission.STORAGE_MANAGER"}}
    },
    {CommonEventSupport::COMMON_EVENT_VOLUME_UNMOUNTED,
        {PermissionState::DEFAULT, {"ohos.permission.STORAGE_MANAGER"}}
    },
    {CommonEventSupport::COMMON_EVENT_VOLUME_MOUNTED,
        {PermissionState::DEFAULT, {"ohos.permission.STORAGE_MANAGER"}}
    },
    {CommonEventSupport::COMMON_EVENT_VOLUME_BAD_REMOVAL,
        {PermissionState::DEFAULT, {"ohos.permission.STORAGE_MANAGER"}}
    },
    {CommonEventSupport::COMMON_EVENT_VOLUME_EJECT,
        {PermissionState::DEFAULT, {"ohos.permission.STORAGE_MANAGER"}}
    },
    {CommonEventSupport::COMMON_EVENT_VISIBLE_ACCOUNTS_UPDATED,
            {PermissionState::DEFAULT, {"ohos.permission.GET_APP_ACCOUNTS"}}
    },
    {CommonEventSupport::COMMON_EVENT_ACCOUNT_DELETED,
        {PermissionState::DEFAULT, {"ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS"}}
    },
    {CommonEventSupport::COMMON_EVENT_FOUNDATION_READY,
        {PermissionState::DEFAULT, {"ohos.permission.RECEIVER_STARTUP_COMPLETED"}}
    },
    {CommonEventSupport::COMMON_EVENT_SLOT_CHANGE,
        {PermissionState::DEFAULT, {"ohos.permission.NOTIFICATION_CONTROLLER"}}
    },
    {CommonEventSupport::COMMON_EVENT_SMS_RECEIVE_COMPLETED,
        {PermissionState::DEFAULT, {"ohos.permission.RECEIVE_SMS"}}
    }
};

static const std::unordered_set<std::string> SYSTEM_API_COMMON_EVENTS {
    CommonEventSupport::COMMON_EVENT_DOMAIN_ACCOUNT_STATUS_CHANGED,
    CommonEventSupport::COMMON_EVENT_DEVICE_IDLE_EXEMPTION_LIST_UPDATED,
    CommonEventSupport::COMMON_EVENT_PACKAGE_INSTALLATION_STARTED,
    CommonEventSupport::COMMON_EVENT_CHARGE_TYPE_CHANGED,
    CommonEventSupport::COMMON_EVENT_DYNAMIC_ICON_CHANGED
};

static const std::vector<std::string> SENSITIVE_COMMON_EVENTS {
    CommonEventSupport::COMMON_EVENT_SMS_RECEIVE_COMPLETED
};

CommonEventPermissionManager::CommonEventPermissionManager()
{
    Init();
}

void CommonEventPermissionManager::Init()
{
    EVENT_LOGD("enter");
    Permission per;
    per.names.reserve(REVERSE);

    for (auto &[eventName, permissions] : COMMON_EVENT_MAP) {
        per.state = permissions.first;
        for (auto &permissionName : permissions.second) {
            per.names.emplace_back(permissionName);
        }
        if (IsSensitiveEvent(eventName)) {
            per.isSensitive = true;
        }
        eventMap_.insert(std::make_pair(eventName, per));
        per.names.clear();
    }
}

Permission CommonEventPermissionManager::GetEventPermission(const std::string &event)
{
    EVENT_LOGD("enter");
    if (eventMap_.find(event) != eventMap_.end()) {
        return eventMap_.find(event)->second;
    }
    Permission per;
    return per;
}

bool CommonEventPermissionManager::IsSensitiveEvent(const std::string &event)
{
    auto it = find(SENSITIVE_COMMON_EVENTS.begin(), SENSITIVE_COMMON_EVENTS.end(), event);
    return it != SENSITIVE_COMMON_EVENTS.end();
}

bool CommonEventPermissionManager::IsSystemAPIEvent(const std::string &event)
{
    return SYSTEM_API_COMMON_EVENTS.find(event) != SYSTEM_API_COMMON_EVENTS.end();
}
}  // namespace EventFwk
}  // namespace OHOS
