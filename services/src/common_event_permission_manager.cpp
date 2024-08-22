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
#include "access_token_helper.h"

namespace OHOS {
namespace EventFwk {
constexpr size_t REVERSE = 3;

constexpr int32_t PHONE_UID = 1001;
constexpr int32_t WIFI_UID = 1010;
constexpr int32_t CONNECT_UID = 1099;
constexpr int32_t BOOT_UID = 1101;
constexpr int32_t TIME_UID = 3013;
constexpr int32_t ACCOUNT_UID = 3058;
constexpr int32_t TIME_TICK_UID = 3819;
constexpr int32_t BMS_UID = 5523;
constexpr int32_t POWER_UID = 5528;

static const std::unordered_map<std::string, std::vector<int32_t>> COMMON_EVENT_MAP_PUBLISHER {
    {CommonEventSupport::COMMON_EVENT_BOOT_COMPLETED, {BOOT_UID}},
    {CommonEventSupport::COMMON_EVENT_USER_SWITCHED, {ACCOUNT_UID}},
    {CommonEventSupport::COMMON_EVENT_USER_UNLOCKED, {ACCOUNT_UID}},
    {CommonEventSupport::COMMON_EVENT_USER_ADDED, {ACCOUNT_UID}},
    {CommonEventSupport::COMMON_EVENT_USER_REMOVED, {ACCOUNT_UID}},
    {CommonEventSupport::COMMON_EVENT_USER_BACKGROUND, {ACCOUNT_UID}},
    {CommonEventSupport::COMMON_EVENT_USER_FOREGROUND, {ACCOUNT_UID}},
    {CommonEventSupport::COMMON_EVENT_USER_STOPPING, {ACCOUNT_UID}},
    {CommonEventSupport::COMMON_EVENT_USER_STOPPED, {ACCOUNT_UID}},
    {CommonEventSupport::COMMON_EVENT_HWID_TOKEN_INVALID, {ACCOUNT_UID}},
    {CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_TOKEN_INVALID, {ACCOUNT_UID}},
    {CommonEventSupport::COMMON_EVENT_HWID_LOGOFF, {ACCOUNT_UID}},
    {CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOFF, {ACCOUNT_UID}},
    {CommonEventSupport::COMMON_EVENT_USER_INFO_UPDATED, {ACCOUNT_UID}},
    {CommonEventSupport::COMMON_EVENT_DOMAIN_ACCOUNT_STATUS_CHANGED, {ACCOUNT_UID}},
    {CommonEventSupport::COMMON_EVENT_HWID_LOGIN, {ACCOUNT_UID}},
    {CommonEventSupport::COMMON_EVENT_HWID_LOGOUT, {ACCOUNT_UID}},
    {CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGIN, {ACCOUNT_UID}},
    {CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOUT, {ACCOUNT_UID}},
    {CommonEventSupport::COMMON_EVENT_WIFI_POWER_STATE, {WIFI_UID}},
    {CommonEventSupport::COMMON_EVENT_WIFI_CONN_STATE, {WIFI_UID}},
    {CommonEventSupport::COMMON_EVENT_AIRPLANE_MODE_CHANGED, {CONNECT_UID}},
    {CommonEventSupport::COMMON_EVENT_CONNECTIVITY_CHANGE, {CONNECT_UID}},
    {CommonEventSupport::COMMON_EVENT_HTTP_PROXY_CHANGE, {CONNECT_UID}},
    {CommonEventSupport::COMMON_EVENT_TIME_CHANGED, {TIME_UID, TIME_TICK_UID}},
    {CommonEventSupport::COMMON_EVENT_LOCALE_CHANGED, {TIME_UID, TIME_TICK_UID}},
    {CommonEventSupport::COMMON_EVENT_TIME_TICK, {TIME_UID, TIME_TICK_UID}},
    {CommonEventSupport::COMMON_EVENT_SANDBOX_PACKAGE_ADDED, {BMS_UID}},
    {CommonEventSupport::COMMON_EVENT_SANDBOX_PACKAGE_REMOVED, {BMS_UID}},
    {CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED, {BMS_UID}},
    {CommonEventSupport::COMMON_EVENT_PACKAGE_INSTALLATION_STARTED, {BMS_UID}},
    {CommonEventSupport::COMMON_EVENT_OVERLAY_PACKAGE_ADDED, {BMS_UID}},
    {CommonEventSupport::COMMON_EVENT_OVERLAY_PACKAGE_CHANGED, {BMS_UID}},
    {CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED, {BMS_UID}},
    {CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED, {BMS_UID}},
    {CommonEventSupport::COMMON_EVENT_SCREEN_OFF, {POWER_UID}},
    {CommonEventSupport::COMMON_EVENT_SCREEN_ON, {POWER_UID}},
    {CommonEventSupport::COMMON_EVENT_BATTERY_CHANGED, {POWER_UID}},
    {CommonEventSupport::COMMON_EVENT_CALL_STATE_CHANGED, {BMS_UID}},
    {CommonEventSupport::COMMON_EVENT_SMS_RECEIVE_COMPLETED, {PHONE_UID}},
    {CommonEventSupport::COMMON_EVENT_SMS_EMERGENCY_CB_RECEIVE_COMPLETED, {PHONE_UID}},
    {CommonEventSupport::COMMON_EVENT_SMS_WAPPUSH_RECEIVE_COMPLETED, {PHONE_UID}},
    {CommonEventSupport::COMMON_EVENT_NITZ_TIME_CHANGED, {PHONE_UID}},
    {CommonEventSupport::COMMON_EVENT_NITZ_TIMEZONE_CHANGED, {PHONE_UID}},
    {CommonEventSupport::COMMON_EVENT_SIM_STATE_CHANGED, {PHONE_UID}},
    {CommonEventSupport::COMMON_EVENT_SIM_CARD_DEFAULT_MAIN_SUBSCRIPTION_CHANGED, {PHONE_UID}},
    {CommonEventSupport::COMMON_EVENT_SET_PRIMARY_SLOT_STATUS, {PHONE_UID}},
    {CommonEventSupport::COMMON_EVENT_CELLULAR_DATA_STATE_CHANGED, {PHONE_UID}},
};

static const std::unordered_map<std::string, std::string> COMMON_EVENT_MAP_PERMISSION_PUBLISHER {
    {CommonEventSupport::COMMON_EVENT_SANDBOX_PACKAGE_ADDED, "ohos.permission.GET_BUNDLE_RESOURCES"},
    {CommonEventSupport::COMMON_EVENT_SANDBOX_PACKAGE_REMOVED, "ohos.permission.GET_BUNDLE_RESOURCES"},
    {CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED, "ohos.permission.GET_BUNDLE_RESOURCES"},
    {CommonEventSupport::COMMON_EVENT_PACKAGE_INSTALLATION_STARTED, "ohos.permission.GET_BUNDLE_RESOURCES"},
    {CommonEventSupport::COMMON_EVENT_OVERLAY_PACKAGE_ADDED, "ohos.permission.GET_BUNDLE_RESOURCES"},
    {CommonEventSupport::COMMON_EVENT_OVERLAY_PACKAGE_CHANGED, "ohos.permission.GET_BUNDLE_RESOURCES"},
    {CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED, "ohos.permission.GET_BUNDLE_RESOURCES"},
    {CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED, "ohos.permission.GET_BUNDLE_RESOURCES"},
};

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
        {PermissionState::DEFAULT, {"ohos.permission.GET_WIFI_PEERS_MAC"}}
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
        {PermissionState::AND, {"ohos.permission.GET_WIFI_INFO", "ohos.permission.GET_WIFI_PEERS_MAC"}}
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
    },
    {CommonEventSupport::COMMON_EVENT_BUNDLE_RESOURCES_CHANGED,
        {PermissionState::DEFAULT, {"ohos.permission.GET_BUNDLE_RESOURCES"}}
    },
    {CommonEventSupport::COMMON_EVENT_VPN_CONNECTION_STATUS_CHANGED,
        {PermissionState::DEFAULT, {"ohos.permission.GET_NETWORK_INFO"}}
    },
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

Permission __attribute__((weak)) CommonEventPermissionManager::GetEventPermission(const std::string &event)
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

bool CommonEventPermissionManager::IsPublishAllowed(const std::string &event, int32_t uid,
    const Security::AccessToken::AccessTokenID &callerToken)
{
    auto iterator = COMMON_EVENT_MAP_PERMISSION_PUBLISHER.find(event);
    if (iterator != COMMON_EVENT_MAP_PERMISSION_PUBLISHER.end()) {
        bool ret = AccessTokenHelper::VerifyAccessToken(callerToken, iterator->second);
        if (!ret) {
            EVENT_LOGW("publish not allowed (uid = %{public}d, perm = %{public}s, ret = %{public}d)",
                uid, iterator->second.c_str(), ret);
        }
        return ret;
    }

    auto it = COMMON_EVENT_MAP_PUBLISHER.find(event);
    if (it != COMMON_EVENT_MAP_PUBLISHER.end()) {
        return std::find(it->second.begin(), it->second.end(), uid) != it->second.end();
    }
    return true;
}
}  // namespace EventFwk
}  // namespace OHOS
