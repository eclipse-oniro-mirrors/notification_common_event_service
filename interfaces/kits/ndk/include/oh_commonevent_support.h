/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OH_COMMONEVENT_SUPPORT_CODE_H
#define OH_COMMONEVENT_SUPPORT_CODE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This commonEvent means when the device finnish booting, but still in the locked state.
 */
static const char* const COMMON_EVENT_LOCKED_BOOT_COMPLETED = "usual.event.LOCKED_BOOT_COMPLETED";

/**
 * This commonEvent means when the device is shutting down, note: turn off, not sleeping.
 */
static const char* const COMMON_EVENT_SHUTDOWN = "usual.event.SHUTDOWN";

/**
 * This commonEvent means when the charging state, level and so on about the battery.
 */
static const char* const COMMON_EVENT_BATTERY_CHANGED = "usual.event.BATTERY_CHANGED";

/**
 * This commonEvent means when the device in low battery state..
 */
static const char* const COMMON_EVENT_BATTERY_LOW = "usual.event.BATTERY_LOW";

/**
 * This commonEvent means when the battery level is an ok state.
 */
static const char* const COMMON_EVENT_BATTERY_OKAY = "usual.event.BATTERY_OKAY";

/**
 * This commonEvent means when the other power is connected to the device.
 */
static const char* const COMMON_EVENT_POWER_CONNECTED = "usual.event.POWER_CONNECTED";

/**
 * This commonEvent means when the other power is removed from the device.
 */
static const char* const COMMON_EVENT_POWER_DISCONNECTED = "usual.event.POWER_DISCONNECTED";

/**
 * This commonEvent means when the screen is turned off.
 */
static const char* const COMMON_EVENT_SCREEN_OFF = "usual.event.SCREEN_OFF";

/**
 * This commonEvent means when the device is awakened and interactive.
 */
static const char* const COMMON_EVENT_SCREEN_ON = "usual.event.SCREEN_ON";

/**
 * This commonEvent means when the device is about to enter the hibernate mode.
 */
static const char* const COMMON_EVENT_ENTER_HIBERNATE = "usual.event.ENTER_HIBERNATE";

/**
 * This commonEvent means when the device exits the hibernate mode.
 */
static const char* const COMMON_EVENT_EXIT_HIBERNATE = "usual.event.EXIT_HIBERNATE";

/**
 * This commonEvent means when the thermal state level change
 */
static const char* const COMMON_EVENT_THERMAL_LEVEL_CHANGED = "usual.event.THERMAL_LEVEL_CHANGED";

/**
 * This commonEvent means when the current time is changed.
 */
static const char* const COMMON_EVENT_TIME_TICK = "usual.event.TIME_TICK";

/**
 * This commonEvent means when the time is set.
 */
static const char* const COMMON_EVENT_TIME_CHANGED = "usual.event.TIME_CHANGED";

/**
 * This commonEvent means when the time zone is changed.
 */
static const char* const COMMON_EVENT_TIMEZONE_CHANGED = "usual.event.TIMEZONE_CHANGED";

/**
 * This commonEvent means when a new application package is installed on the device.
 */
static const char* const COMMON_EVENT_PACKAGE_ADDED = "usual.event.PACKAGE_ADDED";

/**
 * This commonEvent means when an existing application package is removed from the device.
 */
static const char* const COMMON_EVENT_PACKAGE_REMOVED = "usual.event.PACKAGE_REMOVED";

/**
 * This commonEvent means when an existing application package is removed from the device.
 */
static const char* const COMMON_EVENT_BUNDLE_REMOVED = "usual.event.BUNDLE_REMOVED";

/**
 * This commonEvent means when an existing application package is completely removed from the device.
 */
static const char* const COMMON_EVENT_PACKAGE_FULLY_REMOVED = "usual.event.PACKAGE_FULLY_REMOVED";

/**
 * This commonEvent means when an existing application package has been changed.
 */
static const char* const COMMON_EVENT_PACKAGE_CHANGED = "usual.event.PACKAGE_CHANGED";

/**
 * This commonEvent means the user has restarted a package, and all of its processes have been killed.
 */
static const char* const COMMON_EVENT_PACKAGE_RESTARTED = "usual.event.PACKAGE_RESTARTED";

/**
 * This commonEvent means the user has cleared the package data.
 */
static const char* const COMMON_EVENT_PACKAGE_DATA_CLEARED = "usual.event.PACKAGE_DATA_CLEARED";

/**
 * This commonEvent means the user has cleared the package cache.
 */
static const char* const COMMON_EVENT_PACKAGE_CACHE_CLEARED = "usual.event.PACKAGE_CACHE_CLEARED";

/**
 * This commonEvent means the packages have been suspended.
 */
static const char* const COMMON_EVENT_PACKAGES_SUSPENDED = "usual.event.PACKAGES_SUSPENDED";

/**
 * This commonEvent Sent to a package that has been suspended by the system.
 */
static const char* const COMMON_EVENT_MY_PACKAGE_SUSPENDED = "usual.event.MY_PACKAGE_SUSPENDED";

/**
 * Sent to a package that has been un-suspended.
 */
static const char* const COMMON_EVENT_MY_PACKAGE_UNSUSPENDED = "usual.event.MY_PACKAGE_UNSUSPENDED";

/**
 * The current device's locale has changed.
 */
static const char* const COMMON_EVENT_LOCALE_CHANGED = "usual.event.LOCALE_CHANGED";

/**
 *  Indicates low memory condition notification acknowledged by user and package management should be started.
 */
static const char* const COMMON_EVENT_MANAGE_PACKAGE_STORAGE = "usual.event.MANAGE_PACKAGE_STORAGE";

/**
 * Remind new user of that the service has been unlocked.
 */
static const char* const COMMON_EVENT_USER_UNLOCKED = "usual.event.USER_UNLOCKED";

/**
 * Distributed account login successfully.
 */
static const char* const COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGIN = "common.event.DISTRIBUTED_ACCOUNT_LOGIN";

/**
 * Distributed account logout successfully.
 */
static const char* const COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOUT = "common.event.DISTRIBUTED_ACCOUNT_LOGOUT";

/**
 * Distributed account is invalid.
 */
static const char* const COMMON_EVENT_DISTRIBUTED_ACCOUNT_TOKEN_INVALID =
    "common.event.DISTRIBUTED_ACCOUNT_TOKEN_INVALID";

/**
 * Distributed account logs off.
 */
static const char* const COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOFF = "common.event.DISTRIBUTED_ACCOUNT_LOGOFF";

/**
 * WIFI state.
 */
static const char* const COMMON_EVENT_WIFI_POWER_STATE = "usual.event.wifi.POWER_STATE";

/**
 * WIFI scan results.
 */
static const char* const COMMON_EVENT_WIFI_SCAN_FINISHED = "usual.event.wifi.SCAN_FINISHED";

/**
 * WIFI RSSI change.
 */
static const char* const COMMON_EVENT_WIFI_RSSI_VALUE = "usual.event.wifi.RSSI_VALUE";

/**
 * WIFI connect state.
 */
static const char* const COMMON_EVENT_WIFI_CONN_STATE = "usual.event.wifi.CONN_STATE";

/**
 * WIFI hotspot state.
 */
static const char* const COMMON_EVENT_WIFI_HOTSPOT_STATE = "usual.event.wifi.HOTSPOT_STATE";

/**
 * WIFI ap sta join.
 */
static const char* const COMMON_EVENT_WIFI_AP_STA_JOIN = "usual.event.wifi.WIFI_HS_STA_JOIN";

/**
 * WIFI ap sta join.
 */
static const char* const COMMON_EVENT_WIFI_AP_STA_LEAVE = "usual.event.wifi.WIFI_HS_STA_LEAVE";

/**
 * Indicates Wi-Fi MpLink state notification acknowledged by binding or unbinding MpLink.
 */
static const char* const COMMON_EVENT_WIFI_MPLINK_STATE_CHANGE = "usual.event.wifi.mplink.STATE_CHANGE";

/**
 * Indicates Wi-Fi P2P connection state notification acknowledged by connecting or disconnected P2P.
 */
static const char* const COMMON_EVENT_WIFI_P2P_CONN_STATE = "usual.event.wifi.p2p.CONN_STATE_CHANGE";

/**
 * Indicates that the Wi-Fi P2P state change.
 */
static const char* const COMMON_EVENT_WIFI_P2P_STATE_CHANGED = "usual.event.wifi.p2p.STATE_CHANGE";

/**
 * Indicates that the Wi-Fi P2P peers state change.
 */
static const char* const COMMON_EVENT_WIFI_P2P_PEERS_STATE_CHANGED = "usual.event.wifi.p2p.DEVICES_CHANGE";

/**
 * Indicates that the Wi-Fi P2P discovery state change.
 */
static const char* const COMMON_EVENT_WIFI_P2P_PEERS_DISCOVERY_STATE_CHANGED =
    "usual.event.wifi.p2p.PEER_DISCOVERY_STATE_CHANGE";

/**
 * Indicates that the Wi-Fi P2P current device state change.
 */
static const char* const COMMON_EVENT_WIFI_P2P_CURRENT_DEVICE_STATE_CHANGED =
    "usual.event.wifi.p2p.CURRENT_DEVICE_CHANGE";

/**
 * Indicates that the Wi-Fi P2P group info is changed.
 */
static const char* const COMMON_EVENT_WIFI_P2P_GROUP_STATE_CHANGED = "usual.event.wifi.p2p.GROUP_STATE_CHANGED";

/**
 * Nfc state change.
 */
static const char* const COMMON_EVENT_NFC_ACTION_ADAPTER_STATE_CHANGED = "usual.event.nfc.action.ADAPTER_STATE_CHANGED";

/**
 * Nfc field on detected.
 */
static const char* const COMMON_EVENT_NFC_ACTION_RF_FIELD_ON_DETECTED = "usual.event.nfc.action.RF_FIELD_ON_DETECTED";

/**
 * Nfc field off detected.
 */
static const char* const COMMON_EVENT_NFC_ACTION_RF_FIELD_OFF_DETECTED = "usual.event.nfc.action.RF_FIELD_OFF_DETECTED";

/**
 * Sent when stop charging battery.
 */
static const char* const COMMON_EVENT_DISCHARGING = "usual.event.DISCHARGING";

/**
 * Sent when start charging battery.
 */
static const char* const COMMON_EVENT_CHARGING = "usual.event.CHARGING";

/**
 * Sent when device's idle mode changed
 */
static const char* const COMMON_EVENT_DEVICE_IDLE_MODE_CHANGED = "usual.event.DEVICE_IDLE_MODE_CHANGED";

/**
 * Sent when device's charge idle mode changed.
 */
static const char* const COMMON_EVENT_CHARGE_IDLE_MODE_CHANGED = "usual.event.CHARGE_IDLE_MODE_CHANGED";

/**
 * Sent when device's power save mode changed
 */
static const char* const COMMON_EVENT_POWER_SAVE_MODE_CHANGED = "usual.event.POWER_SAVE_MODE_CHANGED";

/**
 * The usb state change events.
 * This is a protected common event that can only be sent by system.
 */
static const char* const COMMON_EVENT_USB_STATE = "usual.event.hardware.usb.action.USB_STATE";

/**
 * The usb port changed.
 * This is a protected common event that can only be sent by system.
 */
static const char* const COMMON_EVENT_USB_PORT_CHANGED = "usual.event.hardware.usb.action.USB_PORT_CHANGED";

/**
 * The usb device attached.
 * This is a protected common event that can only be sent by system.
 */
static const char* const COMMON_EVENT_USB_DEVICE_ATTACHED = "usual.event.hardware.usb.action.USB_DEVICE_ATTACHED";

/**
 * The usb device detached.
 * This is a protected common event that can only be sent by system.
 */
static const char* const COMMON_EVENT_USB_DEVICE_DETACHED = "usual.event.hardware.usb.action.USB_DEVICE_DETACHED";

/**
 * Indicates the common event Action indicating that the airplane mode status of the device changes.
 * Users can register this event to listen to the change of the airplane mode status of the device.
 */
static const char* const COMMON_EVENT_AIRPLANE_MODE_CHANGED = "usual.event.AIRPLANE_MODE";

/**
 * sent by the window manager service when the window mode is split.
 */
static const char* const COMMON_EVENT_SPLIT_SCREEN = "common.event.SPLIT_SCREEN";

/**
 * Indicate the result of quick fix apply.
 * This common event can be triggered only by system.
 */
static const char* const COMMON_EVENT_QUICK_FIX_APPLY_RESULT = "usual.event.QUICK_FIX_APPLY_RESULT";

/**
 * Indicate the result of quick fix revoke.
 * This common event can be triggered only by system.
 */
static const char* const COMMON_EVENT_QUICK_FIX_REVOKE_RESULT = "usual.event.QUICK_FIX_REVOKE_RESULT";

/**
 * Indicate the action of a common event that the user information has been updated.
 * This common event can be triggered only by system.
 */
static const char* const COMMON_EVENT_USER_INFO_UPDATED = "usual.event.USER_INFO_UPDATED";

/**
 * Indicate http proxy has been changed.
 * This is a protected common event that can only be sent by system.
 */
static const char* const COMMON_EVENT_HTTP_PROXY_CHANGE = "usual.event.HTTP_PROXY_CHANGE";

/**
 * Indicates the action of a common event that the phone SIM card state has changed.
 * This is a protected common event that can only be sent by system.
 */
static const char* const COMMON_EVENT_SIM_STATE_CHANGED = "usual.event.SIM_STATE_CHANGED";

/**
 * Indicates the action of a common event that the call state has been changed.
 * To subscribe to this protected common event, your application must have the ohos.permission.GET_TELEPHONY_STATE
 * permission.
 * This is a protected common event that can only be sent by system.
 */
static const char* const COMMON_EVENT_CALL_STATE_CHANGED = "usual.event.CALL_STATE_CHANGED";

/**
 * Indicates the action of a common event that the network state has been changed.
 * This is a protected common event that can only be sent by system.
 */
static const char* const COMMON_EVENT_NETWORK_STATE_CHANGED = "usual.event.NETWORK_STATE_CHANGED";

/**
 * Indicates the action of a common event that the signal info has been changed.
 * This is a protected common event that can only be sent by system.
 */
static const char* const COMMON_EVENT_SIGNAL_INFO_CHANGED = "usual.event.SIGNAL_INFO_CHANGED";

/**
 * This commonEvent means when the screen is unlocked.
 */
static const char* const COMMON_EVENT_SCREEN_UNLOCKED = "usual.event.SCREEN_UNLOCKED";

/**
 * This commonEvent means when the screen is locked.
 */
static const char* const COMMON_EVENT_SCREEN_LOCKED = "usual.event.SCREEN_LOCKED";

/**
 * Indicates the action of a common event that the network connectivity changed.
 * This is a protected common event that can only be sent by system.
 */
static const char* const COMMON_EVENT_CONNECTIVITY_CHANGE = "usual.event.CONNECTIVITY_CHANGE";

/**
 * This common event means that minors mode is enabled.
 * This is a protected common event that can only be sent by system.
 */
static const char* const COMMON_EVENT_MINORSMODE_ON = "usual.event.MINORSMODE_ON";

/**
 * This common event means that minors mode is disabled.
 * This is a protected common event that can only be sent by system.
 */
static const char* const COMMON_EVENT_MINORSMODE_OFF = "usual.event.MINORSMODE_OFF";

/**
 * This common event means that datashare is ready.
 * This is a protected common event that can only be sent by system.
 */
static const char* const COMMON_EVENT_DATA_SHARE_READY = "usual.event.DATA_SHARE_READY";

/**
 * This common event means that the managed browser policy is changed.
 * This is a protected common event that can only be sent by system.
 */
static const char* const COMMON_EVENT_MANAGED_BROWSER_POLICY_CHANGED =
    "usual.event.MANAGED_BROWSER_POLICY_CHANGED";

/**
 * Indicates that the device has entered kiosk mode.
 * This is a protected common event that can only be sent by system.
 */
static const char* const COMMON_EVENT_KIOSK_MODE_ON = "usual.event.KIOSK_MODE_ON";

/**
 * Indicates that the device has exited kiosk mode.
 * This is a protected common event that can only be sent by system.
 */
static const char* const COMMON_EVENT_KIOSK_MODE_OFF = "usual.event.KIOSK_MODE_OFF";

/**
 * Indicates that the device has exited kiosk mode.
 * This is a protected common event that can only be sent by system.
 */
static const char* const COMMON_EVENT_SCREEN_SHARE = "usual.event.SCREEN_SHARE";
#ifdef __cplusplus
}
#endif
#endif // OH_COMMONEVENT_SUPPORT_CODE_H
