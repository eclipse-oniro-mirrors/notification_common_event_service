/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_COMMON_EVENT_MANAGER_INCLUDE_ANI_COMMON_EVENT_MANAGER_H
#define BASE_NOTIFICATION_COMMON_EVENT_MANAGER_INCLUDE_ANI_COMMON_EVENT_MANAGER_H

#include <mutex>

#include "common_event_manager.h"

class SubscriberInstance : public OHOS::EventFwk::CommonEventSubscriber {
public:
    SubscriberInstance(const OHOS::EventFwk::CommonEventSubscribeInfo& sp);
    virtual ~SubscriberInstance();

    void OnReceiveEvent(const OHOS::EventFwk::CommonEventData& data) override;

private:
    std::mutex refMutex_;
};

class SubscriberInstanceWrapper {
public:
    SubscriberInstanceWrapper(const OHOS::EventFwk::CommonEventSubscribeInfo& info);
    std::shared_ptr<SubscriberInstance> GetSubscriber();

private:
    std::shared_ptr<SubscriberInstance> subscriber = nullptr;
};

class EnumConvertUtils {
public:
    static std::string Support_ConvertSts2Native(const int index);
    static int Support_ConvertNative2Sts(const std::string nativeValue);
private:
    static constexpr std::array<const char *, 200> SupportArray = {
        "usual.event.BOOT_COMPLETED",
        "usual.event.LOCKED_BOOT_COMPLETED",
        "usual.event.SHUTDOWN",
        "usual.event.BATTERY_CHANGED",
        "usual.event.BATTERY_LOW",
        "usual.event.BATTERY_OKAY",
        "usual.event.POWER_CONNECTED",
        "usual.event.POWER_DISCONNECTED",
        "usual.event.SCREEN_OFF",
        "usual.event.SCREEN_ON",
        "usual.event.THERMAL_LEVEL_CHANGED",
        "usual.event.ENTER_FORCE_SLEEP",
        "usual.event.EXIT_FORCE_SLEEP",
        "usual.event.USER_PRESENT",
        "usual.event.TIME_TICK",
        "usual.event.TIME_CHANGED",
        "usual.event.DATE_CHANGED",
        "usual.event.TIMEZONE_CHANGED",
        "usual.event.CLOSE_SYSTEM_DIALOGS",
        "usual.event.PACKAGE_ADDED",
        "usual.event.PACKAGE_REPLACED",
        "usual.event.MY_PACKAGE_REPLACED",
        "usual.event.PACKAGE_REMOVED",
        "usual.event.BUNDLE_REMOVED",
        "usual.event.PACKAGE_FULLY_REMOVED",
        "usual.event.PACKAGE_CHANGED",
        "usual.event.PACKAGE_RESTARTED",
        "usual.event.PACKAGE_DATA_CLEARED",
        "usual.event.PACKAGE_CACHE_CLEARED",
        "usual.event.PACKAGES_SUSPENDED",
        "usual.event.PACKAGES_UNSUSPENDED",
        "usual.event.MY_PACKAGE_SUSPENDED",
        "usual.event.MY_PACKAGE_UNSUSPENDED",
        "usual.event.UID_REMOVED",
        "usual.event.PACKAGE_FIRST_LAUNCH",
        "usual.event.PACKAGE_NEEDS_VERIFICATION",
        "usual.event.PACKAGE_VERIFIED",
        "usual.event.EXTERNAL_APPLICATIONS_AVAILABLE",
        "usual.event.EXTERNAL_APPLICATIONS_UNAVAILABLE",
        "usual.event.CONFIGURATION_CHANGED",
        "usual.event.LOCALE_CHANGED",
        "usual.event.MANAGE_PACKAGE_STORAGE",
        "common.event.DRIVE_MODE",
        "common.event.HOME_MODE",
        "common.event.OFFICE_MODE",
        "usual.event.USER_STARTED",
        "usual.event.USER_BACKGROUND",
        "usual.event.USER_FOREGROUND",
        "usual.event.USER_SWITCHED",
        "usual.event.USER_STARTING",
        "usual.event.USER_UNLOCKED",
        "usual.event.USER_STOPPING",
        "usual.event.USER_STOPPED",
        "common.event.DISTRIBUTED_ACCOUNT_LOGIN",
        "common.event.DISTRIBUTED_ACCOUNT_LOGOUT",
        "common.event.DISTRIBUTED_ACCOUNT_TOKEN_INVALID",
        "common.event.DISTRIBUTED_ACCOUNT_LOGOFF",
        "usual.event.wifi.POWER_STATE",
        "usual.event.wifi.SCAN_FINISHED",
        "usual.event.wifi.RSSI_VALUE",
        "usual.event.wifi.CONN_STATE",
        "usual.event.wifi.HOTSPOT_STATE",
        "usual.event.wifi.WIFI_HS_STA_JOIN",
        "usual.event.wifi.WIFI_HS_STA_LEAVE",
        "usual.event.wifi.mplink.STATE_CHANGE",
        "usual.event.wifi.p2p.CONN_STATE_CHANGE",
        "usual.event.wifi.p2p.STATE_CHANGE",
        "usual.event.wifi.p2p.DEVICES_CHANGE",
        "usual.event.wifi.p2p.PEER_DISCOVERY_STATE_CHANGE",
        "usual.event.wifi.p2p.CURRENT_DEVICE_CHANGE",
        "usual.event.wifi.p2p.GROUP_STATE_CHANGED",
        "usual.event.bluetooth.handsfree.ag.CONNECT_STATE_UPDATE",
        "usual.event.bluetooth.handsfree.ag.CURRENT_DEVICE_UPDATE",
        "usual.event.bluetooth.handsfree.ag.AUDIO_STATE_UPDATE",
        "usual.event.bluetooth.a2dpsource.CONNECT_STATE_UPDATE",
        "usual.event.bluetooth.a2dpsource.CURRENT_DEVICE_UPDATE",
        "usual.event.bluetooth.a2dpsource.PLAYING_STATE_UPDATE",
        "usual.event.bluetooth.a2dpsource.AVRCP_CONNECT_STATE_UPDATE",
        "usual.event.bluetooth.a2dpsource.CODEC_VALUE_UPDATE",
        "usual.event.bluetooth.remotedevice.DISCOVERED",
        "usual.event.bluetooth.remotedevice.CLASS_VALUE_UPDATE",
        "usual.event.bluetooth.remotedevice.ACL_CONNECTED",
        "usual.event.bluetooth.remotedevice.ACL_DISCONNECTED",
        "usual.event.bluetooth.remotedevice.NAME_UPDATE",
        "usual.event.bluetooth.remotedevice.PAIR_STATE",
        "usual.event.bluetooth.remotedevice.BATTERY_VALUE_UPDATE",
        "usual.event.bluetooth.remotedevice.SDP_RESULT",
        "usual.event.bluetooth.remotedevice.UUID_VALUE",
        "usual.event.bluetooth.remotedevice.PAIRING_REQ",
        "usual.event.bluetooth.remotedevice.PAIRING_CANCEL",
        "usual.event.bluetooth.remotedevice.CONNECT_REQ",
        "usual.event.bluetooth.remotedevice.CONNECT_REPLY",
        "usual.event.bluetooth.remotedevice.CONNECT_CANCEL",
        "usual.event.bluetooth.handsfreeunit.CONNECT_STATE_UPDATE",
        "usual.event.bluetooth.handsfreeunit.AUDIO_STATE_UPDATE",
        "usual.event.bluetooth.handsfreeunit.AG_COMMON_EVENT",
        "usual.event.bluetooth.handsfreeunit.AG_CALL_STATE_UPDATE",
        "usual.event.bluetooth.host.STATE_UPDATE",
        "usual.event.bluetooth.host.REQ_DISCOVERABLE",
        "usual.event.bluetooth.host.REQ_ENABLE",
        "usual.event.bluetooth.host.REQ_DISABLE",
        "usual.event.bluetooth.host.SCAN_MODE_UPDATE",
        "usual.event.bluetooth.host.DISCOVERY_STARTED",
        "usual.event.bluetooth.host.DISCOVERY_FINISHED",
        "usual.event.bluetooth.host.NAME_UPDATE",
        "usual.event.bluetooth.a2dpsink.CONNECT_STATE_UPDATE",
        "usual.event.bluetooth.a2dpsink.PLAYING_STATE_UPDATE",
        "usual.event.bluetooth.a2dpsink.AUDIO_STATE_UPDATE",
        "usual.event.nfc.action.ADAPTER_STATE_CHANGED",
        "usual.event.nfc.action.RF_FIELD_ON_DETECTED",
        "usual.event.nfc.action.RF_FIELD_OFF_DETECTED",
        "usual.event.DISCHARGING",
        "usual.event.CHARGING",
        "usual.event.CHARGE_TYPE_CHANGED",
        "usual.event.DEVICE_IDLE_MODE_CHANGED",
        "usual.event.CHARGE_IDLE_MODE_CHANGED",
        "usual.event.DEVICE_IDLE_EXEMPTION_LIST_UPDATED",
        "usual.event.POWER_SAVE_MODE_CHANGED",
        "usual.event.USER_ADDED",
        "usual.event.USER_REMOVED",
        "common.event.ABILITY_ADDED",
        "common.event.ABILITY_REMOVED",
        "common.event.ABILITY_UPDATED",
        "usual.event.location.MODE_STATE_CHANGED",
        "common.event.IVI_SLEEP",
        "common.event.IVI_PAUSE",
        "common.event.IVI_STANDBY",
        "common.event.IVI_LASTMODE_SAVE",
        "common.event.IVI_VOLTAGE_ABNORMAL",
        "common.event.IVI_HIGH_TEMPERATURE",
        "common.event.IVI_EXTREME_TEMPERATURE",
        "common.event.IVI_TEMPERATURE_ABNORMAL",
        "common.event.IVI_VOLTAGE_RECOVERY",
        "common.event.IVI_TEMPERATURE_RECOVERY",
        "common.event.IVI_ACTIVE",
        "usual.event.hardware.usb.action.USB_STATE",
        "usual.event.hardware.usb.action.USB_PORT_CHANGED",
        "usual.event.hardware.usb.action.USB_DEVICE_ATTACHED",
        "usual.event.hardware.usb.action.USB_DEVICE_DETACHED",
        "usual.event.hardware.usb.action.USB_ACCESSORY_ATTACHED",
        "usual.event.hardware.usb.action.USB_ACCESSORY_DETACHED",
        "usual.event.data.DISK_REMOVED",
        "usual.event.data.DISK_UNMOUNTED",
        "usual.event.data.DISK_MOUNTED",
        "usual.event.data.DISK_BAD_REMOVAL",
        "usual.event.data.DISK_UNMOUNTABLE",
        "usual.event.data.DISK_EJECT",
        "usual.event.data.VOLUME_REMOVED",
        "usual.event.data.VOLUME_UNMOUNTED",
        "usual.event.data.VOLUME_MOUNTED",
        "usual.event.data.VOLUME_BAD_REMOVAL",
        "usual.event.data.VOLUME_EJECT",
        "usual.event.data.VISIBLE_ACCOUNTS_UPDATED",
        "usual.event.data.ACCOUNT_DELETED",
        "common.event.FOUNDATION_READY",
        "usual.event.AIRPLANE_MODE",
        "common.event.SPLIT_SCREEN",
        "usual.event.SLOT_CHANGE",
        "usual.event.SPN_INFO_CHANGED",
        "usual.event.QUICK_FIX_APPLY_RESULT",
        "usual.event.QUICK_FIX_REVOKE_RESULT",
        "usual.event.USER_INFO_UPDATED",
        "usual.event.HTTP_PROXY_CHANGE",
        "usual.event.SIM_STATE_CHANGED",
        "usual.event.SMS_RECEIVE_COMPLETED",
        "usual.event.SMS_EMERGENCY_CB_RECEIVE_COMPLETED",
        "usual.event.SMS_CB_RECEIVE_COMPLETED",
        "usual.event.STK_COMMAND",
        "usual.event.STK_SESSION_END",
        "usual.event.STK_CARD_STATE_CHANGED",
        "usual.event.STK_ALPHA_IDENTIFIER",
        "usual.event.SMS_WAPPUSH_RECEIVE_COMPLETED",
        "usual.event.OPERATOR_CONFIG_CHANGED",
        "usual.event.SIM.DEFAULT_SMS_SUBSCRIPTION_CHANGED",
        "usual.event.SIM.DEFAULT_DATA_SUBSCRIPTION_CHANGED",
        "usual.event.SIM.DEFAULT_MAIN_SUBSCRIPTION_CHANGED",
        "usual.event.SET_PRIMARY_SLOT_STATUS",
        "usual.event.PRIMARY_SLOT_ROAMING",
        "usual.event.SIM.DEFAULT_VOICE_SUBSCRIPTION_CHANGED",
        "usual.event.CALL_STATE_CHANGED",
        "usual.event.CELLULAR_DATA_STATE_CHANGED",
        "usual.event.NETWORK_STATE_CHANGED",
        "usual.event.SIGNAL_INFO_CHANGED",
        "usual.event.INCOMING_CALL_MISSED",
        "usual.event.RADIO_STATE_CHANGE",
        "usual.event.DOMAIN_ACCOUNT_STATUS_CHANGED",
        "usual.event.SCREEN_UNLOCKED",
        "usual.event.SCREEN_LOCKED",
        "usual.event.CONNECTIVITY_CHANGE",
        "common.event.SPECIAL_CODE",
        "usual.event.AUDIO_QUALITY_CHANGE",
        "usual.event.PRIVACY_STATE_CHANGED",
        "usual.event.PACKAGE_INSTALLATION_STARTED",
        "usual.event.DYNAMIC_ICON_CHANGED",
        "usual.event.MINORSMODE_ON",
        "usual.event.MINORSMODE_OFF",
        "usual.event.BUNDLE_RESOURCES_CHANGED",
        "usual.event.DATA_SHARE_READY",
        "usual.event.VPN_CONNECTION_STATUS_CHANGED",
        "usual.event.RESTORE_START",
    };
};

#endif // BASE_NOTIFICATION_COMMON_EVENT_MANAGER_INCLUDE_ANI_COMMON_EVENT_MANAGER_H
