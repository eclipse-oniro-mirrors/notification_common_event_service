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

import hilog from '@ohos.hilog';
import{ AsyncCallback, BusinessError } from '@ohos.base';
import{ CommonEventPublishData } from 'commonEvent.commonEventPublishData';
import{ CommonEventData } from 'commonEvent.commonEventData';
import{ CommonEventSubscribeInfo } from 'commonEvent.commonEventSubscribeInfo';
import{ CommonEventSubscriber } from 'commonEvent.commonEventSubscriber';

const TAG: string = 'commonEventManager';
const ERROR_PARAM_INVALID = 401;
const errorParamInvalid: BusinessError<string> = {code: ERROR_PARAM_INVALID, data: "Invalid parameter"};

type ResolveCallback<T> = (data: T) => void;
type RejectCallback = (err: Object) => void;

namespace commonEventManager {
    loadLibrary("ani_commoneventmanager.z");
    export native function publishExecute(event: string):int;
    export native function publishWithOptionsExecute(event: string, options: CommonEventPublishData):int;
    export native function publishAsUserExecute(event: string, userId: int):int;
    export native function publishAsUserWithOptionsExecute(event: string, userId: int,
        options: CommonEventPublishData):int;
    export native function createSubscriberExecute(subscribeInfo: CommonEventSubscribeInfo):CommonEventSubscriber;
    export native function subscribeExecute(subscriber: CommonEventSubscriber,
        callback: AsyncCallback<CommonEventData, void>):int;
    export native function unsubscribeExecute(subscriber: CommonEventSubscriber):int;
    export native function removeStickyCommonEventExecute(event: string):int;
    export native function setStaticSubscriberStateExecute(enable: boolean):int;
    export native function setStaticSubscriberStateWithEventsExecute(enable: boolean,events?: Array<string>):int;

    export function publish(event: string, callback: AsyncCallback<void, void>): void {
        hilog.info(0x0000, TAG, 'publish called event: %{public}s', event);
        let task = taskpool.execute(commonEventManager.publishExecute, event);
        task.then((e: NullishType)=>{
            let resultCode: Int  = e as Int;
            hilog.info(0x0000, TAG, 'publish call result:%{public}d.', resultCode.intValue());
            if (resultCode == 0) {
                callback(null, undefined);
            } else {
                let r: BusinessError = { code: resultCode.intValue(), data: undefined };
                callback(r, undefined);
            }
        }, (error:Object): void => {
            hilog.error(0x0000, TAG, 'publish error.');
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    export function publish(event: string, options: CommonEventPublishData, callback: AsyncCallback<void, void>): void {
        hilog.info(0x0000, TAG, 'publish with option call.');
        let task = taskpool.execute(commonEventManager.publishWithOptionsExecute, event, options);
        task.then((e: NullishType)=>{
            let resultCode: Int  = e as Int;
            hilog.info(0x0000, TAG, 'publish with option result:%{public}d.', resultCode.intValue());
            if (resultCode == 0) {
                callback(null, undefined);
            } else {
                let r: BusinessError = { code: resultCode.intValue(), data: undefined };
                callback(r, undefined);
            }
        }, (error:Object): void => {
            hilog.error(0x0000, TAG, 'publish with option error.');
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    export function publishAsUser(event: string, userId: number, callback: AsyncCallback<void, void>): void {
        let publishAsUserId: Int  = userId as Int;
        let task = taskpool.execute(commonEventManager.publishAsUserExecute, event, publishAsUserId);
        task.then((e: NullishType)=>{
            let resultCode: Int  = e as Int;
            if (resultCode == 0) {
                callback(null, undefined);
            } else {
                let r: BusinessError = { code: resultCode.intValue(), data: undefined };
                callback(r, undefined);
            }
        }, (error:Object): void => {
            hilog.error(0xD001202, TAG, 'publishAsUser error.');
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    export function publishAsUser(event: string, userId: number, options: CommonEventPublishData,
        callback: AsyncCallback<void, void>): void {
        let publishAsUserId: Int  = userId as Int;
        let task = taskpool.execute(commonEventManager.publishAsUserWithOptionsExecute, event, publishAsUserId, options);
        task.then((e: NullishType)=>{
            let resultCode: Int  = e as Int;
            if (resultCode == 0) {
                callback(null, undefined);
            } else {
                let r: BusinessError = { code: resultCode.intValue(), data: undefined };
                callback(r, undefined);
            }
        }, (error:Object): void => {
            hilog.error(0xD001202, TAG, 'publishAsUser with option error.');
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    export function createSubscriber(subscribeInfo: CommonEventSubscribeInfo,
        callback: AsyncCallback<CommonEventSubscriber, void>): void {
        hilog.info(0x0000, TAG, 'createSubscriber callback call.');
        let task = taskpool.execute(commonEventManager.createSubscriberExecute, subscribeInfo);
        task.then((e: NullishType)=>{
            let result: CommonEventSubscriber = e as CommonEventSubscriber;
            hilog.info(0x0000, TAG, 'createSubscriber result.');
            callback(null, result);
        }, (error: Object): void => {
            hilog.error(0x0000, TAG, 'createSubscriber error.');
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    export function createSubscriber(subscribeInfo: CommonEventSubscribeInfo):Promise<CommonEventSubscriber> {
        hilog.info(0x0000, TAG, 'createSubscriber Promise call');
        let p = new Promise<CommonEventSubscriber>((resolve: (v: CommonEventSubscriber) => void) => {
            let p1 = taskpool.execute(commonEventManager.createSubscriberExecute, subscribeInfo);
            p1.then((e :NullishType)=>{
                hilog.info(0x0000, TAG, 'createSubscriber Promise result.');
                let result: CommonEventSubscriber  = e as CommonEventSubscriber;
                resolve(result);
            }, (err: Object): void => {
                hilog.error(0x0000, TAG, 'createSubscriber Promise error');
            });
        });
        return p;
    }

    export function createSubscriberSync(subscribeInfo: CommonEventSubscribeInfo): CommonEventSubscriber{
        hilog.info(0x0000, TAG, 'createSubscriberSync call');
        return commonEventManager.createSubscriberExecute(subscribeInfo);
    }

    export function subscribe(subscriber: CommonEventSubscriber, callback: AsyncCallback<CommonEventData, void>): void {
        hilog.info(0x0000, TAG, 'subscribe call.');
        let task = taskpool.execute(commonEventManager.subscribeExecute, subscriber, callback);
        task.then((e: NullishType)=>{
            let resultCode: Int  = e as Int;
            hilog.info(0x0000, TAG, 'subscribe result:%{public}d.', resultCode.intValue());
            if (resultCode != 0) {
                let r: BusinessError = { code: resultCode.intValue(), data: undefined };
                callback(r, undefined);
            }
        }, (error:Object): void => {
            hilog.error(0x0000, TAG, 'subscribe error');
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    export function unsubscribe(subscriber: CommonEventSubscriber, callback?: AsyncCallback<void, void>): void {
        hilog.info(0x0000, TAG, 'unsubscribe call.');
        let task = taskpool.execute(commonEventManager.unsubscribeExecute, subscriber);
        task.then((e: NullishType)=>{
            let resultCode: Int  = e as Int;
            hilog.info(0x0000, TAG, 'unsubscribe result:%{public}d.', resultCode.intValue());
            if (callback != undefined) {
                if (resultCode == 0) {
                    callback(null, undefined);
                } else {
                    let r: BusinessError = { code: resultCode.intValue(), data: undefined };
                    callback(r, undefined);
                }
            }
        }, (error:Object): void => {
            hilog.error(0x0000, TAG, 'unsubscribe error');
            if (callback != undefined) {
                let err: BusinessError = error as BusinessError;
                callback(err, undefined);
            }
        });
    }

    export function removeStickyCommonEvent(event: string, callback: AsyncCallback<void, void>): void {
        if (event == undefined) {
            throw errorParamInvalid;
        }
        let task = taskpool.execute(commonEventManager.removeStickyCommonEventExecute, event);
        task.then((e: NullishType)=>{
            callback(null, undefined);
        }, (error: Object): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    export function removeStickyCommonEvent(event: string): Promise<void> {
        if (event == undefined) {
            throw errorParamInvalid;
        }
        let p = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let task = taskpool.execute(commonEventManager.removeStickyCommonEventExecute, event);
            task.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Object): void => {
                hilog.error(0xD001202, TAG, 'removeStickyCommonEvent Promise error');
                reject(error);
            });
        });
        return p;
    }

    export function setStaticSubscriberState(enable: boolean, callback: AsyncCallback<void, void>): void {
        let task = taskpool.execute(commonEventManager.setStaticSubscriberStateExecute, enable);
        task.then((e: NullishType)=>{
            callback(null, undefined);
        }, (error: Object): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    export function setStaticSubscriberState(enable: boolean): Promise<void> {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
        let task = taskpool.execute(commonEventManager.setStaticSubscriberStateExecute, enable);
        task.then((e: NullishType): void => {
            resolve(undefined);
        }, (error: Object): void => {
            hilog.error(0xD001202, TAG, 'setStaticSubscriberState Promise error');
            reject(error);
        });
    });
        return pPromise;
    }

    export function setStaticSubscriberState(enable: boolean, events?: Array<string>): Promise<void> {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
        let task = taskpool.execute(commonEventManager.setStaticSubscriberStateWithEventsExecute, enable, events);
        task.then((e: NullishType): void => {
            resolve(undefined);
        }, (error: Object): void => {
            hilog.error(0xD001202, TAG, 'setStaticSubscriberStateExecute Promise error.');
            reject(error);
        });
    });
        return pPromise;
}

    export enum Support {
        COMMON_EVENT_BOOT_COMPLETED = 'usual.event.BOOT_COMPLETED',
        COMMON_EVENT_LOCKED_BOOT_COMPLETED = 'usual.event.LOCKED_BOOT_COMPLETED',
        COMMON_EVENT_SHUTDOWN = 'usual.event.SHUTDOWN',
        COMMON_EVENT_BATTERY_CHANGED = 'usual.event.BATTERY_CHANGED',
        COMMON_EVENT_BATTERY_LOW = 'usual.event.BATTERY_LOW',
        COMMON_EVENT_BATTERY_OKAY = 'usual.event.BATTERY_OKAY',
        COMMON_EVENT_POWER_CONNECTED = 'usual.event.POWER_CONNECTED',
        COMMON_EVENT_POWER_DISCONNECTED = 'usual.event.POWER_DISCONNECTED',
        COMMON_EVENT_SCREEN_OFF = 'usual.event.SCREEN_OFF',
        COMMON_EVENT_SCREEN_ON = 'usual.event.SCREEN_ON',
        COMMON_EVENT_THERMAL_LEVEL_CHANGED = 'usual.event.THERMAL_LEVEL_CHANGED',
        COMMON_EVENT_ENTER_FORCE_SLEEP = 'usual.event.ENTER_FORCE_SLEEP',
        COMMON_EVENT_EXIT_FORCE_SLEEP = 'usual.event.EXIT_FORCE_SLEEP',
        COMMON_EVENT_ENTER_HIBERNATE = 'usual.event.ENTER_HIBERNATE',
        COMMON_EVENT_EXIT_HIBERNATE = 'usual.event.EXIT_HIBERNATE',
        COMMON_EVENT_TIME_TICK = 'usual.event.TIME_TICK',
        COMMON_EVENT_TIME_CHANGED = 'usual.event.TIME_CHANGED',
        COMMON_EVENT_DATE_CHANGED = 'usual.event.DATE_CHANGED',
        COMMON_EVENT_TIMEZONE_CHANGED = 'usual.event.TIMEZONE_CHANGED',
        COMMON_EVENT_CLOSE_SYSTEM_DIALOGS = 'usual.event.CLOSE_SYSTEM_DIALOGS',
        COMMON_EVENT_PACKAGE_ADDED = 'usual.event.PACKAGE_ADDED',
        COMMON_EVENT_PACKAGE_REPLACED = 'usual.event.PACKAGE_REPLACED',
        COMMON_EVENT_MY_PACKAGE_REPLACED = 'usual.event.MY_PACKAGE_REPLACED',
        COMMON_EVENT_PACKAGE_REMOVED = 'usual.event.PACKAGE_REMOVED',
        COMMON_EVENT_BUNDLE_REMOVED = 'usual.event.BUNDLE_REMOVED',
        COMMON_EVENT_PACKAGE_FULLY_REMOVED = 'usual.event.PACKAGE_FULLY_REMOVED',
        COMMON_EVENT_PACKAGE_CHANGED = 'usual.event.PACKAGE_CHANGED',
        COMMON_EVENT_PACKAGE_RESTARTED = 'usual.event.PACKAGE_RESTARTED',
        COMMON_EVENT_PACKAGE_DATA_CLEARED = 'usual.event.PACKAGE_DATA_CLEARED',
        COMMON_EVENT_PACKAGE_CACHE_CLEARED = 'usual.event.PACKAGE_CACHE_CLEARED',
        COMMON_EVENT_PACKAGES_SUSPENDED = 'usual.event.PACKAGES_SUSPENDED',
        COMMON_EVENT_PACKAGES_UNSUSPENDED = 'usual.event.PACKAGES_UNSUSPENDED',
        COMMON_EVENT_MY_PACKAGE_SUSPENDED = 'usual.event.MY_PACKAGE_SUSPENDED',
        COMMON_EVENT_MY_PACKAGE_UNSUSPENDED = 'usual.event.MY_PACKAGE_UNSUSPENDED',
        COMMON_EVENT_UID_REMOVED = 'usual.event.UID_REMOVED',
        COMMON_EVENT_PACKAGE_FIRST_LAUNCH = 'usual.event.PACKAGE_FIRST_LAUNCH',
        COMMON_EVENT_PACKAGE_NEEDS_VERIFICATION = 'usual.event.PACKAGE_NEEDS_VERIFICATION',
        COMMON_EVENT_PACKAGE_VERIFIED = 'usual.event.PACKAGE_VERIFIED',
        COMMON_EVENT_EXTERNAL_APPLICATIONS_AVAILABLE = 'usual.event.EXTERNAL_APPLICATIONS_AVAILABLE',
        COMMON_EVENT_EXTERNAL_APPLICATIONS_UNAVAILABLE = 'usual.event.EXTERNAL_APPLICATIONS_UNAVAILABLE',
        COMMON_EVENT_CONFIGURATION_CHANGED = 'usual.event.CONFIGURATION_CHANGED',
        COMMON_EVENT_LOCALE_CHANGED = 'usual.event.LOCALE_CHANGED',
        COMMON_EVENT_MANAGE_PACKAGE_STORAGE = 'usual.event.MANAGE_PACKAGE_STORAGE',
        COMMON_EVENT_DRIVE_MODE = 'common.event.DRIVE_MODE',
        COMMON_EVENT_HOME_MODE = 'common.event.HOME_MODE',
        COMMON_EVENT_OFFICE_MODE = 'common.event.OFFICE_MODE',
        COMMON_EVENT_USER_STARTED = 'usual.event.USER_STARTED',
        COMMON_EVENT_USER_BACKGROUND = 'usual.event.USER_BACKGROUND',
        COMMON_EVENT_USER_FOREGROUND = 'usual.event.USER_FOREGROUND',
        COMMON_EVENT_USER_SWITCHED = 'usual.event.USER_SWITCHED',
        COMMON_EVENT_USER_STARTING = 'usual.event.USER_STARTING',
        COMMON_EVENT_USER_UNLOCKED = 'usual.event.USER_UNLOCKED',
        COMMON_EVENT_USER_STOPPING = 'usual.event.USER_STOPPING',
        COMMON_EVENT_USER_STOPPED = 'usual.event.USER_STOPPED',
        COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGIN = 'common.event.DISTRIBUTED_ACCOUNT_LOGIN',
        COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOUT = 'common.event.DISTRIBUTED_ACCOUNT_LOGOUT',
        COMMON_EVENT_DISTRIBUTED_ACCOUNT_TOKEN_INVALID = 'common.event.DISTRIBUTED_ACCOUNT_TOKEN_INVALID',
        COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOFF = 'common.event.DISTRIBUTED_ACCOUNT_LOGOFF',
        COMMON_EVENT_WIFI_POWER_STATE = 'usual.event.wifi.POWER_STATE',
        COMMON_EVENT_WIFI_SCAN_FINISHED = 'usual.event.wifi.SCAN_FINISHED',
        COMMON_EVENT_WIFI_RSSI_VALUE = 'usual.event.wifi.RSSI_VALUE',
        COMMON_EVENT_WIFI_CONN_STATE = 'usual.event.wifi.CONN_STATE',
        COMMON_EVENT_WIFI_HOTSPOT_STATE = 'usual.event.wifi.HOTSPOT_STATE',
        COMMON_EVENT_WIFI_AP_STA_JOIN = 'usual.event.wifi.WIFI_HS_STA_JOIN',
        COMMON_EVENT_WIFI_AP_STA_LEAVE = 'usual.event.wifi.WIFI_HS_STA_LEAVE',
        COMMON_EVENT_WIFI_MPLINK_STATE_CHANGE = 'usual.event.wifi.mplink.STATE_CHANGE',
        COMMON_EVENT_WIFI_P2P_CONN_STATE = 'usual.event.wifi.p2p.CONN_STATE_CHANGE',
        COMMON_EVENT_WIFI_P2P_STATE_CHANGED = 'usual.event.wifi.p2p.STATE_CHANGE',
        COMMON_EVENT_WIFI_P2P_PEERS_STATE_CHANGED = 'usual.event.wifi.p2p.DEVICES_CHANGE',
        COMMON_EVENT_WIFI_P2P_PEERS_DISCOVERY_STATE_CHANGED = 'usual.event.wifi.p2p.PEER_DISCOVERY_STATE_CHANGE',
        COMMON_EVENT_WIFI_P2P_CURRENT_DEVICE_STATE_CHANGED = 'usual.event.wifi.p2p.CURRENT_DEVICE_CHANGE',
        COMMON_EVENT_WIFI_P2P_GROUP_STATE_CHANGED = 'usual.event.wifi.p2p.GROUP_STATE_CHANGED',
        COMMON_EVENT_BLUETOOTH_HANDSFREE_AG_CONNECT_STATE_UPDATE =
            'usual.event.bluetooth.handsfree.ag.CONNECT_STATE_UPDATE',
        COMMON_EVENT_BLUETOOTH_HANDSFREE_AG_CURRENT_DEVICE_UPDATE =
            'usual.event.bluetooth.handsfree.ag.CURRENT_DEVICE_UPDATE',
        COMMON_EVENT_BLUETOOTH_HANDSFREE_AG_AUDIO_STATE_UPDATE =
            'usual.event.bluetooth.handsfree.ag.AUDIO_STATE_UPDATE',
        COMMON_EVENT_BLUETOOTH_A2DPSOURCE_CONNECT_STATE_UPDATE =
            'usual.event.bluetooth.a2dpsource.CONNECT_STATE_UPDATE',
        COMMON_EVENT_BLUETOOTH_A2DPSOURCE_CURRENT_DEVICE_UPDATE =
            'usual.event.bluetooth.a2dpsource.CURRENT_DEVICE_UPDATE',
        COMMON_EVENT_BLUETOOTH_A2DPSOURCE_PLAYING_STATE_UPDATE =
            'usual.event.bluetooth.a2dpsource.PLAYING_STATE_UPDATE',
        COMMON_EVENT_BLUETOOTH_A2DPSOURCE_AVRCP_CONNECT_STATE_UPDATE =
            'usual.event.bluetooth.a2dpsource.AVRCP_CONNECT_STATE_UPDATE',
        COMMON_EVENT_BLUETOOTH_A2DPSOURCE_CODEC_VALUE_UPDATE =
            'usual.event.bluetooth.a2dpsource.CODEC_VALUE_UPDATE',
        COMMON_EVENT_BLUETOOTH_REMOTEDEVICE_DISCOVERED = 'usual.event.bluetooth.remotedevice.DISCOVERED',
        COMMON_EVENT_BLUETOOTH_REMOTEDEVICE_CLASS_VALUE_UPDATE =
            'usual.event.bluetooth.remotedevice.CLASS_VALUE_UPDATE',
        COMMON_EVENT_BLUETOOTH_REMOTEDEVICE_ACL_CONNECTED = 'usual.event.bluetooth.remotedevice.ACL_CONNECTED',
        COMMON_EVENT_BLUETOOTH_REMOTEDEVICE_ACL_DISCONNECTED = 'usual.event.bluetooth.remotedevice.ACL_DISCONNECTED',
        COMMON_EVENT_BLUETOOTH_REMOTEDEVICE_NAME_UPDATE = 'usual.event.bluetooth.remotedevice.NAME_UPDATE',
        COMMON_EVENT_BLUETOOTH_REMOTEDEVICE_PAIR_STATE = 'usual.event.bluetooth.remotedevice.PAIR_STATE',
        COMMON_EVENT_BLUETOOTH_REMOTEDEVICE_BATTERY_VALUE_UPDATE =
            'usual.event.bluetooth.remotedevice.BATTERY_VALUE_UPDATE',
        COMMON_EVENT_BLUETOOTH_REMOTEDEVICE_SDP_RESULT = 'usual.event.bluetooth.remotedevice.SDP_RESULT',
        COMMON_EVENT_BLUETOOTH_REMOTEDEVICE_UUID_VALUE = 'usual.event.bluetooth.remotedevice.UUID_VALUE',
        COMMON_EVENT_BLUETOOTH_REMOTEDEVICE_PAIRING_REQ = 'usual.event.bluetooth.remotedevice.PAIRING_REQ',
        COMMON_EVENT_BLUETOOTH_REMOTEDEVICE_PAIRING_CANCEL = 'usual.event.bluetooth.remotedevice.PAIRING_CANCEL',
        COMMON_EVENT_BLUETOOTH_REMOTEDEVICE_CONNECT_REQ = 'usual.event.bluetooth.remotedevice.CONNECT_REQ',
        COMMON_EVENT_BLUETOOTH_REMOTEDEVICE_CONNECT_REPLY = 'usual.event.bluetooth.remotedevice.CONNECT_REPLY',
        COMMON_EVENT_BLUETOOTH_REMOTEDEVICE_CONNECT_CANCEL = 'usual.event.bluetooth.remotedevice.CONNECT_CANCEL',
        COMMON_EVENT_BLUETOOTH_HANDSFREEUNIT_CONNECT_STATE_UPDATE =
            'usual.event.bluetooth.handsfreeunit.CONNECT_STATE_UPDATE',
        COMMON_EVENT_BLUETOOTH_HANDSFREEUNIT_AUDIO_STATE_UPDATE =
            'usual.event.bluetooth.handsfreeunit.AUDIO_STATE_UPDATE',
        COMMON_EVENT_BLUETOOTH_HANDSFREEUNIT_AG_COMMON_EVENT = 'usual.event.bluetooth.handsfreeunit.AG_COMMON_EVENT',
        COMMON_EVENT_BLUETOOTH_HANDSFREEUNIT_AG_CALL_STATE_UPDATE =
            'usual.event.bluetooth.handsfreeunit.AG_CALL_STATE_UPDATE',
        COMMON_EVENT_BLUETOOTH_HOST_STATE_UPDATE = 'usual.event.bluetooth.host.STATE_UPDATE',
        COMMON_EVENT_BLUETOOTH_HOST_REQ_DISCOVERABLE = 'usual.event.bluetooth.host.REQ_DISCOVERABLE',
        COMMON_EVENT_BLUETOOTH_HOST_REQ_ENABLE = 'usual.event.bluetooth.host.REQ_ENABLE',
        COMMON_EVENT_BLUETOOTH_HOST_REQ_DISABLE = 'usual.event.bluetooth.host.REQ_DISABLE',
        COMMON_EVENT_BLUETOOTH_HOST_SCAN_MODE_UPDATE = 'usual.event.bluetooth.host.SCAN_MODE_UPDATE',
        COMMON_EVENT_BLUETOOTH_HOST_DISCOVERY_STARTED = 'usual.event.bluetooth.host.DISCOVERY_STARTED',
        COMMON_EVENT_BLUETOOTH_HOST_DISCOVERY_FINISHED = 'usual.event.bluetooth.host.DISCOVERY_FINISHED',
        COMMON_EVENT_BLUETOOTH_HOST_NAME_UPDATE = 'usual.event.bluetooth.host.NAME_UPDATE',
        COMMON_EVENT_BLUETOOTH_A2DPSINK_CONNECT_STATE_UPDATE = 'usual.event.bluetooth.a2dpsink.CONNECT_STATE_UPDATE',
        COMMON_EVENT_BLUETOOTH_A2DPSINK_PLAYING_STATE_UPDATE = 'usual.event.bluetooth.a2dpsink.PLAYING_STATE_UPDATE',
        COMMON_EVENT_BLUETOOTH_A2DPSINK_AUDIO_STATE_UPDATE = 'usual.event.bluetooth.a2dpsink.AUDIO_STATE_UPDATE',
        COMMON_EVENT_NFC_ACTION_ADAPTER_STATE_CHANGED = 'usual.event.nfc.action.ADAPTER_STATE_CHANGED',
        COMMON_EVENT_NFC_ACTION_RF_FIELD_ON_DETECTED = 'usual.event.nfc.action.RF_FIELD_ON_DETECTED',
        COMMON_EVENT_NFC_ACTION_RF_FIELD_OFF_DETECTED = 'usual.event.nfc.action.RF_FIELD_OFF_DETECTED',
        COMMON_EVENT_DISCHARGING = 'usual.event.DISCHARGING',
        COMMON_EVENT_CHARGING = 'usual.event.CHARGING',
        COMMON_EVENT_CHARGE_TYPE_CHANGED = 'usual.event.CHARGE_TYPE_CHANGED',
        COMMON_EVENT_DEVICE_IDLE_MODE_CHANGED = 'usual.event.DEVICE_IDLE_MODE_CHANGED',
        COMMON_EVENT_CHARGE_IDLE_MODE_CHANGED = 'usual.event.CHARGE_IDLE_MODE_CHANGED',
        COMMON_EVENT_DEVICE_IDLE_EXEMPTION_LIST_UPDATED = 'usual.event.DEVICE_IDLE_EXEMPTION_LIST_UPDATED',
        COMMON_EVENT_POWER_SAVE_MODE_CHANGED = 'usual.event.POWER_SAVE_MODE_CHANGED',
        COMMON_EVENT_USER_ADDED = 'usual.event.USER_ADDED',
        COMMON_EVENT_USER_REMOVED = 'usual.event.USER_REMOVED',
        COMMON_EVENT_ABILITY_ADDED = 'common.event.ABILITY_ADDED',
        COMMON_EVENT_ABILITY_REMOVED = 'common.event.ABILITY_REMOVED',
        COMMON_EVENT_ABILITY_UPDATED = 'common.event.ABILITY_UPDATED',
        COMMON_EVENT_LOCATION_MODE_STATE_CHANGED = 'usual.event.location.MODE_STATE_CHANGED',
        COMMON_EVENT_IVI_SLEEP = 'common.event.IVI_SLEEP',
        COMMON_EVENT_IVI_PAUSE = 'common.event.IVI_PAUSE',
        COMMON_EVENT_IVI_STANDBY = 'common.event.IVI_STANDBY',
        COMMON_EVENT_IVI_LASTMODE_SAVE = 'common.event.IVI_LASTMODE_SAVE',
        COMMON_EVENT_IVI_VOLTAGE_ABNORMAL = 'common.event.IVI_VOLTAGE_ABNORMAL',
        COMMON_EVENT_IVI_HIGH_TEMPERATURE = 'common.event.IVI_HIGH_TEMPERATURE',
        COMMON_EVENT_IVI_EXTREME_TEMPERATURE = 'common.event.IVI_EXTREME_TEMPERATURE',
        COMMON_EVENT_IVI_TEMPERATURE_ABNORMAL = 'common.event.IVI_TEMPERATURE_ABNORMAL',
        COMMON_EVENT_IVI_VOLTAGE_RECOVERY = 'common.event.IVI_VOLTAGE_RECOVERY',
        COMMON_EVENT_IVI_TEMPERATURE_RECOVERY = 'common.event.IVI_TEMPERATURE_RECOVERY',
        COMMON_EVENT_IVI_ACTIVE = 'common.event.IVI_ACTIVE',
        COMMON_EVENT_USB_STATE = 'usual.event.hardware.usb.action.USB_STATE',
        COMMON_EVENT_USB_PORT_CHANGED = 'usual.event.hardware.usb.action.USB_PORT_CHANGED',
        COMMON_EVENT_USB_DEVICE_ATTACHED = 'usual.event.hardware.usb.action.USB_DEVICE_ATTACHED',
        COMMON_EVENT_USB_DEVICE_DETACHED = 'usual.event.hardware.usb.action.USB_DEVICE_DETACHED',
        COMMON_EVENT_USB_ACCESSORY_ATTACHED = 'usual.event.hardware.usb.action.USB_ACCESSORY_ATTACHED',
        COMMON_EVENT_USB_ACCESSORY_DETACHED = 'usual.event.hardware.usb.action.USB_ACCESSORY_DETACHED',
        COMMON_EVENT_DISK_REMOVED = 'usual.event.data.DISK_REMOVED',
        COMMON_EVENT_DISK_UNMOUNTED = 'usual.event.data.DISK_UNMOUNTED',
        COMMON_EVENT_DISK_MOUNTED = 'usual.event.data.DISK_MOUNTED',
        COMMON_EVENT_DISK_BAD_REMOVAL = 'usual.event.data.DISK_BAD_REMOVAL',
        COMMON_EVENT_DISK_UNMOUNTABLE = 'usual.event.data.DISK_UNMOUNTABLE',
        COMMON_EVENT_DISK_EJECT = 'usual.event.data.DISK_EJECT',
        COMMON_EVENT_VOLUME_REMOVED = 'usual.event.data.VOLUME_REMOVED',
        COMMON_EVENT_VOLUME_UNMOUNTED = 'usual.event.data.VOLUME_UNMOUNTED',
        COMMON_EVENT_VOLUME_MOUNTED = 'usual.event.data.VOLUME_MOUNTED',
        COMMON_EVENT_VOLUME_BAD_REMOVAL = 'usual.event.data.VOLUME_BAD_REMOVAL',
        COMMON_EVENT_VOLUME_EJECT = 'usual.event.data.VOLUME_EJECT',
        COMMON_EVENT_VISIBLE_ACCOUNTS_UPDATED = 'usual.event.data.VISIBLE_ACCOUNTS_UPDATED',
        COMMON_EVENT_ACCOUNT_DELETED = 'usual.event.data.ACCOUNT_DELETED',
        COMMON_EVENT_FOUNDATION_READY = 'common.event.FOUNDATION_READY',
        COMMON_EVENT_AIRPLANE_MODE_CHANGED = 'usual.event.AIRPLANE_MODE',
        COMMON_EVENT_SPLIT_SCREEN = 'common.event.SPLIT_SCREEN',
        COMMON_EVENT_SLOT_CHANGE = 'usual.event.SLOT_CHANGE',
        COMMON_EVENT_SPN_INFO_CHANGED = 'usual.event.SPN_INFO_CHANGED',
        COMMON_EVENT_QUICK_FIX_APPLY_RESULT = 'usual.event.QUICK_FIX_APPLY_RESULT',
        COMMON_EVENT_QUICK_FIX_REVOKE_RESULT = 'usual.event.QUICK_FIX_REVOKE_RESULT',
        COMMON_EVENT_USER_INFO_UPDATED = 'usual.event.USER_INFO_UPDATED',
        COMMON_EVENT_HTTP_PROXY_CHANGE = 'usual.event.HTTP_PROXY_CHANGE',
        COMMON_EVENT_SIM_STATE_CHANGED = 'usual.event.SIM_STATE_CHANGED',
        COMMON_EVENT_SMS_RECEIVE_COMPLETED = 'usual.event.SMS_RECEIVE_COMPLETED',
        COMMON_EVENT_SMS_EMERGENCY_CB_RECEIVE_COMPLETED = 'usual.event.SMS_EMERGENCY_CB_RECEIVE_COMPLETED',
        COMMON_EVENT_SMS_CB_RECEIVE_COMPLETED = 'usual.event.SMS_CB_RECEIVE_COMPLETED',
        COMMON_EVENT_STK_COMMAND = 'usual.event.STK_COMMAND',
        COMMON_EVENT_STK_SESSION_END = 'usual.event.STK_SESSION_END',
        COMMON_EVENT_STK_CARD_STATE_CHANGED = 'usual.event.STK_CARD_STATE_CHANGED',
        COMMON_EVENT_STK_ALPHA_IDENTIFIER = 'usual.event.STK_ALPHA_IDENTIFIER',
        COMMON_EVENT_SMS_WAPPUSH_RECEIVE_COMPLETED = 'usual.event.SMS_WAPPUSH_RECEIVE_COMPLETED',
        COMMON_EVENT_OPERATOR_CONFIG_CHANGED = 'usual.event.OPERATOR_CONFIG_CHANGED',
        COMMON_EVENT_SIM_CARD_DEFAULT_SMS_SUBSCRIPTION_CHANGED = 'usual.event.SIM.DEFAULT_SMS_SUBSCRIPTION_CHANGED',
        COMMON_EVENT_SIM_CARD_DEFAULT_DATA_SUBSCRIPTION_CHANGED = 'usual.event.SIM.DEFAULT_DATA_SUBSCRIPTION_CHANGED',
        COMMON_EVENT_SIM_CARD_DEFAULT_MAIN_SUBSCRIPTION_CHANGED = 'usual.event.SIM.DEFAULT_MAIN_SUBSCRIPTION_CHANGED',
        COMMON_EVENT_SET_PRIMARY_SLOT_STATUS = 'usual.event.SET_PRIMARY_SLOT_STATUS',
        COMMON_EVENT_PRIMARY_SLOT_ROAMING = 'usual.event.PRIMARY_SLOT_ROAMING',
        COMMON_EVENT_SIM_CARD_DEFAULT_VOICE_SUBSCRIPTION_CHANGED =
            'usual.event.SIM.DEFAULT_VOICE_SUBSCRIPTION_CHANGED',
        COMMON_EVENT_CALL_STATE_CHANGED = 'usual.event.CALL_STATE_CHANGED',
        COMMON_EVENT_CELLULAR_DATA_STATE_CHANGED = 'usual.event.CELLULAR_DATA_STATE_CHANGED',
        COMMON_EVENT_NETWORK_STATE_CHANGED = 'usual.event.NETWORK_STATE_CHANGED',
        COMMON_EVENT_SIGNAL_INFO_CHANGED = 'usual.event.SIGNAL_INFO_CHANGED',
        COMMON_EVENT_INCOMING_CALL_MISSED = 'usual.event.INCOMING_CALL_MISSED',
        COMMON_EVENT_RADIO_STATE_CHANGE = 'usual.event.RADIO_STATE_CHANGE',
        COMMON_EVENT_DOMAIN_ACCOUNT_STATUS_CHANGED = 'usual.event.DOMAIN_ACCOUNT_STATUS_CHANGED',
        COMMON_EVENT_SCREEN_UNLOCKED = 'usual.event.SCREEN_UNLOCKED',
        COMMON_EVENT_SCREEN_LOCKED = 'usual.event.SCREEN_LOCKED',
        COMMON_EVENT_CONNECTIVITY_CHANGE = 'usual.event.CONNECTIVITY_CHANGE',
        COMMON_EVENT_SPECIAL_CODE = 'common.event.SPECIAL_CODE',
        COMMON_EVENT_AUDIO_QUALITY_CHANGE = 'usual.event.AUDIO_QUALITY_CHANGE',
        COMMON_EVENT_PRIVACY_STATE_CHANGED = 'usual.event.PRIVACY_STATE_CHANGED',
        COMMON_EVENT_PACKAGE_INSTALLATION_STARTED = 'usual.event.PACKAGE_INSTALLATION_STARTED',
        COMMON_EVENT_DYNAMIC_ICON_CHANGED = 'usual.event.DYNAMIC_ICON_CHANGED',
        COMMON_EVENT_MINORSMODE_ON = 'usual.event.MINORSMODE_ON',
        COMMON_EVENT_MINORSMODE_OFF = 'usual.event.MINORSMODE_OFF',
        COMMON_EVENT_BUNDLE_RESOURCES_CHANGED = 'usual.event.BUNDLE_RESOURCES_CHANGED',
        COMMON_EVENT_DATA_SHARE_READY = 'usual.event.DATA_SHARE_READY',
        COMMON_EVENT_VPN_CONNECTION_STATUS_CHANGED = 'usual.event.VPN_CONNECTION_STATUS_CHANGED',
        COMMON_EVENT_RESTORE_START = 'usual.event.RESTORE_START',
        COMMON_EVENT_MANAGED_BROWSER_POLICY_CHANGED = 'usual.event.MANAGED_BROWSER_POLICY_CHANGED',
    }

}

export default commonEventManager;
