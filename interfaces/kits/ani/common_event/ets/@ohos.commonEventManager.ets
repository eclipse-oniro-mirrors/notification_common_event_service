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
type RejectCallback = (err: Error) => void;

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
            hilog.info(0x0000, TAG, 'publish call result:%{public}d.', resultCode.toInt());
            let r: BusinessError = { code: resultCode.toInt(), data: undefined };
            callback(r, undefined);
        }, (err:Object): void => {
            hilog.error(0x0000, TAG, 'publish error.');
        });
    }

    export function publish(event: string, options: CommonEventPublishData, callback: AsyncCallback<void, void>): void {
        hilog.info(0x0000, TAG, 'publish with option call.');
        let task = taskpool.execute(commonEventManager.publishWithOptionsExecute, event, options);
        task.then((e: NullishType)=>{
            let resultCode: Int  = e as Int;
            hilog.info(0x0000, TAG, 'publish with option result:%{public}d.', resultCode.toInt());
            let r: BusinessError = { code: resultCode.toInt(), data: undefined };
            callback(r, undefined);
        }, (err:Object): void => {
            hilog.error(0x0000, TAG, 'publish with option error.');
        });
    }

    export function publishAsUser(event: string, userId: number, callback: AsyncCallback<void, void>): void {
        let publishAsUserId: Int  = userId.toInt();
        let task = taskpool.execute(commonEventManager.publishAsUserExecute, event, publishAsUserId);
        task.then((e: NullishType)=>{
            let resultCode: Int  = e as Int;
            let r: BusinessError = { code: resultCode.toInt(), data: undefined };
            callback(r, undefined);
        }, (err:Object): void => {
            hilog.error(0xD001202, TAG, 'publishAsUser error.');
        });
    }

    export function publishAsUser(event: string, userId: number, options: CommonEventPublishData,
        callback: AsyncCallback<void, void>): void {
        let publishAsUserId: Int  = userId.toInt();
        let task = taskpool.execute(commonEventManager.publishAsUserWithOptionsExecute, event, publishAsUserId, options);
        task.then((e: NullishType)=>{
            let resultCode: Int  = e as Int;
            let r: BusinessError = { code: resultCode.toInt(), data: undefined };
            callback(r, undefined);
        }, (err:Object): void => {
            hilog.error(0xD001202, TAG, 'publishAsUser with option error.');
        });
    }

    export function createSubscriber(subscribeInfo: CommonEventSubscribeInfo,
        callback: AsyncCallback<CommonEventSubscriber, void>): void {
        hilog.info(0x0000, TAG, 'createSubscriber callback call.');
        let task = taskpool.execute(commonEventManager.createSubscriberExecute, subscribeInfo);
        task.then((e: NullishType)=>{
            let result: CommonEventSubscriber = e as CommonEventSubscriber;
            hilog.info(0x0000, TAG, 'createSubscriber result.');
            let r: BusinessError = { code: 0, data: undefined };
            callback(r, result);
        }, (err:Object): void => {
            hilog.error(0x0000, TAG, 'createSubscriber error.');
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
            }, (err: Error): void => {
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
            hilog.info(0x0000, TAG, 'subscribe result:%{public}d.', resultCode.toInt());
            if (resultCode != 0) {
                let a: CommonEventData;
                let r: BusinessError = { code: resultCode.toInt(), data: undefined };
                callback(r, a);
            }
        }, (err:Object): void => {
            hilog.error(0x0000, TAG, 'subscribe error');
        });
    }

    export function unsubscribe(subscriber: CommonEventSubscriber, callback?: AsyncCallback<void, void>): void {
        hilog.info(0x0000, TAG, 'unsubscribe call.');
        let task = taskpool.execute(commonEventManager.unsubscribeExecute, subscriber);
        task.then((e: NullishType)=>{
            let resultCode: Int  = e as Int;
            hilog.info(0x0000, TAG, 'unsubscribe result:%{public}d.', resultCode.toInt());
            let r: BusinessError = { code: resultCode.toInt(), data: undefined };
            if (callback != undefined) {
                callback(r, undefined);
            }
        }, (err:Object): void => {
            hilog.error(0x0000, TAG, 'unsubscribe error');
        });
    }

    export function removeStickyCommonEvent(event: string, callback: AsyncCallback<void, void>): void {
        if (event == undefined) {
            throw errorParamInvalid;
        }
        let task = taskpool.execute(commonEventManager.removeStickyCommonEventExecute, event);
        task.then((e: NullishType)=>{
            let err: BusinessError<void> = {code: 0, data: undefined};
            callback(err, undefined);
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
            }, (error: Error): void => {
                hilog.error(0xD001202, TAG, 'removeStickyCommonEvent Promise error');
                reject(error);
            });
        });
        return p;
    }

    export function setStaticSubscriberState(enable: boolean, callback: AsyncCallback<void, void>): void {
        let task = taskpool.execute(commonEventManager.setStaticSubscriberStateExecute, enable);
        task.then((e: NullishType)=>{
            let err: BusinessError<void> = {code: 0, data: undefined};
            callback(err, undefined);
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
        }, (error: Error): void => {
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
        }, (error: Error): void => {
            hilog.error(0xD001202, TAG, 'setStaticSubscriberStateExecute Promise error.');
            reject(error);
        });
    });
        return pPromise;
}

    export enum Support {
        COMMON_EVENT_SCREEN_OFF = 'usual.event.SCREEN_OFF',
        COMMON_EVENT_SCREEN_ON = 'usual.event.SCREEN_ON',
        COMMON_EVENT_USER_INFO_UPDATED = 'usual.event.USER_INFO_UPDATED',
        COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOUT = 'common.event.DISTRIBUTED_ACCOUNT_LOGOUT',
        COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGIN = 'common.event.DISTRIBUTED_ACCOUNT_LOGIN',
        COMMON_EVENT_HTTP_PROXY_CHANGE = 'usual.event.HTTP_PROXY_CHANGE',
        COMMON_EVENT_MINORSMODE_ON = 'usual.event.MINORSMODE_ON',
        COMMON_EVENT_MINORSMODE_OFF = 'usual.event.MINORSMODE_OFF',
        COMMON_EVENT_TIME_CHANGED = 'usual.event.TIME_CHANGED',
        COMMON_EVENT_TIMEZONE_CHANGED = 'usual.event.TIMEZONE_CHANGED',
        COMMON_EVENT_BOOT_COMPLETED = 'usual.event.BOOT_COMPLETED',
        COMMON_EVENT_VOLUME_EJECT = 'usual.event.data.VOLUME_EJECT',
        COMMON_EVENT_VOLUME_BAD_REMOVAL = 'usual.event.data.VOLUME_BAD_REMOVAL',
        COMMON_EVENT_VOLUME_MOUNTED = 'usual.event.data.VOLUME_MOUNTED',
        COMMON_EVENT_VOLUME_UNMOUNTED = 'usual.event.data.VOLUME_UNMOUNTED',
        COMMON_EVENT_VOLUME_REMOVED = 'usual.event.data.VOLUME_REMOVED',
        COMMON_EVENT_USER_REMOVED = 'usual.event.USER_REMOVED',
        COMMON_EVENT_USER_ADDED = 'usual.event.USER_ADDED',
        COMMON_EVENT_USER_SWITCHED = 'usual.event.USER_SWITCHED',
        COMMON_EVENT_SPLIT_SCREEN = 'common.event.SPLIT_SCREEN',
        COMMON_EVENT_AIRPLANE_MODE_CHANGED = 'usual.event.AIRPLANE_MODE',
        COMMON_EVENT_DATE_CHANGED = 'usual.event.DATE_CHANGED',
        COMMON_EVENT_BATTERY_OKAY = 'usual.event.BATTERY_OKAY',
        COMMON_EVENT_USER_FOREGROUND = 'usual.event.USER_FOREGROUND',
        COMMON_EVENT_PACKAGE_ADDED = 'usual.event.PACKAGE_ADDED',
        COMMON_EVENT_BLUETOOTH_REMOTEDEVICE_ACL_DISCONNECTED = 'usual.event.bluetooth.remotedevice.ACL_DISCONNECTED',
        COMMON_EVENT_POWER_DISCONNECTED = 'usual.event.POWER_DISCONNECTED',
        COMMON_EVENT_POWER_SAVE_MODE_CHANGED = 'usual.event.POWER_SAVE_MODE_CHANGED',
        COMMON_EVENT_SHUTDOWN = 'usual.event.SHUTDOWN',
        COMMON_EVENT_BLUETOOTH_REMOTEDEVICE_ACL_CONNECTED = 'usual.event.bluetooth.remotedevice.ACL_CONNECTED',
        COMMON_EVENT_WIFI_AP_STA_JOIN = 'usual.event.wifi.WIFI_HS_STA_JOIN',
        COMMON_EVENT_PACKAGE_REPLACED = 'usual.event.PACKAGE_REPLACED',
        COMMON_EVENT_USER_BACKGROUND = 'usual.event.USER_BACKGROUND',
        COMMON_EVENT_USER_UNLOCKED = 'usual.event.USER_UNLOCKED',
        COMMON_EVENT_POWER_CONNECTED = 'usual.event.POWER_CONNECTED',
        COMMON_EVENT_WIFI_POWER_STATE = 'usual.event.wifi.POWER_STATE',
        COMMON_EVENT_USER_STARTED = 'usual.event.USER_STARTED',
        COMMON_EVENT_SPN_INFO_CHANGED = 'usual.event.SPN_INFO_CHANGED',
        COMMON_EVENT_BLUETOOTH_REMOTEDEVICE_NAME_UPDATE = 'usual.event.bluetooth.remotedevice.NAME_UPDATE',
        COMMON_EVENT_PACKAGE_REMOVED = 'usual.event.PACKAGE_REMOVED',
        COMMON_EVENT_PACKAGE_DATA_CLEARED = 'usual.event.PACKAGE_DATA_CLEARED',
        COMMON_EVENT_PACKAGES_UNSUSPENDED = 'usual.event.PACKAGES_UNSUSPENDED',
        COMMON_EVENT_BATTERY_CHANGED = 'usual.event.BATTERY_CHANGED',
        COMMON_EVENT_PACKAGE_FULLY_REMOVED = 'usual.event.PACKAGE_FULLY_REMOVED',
        COMMON_EVENT_WIFI_CONN_STATE = 'usual.event.wifi.CONN_STATE',
        COMMON_EVENT_PACKAGE_CHANGED = 'usual.event.PACKAGE_CHANGED',
        COMMON_EVENT_WIFI_AP_STA_LEAVE = 'usual.event.wifi.WIFI_HS_STA_LEAVE',
        COMMON_EVENT_LOCALE_CHANGED = 'usual.event.LOCALE_CHANGED',
        COMMON_EVENT_DISCHARGING = 'usual.event.DISCHARGING',
        COMMON_EVENT_CHARGING = 'usual.event.CHARGING',
        COMMON_EVENT_CHARGE_TYPE_CHANGED = 'usual.event.CHARGE_TYPE_CHANGED',
        COMMON_EVENT_DYNAMIC_ICON_CHANGED = 'usual.event.DYNAMIC_ICON_CHANGED',
        COMMON_EVENT_SCREEN_LOCKED = 'usual.event.SCREEN_LOCKED',
        COMMON_EVENT_SCREEN_UNLOCKED = 'usual.event.SCREEN_UNLOCKED',
    }

}

export default commonEventManager;
