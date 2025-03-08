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

import { CommonEventPublishData } from 'commonEventPublishData';
import { CommonEventData } from 'commonEventData';
import { CommonEventSubscribeInfo } from 'commonEventSubscribeInfo';
import { CommonEventSubscriber } from 'commonEventSubscriber';

export class BusinessError<T = void> {
    code: number;
    data: T;
}

export type AsyncCallback<T, E = void> = (err: BusinessError<E>, data: T) => void;

export namespace commonEventManager {

    export native function publishExecute(event: string):int;
    export native function publishWithOptionsExecute(event: string, options: CommonEventPublishData):int;
    export native function createSubscriberExecute(subscribeInfo: CommonEventSubscribeInfo):CommonEventSubscriber;
    export native function subscribeExecute(subscriber: CommonEventSubscriber,
        callback: AsyncCallback<CommonEventData, void>):int;
    export native function unsubscribeExecute(subscriber: CommonEventSubscriber):int;

    export function publish(event: string, callback: AsyncCallback<void, void>): void {
        console.log("publish call.");
        let task = taskpool.execute(commonEventManager.publishExecute, event);
        task.then((e: NullishType)=>{
            let resultCode: Int  = e as Int;
            console.log("publish call result:" + resultCode.intValue());
            let r: BusinessError = { code: resultCode.intValue(), data: undefined };
            callback(r, undefined);
        }, (err:Object): void => {
            console.log("publish call error:" + err);
        });
    }

    export function publish(event: string, options: CommonEventPublishData, callback: AsyncCallback<void, void>): void {
        console.info("publish with option call.");
        let task = taskpool.execute(commonEventManager.publishWithOptionsExecute, event, options);
        task.then((e: NullishType)=>{
            let resultCode: Int  = e as Int;
            console.log("publish with option result:" + resultCode.intValue());
            let r: BusinessError = { code: resultCode.intValue(), data: undefined };
            callback(r, undefined);
        }, (err:Object): void => {
            console.log("publish with option error:" + err);
        });
    }

    export function createSubscriber(subscribeInfo: CommonEventSubscribeInfo,
        callback: AsyncCallback<CommonEventSubscriber, void>): void {
        console.info("createSubscriber callback call.");
        let task = taskpool.execute(commonEventManager.createSubscriberExecute, subscribeInfo);
        task.then((e: NullishType)=>{
            let result: CommonEventSubscriber = e as CommonEventSubscriber;
            console.log("createSubscriber result.");
            let r: BusinessError = { code: 0, data: undefined };
            callback(r, result);
        }, (err:Object): void => {
            console.log("createSubscriber error:" + err);
        });
    }

    export function createSubscriber(subscribeInfo: CommonEventSubscribeInfo):Promise<CommonEventSubscriber> {
        console.info("createSubscriber Promise call.");
        let p = new Promise<CommonEventSubscriber>((resolve: (v: CommonEventSubscriber) => void,
            reject: (error: Object) => void) => {
            let p1 = taskpool.execute(commonEventManager.createSubscriberExecute, subscribeInfo);
            p1.then((e :NullishType)=>{
                console.log("createSubscriber Promise result");
                let result: CommonEventSubscriber  = e as CommonEventSubscriber;
                resolve(result);
            }, (err:Object): void => {
                console.log("createSubscriber Promise error:" + err);
            });
        });
        return p;
    }

    export function createSubscriberSync(subscribeInfo: CommonEventSubscribeInfo): CommonEventSubscriber{
        console.info("createSubscriberSync call.");
        return commonEventManager.createSubscriberExecute(subscribeInfo);
    }

    export function subscribe(subscriber: CommonEventSubscriber, callback: AsyncCallback<CommonEventData, void>): void {
        console.info("subscribe call.");
        let task = taskpool.execute(commonEventManager.subscribeExecute, subscriber, callback);
        task.then((e: NullishType)=>{
            let resultCode: Int  = e as Int;
            console.log("subscribe result:" + resultCode.intValue());
            let a: CommonEventData;
            let r: BusinessError = { code: resultCode.intValue(), data: undefined };
            callback(r, a);
        }, (err:Object): void => {
            console.log("subscribe error:" + err);
        });
    }

    export function unsubscribe(subscriber: CommonEventSubscriber, callback?: AsyncCallback<void, void>): void {
        console.info("unsubscribe call.");
        let task = taskpool.execute(commonEventManager.unsubscribeExecute, subscriber);
        task.then((e: NullishType)=>{
            let resultCode: Int  = e as Int;
            console.log("unsubscribe result:" + resultCode.intValue());
            let r: BusinessError = { code: resultCode.intValue(), data: undefined };
            if (callback != undefined) {
                callback(r, undefined);
            }
        }, (err:Object): void => {
            console.log("unsubscribe error:" + err);
        });
    }
}
