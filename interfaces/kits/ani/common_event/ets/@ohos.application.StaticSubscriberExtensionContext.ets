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
import { BusinessError, AsyncCallback } from '@ohos.base';
import Want from '@ohos.app.ability.Want';
import ExtensionContext from 'application.ExtensionContext';
import hilog from '@ohos.hilog';

const TAG: string = 'commonEventManager';

class Cleaner {
    private ptr: long = 0 

    constructor(ptr:long) {
        this.ptr = ptr
    }
    native clean(): void
}

function callback(cleaner: Cleaner): void {
    cleaner.clean()
}
let destroyRegister = new FinalizationRegistry<Cleaner>(callback)
let unregisterToken = new object()


type ResolveCallback<T> = (data: T) => void;
type RejectCallback = (err: Error) => void;

export class StaticSubscriberExtensionContext extends ExtensionContext {
    static {loadLibrary("static_subscriber_extension_ani.z")}
    private nativeStaticSubscriberExtensionContext: long = 0;
    native nativeStartAbilitySync(want: Want): void;

    static native transferToDynamicContext(input: Object): Any;
    static native transferToStaticContext(input: Any): Object;

    static transferDynamic(input: Object): Any {
        return StaticSubscriberExtensionContext.transferToDynamicContext(input);
    }
    static transferStatic(input: Any): Object {
        return StaticSubscriberExtensionContext.transferToStaticContext(input);
    }

    startAbility(want: Want, callback: AsyncCallback<void, void>): void {
        let task = taskpool.execute(this.nativeStartAbilitySync, want);
        task.then((e: Any)=>{
            callback(null, undefined);
        }, (error: Object): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    startAbility(want: Want): Promise<void> {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let task = taskpool.execute(this.nativeStartAbilitySync, want);
            task.then((e: Any): void => {
                resolve(undefined);
            }, (error: Error): void => {
                hilog.error(0xD001202, TAG, 'nativeStartAbilitySync Promise error');
                reject(error);
            });
        });
        return pPromise;
    }

    private cleaner: Cleaner | null = null;
    constructor(wrapper:long) {
        this.nativeStaticSubscriberExtensionContext = wrapper;
        this.registerCleaner(this.nativeStaticSubscriberExtensionContext)
    }

    registerCleaner(ptr: long): void {
        this.cleaner = new Cleaner(ptr)
        destroyRegister.register(this, this.cleaner!, unregisterToken);
    }
}