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
import { AsyncCallback, BusinessError } from '@ohos.base';
import { CommonEventSubscribeInfo } from 'commonEvent.commonEventSubscribeInfo';

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
const TAG: string = 'commonEventSubscriber';
export interface CommonEventSubscriber {
    getCode(callback: AsyncCallback<int>): void;
    getCode(): Promise<int>;
    getCodeSync(): int;
    setCode(code: int, callback: AsyncCallback<void>): void;
    setCode(code: int): Promise<void>;
    setCodeSync(code: int): void;
    getData(callback: AsyncCallback<string>): void;
    getData(): Promise<string>;
    getDataSync(): string;
    setData(data: string, callback: AsyncCallback<void>): void;
    setData(data: string): Promise<void>;
    setDataSync(data: string): void;
    setCodeAndData(code: int, data: string, callback: AsyncCallback<void>): void;
    setCodeAndData(code: int, data: string): Promise<void>;
    setCodeAndDataSync(code: int, data: string): void;
    isOrderedCommonEvent(callback: AsyncCallback<boolean>): void;
    isOrderedCommonEvent(): Promise<boolean>;
    isOrderedCommonEventSync(): boolean;
    isStickyCommonEvent(callback: AsyncCallback<boolean>): void;
    isStickyCommonEvent(): Promise<boolean>;
    isStickyCommonEventSync(): boolean;
    abortCommonEvent(callback: AsyncCallback<void>): void;
    abortCommonEvent(): Promise<void>;
    abortCommonEventSync(): void;
    clearAbortCommonEvent(callback: AsyncCallback<void>): void;
    clearAbortCommonEvent(): Promise<void>;
    clearAbortCommonEventSync(): void;
    getAbortCommonEvent(callback: AsyncCallback<boolean>): void;
    getAbortCommonEvent(): Promise<boolean>;
    getAbortCommonEventSync(): boolean;
    getSubscribeInfo(callback: AsyncCallback<CommonEventSubscribeInfo|null>): void;
    getSubscribeInfo(): Promise<CommonEventSubscribeInfo|null>;
    getSubscribeInfoSync(): CommonEventSubscribeInfo|null;
    finishCommonEvent(callback: AsyncCallback<void>): void;
    finishCommonEvent(): Promise<void>;
}

class CommonEventSubscriberInner implements CommonEventSubscriber {
    static {loadLibrary("ani_commoneventmanager.z")}
    private subscriberInstanceWrapper: long = 0;

    public native nativeGetCode(): int;
    public native nativeSetCode(code: int): int;
    public native nativeGetData(): string;
    public native nativeSetData(data: string): int;
    public native nativeSetCodeAndData(code: int, data: string): int;
    public native nativeIsOrderedCommonEvent(): boolean;
    public native nativeIsStickyCommonEvent(): boolean;
    public native nativeAbortCommonEvent(): int;
    public native nativeClearAbortCommonEvent(): int;
    public native nativeGetAbortCommonEvent(): boolean;
    public native nativeGetSubscribeInfo(): CommonEventSubscribeInfo|null;
    public native nativeFinishCommonEvent(): int;

    private static native transferToDynamicSubscriber(input: Object): Any;
    private static native transferToStaticSubscriber(input: Any): Object;
    
    static transferDynamic(input: Object): Any {
        return CommonEventSubscriberInner.transferToDynamicSubscriber(input);
    }
    static transferStatic(input: Any): Object {
        return CommonEventSubscriberInner.transferToStaticSubscriber(input);
    }

    public getCode(callback: AsyncCallback<int>): void {
        let p = taskpool.execute((): int => { return this.nativeGetCode(); });
        p.then((data: NullishType): void => {
            let ret : int = data as int;
            callback(null, ret);
        }, (error: Error): void => {
            let ret: int = -1;
            let err: BusinessError = error as BusinessError;
            callback(err, ret);
        });
    }

    public getCode(): Promise<int> {
        let pPromise = new Promise<int>((resolve: ResolveCallback<int>, reject: RejectCallback): void => {
            let p = taskpool.execute((): int => { return this.nativeGetCode(); });
            p.then((data: NullishType): void => {
                let ret : int = data as int;
                resolve(ret);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    public getCodeSync(): int {
        let ret : int = 0;
        try {
            ret = this.nativeGetCode() as int;
            return ret;
        } catch (err) {
            return ret;
        }
    }

    public setCode(code: int, callback: AsyncCallback<void>): void {
        let pcode: Int = code as Int;
        let p = taskpool.execute((): int => { return this.nativeSetCode(pcode); });
        p.then((data: NullishType): void => {
            callback(null, undefined);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    public setCode(code: int): Promise<void> {
        let pcode: Int = code as Int;
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): int => { return this.nativeSetCode(pcode); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    public setCodeSync(code: int): void {
        try {
            let pcode: Int = code as Int;
            this.nativeSetCode(pcode);
            return;
        } catch (err) {
            hilog.error(0xD001202, TAG, 'asyncResult is nullptr');
        }
    }

    public getData(callback: AsyncCallback<string>): void {
        let p = taskpool.execute((): string => { return this.nativeGetData(); });
        p.then((data: NullishType): void => {
            let ret : string = data as string;
            callback(null, ret);
        }, (error: Object): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }

    public getData(): Promise<string> {
        let pPromise = new Promise<string>((resolve: ResolveCallback<string>, reject: RejectCallback):void => {
            let p = taskpool.execute((): string => { return this.nativeGetData(); });
            p.then((data :NullishType): void => {
                let ret : string = data as string;
                resolve(ret);
            }, (err:Error): void => {
                reject(err);
            });
        });
        return pPromise;
    }

    public getDataSync(): string {
        let ret : string = '';
        try {
            ret = this.nativeGetData() as string;
            return ret;
        } catch (err) {
            return ret;
        }
    }

    public setData(data: string, callback: AsyncCallback<void>): void {
        let p = taskpool.execute((): int => { return this.nativeSetData(data); });
        p.then((e: NullishType): void => {
            callback(null, undefined);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }

    public setData(data: string): Promise<void> {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): int => { return this.nativeSetData(data); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    public setDataSync(data: string): void {
        try {
            this.nativeSetData(data);
            return;
        } catch (err) {
            hilog.error(0xD001202, TAG, 'asyncResult is nullptr');
        }
    }

    public setCodeAndData(code: int, data: string, callback: AsyncCallback<void>): void {
        let pcode: Int = code as Int;
        let p = taskpool.execute((): int => { return this.nativeSetCodeAndData(pcode, data); });
        p.then((e: NullishType): void => {
            callback(null, undefined);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }

    public setCodeAndData(code: int, data: string): Promise<void> {
        let pcode: Int = code as Int;
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): int => { return this.nativeSetCodeAndData(pcode, data); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    public setCodeAndDataSync(code: int, data: string): void {
        try {
            let pcode: Int = code as Int;
            this.nativeSetCodeAndData(pcode, data);
            return;
        } catch (err) {
            hilog.error(0xD001202, TAG, 'asyncResult is nullptr');
        }
    }

    public isOrderedCommonEvent(callback: AsyncCallback<boolean>): void {
        let p = taskpool.execute((): boolean => { return this.nativeIsOrderedCommonEvent(); });
        p.then((data: NullishType): void => {
            let ret : boolean = data as boolean;
            callback(null, ret);
        }, (error: Error): void => {
            let ret : boolean = false;
            let err: BusinessError = error as BusinessError;
            callback(err, ret);
        })
    }

    public isOrderedCommonEvent(): Promise<boolean> {
        let pPromise = new Promise<boolean>((resolve: ResolveCallback<boolean>, reject: RejectCallback): void => {
            let p = taskpool.execute((): boolean => { return this.nativeIsOrderedCommonEvent(); });
            p.then((data: NullishType): void => {
                let ret : boolean = data as boolean;
                resolve(ret);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    public isOrderedCommonEventSync(): boolean {
        try {
            return this.nativeIsOrderedCommonEvent();
        } catch (err) {
            hilog.error(0xD001202, TAG, 'asyncResult is nullptr');
            return false;
        }
    }

    public isStickyCommonEvent(callback: AsyncCallback<boolean>): void {
        let p = taskpool.execute((): boolean => { return this.nativeIsStickyCommonEvent(); });
        p.then((data: NullishType): void => {
            let ret : boolean = data as boolean;
            callback(null, ret);
        }, (error: Error): void => {
            let ret : boolean = false;
            let err: BusinessError = error as BusinessError;
            callback(err, ret);
        })
    }

    public isStickyCommonEvent(): Promise<boolean> {
        let pPromise = new Promise<boolean>((resolve: ResolveCallback<boolean>, reject: RejectCallback): void => {
            let p = taskpool.execute((): boolean => { return this.nativeIsStickyCommonEvent(); });
            p.then((data: NullishType): void => {
                let ret : boolean = data as boolean;
                resolve(ret);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    public isStickyCommonEventSync(): boolean {
        try {
            return this.nativeIsStickyCommonEvent();
        } catch (err) {
            hilog.error(0xD001202, TAG, 'asyncResult is nullptr');
            return false;
        }
    }

    public abortCommonEvent(callback: AsyncCallback<void>): void {
        let p = taskpool.execute((): int => { return this.nativeAbortCommonEvent(); });
        p.then((data: NullishType): void => {
            callback(null, undefined);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    public abortCommonEvent(): Promise<void> {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): int => { return this.nativeAbortCommonEvent(); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    public abortCommonEventSync(): void {
        try {
            this.nativeAbortCommonEvent();
            return;
        } catch (err) {
            hilog.error(0xD001202, TAG, 'asyncResult is nullptr');
        }
    }

    public clearAbortCommonEvent(callback: AsyncCallback<void>): void {
        let p = taskpool.execute((): int => { return this.nativeClearAbortCommonEvent(); });
        p.then((data: NullishType): void => {
            callback(null, undefined);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    public clearAbortCommonEvent(): Promise<void> {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): int => { return this.nativeClearAbortCommonEvent(); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    public clearAbortCommonEventSync(): void {
        try {
            this.nativeClearAbortCommonEvent();
            return;
        } catch (err) {
            hilog.error(0xD001202, TAG, 'asyncResult is nullptr');
        }
    }

    public getAbortCommonEvent(callback: AsyncCallback<boolean>): void {
        let p = taskpool.execute((): boolean => { return this.nativeGetAbortCommonEvent(); });
        p.then((data: NullishType): void => {
            let ret : boolean = data as boolean;
            callback(null, ret);
        }, (error: Error): void => {
            let ret : boolean = false;
            let err: BusinessError = error as BusinessError;
            callback(err, ret);
        })
    }

    public getAbortCommonEvent(): Promise<boolean> {
        let pPromise = new Promise<boolean>((resolve: ResolveCallback<boolean>, reject: RejectCallback): void => {
            let p = taskpool.execute((): boolean => { return this.nativeGetAbortCommonEvent(); });
            p.then((data: NullishType): void => {
                let ret : boolean = data as boolean;
                resolve(ret);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    public getAbortCommonEventSync(): boolean {
        let ret : boolean = false;
        try {
            ret = this.nativeGetAbortCommonEvent() as boolean;
            return ret;
        } catch (err) {
            return ret;
        }
    }

    public getSubscribeInfo(callback: AsyncCallback<CommonEventSubscribeInfo|null>): void {
        let p = taskpool.execute((): CommonEventSubscribeInfo|null => { return this.nativeGetSubscribeInfo(); });
        p.then((data: NullishType): void => {
            callback(null, data as CommonEventSubscribeInfo|null);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }

    public getSubscribeInfo(): Promise<CommonEventSubscribeInfo|null> {
        let pPromise = new Promise<CommonEventSubscribeInfo|null>((resolve: ResolveCallback<CommonEventSubscribeInfo|null>,
                reject: RejectCallback): void => {
            let p = taskpool.execute((): CommonEventSubscribeInfo|null => { return this.nativeGetSubscribeInfo(); });
            p.then((data: NullishType): void => {
                resolve(data as CommonEventSubscribeInfo|null);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    public getSubscribeInfoSync(): CommonEventSubscribeInfo|null {
        return this.nativeGetSubscribeInfo();
    }

    public finishCommonEvent(callback: AsyncCallback<void>): void {
        let p = taskpool.execute((): int => { return this.nativeFinishCommonEvent(); });
        p.then((data: NullishType): void => {
            callback(null, undefined);
        }, (error: Error): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        });
    }

    public finishCommonEvent(): Promise<void> {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): int => { return this.nativeFinishCommonEvent(); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    private cleaner: Cleaner | null = null;

    constructor(wrapper:long) {
        if(this.subscriberInstanceWrapper == 0){
            this.subscriberInstanceWrapper = wrapper;
        }
        this.registerCleaner(this.subscriberInstanceWrapper)
    }

    registerCleaner(ptr: long): void {
        this.cleaner = new Cleaner(ptr)
        destroyRegister.register(this, this.cleaner!, unregisterToken);
    }
}