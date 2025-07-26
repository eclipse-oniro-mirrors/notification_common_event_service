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

type ResolveCallback<T> = (data: T) => void;
type RejectCallback = (err: Error) => void;

loadLibrary("ani_commoneventmanager.z");
export class StaticSubscriberExtensionContext extends ExtensionContext {
    nativeStaticSubscriberExtensionContext: long = 0;
    native nativeStartAbilitySync(want: Want): void;

    startAbility(want: Want, callback: AsyncCallback<void, void>): void {
        let task = taskpool.execute(this.nativeStartAbilitySync, want);
        task.then((e: NullishType)=>{
          callback(null, undefined);
      }, (error: Object): void => {
          let err: BusinessError = error as BusinessError;
          callback(err, undefined);
      });
    }

    startAbility(want: Want): Promise<void> {
      let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
      let task = taskpool.execute(this.nativeStartAbilitySync, want);
      task.then((e: NullishType): void => {
          resolve(undefined);
      }, (error: Error): void => {
          hilog.error(0xD001202, TAG, 'nativeStartAbilitySync Promise error');
          reject(error);
      });
  });
      return pPromise;
  }
}