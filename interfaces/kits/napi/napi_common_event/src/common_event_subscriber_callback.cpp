/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "napi_common_event.h"
#include <memory>
#include "event_log_wrapper.h"

namespace OHOS {
namespace EventManagerFwkNapi {

static void ReleaseTsfn(napi_env env, napi_threadsafe_function tsfn)
{
    if (env == nullptr || tsfn == nullptr) {
        return;
    }
    EVENT_LOGD(LOG_TAG_CES_NAPI, "Release threadsafe function");
    napi_release_threadsafe_function(tsfn, napi_tsfn_release);
}

void SubscriberInstance::SetCallbackRef(const napi_ref &ref)
{
    std::lock_guard<ffrt::mutex> lockRef(refMutex_);
    ref_ = ref;
}

void SubscriberInstance::HandoverCallbackRef(napi_ref &callback)
{
    if (callback == nullptr) {
        return;
    }
    std::lock_guard<ffrt::mutex> lockRef(refMutex_);
    if (ref_ == callback) {
        // This attempt is the latest one, it replaces the subscription owned so far
        if (ownedRef_ != nullptr && ownedRef_ != callback) {
            napi_delete_reference(env_, ownedRef_);
        }
        ownedRef_ = callback;
    } else {
        // A newer subscribe attempt has taken over the view, or the subscription was removed while this attempt was
        // in flight. The ref is not used for delivery any more, and the ref owned by this subscriber is kept because
        // it may belong to the newer attempt.
        EVENT_LOGW(LOG_TAG_CES_NAPI,
            "Subscribe[%{public}llu] is no longer the latest one or was unsubscribed, release its callback ref",
            id_.load());
        napi_delete_reference(env_, callback);
    }
    callback = nullptr;
}

void SubscriberInstance::WithdrawCallbackRef(napi_ref &callback)
{
    if (callback == nullptr) {
        return;
    }
    std::lock_guard<ffrt::mutex> lockRef(refMutex_);
    if (ref_ == callback) {
        ref_ = nullptr;
    }
    napi_delete_reference(env_, callback);
    callback = nullptr;
}

void SubscriberInstance::ReleaseCallbackRef()
{
    std::lock_guard<ffrt::mutex> lockRef(refMutex_);
    if (ref_ != nullptr && ref_ != ownedRef_) {
        // The ref belongs to a subscribe attempt still in flight, which releases it by itself
        EVENT_LOGD(LOG_TAG_CES_NAPI, "Callback ref belongs to an in-flight subscribe, only unlink it");
    }
    if (ownedRef_ != nullptr) {
        napi_delete_reference(env_, ownedRef_);
        ownedRef_ = nullptr;
    }
    ref_ = nullptr;
}

napi_ref SubscriberInstance::GetCallbackRef()
{
    std::lock_guard<ffrt::mutex> lockRef(refMutex_);
    return ref_;
}

void SubscriberInstance::SetThreadSafeFunction(const napi_threadsafe_function &tsfn)
{
    std::lock_guard<ffrt::mutex> lock(envMutex_);
    tsfn_ = tsfn;
}

void SubscriberInstance::HandoverThreadSafeFunction(napi_threadsafe_function &tsfn)
{
    if (tsfn == nullptr) {
        return;
    }
    std::lock_guard<ffrt::mutex> lock(envMutex_);
    if (tsfn_ == tsfn) {
        // This attempt is the latest one, it replaces the threadsafe function owned so far
        if (ownedTsfn_ != nullptr && ownedTsfn_ != tsfn) {
            ReleaseTsfn(env_, ownedTsfn_);
        }
        ownedTsfn_ = tsfn;
    } else {
        // Same as HandoverCallbackRef: the threadsafe function owned by this subscriber may belong to a newer attempt
        ReleaseTsfn(env_, tsfn);
    }
    tsfn = nullptr;
}

void SubscriberInstance::WithdrawThreadSafeFunction(napi_threadsafe_function &tsfn)
{
    if (tsfn == nullptr) {
        return;
    }
    std::lock_guard<ffrt::mutex> lock(envMutex_);
    if (tsfn_ == tsfn) {
        tsfn_ = nullptr;
    }
    ReleaseTsfn(env_, tsfn);
    tsfn = nullptr;
}

void SubscriberInstance::ReleaseThreadSafeFunction()
{
    std::lock_guard<ffrt::mutex> lock(envMutex_);
    // tsfn_ may belong to a subscribe attempt still in flight, which releases it by itself
    ReleaseTsfn(env_, ownedTsfn_);
    ownedTsfn_ = nullptr;
    tsfn_ = nullptr;
}
}  // namespace EventManagerFwkNapi
}  // namespace OHOS
