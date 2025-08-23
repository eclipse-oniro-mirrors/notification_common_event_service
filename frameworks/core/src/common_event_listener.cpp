/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "common_event_listener.h"
#include "event_log_wrapper.h"
#include "event_trace_wrapper.h"
#include "hitrace_meter_adapter.h"
#include "ffrt.h"

namespace OHOS {
namespace EventFwk {
std::shared_ptr<AppExecFwk::EventRunner> CommonEventListener::commonRunner_ = nullptr;
std::atomic<int> ffrtIndex = 0;

CommonEventListener::CommonEventListener(const std::shared_ptr<CommonEventSubscriber> &commonEventSubscriber)
    : commonEventSubscriber_(commonEventSubscriber)
{
    Init();
}

CommonEventListener::~CommonEventListener()
{}

ErrCode CommonEventListener::NotifyEvent(const CommonEventData &commonEventData, bool ordered, bool sticky)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    EVENT_LOGD("enter");

    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsReady()) {
        EVENT_LOGE("not ready");
        return IPC_INVOKER_ERR;
    }

    wptr<CommonEventListener> wp = this;
    std::function<void()> onReceiveEventFunc = [wp, commonEventData, ordered, sticky] () {
        sptr<CommonEventListener> sThis = wp.promote();
        if (sThis == nullptr) {
            EVENT_LOGE("invalid listener");
            return;
        }
        sThis->OnReceiveEvent(commonEventData, ordered, sticky);
    };

    if (handler_) {
        handler_->PostTask(onReceiveEventFunc, "CommonEvent" + commonEventData.GetWant().GetAction());
    }

    if (listenerQueue_) {
        static_cast<ffrt::queue*>(listenerQueue_)->submit(onReceiveEventFunc);
    }
    return ERR_NONE;
}

__attribute__((no_sanitize("cfi"))) ErrCode CommonEventListener::Init()
{
    EVENT_LOGD("ready to init");
    std::lock_guard<std::mutex> lock(mutex_);
    if (!commonEventSubscriber_) {
        EVENT_LOGE("Failed to init due to subscriber is nullptr");
        return ERR_INVALID_OPERATION;
    }
    auto threadMode = commonEventSubscriber_->GetSubscribeInfo().GetThreadMode();
    EVENT_LOGD("thread mode: %{public}d", threadMode);
    if (threadMode == CommonEventSubscribeInfo::HANDLER) {
        if (!runner_) {
            runner_ = EventRunner::GetMainEventRunner();
            if (!runner_) {
                EVENT_LOGE("Failed to init due to create runner error");
                return ERR_INVALID_OPERATION;
            }
        }
        if (!handler_) {
            handler_ = std::make_shared<EventHandler>(runner_);
            if (!handler_) {
                EVENT_LOGE("Failed to init due to create handler error");
                return ERR_INVALID_OPERATION;
            }
        }
    } else {
        InitListenerQueue();
        if (listenerQueue_ == nullptr) {
            EVENT_LOGE("Failed to init due to create ffrt queue error");
            return ERR_INVALID_OPERATION;
        }
    }
    return ERR_OK;
}

std::shared_ptr<AppExecFwk::EventRunner> CommonEventListener::GetCommonRunner()
{
    if (CommonEventListener::commonRunner_ == nullptr) {
        CommonEventListener::commonRunner_ = EventRunner::Create("OS_cesComLstnr");
    }

    return CommonEventListener::commonRunner_;
}

void CommonEventListener::InitListenerQueue()
{
    if (listenerQueue_ == nullptr) {
        ffrtIndex.fetch_add(1);
        std::string id = "ces_queue_" + std::to_string(ffrtIndex.load());
        listenerQueue_ = static_cast<void*>(new ffrt::queue(id.c_str()));
    }
    return;
}

bool CommonEventListener::IsReady()
{
    if (!listenerQueue_ && !handler_) {
        return false;
    }
    return true;
}

__attribute__((no_sanitize("cfi"))) void CommonEventListener::OnReceiveEvent(
    const CommonEventData &commonEventData, const bool &ordered, const bool &sticky)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    EVENT_LOGD("enter %{public}s", commonEventData.GetWant().GetAction().c_str());

    int32_t code = commonEventData.GetCode();
    std::string data = commonEventData.GetData();

    std::shared_ptr<AsyncCommonEventResult> result =
        std::make_shared<AsyncCommonEventResult>(code, data, ordered, sticky, this);
    if (result == nullptr) {
        EVENT_LOGE("Failed to create AsyncCommonEventResult");
        return;
    }
    std::shared_ptr<CommonEventSubscriber> subscriber = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        subscriber = commonEventSubscriber_;
    }
    if (!subscriber) {
        EVENT_LOGE("CommonEventSubscriber ptr is nullptr");
        return;
    }
    subscriber->SetAsyncCommonEventResult(result);
    subscriber->OnReceiveEvent(commonEventData);
    if (ordered && (subscriber->GetAsyncCommonEventResult() != nullptr)) {
        subscriber->GetAsyncCommonEventResult()->FinishCommonEvent();
    }
    EVENT_LOGD("end");
}

void CommonEventListener::Stop()
{
    EVENT_LOGD("enter");
    void *queue = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (listenerQueue_) {
            queue = listenerQueue_;
            listenerQueue_ = nullptr;
        }
        handler_ = nullptr;
        commonEventSubscriber_ = nullptr;
        runner_ = nullptr;
    }
    if (queue) {
        ffrt::submit([queue]() {
            delete static_cast<ffrt::queue*>(queue);
        });
    }
}
}  // namespace EventFwk
}  // namespace OHOS
