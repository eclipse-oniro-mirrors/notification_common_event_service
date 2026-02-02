/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "static_subscriber_connection.h"

#include "ability_manager_helper.h"
#include "event_log_wrapper.h"
#include "event_report.h"

namespace OHOS {
namespace EventFwk {
void StaticSubscriberConnection::OnAbilityConnectDone(
    const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    std::lock_guard<ffrt::recursive_mutex> lock(mutex_);
    InitProxy(remoteObject);
    std::string bundleName = element.GetURI();
    EVENT_LOGI(LOG_TAG_STATIC, "called, %{public}s", bundleName.c_str());
    for (auto &event : events_) {
        NotifyEvent(event);
    }
    events_.clear();
}

void StaticSubscriberConnection::NotifyEvent(const CommonEventData &event)
{
    std::lock_guard<ffrt::recursive_mutex> lock(mutex_);
    if (proxy_ == nullptr) {
        events_.push_back(event);
        EVENT_LOGW_LIMIT(LOG_TAG_STATIC, "Cache events");
        return;
    }
    action_.push_back(event.GetWant().GetAction());
    wptr<StaticSubscriberConnection> wThis = this;
    staticNotifyQueue_->submit([event, wThis]() {
        sptr<StaticSubscriberConnection> sThis = wThis.promote();
        if (!sThis) {
            EVENT_LOGE(LOG_TAG_STATIC, "Connection expired, skip Notify");
            return;
        }
        int32_t funcResult = -1;
        ErrCode ec = sThis->proxy_->OnReceiveEvent(event, funcResult);
        EVENT_LOGI(LOG_TAG_STATIC, "Notify %{public}s to %{public}s end, code %{public}d",
            event.GetWant().GetAction().c_str(), sThis->connectionKey_.c_str(), ec);
        AbilityManagerHelper::GetInstance()->DisconnectServiceAbilityDelay(sThis, event.GetWant().GetAction());
    });
}

void StaticSubscriberConnection::RemoveEvent(const std::string &action)
{
    std::lock_guard<ffrt::recursive_mutex> lock(mutex_);
    auto it = std::find(action_.begin(), action_.end(), action);
    if (it != action_.end()) {
        action_.erase(it);
    }
}

void StaticSubscriberConnection::InitProxy(const sptr<IRemoteObject> &remoteObject)
{
    if (remoteObject == nullptr) {
        return;
    }
    proxy_ = iface_cast<IStaticSubscriber>(remoteObject);
    if (proxy_ == nullptr) {
        EVENT_LOGE(LOG_TAG_STATIC, "failed to create StaticSubscriberProxy!");
        return;
    }
    wptr<StaticSubscriberConnection> wThis = this;
    deathRecipient_ = new (std::nothrow) RemoteDeathRecipient([wThis] (const wptr<IRemoteObject> &remote) {
        sptr<StaticSubscriberConnection> sThis = wThis.promote();
        if (sThis == nullptr) {
            return;
        }
        AbilityManagerHelper::GetInstance()->RemoveConnection(sThis);
    });
    if (deathRecipient_ == nullptr) {
        EVENT_LOGE(LOG_TAG_STATIC, "Failed to create RemoteDeathRecipient instance");
        return;
    }
    proxy_->AsObject()->AddDeathRecipient(deathRecipient_);
}

void StaticSubscriberConnection::Clear()
{
    std::lock_guard<ffrt::recursive_mutex> lock(mutex_);
    if (proxy_ && deathRecipient_) {
        proxy_->AsObject()->RemoveDeathRecipient(deathRecipient_);
    }
    proxy_ = nullptr;
}

void StaticSubscriberConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode)
{}
}  // namespace EventFwk
}  // namespace OHOS
