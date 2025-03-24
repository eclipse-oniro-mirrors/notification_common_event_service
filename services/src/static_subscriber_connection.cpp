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
    EVENT_LOGI_LIMIT("enter");
    sptr<StaticSubscriberConnection> sThis = this;
    auto proxy = sThis->GetProxy(remoteObject);
    std::string bundleName = element.GetURI();
    ffrt::submit([=] () {
        if (proxy) {
            int32_t funcResult = -1;
            ErrCode ec = proxy->OnReceiveEvent(event_, funcResult);
            EVENT_LOGI("OnAbilityConnectDone end, bundle = %{public}s, code = %{public}d", bundleName.c_str(), ec);
        }
        AbilityManagerHelper::GetInstance()->DisconnectServiceAbilityDelay(sThis);
    });
}

sptr<StaticSubscriberProxy> StaticSubscriberConnection::GetProxy(const sptr<IRemoteObject> &remoteObject)
{
    if (proxy_ == nullptr) {
        std::lock_guard<std::mutex> lock(proxyMutex_);
        if (proxy_ == nullptr) {
            proxy_ = new (std::nothrow) StaticSubscriberProxy(remoteObject);
            if (proxy_ == nullptr) {
                EVENT_LOGE("failed to create StaticSubscriberProxy!");
            }
        }
    }
    return proxy_;
}

void StaticSubscriberConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode)
{
    EVENT_LOGI_LIMIT("enter");
}
}  // namespace EventFwk
}  // namespace OHOS
