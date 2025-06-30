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

#ifndef FOUNDATION_EVENT_CESFWK_SERVICES_INCLUDE_STATIC_SUBSCRIBER_CONNECTION_H
#define FOUNDATION_EVENT_CESFWK_SERVICES_INCLUDE_STATIC_SUBSCRIBER_CONNECTION_H

#include <ffrt.h>

#include "ability_connect_callback_stub.h"
#include "common_event_data.h"
#include "static_subscriber_proxy.h"

namespace OHOS {
namespace EventFwk {
class StaticSubscriberConnection : public AAFwk::AbilityConnectionStub {
public:
    /**
     * Constructor.
     *
     * @param event, Indicates the common event data.
     */
    explicit StaticSubscriberConnection(const CommonEventData &event, const std::string &connectionKey)
    {
        staticNotifyQueue_ = std::make_shared<ffrt::queue>("StaticSubscriberConnection");
        events_.push_back(event);
        connectionKey_ = connectionKey;
    }

    /**
     * OnAbilityConnectDone, Ability Manager Service notify caller ability the result of connect.
     *
     * @param element, Indicates elementName of service ability.
     * @param remoteObject, Indicates the session proxy of service ability.
     * @param resultCode, Returns ERR_OK on success, others on failure.
     */
    void OnAbilityConnectDone(
        const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode) override;

    /**
     * OnAbilityDisconnectDone, Ability Manager Service notify caller ability the result of disconnect.
     *
     * @param element, Indicates elementName of service ability.
     * @param resultCode, Returns ERR_OK on success, others on failure.
     */
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode) override;

    void NotifyEvent(const CommonEventData &event);
    void RemoveEvent(const std::string &action);
    bool IsEmptyAction()
    {
        return action_.empty();
    }

private:
    sptr<StaticSubscriberProxy> GetProxy(const sptr<IRemoteObject> &remoteObject);
    sptr<StaticSubscriberProxy> proxy_ = nullptr;
    ffrt::recursive_mutex mutex_;
    std::vector<CommonEventData> events_;
    std::vector<std::string> action_;
    std::shared_ptr<ffrt::queue> staticNotifyQueue_ = nullptr;
    std::string connectionKey_ = "";
};
}  // namespace EventFwk
}  // namespace OHOS
#endif  // FOUNDATION_EVENT_CESFWK_SERVICES_INCLUDE_STATIC_SUBSCRIBER_CONNECTION_H
