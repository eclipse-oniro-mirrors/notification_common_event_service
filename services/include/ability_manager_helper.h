/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_EVENT_CESFWK_SERVICES_INCLUDE_ABILITY_MANAGER_HELPER_H
#define FOUNDATION_EVENT_CESFWK_SERVICES_INCLUDE_ABILITY_MANAGER_HELPER_H

#include "ability_connect_callback_interface.h"
#include "ability_manager_interface.h"
#include "ability_manager_death_recipient.h"
#include "common_event_data.h"
#include "event_handler.h"
#include "ffrt.h"
#include "singleton.h"
#include "static_subscriber_connection.h"

namespace OHOS {
namespace EventFwk {
class AbilityManagerHelper : public DelayedSingleton<AbilityManagerHelper> {
public:
    AbilityManagerHelper() {}

    virtual ~AbilityManagerHelper() {}

    /**
     * @brief SetEventHandler.
     * @param handler event handler
     */
    inline void SetEventHandler(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
    {
        eventHandler_ = handler;
    }

    /**
     * Connects ability.
     *
     * @param want Indicates ability inofmation.
     * @param event Indicates the common event
     * @param callerToken Indicates the token of caller.
     * @param userId Indicates the ID of user.
     * @return Returns result code.
     */
    int ConnectAbility(const AAFwk::Want &want, const CommonEventData &event,
        const sptr<IRemoteObject> &callerToken, const int32_t &userId);

    /**
     * Clears ability manager service remote object.
     *
     */
    void Clear();

    /**
     * @brief Disconnect ability delay.
     * @param connection Indicates the connection want to disconnect.
     */
    void DisconnectServiceAbilityDelay(const sptr<StaticSubscriberConnection> &connection);
private:
    bool GetAbilityMgrProxy();
    void DisconnectAbility(const sptr<StaticSubscriberConnection> &connection);

    std::mutex mutex_;
    sptr<AAFwk::IAbilityManager> abilityMgr_;
    sptr<AbilityManagerDeathRecipient> deathRecipient_;
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler_ = nullptr;
    std::set<sptr<StaticSubscriberConnection>> subscriberConnection_;
    std::shared_ptr<ffrt::queue> ffrt_ = nullptr;
};
}  // namespace EventFwk
}  // namespace OHOS

#endif  // FOUNDATION_EVENT_CESFWK_SERVICES_INCLUDE_ABILITY_MANAGER_HELPER_H
