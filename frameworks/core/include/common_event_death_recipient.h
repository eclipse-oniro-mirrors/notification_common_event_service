/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_EVENT_CESFWK_INNERKITS_INCLUDE_COMMON_EVENT_DEATH_RECIPIENT_H
#define FOUNDATION_EVENT_CESFWK_INNERKITS_INCLUDE_COMMON_EVENT_DEATH_RECIPIENT_H

#include <singleton.h>

#include "system_ability_status_change_stub.h"

namespace OHOS {
namespace EventFwk {
class CommonEventDeathRecipient : public DelayedSingleton<CommonEventDeathRecipient> {
public:
    CommonEventDeathRecipient() = default;

    ~CommonEventDeathRecipient() = default;

    void SubscribeSAManager();

    bool GetIsSubscribeSAManager();
private:
    class SystemAbilityStatusChangeListener : public SystemAbilityStatusChangeStub {
    public:
        SystemAbilityStatusChangeListener() = default;
        ~SystemAbilityStatusChangeListener() = default;
        void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
        void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;

    private:
        bool isSAOffline = false;
    };

    sptr<ISystemAbilityStatusChange> statusChangeListener_ = nullptr;
};
}  // namespace EventFwk
}  // namespace OHOS

#endif  // FOUNDATION_EVENT_CESFWK_INNERKITS_INCLUDE_COMMON_EVENT_DEATH_RECIPIENT_H
