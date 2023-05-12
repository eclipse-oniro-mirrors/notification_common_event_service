/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "static_subscriber_extension_context.h"

#include "ability_business_error.h"
#include "ability_manager_client.h"
#include "ability_manager_errors.h"
#include "accesstoken_kit.h"
#include "event_log_wrapper.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace EventFwk {
namespace {
constexpr const char* PERMISSION_START_ABILITIES_FROM_BACKGROUND = "ohos.permission.START_ABILITIES_FROM_BACKGROUND";
}
const size_t StaticSubscriberExtensionContext::CONTEXT_TYPE_ID(
    std::hash<const char*> {} ("StaticSubscriberExtensionContext"));

StaticSubscriberExtensionContext::StaticSubscriberExtensionContext() {}

StaticSubscriberExtensionContext::~StaticSubscriberExtensionContext() {}

bool StaticSubscriberExtensionContext::CheckCallerIsSystemApp()
{
    auto selfToken = IPCSkeleton::GetSelfTokenID();
    if (!Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken)) {
        EVENT_LOGE("current app is not system app, not allow.");
        return false;
    }
    return true;
}

ErrCode StaticSubscriberExtensionContext::StartAbility(const AAFwk::Want& want)
{
    EVENT_LOGD("called");
    ErrCode err = ERR_OK;

    if (!CheckCallerIsSystemApp()) {
        EVENT_LOGE("This application is not system-app, can not use system-api");
        err = AAFwk::ERR_NOT_SYSTEM_APP;
        return err;
    }

    std::string callerBundleName = GetBundleName();
    std::string calledBundleName = want.GetBundle();
    if (calledBundleName != callerBundleName) {
        EVENT_LOGE("This application won't start no-self-ability.");
        err = AAFwk::ERR_NOT_SELF_APPLICATION;
        return err;
    }

    if (!VerifyCallingPermission(PERMISSION_START_ABILITIES_FROM_BACKGROUND)) {
        EVENT_LOGE("Caller has none of PERMISSION_START_ABILITIES_FROM_BACKGROUND, Fail.");
        err = AAFwk::CHECK_PERMISSION_FAILED;
        return err;
    }
    
    err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want, token_);
    EVENT_LOGI("StaticSubscriberExtensionContext::StartAbility. End calling StartAbility. err=%{public}d", err);
    return err;
}

bool StaticSubscriberExtensionContext::VerifyCallingPermission(const std::string& permissionName) const
{
    EVENT_LOGD("VerifyCallingPermission permission %{public}s", permissionName.c_str());
    auto callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t ret = Security::AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, permissionName);
    if (ret == Security::AccessToken::PermissionState::PERMISSION_DENIED) {
        EVENT_LOGE("permission %{public}s: PERMISSION_DENIED", permissionName.c_str());
        return false;
    }
    EVENT_LOGD("verify AccessToken success");
    return true;
}
} // namespace EventFwk
} // namespace OHOS
