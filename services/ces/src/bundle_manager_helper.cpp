/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "bundle_manager_helper.h"

#include "bundle_constants.h"
#include "bundle_mgr_client.h"
#include "event_log_wrapper.h"
#include "iservice_registry.h"
#include "nlohmann/json.hpp"
#include "os_account_manager.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace EventFwk {
const std::string META_NAME_STATIC_SUBSCRIBER = "ohos.extension.staticSubscriber";

using namespace OHOS::AppExecFwk::Constants;

BundleManagerHelper::BundleManagerHelper() : sptrBundleMgr_(nullptr), bmsDeath_(nullptr)
{}

BundleManagerHelper::~BundleManagerHelper()
{}

std::string BundleManagerHelper::GetBundleName(int uid)
{
    EVENT_LOGI("enter");

    std::lock_guard<std::mutex> lock(mutex_);
    std::string bundleName = "";

    if (!GetBundleMgrProxy()) {
        return bundleName;
    }

    sptrBundleMgr_->GetBundleNameForUid(uid, bundleName);

    return bundleName;
}

bool BundleManagerHelper::QueryExtensionInfos(std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos)
{
    EVENT_LOGI("enter");

    std::lock_guard<std::mutex> lock(mutex_);

    if (!GetBundleMgrProxy()) {
        return false;
    }
    std::vector<AccountSA::OsAccountInfo> osAccountInfos;
    ErrCode ret = OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(activeUserId);
    if (ret != ERR_OK) {
        EVENT_LOGE("failed to QueryActiveOsAccountIds!");
        return false;
    }
    if (osAccountInfos.size() == 0) {
        EVENT_LOGE("no os account acquired!");
        return false;
    }
    int userId = osAccountInfos[0].GetLocalId(); // get first active account
    EVENT_LOGE("active userId = %{public}d", userId);
    return sptrBundleMgr_->QueryExtensionAbilityInfos(AppExecFwk::ExtensionAbilityType::STATICSUBSCRIBER,
        userId, extensionInfos);
}

bool BundleManagerHelper::GetResConfigFile(const AppExecFwk::ExtensionAbilityInfo &extension,
                                           std::vector<std::string> &profileInfos)
{
    EVENT_LOGI("enter");

    std::lock_guard<std::mutex> lock(mutex_);

    if (!GetBundleMgrProxy()) {
        return false;
    }

    AppExecFwk::BundleMgrClient client;
    return client.GetResConfigFile(extension, META_NAME_STATIC_SUBSCRIBER, profileInfos);
}

bool BundleManagerHelper::CheckIsSystemAppByUid(uid_t uid)
{
    EVENT_LOGI("enter");

    std::lock_guard<std::mutex> lock(mutex_);

    bool isSystemApp = false;

    if (!GetBundleMgrProxy()) {
        return isSystemApp;
    }

    isSystemApp = sptrBundleMgr_->CheckIsSystemAppByUid(uid);

    return isSystemApp;
}

bool BundleManagerHelper::CheckPermission(const std::string &bundleName, const std::string &permission)
{
    EVENT_LOGI("enter");

    std::lock_guard<std::mutex> lock(mutex_);

    if (!GetBundleMgrProxy()) {
        return false;
    }

    int ret = sptrBundleMgr_->CheckPermission(bundleName, permission);
    if (ret != PERMISSION_GRANTED) {
        return false;
    }

    return true;
}

bool BundleManagerHelper::GetBundleMgrProxy()
{
    EVENT_LOGD("enter");

    if (!sptrBundleMgr_) {
        sptr<ISystemAbilityManager> systemAbilityManager =
            SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (!systemAbilityManager) {
            EVENT_LOGE("Failed to get system ability mgr.");
            return false;
        }

        sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
        if (!remoteObject) {
            EVENT_LOGE("Failed to get bundle manager service.");
            return false;
        }

        sptrBundleMgr_ = iface_cast<IBundleMgr>(remoteObject);
        if ((!sptrBundleMgr_) || (!sptrBundleMgr_->AsObject())) {
            EVENT_LOGE("Failed to get system bundle manager services ability");
            return false;
        }

        bmsDeath_ = new BMSDeathRecipient();
        if (!bmsDeath_) {
            EVENT_LOGE("Failed to create death Recipient ptr BMSDeathRecipient");
            return false;
        }
        if (!sptrBundleMgr_->AsObject()->AddDeathRecipient(bmsDeath_)) {
            EVENT_LOGW("Failed to add death recipient");
        }
    }

    return true;
}

void BundleManagerHelper::ClearBundleManagerHelper()
{
    EVENT_LOGI("enter");

    std::lock_guard<std::mutex> lock(mutex_);

    if ((sptrBundleMgr_ != nullptr) && (sptrBundleMgr_->AsObject() != nullptr)) {
        sptrBundleMgr_->AsObject()->RemoveDeathRecipient(bmsDeath_);
    }
    sptrBundleMgr_ = nullptr;
}
}  // namespace EventFwk
}  // namespace OHOS