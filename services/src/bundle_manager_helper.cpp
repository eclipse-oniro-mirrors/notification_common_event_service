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

#include "bundle_manager_helper.h"

#include "bundle_constants.h"
#include "bundle_mgr_client.h"
#include "event_log_wrapper.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "nlohmann/json.hpp"
#include "os_account_manager_helper.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace EventFwk {
const std::string META_NAME_STATIC_SUBSCRIBER = "ohos.extension.staticSubscriber";

using namespace OHOS::AppExecFwk::Constants;

BundleManagerHelper::BundleManagerHelper() : sptrBundleMgr_(nullptr), bmsDeath_(nullptr)
{}

BundleManagerHelper::~BundleManagerHelper()
{}

std::string BundleManagerHelper::GetBundleName(const uid_t uid)
{
    EVENT_LOGD("enter");

    std::lock_guard<std::mutex> lock(mutex_);
    std::string bundleName = "";

    if (!GetBundleMgrProxyAsync()) {
        EVENT_LOGE_LIMIT("failed to get bms proxy");
        return bundleName;
    }
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    sptrBundleMgr_->GetNameForUid(uid, bundleName);
    IPCSkeleton::SetCallingIdentity(identity);
    return bundleName;
}

bool BundleManagerHelper::QueryExtensionInfos(std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos,
    const int32_t &userId)
{
    EVENT_LOGD("enter");

    std::lock_guard<std::mutex> lock(mutex_);

    if (!GetBundleMgrProxy()) {
        EVENT_LOGE("failed to get bms proxy");
        return false;
    }

    return sptrBundleMgr_->QueryExtensionAbilityInfos(AppExecFwk::ExtensionAbilityType::STATICSUBSCRIBER,
        userId, extensionInfos);
}

bool BundleManagerHelper::QueryExtensionInfos(std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos)
{
    EVENT_LOGD("enter");

    std::lock_guard<std::mutex> lock(mutex_);

    if (!GetBundleMgrProxy()) {
        EVENT_LOGE("failed to get bms proxy");
        return false;
    }
    std::vector<int> osAccountIds;
    if (DelayedSingleton<OsAccountManagerHelper>::GetInstance()->QueryActiveOsAccountIds(osAccountIds) != ERR_OK) {
        EVENT_LOGE("failed to QueryActiveOsAccountIds!");
        return false;
    }
    if (osAccountIds.size() == 0) {
        EVENT_LOGE("no os account acquired!");
        return false;
    }
    for (auto userId : osAccountIds) {
        EVENT_LOGD("active userId = %{public}d", userId);
        sptrBundleMgr_->QueryExtensionAbilityInfos(AppExecFwk::ExtensionAbilityType::STATICSUBSCRIBER,
            userId, extensionInfos);
    }
    return true;
}

bool BundleManagerHelper::GetResConfigFile(const AppExecFwk::ExtensionAbilityInfo &extension,
                                           std::vector<std::string> &profileInfos)
{
    EVENT_LOGD("enter");

    std::lock_guard<std::mutex> lock(mutex_);

    if (!GetBundleMgrProxy()) {
        EVENT_LOGE("failed to get bms proxy");
        return false;
    }

    AppExecFwk::BundleMgrClient client;
    return client.GetResConfigFile(extension, META_NAME_STATIC_SUBSCRIBER, profileInfos);
}

bool BundleManagerHelper::CheckIsSystemAppByUid(const uid_t uid)
{
    EVENT_LOGD("enter");

    std::lock_guard<std::mutex> lock(mutex_);

    bool isSystemApp = false;

    if (!GetBundleMgrProxy()) {
        EVENT_LOGE("failed to get bms proxy");
        return isSystemApp;
    }

    isSystemApp = sptrBundleMgr_->CheckIsSystemAppByUid(uid);

    return isSystemApp;
}

bool BundleManagerHelper::CheckIsSystemAppByBundleName(const std::string &bundleName, const int32_t &userId)
{
    EVENT_LOGD("enter");

    std::lock_guard<std::mutex> lock(mutex_);

    bool isSystemApp = false;

    if (!GetBundleMgrProxy()) {
        return isSystemApp;
    }
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    int32_t uid = sptrBundleMgr_->GetUidByBundleName(bundleName, userId);
    IPCSkeleton::SetCallingIdentity(identity);
    if (uid < 0) {
        EVENT_LOGW("get invalid uid from bundle %{public}s of userId %{public}d", bundleName.c_str(), userId);
    }
    isSystemApp = sptrBundleMgr_->CheckIsSystemAppByUid(uid);

    return isSystemApp;
}

bool BundleManagerHelper::GetBundleMgrProxyAsync()
{
    return GetBundleMgrProxyInner(true);
}

bool BundleManagerHelper::GetBundleMgrProxy()
{
    return GetBundleMgrProxyInner(false);
}

bool BundleManagerHelper::GetBundleMgrProxyInner(bool isAsync)
{
    EVENT_LOGD("enter");
    sptr<IRemoteObject> remoteObject;

    if (!sptrBundleMgr_) {
        sptr<ISystemAbilityManager> systemAbilityManager =
            SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (!systemAbilityManager) {
            EVENT_LOGE("Failed to get system ability mgr.");
            return false;
        }

        if (isAsync) {
            remoteObject = systemAbilityManager->CheckSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
        } else {
            remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
        }

        if (!remoteObject) {
            EVENT_LOGE("Failed to get bundle manager service.");
            return false;
        }

        sptrBundleMgr_ = iface_cast<IBundleMgr>(remoteObject);
        if ((!sptrBundleMgr_) || (!sptrBundleMgr_->AsObject())) {
            EVENT_LOGE("Failed to get system bundle manager services ability");
            return false;
        }

        bmsDeath_ = new (std::nothrow) BMSDeathRecipient();
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
    EVENT_LOGD("enter");

    std::lock_guard<std::mutex> lock(mutex_);

    if ((sptrBundleMgr_ != nullptr) && (sptrBundleMgr_->AsObject() != nullptr)) {
        sptrBundleMgr_->AsObject()->RemoveDeathRecipient(bmsDeath_);
    }
    sptrBundleMgr_ = nullptr;
}

bool BundleManagerHelper::GetApplicationInfos(const AppExecFwk::ApplicationFlag &flag,
    std::vector<AppExecFwk::ApplicationInfo> &appInfos)
{
    EVENT_LOGD("enter");

    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<int> osAccountIds {};
    if (DelayedSingleton<OsAccountManagerHelper>::GetInstance()->QueryActiveOsAccountIds(osAccountIds) != ERR_OK
        || osAccountIds.empty()) {
        EVENT_LOGE("failed to QueryActiveOsAccountIds!");
        return false;
    }

    if (!GetBundleMgrProxy()) {
        EVENT_LOGE("failed to get bms proxy");
        return false;
    }

    return sptrBundleMgr_->GetApplicationInfos(flag, osAccountIds[0], appInfos);
}
}  // namespace EventFwk
}  // namespace OHOS