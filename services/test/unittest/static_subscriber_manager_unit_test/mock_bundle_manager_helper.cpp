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

namespace OHOS {
namespace EventFwk {
BundleManagerHelper::BundleManagerHelper() : sptrBundleMgr_(nullptr), bmsDeath_(nullptr)
{}

BundleManagerHelper::~BundleManagerHelper()
{}

std::string BundleManagerHelper::GetBundleName(uid_t uid)
{
    return "";
}

bool BundleManagerHelper::QueryExtensionInfos(std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos,
    const int32_t &userId)
{
    return true;
}

bool BundleManagerHelper::QueryExtensionInfos(std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos)
{
    return true;
}

bool BundleManagerHelper::GetResConfigFile(const AppExecFwk::ExtensionAbilityInfo &extension,
                                           std::vector<std::string> &profileInfos)
{
    return true;
}

bool BundleManagerHelper::CheckIsSystemAppByUid(uid_t uid)
{
    return true;
}

bool BundleManagerHelper::GetBundleMgrProxy()
{
    return true;
}

void BundleManagerHelper::ClearBundleManagerHelper()
{
}
}  // namespace EventFwk
}  // namespace OHOS