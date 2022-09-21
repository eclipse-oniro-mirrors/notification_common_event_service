/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

using namespace OHOS;
using namespace OHOS::AppExecFwk;
namespace {
bool g_MockQueryExtensionInfosRet = true;
std::vector<ExtensionAbilityInfo> g_mockExtensionInfos;
bool g_MockGetResConfigFileRet = true;
std::vector<std::string> g_mockProfileInfos;
}

void MockQueryExtensionInfos(bool mockRet, uint8_t mockCase)
{
    g_mockExtensionInfos.clear();
    g_MockQueryExtensionInfosRet = mockRet;
    switch (mockCase) {
        case 1: { // case for basic
            ExtensionAbilityInfo info0;
            info0.bundleName = "com.ohos.systemui";
            info0.name = "StaticSubscriber";
            g_mockExtensionInfos.emplace_back(info0);
            break;
        }
        case 2: { // case for one invalid
            ExtensionAbilityInfo info0;
            info0.bundleName = "com.ohos.systemui1";
            info0.name = "StaticSubscriber";
            g_mockExtensionInfos.emplace_back(info0);
            break;
        }
        case 3: { // case for two
            ExtensionAbilityInfo info0;
            info0.bundleName = "com.ohos.systemui";
            info0.name = "StaticSubscriber";
            g_mockExtensionInfos.emplace_back(info0);
            ExtensionAbilityInfo info1;
            info1.bundleName = "com.ohos.systemui1";
            info1.name = "StaticSubscriber";
            g_mockExtensionInfos.emplace_back(info1);
            break;
        }
        default:
            break;
    }
}

void MockGetResConfigFile(bool mockRet, uint8_t mockCase)
{
    g_MockGetResConfigFileRet = mockRet;
    g_mockProfileInfos.clear();
    switch (mockCase) {
        case 1: { // case for basic
            std::string profile0 =
                "{"
                "    \"commonEvents\":["
                "        {"
                "            \"events\":[\"usual.event.TIME_TICK\"],"
                "            \"name\":\"StaticSubscriber\","
                "            \"permission\":\"permission0\""
                "        }"
                "    ]"
                "}";
            g_mockProfileInfos.emplace_back(profile0);
            break;
        }
        case 2: { // case for two different
            std::string profile0 =
                "{"
                "    \"commonEvents\":["
                "        {"
                "            \"events\":[\"usual.event.TIME_TICK\"],"
                "            \"name\":\"StaticSubscriber\","
                "            \"permission\":\"\""
                "        }"
                "    ]"
                "}";
            g_mockProfileInfos.emplace_back(profile0);
            std::string profile1 =
                "{"
                "    \"commonEvents\":["
                "        {"
                "            \"events\":[\"usual.event.TIME_TICK1\"],"
                "            \"name\":\"StaticSubscriber\","
                "            \"permission\":\"\""
                "        }"
                "    ]"
                "}";
            g_mockProfileInfos.emplace_back(profile1);
            break;
        }
        case 3: { // case for two same
            std::string profile0 =
                "{"
                "    \"commonEvents\":["
                "        {"
                "            \"events\":[\"usual.event.TIME_TICK\"],"
                "            \"name\":\"StaticSubscriber\","
                "            \"permission\":\"\""
                "        }"
                "    ]"
                "}";
            g_mockProfileInfos.emplace_back(profile0);
            g_mockProfileInfos.emplace_back(profile0);
            break;
        }
        default:
            break;
    }
}

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
    extensionInfos = g_mockExtensionInfos;
    return g_MockQueryExtensionInfosRet;
}

bool BundleManagerHelper::QueryExtensionInfos(std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos)
{
    extensionInfos = g_mockExtensionInfos;
    return g_MockQueryExtensionInfosRet;
}

bool BundleManagerHelper::GetResConfigFile(const AppExecFwk::ExtensionAbilityInfo &extension,
                                           std::vector<std::string> &profileInfos)
{
    profileInfos = g_mockProfileInfos;
    return g_MockGetResConfigFileRet;
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