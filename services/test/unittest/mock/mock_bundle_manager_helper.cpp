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
bool g_mockQueryExtensionInfosRet = true;
std::vector<ExtensionAbilityInfo> g_mockExtensionInfos;
bool g_mockGetResConfigFileRet = true;
std::vector<std::string> g_mockProfileInfos;
std::vector<AppExecFwk::ApplicationInfo> g_mockAppInfos;
bool g_mockIsClearBundleManagerHelperCalled = false;
bool g_mockBundleName = false;
int32_t g_mockUid = -1;
bool g_mockIsSystemApp = false;
constexpr int32_t MOCK_UID = 1000;
}

bool IsClearBundleManagerHelperCalled()
{
    return g_mockIsClearBundleManagerHelperCalled;
}

void SetBundleNameMock()
{
    g_mockBundleName = true;
}

void SetUidMock(int32_t uid)
{
    g_mockUid = uid;
}

void SetSystemMock(bool mockRet)
{
    g_mockIsSystemApp = mockRet;
}

void ResetBundleManagerHelperMock()
{
    g_mockQueryExtensionInfosRet = true;
    g_mockExtensionInfos.clear();
    g_mockGetResConfigFileRet = true;
    g_mockProfileInfos.clear();
    g_mockIsClearBundleManagerHelperCalled = false;
    g_mockBundleName = false;
    g_mockIsSystemApp = false;
    g_mockUid = -1;
}

void MockQueryExtensionInfos(bool mockRet, uint8_t mockCase)
{
    g_mockExtensionInfos.clear();
    g_mockQueryExtensionInfosRet = mockRet;
    switch (mockCase) {
        case 1: { // case for basic
            ExtensionAbilityInfo info0;
            info0.bundleName = "com.ohos.systemui";
            info0.name = "StaticSubscriber";
            info0.permissions.emplace_back("permission0");
            info0.applicationInfo.uid = MOCK_UID;
            g_mockExtensionInfos.emplace_back(info0);
            break;
        }
        case 2: { // case for one different
            ExtensionAbilityInfo info0;
            info0.bundleName = "com.ohos.systemui1";
            info0.name = "StaticSubscriber";
            info0.applicationInfo.uid = MOCK_UID;
            g_mockExtensionInfos.emplace_back(info0);
            break;
        }
        case 3: { // case for two
            ExtensionAbilityInfo info0;
            info0.bundleName = "com.ohos.systemui";
            info0.name = "StaticSubscriber";
            info0.applicationInfo.uid = MOCK_UID;
            g_mockExtensionInfos.emplace_back(info0);
            ExtensionAbilityInfo info1;
            info1.bundleName = "com.ohos.systemui1";
            info1.name = "StaticSubscriber";
            info1.applicationInfo.uid = MOCK_UID;
            g_mockExtensionInfos.emplace_back(info1);
            break;
        }
        case 4: { // case for two different extensionName
            ExtensionAbilityInfo info0;
            info0.bundleName = "com.ohos.systemui";
            info0.name = "StaticSubscriber";
            info0.applicationInfo.uid = MOCK_UID;
            g_mockExtensionInfos.emplace_back(info0);
            ExtensionAbilityInfo info1;
            info1.bundleName = "com.ohos.systemui";
            info1.name = "StaticSubscriber1";
            info1.applicationInfo.uid = MOCK_UID;
            g_mockExtensionInfos.emplace_back(info1);
            break;
        }
        default:
            break;
    }
}

void MockGetResConfigFile(bool mockRet, uint8_t mockCase)
{
    g_mockGetResConfigFileRet = mockRet;
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
        case 4: { // case for two different susbcriber name
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
                "            \"events\":[\"usual.event.TIME_TICK\"],"
                "            \"name\":\"StaticSubscriber1\","
                "            \"permission\":\"\""
                "        }"
                "    ]"
                "}";
            g_mockProfileInfos.emplace_back(profile1);
            break;
        }
        case 5: { // case for basic
            std::string profile0 =
                "{"
                "    \"commonEvents\":["
                "        {"
                "            \"events\":["
                "                \"usual.event.TIME_TICK\","
                "                \"usual.event.PACKAGE_ADDED\""
                "            ],"
                "            \"name\":\"StaticSubscriber\","
                "            \"permission\":\"permission0\""
                "        }"
                "    ]"
                "}";
            g_mockProfileInfos.emplace_back(profile0);
            break;
        }
        default:
            break;
    }
}

void MockGetApplicationInfos(uint8_t mockCase)
{
    g_mockAppInfos.clear();
    switch (mockCase) {
        case 1: {
            ApplicationInfo appInfo0;
            appInfo0.bundleName = "com.ohos.systemui";
            appInfo0.uid = MOCK_UID;
            g_mockAppInfos.emplace_back(appInfo0);
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
    if (g_mockBundleName) {
        return "testBundleName";
    }
    return "";
}

bool BundleManagerHelper::QueryExtensionInfos(std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos,
    const int32_t &userId)
{
    extensionInfos = g_mockExtensionInfos;
    return g_mockQueryExtensionInfosRet;
}

bool BundleManagerHelper::QueryExtensionInfos(std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos)
{
    extensionInfos = g_mockExtensionInfos;
    return g_mockQueryExtensionInfosRet;
}

bool BundleManagerHelper::GetResConfigFile(const AppExecFwk::ExtensionAbilityInfo &extension,
                                           std::vector<std::string> &profileInfos)
{
    profileInfos = g_mockProfileInfos;
    return g_mockGetResConfigFileRet;
}

bool BundleManagerHelper::CheckIsSystemAppByUid(uid_t uid)
{
    return g_mockIsSystemApp;
}

bool BundleManagerHelper::CheckIsSystemAppByBundleName(const std::string &bundleName, const int32_t &userId)
{
    return g_mockIsSystemApp;
}

bool BundleManagerHelper::GetBundleMgrProxy()
{
    return true;
}

void BundleManagerHelper::ClearBundleManagerHelper()
{
    g_mockIsClearBundleManagerHelperCalled = true;
}

bool BundleManagerHelper::GetApplicationInfos(const AppExecFwk::ApplicationFlag &flag,
    std::vector<AppExecFwk::ApplicationInfo> &appInfos)
{
    appInfos = g_mockAppInfos;
    g_mockAppInfos.clear();
    return true;
}

int32_t BundleManagerHelper::GetDefaultUidByBundleName(const std::string &bundle, const int32_t userId)
{
    return g_mockUid;
}
}  // namespace EventFwk
}  // namespace OHOS