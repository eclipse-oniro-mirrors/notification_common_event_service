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

#include <gtest/gtest.h>
#include <numeric>
#define private public
#include "bundle_manager_helper.h"
#undef private
#include "mock_common_event_stub.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EventFwk;
using namespace OHOS::AppExecFwk;

class BundleManagerHelperBranchTest : public testing::Test {
public:
    BundleManagerHelperBranchTest()
    {}
    ~BundleManagerHelperBranchTest()
    {}

    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void BundleManagerHelperBranchTest::SetUpTestCase(void)
{}

void BundleManagerHelperBranchTest::TearDownTestCase(void)
{}

void BundleManagerHelperBranchTest::SetUp(void)
{}

void BundleManagerHelperBranchTest::TearDown(void)
{}

using IBundleMgr = OHOS::AppExecFwk::IBundleMgr;

class TestIBundleMgr : public IBundleMgr {
public:
    TestIBundleMgr() = default;
    virtual ~TestIBundleMgr()
    {};
    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

/**
 * @tc.name: BundleManagerHelper_0013
 * @tc.desc: test QueryExtensionInfos function and GetBundleMgrProxy is true and osAccountIds.size() is 0.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerHelperBranchTest, BundleManagerHelper_0013, Level1)
{
    GTEST_LOG_(INFO) << "BundleManagerHelper_0013 start";
    BundleManagerHelper bundleManagerHelper;
    sptr<IRemoteObject> remoteObject = sptr<IRemoteObject>(new MockCommonEventStub());
    bundleManagerHelper.sptrBundleMgr_ = iface_cast<IBundleMgr>(remoteObject);
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionInfos;
    int32_t userId = 1;
    EXPECT_EQ(false, bundleManagerHelper.QueryExtensionInfos(extensionInfos, userId));
    GTEST_LOG_(INFO) << "BundleManagerHelper_0013 end";
}

/**
 * @tc.name: BundleManagerHelper_1400
 * @tc.desc: test CheckIsSystemAppByBundleName function and GetBundleMgrProxy is false.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerHelperBranchTest, BundleManagerHelper_1400, Level1)
{
    GTEST_LOG_(INFO) << "BundleManagerHelper_1400 start";
    BundleManagerHelper bundleManagerHelper;
    sptr<IRemoteObject> remoteObject = sptr<IRemoteObject>(new MockCommonEventStub());
    bundleManagerHelper.sptrBundleMgr_ = iface_cast<IBundleMgr>(remoteObject);
    std::string bundleName = "aa";
    int32_t userId = 1;
    EXPECT_EQ(false, bundleManagerHelper.CheckIsSystemAppByBundleName(bundleName, userId));
    GTEST_LOG_(INFO) << "BundleManagerHelper_1400 end";
}