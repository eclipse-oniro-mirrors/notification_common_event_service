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

class BundleManagerHelperTest : public testing::Test {
public:
    BundleManagerHelperTest()
    {}
    ~BundleManagerHelperTest()
    {}

    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void BundleManagerHelperTest::SetUpTestCase(void)
{}

void BundleManagerHelperTest::TearDownTestCase(void)
{}

void BundleManagerHelperTest::SetUp(void)
{}

void BundleManagerHelperTest::TearDown(void)
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
 * @tc.name: BundleManagerHelper_0200
 * @tc.desc: test ClearBundleManagerHelper function and sptrBundleMgr_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerHelperTest, BundleManagerHelper_0200, Level1)
{
    GTEST_LOG_(INFO) << "BundleManagerHelper_0200 start";
    std::shared_ptr<BundleManagerHelper> bundleManagerHelper = std::make_shared<BundleManagerHelper>();
    ASSERT_NE(nullptr, bundleManagerHelper);
    bundleManagerHelper->ClearBundleManagerHelper();
    GTEST_LOG_(INFO) << "BundleManagerHelper_0200 end";
}

/**
 * @tc.name: BundleManagerHelper_0300
 * @tc.desc: test GetBundleMgrProxy function and sptrBundleMgr_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerHelperTest, BundleManagerHelper_0300, Level1)
{
    GTEST_LOG_(INFO) << "BundleManagerHelper_0300 start";
    BundleManagerHelper bundleManagerHelper;
    bundleManagerHelper.sptrBundleMgr_ = new (std::nothrow) TestIBundleMgr();
    EXPECT_EQ(true, bundleManagerHelper.GetBundleMgrProxy());
    GTEST_LOG_(INFO) << "BundleManagerHelper_0300 end";
}

/**
 * @tc.name: BundleManagerHelper_0400
 * @tc.desc: test GetBundleMgrProxy function and sptrBundleMgr_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerHelperTest, BundleManagerHelper_0400, Level1)
{
    GTEST_LOG_(INFO) << "BundleManagerHelper_0400 start";
    BundleManagerHelper bundleManagerHelper;
    bundleManagerHelper.sptrBundleMgr_ = nullptr;
    EXPECT_EQ(false, bundleManagerHelper.GetBundleMgrProxy());
    GTEST_LOG_(INFO) << "BundleManagerHelper_0400 end";
}

/**
 * @tc.name: BundleManagerHelper_0500
 * @tc.desc: test GetBundleName function and GetBundleMgrProxy is false.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerHelperTest, BundleManagerHelper_0500, Level1)
{
    GTEST_LOG_(INFO) << "BundleManagerHelper_0500 start";
    BundleManagerHelper bundleManagerHelper;
    bundleManagerHelper.sptrBundleMgr_ = nullptr;
    const uid_t uid = 1;
    EXPECT_EQ("", bundleManagerHelper.GetBundleName(uid));
    GTEST_LOG_(INFO) << "BundleManagerHelper_0500 end";
}

/**
 * @tc.name: BundleManagerHelper_0600
 * @tc.desc: test QueryExtensionInfos function and GetBundleMgrProxy is false.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerHelperTest, BundleManagerHelper_0600, Level1)
{
    GTEST_LOG_(INFO) << "BundleManagerHelper_0600 start";
    BundleManagerHelper bundleManagerHelper;
    bundleManagerHelper.sptrBundleMgr_ = nullptr;
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionInfos;
    const int32_t userId = 1;
    EXPECT_EQ(false, bundleManagerHelper.QueryExtensionInfos(extensionInfos, userId));
    GTEST_LOG_(INFO) << "BundleManagerHelper_0600 end";
}

/**
 * @tc.name: BundleManagerHelper_0700
 * @tc.desc: test QueryExtensionInfos function and GetBundleMgrProxy is false.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerHelperTest, BundleManagerHelper_0700, Level1)
{
    GTEST_LOG_(INFO) << "BundleManagerHelper_0700 start";
    BundleManagerHelper bundleManagerHelper;
    bundleManagerHelper.sptrBundleMgr_ = nullptr;
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionInfos;
    EXPECT_EQ(false, bundleManagerHelper.QueryExtensionInfos(extensionInfos));
    GTEST_LOG_(INFO) << "BundleManagerHelper_0700 end";
}

/**
 * @tc.name: BundleManagerHelper_0800
 * @tc.desc: test QueryExtensionInfos function and GetBundleMgrProxy is true and osAccountIds.size() is 0.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerHelperTest, BundleManagerHelper_0800, Level1)
{
    GTEST_LOG_(INFO) << "BundleManagerHelper_0800 start";
    BundleManagerHelper bundleManagerHelper;
    sptr<IRemoteObject> remoteObject = sptr<IRemoteObject>(new MockCommonEventStub());
    bundleManagerHelper.sptrBundleMgr_ = iface_cast<IBundleMgr>(remoteObject);
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionInfos;
    EXPECT_EQ(false, bundleManagerHelper.QueryExtensionInfos(extensionInfos));
    GTEST_LOG_(INFO) << "BundleManagerHelper_0800 end";
}

/**
 * @tc.name: BundleManagerHelper_0900
 * @tc.desc: test GetResConfigFile function and GetBundleMgrProxy is false.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerHelperTest, BundleManagerHelper_0900, Level1)
{
    GTEST_LOG_(INFO) << "BundleManagerHelper_0900 start";
    BundleManagerHelper bundleManagerHelper;
    bundleManagerHelper.sptrBundleMgr_ = nullptr;
    AppExecFwk::ExtensionAbilityInfo extension;
    std::vector<std::string> profileInfos;
    EXPECT_EQ(false, bundleManagerHelper.GetResConfigFile(extension, profileInfos));
    GTEST_LOG_(INFO) << "BundleManagerHelper_0900 end";
}

/**
 * @tc.name: BundleManagerHelper_1000
 * @tc.desc: test CheckIsSystemAppByUid function and GetBundleMgrProxy is false.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerHelperTest, BundleManagerHelper_1000, Level1)
{
    GTEST_LOG_(INFO) << "BundleManagerHelper_1000 start";
    BundleManagerHelper bundleManagerHelper;
    bundleManagerHelper.sptrBundleMgr_ = nullptr;
    const uid_t uid = 1;
    EXPECT_EQ(false, bundleManagerHelper.CheckIsSystemAppByUid(uid));
    GTEST_LOG_(INFO) << "BundleManagerHelper_1000 end";
}

/**
 * @tc.name: BundleManagerHelper_1100
 * @tc.desc: test CheckIsSystemAppByBundleName function and GetBundleMgrProxy is false.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerHelperTest, BundleManagerHelper_1100, Level1)
{
    GTEST_LOG_(INFO) << "BundleManagerHelper_1100 start";
    BundleManagerHelper bundleManagerHelper;
    bundleManagerHelper.sptrBundleMgr_ = nullptr;
    std::string bundleName = "aa";
    const int32_t userId = 1;
    EXPECT_EQ(false, bundleManagerHelper.CheckIsSystemAppByBundleName(bundleName, userId));
    GTEST_LOG_(INFO) << "BundleManagerHelper_1100 end";
}

/**
 * @tc.name: BundleManagerHelper_1200
 * @tc.desc: test ClearBundleManagerHelper function and sptrBundleMgr_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerHelperTest, BundleManagerHelper_1200, Level1)
{
    GTEST_LOG_(INFO) << "BundleManagerHelper_1200 start";
    std::shared_ptr<BundleManagerHelper> bundleManagerHelper = std::make_shared<BundleManagerHelper>();
    ASSERT_NE(nullptr, bundleManagerHelper);
    sptr<IRemoteObject> remoteObject = sptr<IRemoteObject>(new MockCommonEventStub());
    bundleManagerHelper->sptrBundleMgr_ = iface_cast<IBundleMgr>(remoteObject);
    bundleManagerHelper->ClearBundleManagerHelper();
    GTEST_LOG_(INFO) << "BundleManagerHelper_1200 end";
}