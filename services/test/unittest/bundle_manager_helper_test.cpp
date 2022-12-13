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

#include <gtest/gtest.h>
#include <numeric>
#define private public
#include "bundle_manager_helper.h"
#undef private

using namespace testing::ext;
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

/**
 * @tc.name: BundleManagerHelper_0100
 * @tc.desc: test CheckIsSystemAppByBundleName function.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerHelperTest, BundleManagerHelper_0100, Level1)
{
    GTEST_LOG_(INFO) << "BundleManagerHelper_0100 start";
    BundleManagerHelper bundleManagerHelper;
    std::string bundleName = "aa";
    const int32_t userId = 1;
    EXPECT_EQ(false, bundleManagerHelper.CheckIsSystemAppByBundleName(bundleName, userId));
    GTEST_LOG_(INFO) << "BundleManagerHelper_0100 end";
}

/**
 * @tc.name: BundleManagerHelper_0200
 * @tc.desc: test CheckIsSystemAppByBundleName function.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerHelperTest, BundleManagerHelper_0200, Level1)
{
    GTEST_LOG_(INFO) << "BundleManagerHelper_0200 start";
    BundleManagerHelper bundleManagerHelper;
    bundleManagerHelper.ClearBundleManagerHelper();
    GTEST_LOG_(INFO) << "BundleManagerHelper_0200 end";
}