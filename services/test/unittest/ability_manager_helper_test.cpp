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
#include "ability_manager_helper.h"
#undef private
#include "mock_common_event_stub.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EventFwk;
using namespace OHOS::AppExecFwk;

class AbilityManagerHelperTest : public testing::Test {
public:
    AbilityManagerHelperTest()
    {}
    ~AbilityManagerHelperTest()
    {}

    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AbilityManagerHelperTest::SetUpTestCase(void)
{}

void AbilityManagerHelperTest::TearDownTestCase(void)
{}

void AbilityManagerHelperTest::SetUp(void)
{}

void AbilityManagerHelperTest::TearDown(void)
{}

/**
 * @tc.name: AbilityManagerHelper_0100
 * @tc.desc: test GetAbilityMgrProxy function and abilityMgr_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_0100, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0100 start";
    AbilityManagerHelper abilityManagerHelper;
    sptr<IRemoteObject> remoteObject = sptr<IRemoteObject>(new MockCommonEventStub());
    abilityManagerHelper.abilityMgr_ = iface_cast<AAFwk::IAbilityManager>(remoteObject);
    EXPECT_EQ(true, abilityManagerHelper.GetAbilityMgrProxy());
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0100 end";
}

/**
 * @tc.name: AbilityManagerHelper_0200
 * @tc.desc: test GetAbilityMgrProxy function and abilityMgr_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_0200, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0200 start";
    AbilityManagerHelper abilityManagerHelper;
    abilityManagerHelper.abilityMgr_ = nullptr;
    EXPECT_EQ(false, abilityManagerHelper.GetAbilityMgrProxy());
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0200 end";
}

/**
 * @tc.name: AbilityManagerHelper_0300
 * @tc.desc: test ConnectAbility function and GetAbilityMgrProxy is false.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_0300, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0300 start";
    AbilityManagerHelper abilityManagerHelper;
    abilityManagerHelper.abilityMgr_ = nullptr;
    Want want;
    CommonEventData event;
    sptr<IRemoteObject> callerToken = nullptr;
    int32_t userId = 1;
    EXPECT_EQ(-1, abilityManagerHelper.ConnectAbility(want, event, callerToken, userId));
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0300 end";
}

/**
 * @tc.name: AbilityManagerHelper_0400
 * @tc.desc: test Clear function and abilityMgr_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_0400, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0400 start";
    std::shared_ptr<AbilityManagerHelper> abilityManagerHelper = std::make_shared<AbilityManagerHelper>();
    ASSERT_NE(nullptr, abilityManagerHelper);
    abilityManagerHelper->abilityMgr_ = nullptr;
    abilityManagerHelper->Clear();
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0400 end";
}

/**
 * @tc.name: AbilityManagerHelper_0500
 * @tc.desc: test Clear function and abilityMgr_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_0500, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0500 start";
    std::shared_ptr<AbilityManagerHelper> abilityManagerHelper = std::make_shared<AbilityManagerHelper>();
    ASSERT_NE(nullptr, abilityManagerHelper);
    sptr<IRemoteObject> remoteObject = sptr<IRemoteObject>(new MockCommonEventStub());
    abilityManagerHelper->abilityMgr_ = iface_cast<AAFwk::IAbilityManager>(remoteObject);
    abilityManagerHelper->Clear();
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0500 end";
}