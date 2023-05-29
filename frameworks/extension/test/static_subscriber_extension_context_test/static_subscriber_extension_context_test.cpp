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

#include "ability_manager_errors.h"
#define private public
#define protected public
#include "static_subscriber_extension_context.h"
#undef private
#undef protected

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EventFwk {
class StaticSubscriberExtensionContextTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void StaticSubscriberExtensionContextTest::SetUpTestCase()
{}

void StaticSubscriberExtensionContextTest::TearDownTestCase()
{}

void StaticSubscriberExtensionContextTest::SetUp()
{}

void StaticSubscriberExtensionContextTest::TearDown()
{}

/**
 * @tc.name  : test CheckCallerIsSystemApp
 * @tc.number: StaticSubscriberExtensionContextTest_0100
 * @tc.desc  : test CheckCallerIsSystemApp failed
 */
HWTEST_F(StaticSubscriberExtensionContextTest, StaticSubscriberExtensionContextTest_0100, TestSize.Level1)
{
    auto staticSubscriberExtensionContext = std::make_shared<StaticSubscriberExtensionContext>();
    EXPECT_FALSE(staticSubscriberExtensionContext->CheckCallerIsSystemApp());
}

/**
 * @tc.name  : test StartAbility
 * @tc.number: StaticSubscriberExtensionContextTest_0200
 * @tc.desc  : test StartAbility failed
 */
HWTEST_F(StaticSubscriberExtensionContextTest, StaticSubscriberExtensionContextTest_0200, TestSize.Level1)
{
    auto staticSubscriberExtensionContext = std::make_shared<StaticSubscriberExtensionContext>();
    AAFwk::Want want;
    want.SetBundle("BundleName");
    EXPECT_EQ(staticSubscriberExtensionContext->StartAbility(want), AAFwk::ERR_NOT_SYSTEM_APP);
}

/**
 * @tc.name  : test VerifyCallingPermission
 * @tc.number: StaticSubscriberExtensionContextTest_0300
 * @tc.desc  : test VerifyCallingPermission failed
 */
HWTEST_F(StaticSubscriberExtensionContextTest, StaticSubscriberExtensionContextTest_0300, TestSize.Level1)
{
    auto staticSubscriberExtensionContext = std::make_shared<StaticSubscriberExtensionContext>();
    EXPECT_FALSE(staticSubscriberExtensionContext->VerifyCallingPermission("permission"));
}
} // namespace EventFwk
} // namespace OHOS
