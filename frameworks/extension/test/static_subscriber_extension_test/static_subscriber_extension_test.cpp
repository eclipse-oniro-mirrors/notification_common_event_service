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

#include <chrono>
#include <thread>
#include <gtest/gtest.h>

#define private public
#define protected public
#include "mock_runtime.h"
#include "runtime.h"
#include "static_subscriber_extension.h"
#include "static_subscriber_extension_context.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace testing;
using namespace std::chrono;

namespace OHOS {
namespace EventFwk {
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime;
class StaticSubscriberExtensionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void StaticSubscriberExtensionTest::SetUpTestCase(void)
{}

void StaticSubscriberExtensionTest::TearDownTestCase(void)
{}

void StaticSubscriberExtensionTest::SetUp(void)
{}

void StaticSubscriberExtensionTest::TearDown(void)
{}

class MockStaticSubscriberExtension : public StaticSubscriberExtension
{
public:
    MockStaticSubscriberExtension() {};
    virtual ~MockStaticSubscriberExtension() {};

    void OnReceiveEvent(std::shared_ptr<CommonEventData> data) override
    {
        flag = true;
    }

    bool flag = false;
};

/*
* @tc.number: Create_001
* @tc.name: Create
* @tc.desc: Verify function Create normal branch, Create object pointer is not nullptr
*/
HWTEST_F(StaticSubscriberExtensionTest, Create_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Create_001 start.";
    std::unique_ptr<Runtime> runtime = nullptr;
    auto resulft = StaticSubscriberExtension::Create(runtime);
    EXPECT_TRUE(resulft != nullptr);
    delete resulft;
    resulft = nullptr;
    GTEST_LOG_(INFO) << "Create_001 end.";
}

/*
* @tc.number: Create_002
* @tc.name: Create
* @tc.desc: Verify function Create normal branch, Create object pointer is not nullptr
*/
HWTEST_F(StaticSubscriberExtensionTest, Create_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Create_002 start.";
    std::unique_ptr<MockRuntime> mockRuntime = std::make_unique<MockRuntime>();
    mockRuntime->language = static_cast<MockRuntime::Language>(-1);
    std::unique_ptr<Runtime> runtime = std::move(mockRuntime);
    auto resulft = StaticSubscriberExtension::Create(runtime);
    EXPECT_TRUE(resulft != nullptr);
    delete resulft;
    resulft = nullptr;
    GTEST_LOG_(INFO) << "Create_002 end.";
}

/*
* @tc.number: Create_003
* @tc.name: Create
* @tc.desc: Verify function Create normal branch, Create object pointer is not nullptr
*/
HWTEST_F(StaticSubscriberExtensionTest, Create_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Create_003 start.";
    std::unique_ptr<MockRuntime> mockRuntime = std::make_unique<MockRuntime>();
    mockRuntime->language = MockRuntime::Language::JS;
    std::unique_ptr<Runtime> runtime = std::move(mockRuntime);
    auto resulft = StaticSubscriberExtension::Create(runtime);
    EXPECT_TRUE(resulft != nullptr);
    delete resulft;
    resulft = nullptr;
    GTEST_LOG_(INFO) << "Create_003 end.";
}

/*
* @tc.number: CreateAndInitContext_001
* @tc.name: CreateAndInitContext
* @tc.desc: Verify function CreateAndInitContext normal branch, CreateAndInitContext return pointer is not nullptr
*/
HWTEST_F(StaticSubscriberExtensionTest, CreateAndInitContext_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CreateAndInitContext_001 start.";
    std::unique_ptr<Runtime> runtime = nullptr;
    auto testObject = StaticSubscriberExtension::Create(runtime);
    EXPECT_TRUE(testObject != nullptr);

    const std::shared_ptr<AbilityLocalRecord> record = nullptr;
    const std::shared_ptr<OHOSApplication> application = nullptr;
    std::shared_ptr<AbilityHandler> handler = nullptr;
    const sptr<IRemoteObject> token = nullptr;
    auto resulft = testObject->CreateAndInitContext(record, application, handler, token);

    EXPECT_TRUE(resulft != nullptr);
    delete testObject;
    testObject = nullptr;
    GTEST_LOG_(INFO) << "CreateAndInitContext_001 end.";
}

/*
* @tc.number: CreateAndInitContext_002
* @tc.name: CreateAndInitContext
* @tc.desc: Verify function CreateAndInitContext normal branch, CreateAndInitContext return pointer is not nullptr
*/
HWTEST_F(StaticSubscriberExtensionTest, CreateAndInitContext_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CreateAndInitContext_002 start.";
    std::unique_ptr<Runtime> runtime = nullptr;
    auto testObject = StaticSubscriberExtension::Create(runtime);
    EXPECT_TRUE(testObject != nullptr);

    const std::shared_ptr<AbilityInfo> info = nullptr;
    const std::shared_ptr<OHOSApplication> application = nullptr;
    std::shared_ptr<AbilityHandler> handler = nullptr;
    const sptr<IRemoteObject> token = nullptr;
    const std::shared_ptr<AbilityLocalRecord> record = std::make_shared<AbilityLocalRecord>(info, token);
    auto resulft = testObject->CreateAndInitContext(record, application, handler, token);

    EXPECT_TRUE(resulft != nullptr);
    delete testObject;
    testObject = nullptr;
    GTEST_LOG_(INFO) << "CreateAndInitContext_002 end.";
}

/*
* @tc.number: Init_001
* @tc.name: Init
* @tc.desc: Verify function Init normal branch, GetContext function return pointer is not nullptr
*/
HWTEST_F(StaticSubscriberExtensionTest, Init_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Init_001 start.";
    std::unique_ptr<Runtime> runtime = nullptr;
    auto testObject = StaticSubscriberExtension::Create(runtime);
    EXPECT_TRUE(testObject != nullptr);
    EXPECT_TRUE(testObject->GetContext() == nullptr);

    const std::shared_ptr<AbilityInfo> info = nullptr;
    const std::shared_ptr<OHOSApplication> application = nullptr;
    std::shared_ptr<AbilityHandler> handler = nullptr;
    const sptr<IRemoteObject> token = nullptr;
    const std::shared_ptr<AbilityLocalRecord> record = std::make_shared<AbilityLocalRecord>(info, token);
    testObject->Init(record, application, handler, token);

    EXPECT_TRUE(testObject->GetContext() != nullptr);
    delete testObject;
    testObject = nullptr;
    GTEST_LOG_(INFO) << "Init_001 end.";
}

/*
* @tc.number: OnReceiveEvent_001
* @tc.name: OnReceiveEvent
* @tc.desc: Verify function OnReceiveEvent normal branch, OnReceiveEvent called
*/
HWTEST_F(StaticSubscriberExtensionTest, OnReceiveEvent_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "OnReceiveEvent_001 start.";
    auto testObject = std::make_shared<MockStaticSubscriberExtension>();
    EXPECT_TRUE(testObject != nullptr);
    EXPECT_FALSE(testObject->flag);
    std::shared_ptr<StaticSubscriberExtension> testExtension = testObject;

    std::shared_ptr<CommonEventData> data = nullptr;
    testObject->OnReceiveEvent(data);

    EXPECT_TRUE(testObject->flag);
    GTEST_LOG_(INFO) << "OnReceiveEvent_001 end.";
}
} // namespace EventFwk
} // namespace OHOS
