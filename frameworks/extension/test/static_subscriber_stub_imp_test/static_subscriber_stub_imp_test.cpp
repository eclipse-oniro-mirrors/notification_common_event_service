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
#include "static_subscriber_stub_impl.h"
#include "js_runtime.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace testing;
using namespace std::chrono;

namespace OHOS {
namespace EventFwk {
class StaticSubscriberStubImplTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void StaticSubscriberStubImplTest::SetUpTestCase(void)
{}

void StaticSubscriberStubImplTest::TearDownTestCase(void)
{}

void StaticSubscriberStubImplTest::SetUp(void)
{}

void StaticSubscriberStubImplTest::TearDown(void)
{}

/**
 * @tc.number: StaticSubscriberStubImpl_OnReceiveEvent_001
 * @tc.name: OnReceiveEvent
 * @tc.desc: The extension is not a null ptr value. The test program executes as expected and does not exit abnormally
 */
HWTEST_F(StaticSubscriberStubImplTest, StaticSubscriberStubImpl_OnReceiveEvent_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "StaticSubscriberStubImpl_OnReceiveEvent_001 start.";
    AbilityRuntime::Runtime::Options options;
    std::unique_ptr<AbilityRuntime::Runtime> runtime = AbilityRuntime::Runtime::Create(options);

    std::shared_ptr<JsStaticSubscriberExtension> extension = std::make_shared<JsStaticSubscriberExtension>(
        static_cast<AbilityRuntime::JsRuntime&>(*runtime));
    sptr<StaticSubscriberStubImpl> object = new (std::nothrow) StaticSubscriberStubImpl(extension);
    EXPECT_TRUE(object != nullptr);
    CommonEventData* data = nullptr;
    EXPECT_EQ(object->OnReceiveEvent(data), 0);
    GTEST_LOG_(INFO) << "StaticSubscriberStubImpl_OnReceiveEvent_001 end.";
}

/**
 * @tc.number: StaticSubscriberStubImpl_OnReceiveEvent_002
 * @tc.name: OnReceiveEvent
 * @tc.desc: The extension is a null ptr value. The test program executes as expected and does not exit abnormally
 */
HWTEST_F(StaticSubscriberStubImplTest, StaticSubscriberStubImpl_OnReceiveEvent_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "StaticSubscriberStubImpl_OnReceiveEvent_002 start.";
    const std::shared_ptr<JsStaticSubscriberExtension> extension;
    sptr<StaticSubscriberStubImpl> object = new (std::nothrow) StaticSubscriberStubImpl(extension);
    EXPECT_TRUE(object != nullptr);
    CommonEventData* data = nullptr;
    EXPECT_EQ(object->OnReceiveEvent(data), -1);
    GTEST_LOG_(INFO) << "StaticSubscriberStubImpl_OnReceiveEvent_002 end.";
}
} // namespace EventFwk
} // namespace OHOS
