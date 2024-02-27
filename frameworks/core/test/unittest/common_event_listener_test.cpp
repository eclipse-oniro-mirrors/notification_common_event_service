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

#define private public
#include "common_event_listener.h"
#undef private
#include "common_event_subscriber.h"
#include "common_event_publish_info.h"
#include "common_event_subscribe_info.h"
#include "matching_skills.h"


#include <gtest/gtest.h>

using namespace testing::ext;
using namespace OHOS::EventFwk;

class CommonEventListenerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

class ListenerSubscriberTest : public CommonEventSubscriber {
public:
    explicit ListenerSubscriberTest(const CommonEventSubscribeInfo &sp) : CommonEventSubscriber(sp)
    {}

    ~ListenerSubscriberTest()
    {}

    virtual void OnReceiveEvent(const CommonEventData &data)
    {
    }
};

void CommonEventListenerTest::SetUpTestCase()
{}

void CommonEventListenerTest::TearDownTestCase()
{}

void CommonEventListenerTest::SetUp()
{}

void CommonEventListenerTest::TearDown()
{}

/*
 * tc.number: CommonEventListenerTest_001
 * tc.name: test Init
 * tc.type: FUNC
 * tc.desc: test init function and runner_ commonEventSubscriber is nullptr.
 */
HWTEST_F(CommonEventListenerTest, CommonEventListenerTest_001, TestSize.Level1)
{
    std::shared_ptr<CommonEventSubscriber> commonEventSubscriber = nullptr;
    CommonEventListener commonEventListener(commonEventSubscriber);
    commonEventListener.runner_ = nullptr;
    EXPECT_EQ(OHOS::ERR_INVALID_OPERATION, commonEventListener.Init());
}

/*
 * tc.number: CommonEventListenerTest_002
 * tc.name: test Init
 * tc.type: FUNC
 * tc.desc: test init function commonEventSubscriber is not nullptr.
 */
HWTEST_F(CommonEventListenerTest, CommonEventListenerTest_002, TestSize.Level1)
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent("EVENT");
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<ListenerSubscriberTest> subscriber = std::make_shared<ListenerSubscriberTest>(subscribeInfo);
    CommonEventListener commonEventListener(subscriber);
    EXPECT_EQ(OHOS::ERR_OK, commonEventListener.Init());
}

/*
 * tc.number: CommonEventListenerTest_004
 * tc.name: test Stop
 * tc.type: FUNC
 * tc.desc: test Stop function and handler_ is nullptr.
 */
HWTEST_F(CommonEventListenerTest, CommonEventListenerTest_004, TestSize.Level1)
{
    std::shared_ptr<CommonEventSubscriber> commonEventSubscriber = nullptr;
    std::shared_ptr<CommonEventListener> commonEventListener =
        std::make_shared<CommonEventListener>(commonEventSubscriber);
    ASSERT_NE(nullptr, commonEventListener);
    commonEventListener->handler_ = nullptr;
    commonEventListener->Stop();
}

/*
 * tc.number: CommonEventListenerTest_005
 * tc.name: test Stop
 * tc.type: FUNC
 * tc.desc: test Stop function and handler_ is not nullptr.
 */
HWTEST_F(CommonEventListenerTest, CommonEventListenerTest_005, TestSize.Level1)
{
    std::shared_ptr<CommonEventSubscriber> commonEventSubscriber = nullptr;
    std::shared_ptr<CommonEventListener> commonEventListener =
        std::make_shared<CommonEventListener>(commonEventSubscriber);
    ASSERT_NE(nullptr, commonEventListener);
    commonEventListener->runner_ =  OHOS::AppExecFwk::EventRunner::Create("CesFwkListener");
    commonEventListener->handler_ = std::make_shared< OHOS::AppExecFwk::EventHandler>(commonEventListener->runner_);
    commonEventListener->Stop();
    CommonEventData data;
    commonEventListener->NotifyEvent(data, true, true);
}