/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <iostream>
#include <string>
#include <thread>

#include "common_event_manager.h"
#include "ces_inner_error_code.h"
#include "common_event_subscriber.h"
#include "datetime_ex.h"
#include "event_log_wrapper.h"

#include <gtest/gtest.h>

using namespace testing::ext;

namespace OHOS {
namespace EventFwk {

class CommonEventServicesSystemTest : public CommonEventSubscriber {
public:
    explicit CommonEventServicesSystemTest(const CommonEventSubscribeInfo &subscribeInfo);
    virtual ~CommonEventServicesSystemTest() {};
    virtual void OnReceiveEvent(const CommonEventData &data);
};

CommonEventServicesSystemTest::CommonEventServicesSystemTest(const CommonEventSubscribeInfo &subscribeInfo)
    : CommonEventSubscriber(subscribeInfo)
{}

void CommonEventServicesSystemTest::OnReceiveEvent(const CommonEventData &data)
{
    GTEST_LOG_(INFO) << " ActsCesSpecificationTest:CommonEventServicesSystemTest:OnReceiveEvent \n";
}

class ActsCesSpecificationTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
void ActsCesSpecificationTest::SetUpTestCase()
{}

void ActsCesSpecificationTest::TearDownTestCase()
{}

void ActsCesSpecificationTest::SetUp()
{}

void ActsCesSpecificationTest::TearDown()
{}

/*
 * @tc.number: SubscribeCommonEventExceedLimit_0100
 * @tc.name: verify subscribe exceed limit
 * @tc.desc: Failed to call SubscribeCommonEvent API due to the count of subscriber exceed limit
 */
HWTEST_F(ActsCesSpecificationTest, SubscribeCommonEventExceedLimit_0100, TestSize.Level0)
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent("test");
    for (int i = 0; i < 200; i++) {
        CommonEventSubscribeInfo subscribeInfo(matchingSkills);
        auto subscriberPtr = std::make_shared<CommonEventServicesSystemTest>(subscribeInfo);
        EXPECT_EQ(CommonEventManager::NewSubscribeCommonEvent(subscriberPtr), ERR_OK);
    }
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    auto subscriberPtr = std::make_shared<CommonEventServicesSystemTest>(subscribeInfo);
    EXPECT_EQ(CommonEventManager::NewSubscribeCommonEvent(subscriberPtr),
        Notification::ERR_NOTIFICATION_CES_SUBSCRIBE_EXCEED_LIMIT);
}

/*
 * @tc.number: PublishCommonEventExceedLimit_0100
 * @tc.name: verify publish exceed limit
 * @tc.desc: Failed to call publish common event API due to publish sequency is too high
 */
HWTEST_F(ActsCesSpecificationTest, PublishCommonEventExceedLimit_0100, TestSize.Level0)
{
    Want wantTest;
    wantTest.SetAction("eventAction");
    CommonEventData commonEventData(wantTest);
    CommonEventPublishInfo info;
    for (int i = 0; i < 20; i++) {
        EXPECT_EQ(CommonEventManager::NewPublishCommonEvent(commonEventData, info), ERR_OK);
    }
    EXPECT_EQ(CommonEventManager::NewPublishCommonEvent(commonEventData, info),
        Notification::ERR_NOTIFICATION_CES_EVENT_FREQ_TOO_HIGH);
}
}  // namespace EventFwk
}  // namespace OHOS