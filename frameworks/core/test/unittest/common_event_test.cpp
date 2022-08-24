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

#include "common_event.h"

#include <gtest/gtest.h>

using namespace testing::ext;
using namespace OHOS::EventFwk;

namespace {
    const std::string EVENT = "com.ces.test.event";
    const std::string PERMISSION = "com.ces.test.permission";
    constexpr uint16_t SYSTEM_UID = 1000;
}

class CommonEventTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CommonEventTest::SetUpTestCase()
{}

void CommonEventTest::TearDownTestCase()
{}

void CommonEventTest::SetUp()
{}

void CommonEventTest::TearDown()
{}

/*
 * tc.number: CommonEvent_001
 * tc.name: test PublishCommonEvent
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke PublishCommonEvent interface verify whether it is normal
 */
HWTEST_F(CommonEventTest, CommonEvent_001, TestSize.Level1)
{
    // make a want
    Want want;
    want.SetAction(EVENT);
    // make common event data
    CommonEventData data;
    data.SetWant(want);

    // make publish info
    CommonEventPublishInfo publishInfo;
    publishInfo.SetSticky(true);

    std::vector<std::string> permissions;
    permissions.emplace_back(PERMISSION);
    publishInfo.SetSubscriberPermissions(permissions);

    std::shared_ptr<CommonEventSubscriber> subscriber = nullptr;
    
    CommonEvent commonEvent;
    bool publishCommonEvent = commonEvent.PublishCommonEvent(data, publishInfo, subscriber);
    EXPECT_EQ(true, publishCommonEvent);
}

/*
 * tc.number: CommonEvent_002
 * tc.name: test PublishCommonEvent
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke PublishCommonEvent interface verify whether it is normal
 */
HWTEST_F(CommonEventTest, CommonEvent_002, TestSize.Level1)
{
    // make a want
    Want want;
    want.SetAction(EVENT);
    // make common event data
    CommonEventData data;
    data.SetWant(want);

    // make publish info
    CommonEventPublishInfo publishInfo;
    publishInfo.SetSticky(true);

    std::vector<std::string> permissions;
    permissions.emplace_back(PERMISSION);
    publishInfo.SetSubscriberPermissions(permissions);

    std::shared_ptr<CommonEventSubscriber> subscriber = nullptr;
    
    CommonEvent commonEvent;
    bool publishCommonEvent = commonEvent.PublishCommonEvent(data, publishInfo, subscriber, SYSTEM_UID);
    EXPECT_EQ(true, publishCommonEvent);
}

/*
 * tc.number: CommonEvent_003
 * tc.name: test Freeze
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke Freeze interface verify whether it is normal
 */
HWTEST_F(CommonEventTest, CommonEvent_003, TestSize.Level1)
{
    CommonEvent commonEvent;
    bool freeze = commonEvent.Freeze(SYSTEM_UID);
    EXPECT_EQ(true, freeze);
}

/*
 * tc.number: CommonEvent_004
 * tc.name: test Unfreeze
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke Unfreeze interface verify whether it is normal
 */
HWTEST_F(CommonEventTest, CommonEvent_004, TestSize.Level1)
{
    CommonEvent commonEvent;
    bool unfreeze = commonEvent.Unfreeze(SYSTEM_UID);
    EXPECT_EQ(true, unfreeze);
}

/*
 * tc.number: CommonEvent_005
 * tc.name: test Unfreeze
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke Unfreeze interface verify whether it is normal
 */
HWTEST_F(CommonEventTest, CommonEvent_005, TestSize.Level1)
{
    CommonEvent commonEvent;
    bool unfreezeAll = commonEvent.UnfreezeAll();
    EXPECT_EQ(true, unfreezeAll);
}