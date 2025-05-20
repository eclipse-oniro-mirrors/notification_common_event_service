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

#define private public
#define protected public
#include "static_subscriber_connection.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EventFwk;
using namespace OHOS::AppExecFwk;

extern bool IsOnReceiveEventCalled();
extern void ResetStaticSubscriberProxyMockState();

class StaticSubscriberConnectionUnitTest : public testing::Test {
public:
    StaticSubscriberConnectionUnitTest() {}

    virtual ~StaticSubscriberConnectionUnitTest() {}

    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};

void StaticSubscriberConnectionUnitTest::SetUpTestCase() {}

void StaticSubscriberConnectionUnitTest::TearDownTestCase() {}

void StaticSubscriberConnectionUnitTest::SetUp() {}

void StaticSubscriberConnectionUnitTest::TearDown() {}

/*
 * @tc.name: OnAbilityConnectDoneTest_0100
 * @tc.desc: test if StaticSubscriberConnection's OnAbilityConnectDone function executed as expected in normal case.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 * 
 */
HWTEST_F(StaticSubscriberConnectionUnitTest, OnAbilityConnectDoneTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberConnectionUnitTest, OnAbilityConnectDoneTest_0100, TestSize.Level1";
    CommonEventData data;
    sptr<StaticSubscriberConnection> conn = new (std::nothrow) StaticSubscriberConnection(data);
    ASSERT_NE(nullptr, conn);
    ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = 0;
    conn->OnAbilityConnectDone(element, remoteObject, resultCode);
    sleep(1);
    conn->OnAbilityDisconnectDone(element, resultCode);
    EXPECT_TRUE(IsOnReceiveEventCalled());
    ResetStaticSubscriberProxyMockState();
}

/*
 * @tc.name: NotifyEvent_0100
 * @tc.desc: Test that NotifyEvent can correctly cache event and action.
 * @tc.type: FUNC
 * @tc.require:
 *
 */
HWTEST_F(StaticSubscriberConnectionUnitTest, NotifyEvent_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "NotifyEvent_0100 start!";
    CommonEventData data;
    StaticSubscriberConnection connection(data);
    connection.NotifyEvent(data);
    EXPECT_EQ(connection.events_.size(), 2);
    GTEST_LOG_(INFO) << "NotifyEvent_0100 end!";
}

/*
 * @tc.name: RemoveEvent_0100
 * @tc.desc: Test that RemoveEvent can correctly remove the specified action from action_.
 * @tc.type: FUNC
 * @tc.require:
 *
 */
HWTEST_F(StaticSubscriberConnectionUnitTest, RemoveEvent_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "RemoveEvent_0100 start!";
    CommonEventData data;
    StaticSubscriberConnection connection(data);
    connection.NotifyEvent(data);
    connection.RemoveEvent(data.GetWant().GetAction());
    EXPECT_TRUE(connection.action_.empty());
    GTEST_LOG_(INFO) << "RemoveEvent_0100 end!";
}

/*
 * @tc.name: RemoveEvent_0200
 * @tc.desc: Test that RemoveEvent removes only the first occurrence of the specified action in action_.
 * @tc.type: FUNC
 * @tc.require:
 *
 */
HWTEST_F(StaticSubscriberConnectionUnitTest, RemoveEvent_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "RemoveEvent_0200 start!";
    CommonEventData data;
    StaticSubscriberConnection connection(data);

    std::string action = data.GetWant().GetAction();
    connection.action_.push_back(action);
    connection.action_.push_back(action);
    connection.action_.push_back(action);
    connection.RemoveEvent(action);
    int count = 0;
    for (const auto& act : connection.action_) {
        if (act == action) {
            ++count;
        }
    }
    EXPECT_EQ(count, 2);
    EXPECT_EQ(connection.action_.size(), 2);
    GTEST_LOG_(INFO) << "RemoveEvent_0200 end!";
}

/*
 * @tc.name: IsEmptyAction_0100
 * @tc.desc: Test that IsEmptyAction returns true when events_ is empty and false when not empty.
 * @tc.type: FUNC
 * @tc.require:
 *
 */
HWTEST_F(StaticSubscriberConnectionUnitTest, IsEmptyAction_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "IsEmptyAction_0100 start!";
    CommonEventData data;
    StaticSubscriberConnection connection(data);
    connection.action_.clear();
    EXPECT_TRUE(connection.IsEmptyAction());

    connection.action_.push_back(data.GetWant().GetAction());
    EXPECT_FALSE(connection.IsEmptyAction());

    GTEST_LOG_(INFO) << "IsEmptyAction_0100 end!";
}