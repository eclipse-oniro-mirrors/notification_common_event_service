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

#include <memory>
#define private public
#include "common_event.h"
#include "common_event_data.h"
#include "common_event_death_recipient.h"
#include "common_event_stub.h"
#include "common_event_manager.h"
#include "common_event_subscriber.h"
#include "event_receive_proxy.h"
#include "common_event_publish_info.h"
#include "matching_skills.h"
#undef private
#include "ces_inner_error_code.h"
#include "mock_common_event_stub.h"
#include "want.h"

#include <gtest/gtest.h>

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AAFwk;
using namespace OHOS::EventFwk;

class DreivedSubscriber : public CommonEventSubscriber {
public:
    explicit DreivedSubscriber(const CommonEventSubscribeInfo &sp) : CommonEventSubscriber(sp)
    {}

    ~DreivedSubscriber()
    {}

    virtual void OnReceiveEvent(const CommonEventData &data)
    {}
};


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
 * tc.name: CreateCommonEventListener
 * tc.type: FUNC
 * tc.desc: test CreateCommonEventListener function and subscriber is nullptr.
 */
HWTEST_F(CommonEventTest, CommonEvent_001, TestSize.Level1)
{
    uint8_t subscribeFailed = 2;
    CommonEvent commonEvent;
    std::shared_ptr<CommonEventSubscriber> subscriber = nullptr;
    sptr<IRemoteObject> commonEventListener = nullptr;
    EXPECT_EQ(subscribeFailed, commonEvent.CreateCommonEventListener(subscriber, commonEventListener));
}

/*
 * tc.number: CommonEvent_002
 * tc.name: GetCommonEventProxy
 * tc.type: FUNC
 * tc.desc: test GetCommonEventProxy function and commonEventProxy_ is not nullptr.
 */
HWTEST_F(CommonEventTest, CommonEvent_002, TestSize.Level1)
{
    CommonEvent commonEvent;
    auto stubPtr = sptr<IRemoteObject>(new MockCommonEventStub());
    commonEvent.commonEventProxy_ = iface_cast<ICommonEvent>(stubPtr);
    commonEvent.isProxyValid_ = true;
    EXPECT_EQ(commonEvent.commonEventProxy_, commonEvent.GetCommonEventProxy());
}

/*
 * tc.number: CommonEvent_003
 * tc.name: GetCommonEventProxy
 * tc.type: FUNC
 * tc.desc: test GetCommonEventProxy function and commonEventProxy_ is nullptr.
 */
HWTEST_F(CommonEventTest, CommonEvent_003, TestSize.Level1)
{
    CommonEvent commonEvent;
    commonEvent.commonEventProxy_ = nullptr;
    commonEvent.isProxyValid_ = false;
    EXPECT_EQ(nullptr, commonEvent.GetCommonEventProxy());
}

/*
 * tc.number: CommonEvent_004
 * tc.name: GetCommonEventProxy
 * tc.type: FUNC
 * tc.desc: test GetCommonEventProxy function.
 */
HWTEST_F(CommonEventTest, CommonEvent_004, TestSize.Level1)
{
    CommonEvent commonEvent;
    auto stubPtr = sptr<IRemoteObject>(new MockCommonEventStub());
    commonEvent.commonEventProxy_ = iface_cast<ICommonEvent>(stubPtr);
    commonEvent.isProxyValid_ = false;
    EXPECT_EQ(nullptr, commonEvent.GetCommonEventProxy());
}

/*
 * tc.number: CommonEvent_005
 * tc.name: GetCommonEventProxy
 * tc.type: FUNC
 * tc.desc: test GetCommonEventProxy function.
 */
HWTEST_F(CommonEventTest, CommonEvent_005, TestSize.Level1)
{
    CommonEvent commonEvent;
    commonEvent.commonEventProxy_ = nullptr;
    commonEvent.isProxyValid_ = true;
    EXPECT_EQ(nullptr, commonEvent.GetCommonEventProxy());
}

/*
 * tc.number: CommonEvent_006
 * tc.name: UnfreezeAll
 * tc.type: FUNC
 * tc.desc: test UnfreezeAll function and GetCommonEventProxy is false.
 */
HWTEST_F(CommonEventTest, CommonEvent_006, TestSize.Level1)
{
    CommonEvent commonEvent;
    auto stubPtr = sptr<IRemoteObject>(new MockCommonEventStub());
    commonEvent.commonEventProxy_ = iface_cast<ICommonEvent>(stubPtr);
    commonEvent.isProxyValid_ = false;
    EXPECT_EQ(false, commonEvent.UnfreezeAll());
}

/*
 * tc.number: CommonEvent_007
 * tc.name: Unfreeze
 * tc.type: FUNC
 * tc.desc: test Unfreeze function and GetCommonEventProxy is false.
 */
HWTEST_F(CommonEventTest, CommonEvent_007, TestSize.Level1)
{
    CommonEvent commonEvent;
    commonEvent.commonEventProxy_ = nullptr;
    commonEvent.isProxyValid_ = true;
    uid_t uid = 1;
    EXPECT_EQ(false, commonEvent.Unfreeze(uid));
}

/*
 * tc.number: CommonEvent_008
 * tc.name: Freeze
 * tc.type: FUNC
 * tc.desc: test Unfreeze function and GetCommonEventProxy is false.
 */
HWTEST_F(CommonEventTest, CommonEvent_008, TestSize.Level1)
{
    CommonEvent commonEvent;
    commonEvent.commonEventProxy_ = nullptr;
    commonEvent.isProxyValid_ = true;
    uid_t uid = 1;
    EXPECT_EQ(false, commonEvent.Freeze(uid));
}

/*
 * tc.number: CommonEvent_009
 * tc.name: ResetCommonEventProxy
 * tc.type: FUNC
 * tc.desc: test ResetCommonEventProxy function.
 */
HWTEST_F(CommonEventTest, CommonEvent_009, TestSize.Level1)
{
    std::shared_ptr<CommonEvent> commonEvent = std::make_shared<CommonEvent>();
    ASSERT_NE(nullptr, commonEvent);
    auto stubPtr = sptr<IRemoteObject>(new MockCommonEventStub());
    commonEvent->commonEventProxy_ = iface_cast<ICommonEvent>(stubPtr);
    commonEvent->ResetCommonEventProxy();
}

/*
 * tc.number: CommonEvent_010
 * tc.name: DumpState
 * tc.type: FUNC
 * tc.desc: test DumpState function and GetCommonEventProxy is false.
 */
HWTEST_F(CommonEventTest, CommonEvent_010, TestSize.Level1)
{
    CommonEvent commonEvent;
    commonEvent.commonEventProxy_ = nullptr;
    commonEvent.isProxyValid_ = true;
    uint8_t dumpType = 1;
    std::string event = "aa";
    int32_t userId = 1;
    std::vector<std::string> state;
    EXPECT_EQ(false, commonEvent.DumpState(dumpType, event, userId, state));
}

/*
 * tc.number: CommonEvent_011
 * tc.name: FinishReceiver
 * tc.type: FUNC
 * tc.desc: test FinishReceiver function and GetCommonEventProxy is false.
 */
HWTEST_F(CommonEventTest, CommonEvent_011, TestSize.Level1)
{
    CommonEvent commonEvent;
    commonEvent.commonEventProxy_ = nullptr;
    commonEvent.isProxyValid_ = true;
    sptr<IRemoteObject> proxy = sptr<IRemoteObject>(new MockCommonEventStub());
    int32_t code = 1;
    std::string data = "aa";
    bool abortEvent = true;
    EXPECT_EQ(false, commonEvent.FinishReceiver(proxy, code, data, abortEvent));
}

/*
 * tc.number: CommonEvent_012
 * tc.name: GetStickyCommonEvent
 * tc.type: FUNC
 * tc.desc: test GetStickyCommonEvent function and GetCommonEventProxy is false.
 */
HWTEST_F(CommonEventTest, CommonEvent_012, TestSize.Level1)
{
    CommonEvent commonEvent;
    commonEvent.commonEventProxy_ = nullptr;
    commonEvent.isProxyValid_ = true;
    std::string event = "aa";
    CommonEventData eventData;
    EXPECT_EQ(false, commonEvent.GetStickyCommonEvent(event, eventData));
}

/*
 * tc.number: CommonEvent_013
 * tc.name: GetStickyCommonEvent
 * tc.type: FUNC
 * tc.desc: test GetStickyCommonEvent function and GetCommonEventProxy is true.
 */
HWTEST_F(CommonEventTest, CommonEvent_013, TestSize.Level1)
{
    CommonEvent commonEvent;
    auto stubPtr = sptr<IRemoteObject>(new MockCommonEventStub());
    commonEvent.commonEventProxy_ = iface_cast<ICommonEvent>(stubPtr);
    commonEvent.isProxyValid_ = true;
    std::string event = "";
    CommonEventData eventData;
    EXPECT_EQ(false, commonEvent.GetStickyCommonEvent(event, eventData));
}

/*
 * tc.number: PublishParameterCheck_001
 * tc.name: PublishParameterCheck
 * tc.type: FUNC
 * tc.desc: test PublishParameterCheck function.
 */
HWTEST_F(CommonEventTest, PublishParameterCheck_001, TestSize.Level1)
{
    CommonEvent commonEvent;
    CommonEventData data;
    CommonEventPublishInfo publishInfo;
    publishInfo.SetOrdered(false);
    MatchingSkills matchingSkills_;
    CommonEventSubscribeInfo subscribeInfo(matchingSkills_);
    std::shared_ptr<DreivedSubscriber> subscriber = std::make_shared<DreivedSubscriber>(subscribeInfo);
    sptr<IRemoteObject> commonEventListener = nullptr;
    EXPECT_EQ(false, commonEvent.PublishParameterCheck(data, publishInfo, subscriber, commonEventListener));
}

/*
 * tc.number: PublishParameterCheck_002
 * tc.name: PublishParameterCheck
 * tc.type: FUNC
 * tc.desc: test PublishParameterCheck function.
 */
HWTEST_F(CommonEventTest, PublishParameterCheck_002, TestSize.Level1)
{
    CommonEvent commonEvent;
    CommonEventData data;
    CommonEventPublishInfo publishInfo;
    publishInfo.SetOrdered(true);
    std::shared_ptr<CommonEventSubscriber> subscriber = nullptr;
    sptr<IRemoteObject> commonEventListener = nullptr;
    EXPECT_EQ(true, commonEvent.PublishParameterCheck(data, publishInfo, subscriber, commonEventListener));
}

/*
 * tc.number: CommonEvent_016
 * tc.name: PublishCommonEventAsUser
 * tc.type: FUNC
 * tc.desc: test PublishCommonEventAsUser function.
 */
HWTEST_F(CommonEventTest, CommonEvent_016, TestSize.Level1)
{
    CommonEvent commonEvent;
    auto stubPtr = sptr<IRemoteObject>(new MockCommonEventStub());
    commonEvent.commonEventProxy_ = iface_cast<ICommonEvent>(stubPtr);
    commonEvent.isProxyValid_ = true;
    CommonEventData data;
    CommonEventPublishInfo publishInfo;
    publishInfo.SetOrdered(true);
    std::shared_ptr<CommonEventSubscriber> subscriber = nullptr;
    uid_t uid = 1;
    int32_t userId = 1;
    int32_t callToken = 0;
    EXPECT_EQ(true, commonEvent.PublishCommonEventAsUser(data, publishInfo, subscriber, uid, callToken, userId));
}

/*
 * tc.number: CommonEvent_017
 * tc.name: PublishCommonEvent
 * tc.type: FUNC
 * tc.desc: test PublishCommonEvent function.
 */
HWTEST_F(CommonEventTest, CommonEvent_017, TestSize.Level1)
{
    CommonEvent commonEvent;
    CommonEventData data;
    CommonEventPublishInfo publishInfo;
    publishInfo.SetOrdered(true);
    std::shared_ptr<CommonEventSubscriber> subscriber = nullptr;
    EXPECT_EQ(false, commonEvent.PublishCommonEvent(data, publishInfo, subscriber));
}

/*
 * tc.number: SetStaticSubscriberState_001
 * tc.name: SetStaticSubscriberState
 * tc.type: FUNC
 * tc.desc: test SetStaticSubscriberState function.
 */
HWTEST_F(CommonEventTest, SetStaticSubscriberState_001, TestSize.Level1)
{
    CommonEvent commonEvent;
    EXPECT_EQ(
        OHOS::Notification::ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, commonEvent.SetStaticSubscriberState(true));
}