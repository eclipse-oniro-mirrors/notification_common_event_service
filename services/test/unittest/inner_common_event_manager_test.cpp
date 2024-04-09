/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "common_event.h"
#include "common_event_manager.h"
#include "common_event_stub.h"
#include "common_event_subscriber_manager.h"
#include "inner_common_event_manager.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EventFwk;
using namespace OHOS::AppExecFwk;

class InnerCommonEventManagerTest : public testing::Test {
public:
    InnerCommonEventManagerTest()
    {}
    ~InnerCommonEventManagerTest()
    {}

    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

class DreivedSubscriber : public CommonEventSubscriber {
public:
    explicit DreivedSubscriber(const CommonEventSubscribeInfo &sp) : CommonEventSubscriber(sp)
    {}

    ~DreivedSubscriber()
    {}

    virtual void OnReceiveEvent(const CommonEventData &data)
    {}
};

void InnerCommonEventManagerTest::SetUpTestCase(void)
{}

void InnerCommonEventManagerTest::TearDownTestCase(void)
{}

void InnerCommonEventManagerTest::SetUp(void)
{}

void InnerCommonEventManagerTest::TearDown(void)
{}

/**
 * @tc.name: InnerCommonEventManager_0100
 * @tc.desc: test UnsubscribeCommonEvent function and commonEventListener is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(InnerCommonEventManagerTest, InnerCommonEventManager_0100, Level1)
{
    GTEST_LOG_(INFO) << "InnerCommonEventManager_0100 start";
    InnerCommonEventManager innerCommonEventManager;
    sptr<IRemoteObject> commonEventListener = nullptr;
    EXPECT_EQ(false, innerCommonEventManager.UnsubscribeCommonEvent(commonEventListener));
    GTEST_LOG_(INFO) << "InnerCommonEventManager_0100 end";
}

/**
 * @tc.name: InnerCommonEventManager_0200
 * @tc.desc: test UnsubscribeCommonEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(InnerCommonEventManagerTest, InnerCommonEventManager_0200, Level1)
{
    GTEST_LOG_(INFO) << "InnerCommonEventManager_0200 start";
    InnerCommonEventManager innerCommonEventManager;
    // set commonEventListener
    MatchingSkills matchingSkills_;
    CommonEventSubscribeInfo subscribeInfo(matchingSkills_);
    std::shared_ptr<DreivedSubscriber> subscriber = std::make_shared<DreivedSubscriber>(subscribeInfo);
    sptr<IRemoteObject> commonEventListener = new CommonEventListener(subscriber);
    // set controlPtr_ is nullptr
    innerCommonEventManager.controlPtr_ = nullptr;
    EXPECT_EQ(false, innerCommonEventManager.UnsubscribeCommonEvent(commonEventListener));
    GTEST_LOG_(INFO) << "InnerCommonEventManager_0200 end";
}

/**
 * @tc.name: InnerCommonEventManager_0300
 * @tc.desc: test DumpState function.
 * @tc.type: FUNC
 */
HWTEST_F(InnerCommonEventManagerTest, InnerCommonEventManager_0300, Level1)
{
    GTEST_LOG_(INFO) << "InnerCommonEventManager_0300 start";
    std::shared_ptr<InnerCommonEventManager> innerCommonEventManager = std::make_shared<InnerCommonEventManager>();
    ASSERT_NE(nullptr, innerCommonEventManager);
    uint8_t dumpType = DumpEventType::PENDING;
    std::string event = "";
    int32_t userId = 1;
    std::vector<std::string> state;
    // set controlPtr_ is nullptr
    innerCommonEventManager->controlPtr_ = nullptr;
    innerCommonEventManager->DumpState(dumpType, event, userId, state);
    GTEST_LOG_(INFO) << "InnerCommonEventManager_0300 end";
}

/**
 * @tc.name: InnerCommonEventManager_0400
 * @tc.desc: test DumpState function and controlPtr_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(InnerCommonEventManagerTest, InnerCommonEventManager_0400, Level1)
{
    GTEST_LOG_(INFO) << "InnerCommonEventManager_0400 start";
    std::shared_ptr<InnerCommonEventManager> innerCommonEventManager = std::make_shared<InnerCommonEventManager>();
    ASSERT_NE(nullptr, innerCommonEventManager);
    uint8_t dumpType = DumpEventType::PENDING;
    std::string event = "";
    int32_t userId = 1;
    std::vector<std::string> state;
    innerCommonEventManager->DumpState(dumpType, event, userId, state);
    GTEST_LOG_(INFO) << "InnerCommonEventManager_0400 end";
}

/**
 * @tc.name: InnerCommonEventManager_0500
 * @tc.desc: test DumpState function and controlPtr_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(InnerCommonEventManagerTest, InnerCommonEventManager_0500, Level1)
{
    GTEST_LOG_(INFO) << "InnerCommonEventManager_0500 start";
    std::shared_ptr<InnerCommonEventManager> innerCommonEventManager = std::make_shared<InnerCommonEventManager>();
    ASSERT_NE(nullptr, innerCommonEventManager);
    uint8_t dumpType = DumpEventType::HISTORY;
    std::string event = "";
    int32_t userId = 1;
    std::vector<std::string> state;
    innerCommonEventManager->DumpState(dumpType, event, userId, state);
    GTEST_LOG_(INFO) << "InnerCommonEventManager_0500 end";
}

/**
 * @tc.name: InnerCommonEventManager_0600
 * @tc.desc: test DumpState function.
 * @tc.type: FUNC
 */
HWTEST_F(InnerCommonEventManagerTest, InnerCommonEventManager_0600, Level1)
{
    GTEST_LOG_(INFO) << "InnerCommonEventManager_0600 start";
    std::shared_ptr<InnerCommonEventManager> innerCommonEventManager = std::make_shared<InnerCommonEventManager>();
    ASSERT_NE(nullptr, innerCommonEventManager);
    uint8_t dumpType = DumpEventType::HISTORY;
    std::string event = "";
    int32_t userId = 1;
    std::vector<std::string> state;
    // set controlPtr_ is nullptr
    innerCommonEventManager->controlPtr_ = nullptr;
    innerCommonEventManager->DumpState(dumpType, event, userId, state);
    GTEST_LOG_(INFO) << "InnerCommonEventManager_0600 end";
}

/**
 * @tc.name: InnerCommonEventManager_0700
 * @tc.desc: test DumpState function and dumpType is default.
 * @tc.type: FUNC
 */
HWTEST_F(InnerCommonEventManagerTest, InnerCommonEventManager_0700, Level1)
{
    GTEST_LOG_(INFO) << "InnerCommonEventManager_0700 start";
    std::shared_ptr<InnerCommonEventManager> innerCommonEventManager = std::make_shared<InnerCommonEventManager>();
    ASSERT_NE(nullptr, innerCommonEventManager);
    uint8_t dumpType = 100;
    std::string event = "";
    int32_t userId = 1;
    std::vector<std::string> state;
    // set controlPtr_ is nullptr
    innerCommonEventManager->controlPtr_ = nullptr;
    innerCommonEventManager->DumpState(dumpType, event, userId, state);
    GTEST_LOG_(INFO) << "InnerCommonEventManager_0700 end";
}

/**
 * @tc.name: InnerCommonEventManager_0800
 * @tc.desc: test DumpState function and dumpType is default controlPtr_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(InnerCommonEventManagerTest, InnerCommonEventManager_0800, Level1)
{
    GTEST_LOG_(INFO) << "InnerCommonEventManager_0800 start";
    std::shared_ptr<InnerCommonEventManager> innerCommonEventManager = std::make_shared<InnerCommonEventManager>();
    ASSERT_NE(nullptr, innerCommonEventManager);
    uint8_t dumpType = 100;
    std::string event = "";
    int32_t userId = 1;
    std::vector<std::string> state;
    innerCommonEventManager->DumpState(dumpType, event, userId, state);
    GTEST_LOG_(INFO) << "InnerCommonEventManager_0800 end";
}

/**
 * @tc.name: InnerCommonEventManager_0900
 * @tc.desc: test FinishReceiver function.
 * @tc.type: FUNC
 */
HWTEST_F(InnerCommonEventManagerTest, InnerCommonEventManager_0900, Level1)
{
    GTEST_LOG_(INFO) << "InnerCommonEventManager_0900 start";
    std::shared_ptr<InnerCommonEventManager> innerCommonEventManager = std::make_shared<InnerCommonEventManager>();
    ASSERT_NE(nullptr, innerCommonEventManager);
    sptr<IRemoteObject> proxy = nullptr;
    int32_t code = 1;
    std::string receiverData = "";
    bool abortEvent = true;
    // set controlPtr_ is nullptr
    innerCommonEventManager->controlPtr_ = nullptr;
    innerCommonEventManager->FinishReceiver(proxy, code, receiverData, abortEvent);
    GTEST_LOG_(INFO) << "InnerCommonEventManager_0900 end";
}

/**
 * @tc.name: InnerCommonEventManager_1000
 * @tc.desc: test Unfreeze function.
 * @tc.type: FUNC
 */
HWTEST_F(InnerCommonEventManagerTest, InnerCommonEventManager_1000, Level1)
{
    GTEST_LOG_(INFO) << "InnerCommonEventManager_1000 start";
    std::shared_ptr<InnerCommonEventManager> innerCommonEventManager = std::make_shared<InnerCommonEventManager>();
    ASSERT_NE(nullptr, innerCommonEventManager);
    uid_t uid = 1;
    // set controlPtr_ is nullptr
    innerCommonEventManager->controlPtr_ = nullptr;
    innerCommonEventManager->Unfreeze(uid);
    GTEST_LOG_(INFO) << "InnerCommonEventManager_1000 end";
}

/**
 * @tc.name: InnerCommonEventManager_1100
 * @tc.desc: test UnfreezeAll function.
 * @tc.type: FUNC
 */
HWTEST_F(InnerCommonEventManagerTest, InnerCommonEventManager_1100, Level1)
{
    GTEST_LOG_(INFO) << "InnerCommonEventManager_1100 start";
    std::shared_ptr<InnerCommonEventManager> innerCommonEventManager = std::make_shared<InnerCommonEventManager>();
    ASSERT_NE(nullptr, innerCommonEventManager);
    // set controlPtr_ is nullptr
    innerCommonEventManager->controlPtr_ = nullptr;
    innerCommonEventManager->UnfreezeAll();
    GTEST_LOG_(INFO) << "InnerCommonEventManager_1100 end";
}

/**
 * @tc.name: InnerCommonEventManager_1200
 * @tc.desc: test PublishStickyEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(InnerCommonEventManagerTest, InnerCommonEventManager_1200, Level1)
{
    GTEST_LOG_(INFO) << "InnerCommonEventManager_1200 start";
    InnerCommonEventManager innerCommonEventManager;
    std::shared_ptr<CommonEventSubscribeInfo> sp = nullptr;
    std::shared_ptr<EventSubscriberRecord> subscriberRecord = nullptr;
    EXPECT_EQ(false, innerCommonEventManager.PublishStickyEvent(sp, subscriberRecord));
    GTEST_LOG_(INFO) << "InnerCommonEventManager_1200 end";
}

/**
 * @tc.name: InnerCommonEventManager_1300
 * @tc.desc: test PublishStickyEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(InnerCommonEventManagerTest, InnerCommonEventManager_1300, Level1)
{
    GTEST_LOG_(INFO) << "InnerCommonEventManager_1300 start";
    InnerCommonEventManager innerCommonEventManager;
    MatchingSkills matchingSkills_;
    std::shared_ptr<CommonEventSubscribeInfo> sp = std::make_shared<CommonEventSubscribeInfo>(matchingSkills_);
    std::shared_ptr<EventSubscriberRecord> subscriberRecord = nullptr;
    EXPECT_EQ(false, innerCommonEventManager.PublishStickyEvent(sp, subscriberRecord));
    GTEST_LOG_(INFO) << "InnerCommonEventManager_1300 end";
}

/**
 * @tc.name: InnerCommonEventManager_1400
 * @tc.desc: test HiDump function.
 * @tc.type: FUNC
 */
HWTEST_F(InnerCommonEventManagerTest, InnerCommonEventManager_1400, Level1)
{
    GTEST_LOG_(INFO) << "InnerCommonEventManager_1400 start";
    std::shared_ptr<InnerCommonEventManager> innerCommonEventManager = std::make_shared<InnerCommonEventManager>();
    ASSERT_NE(nullptr, innerCommonEventManager);
    std::vector<std::u16string> args;
    std::string result = "";
    innerCommonEventManager->HiDump(args, result);
    GTEST_LOG_(INFO) << "InnerCommonEventManager_1400 end";
}

/**
 * @tc.name: InnerCommonEventManager_1500
 * @tc.desc: test HiDump function.
 * @tc.type: FUNC
 */
HWTEST_F(InnerCommonEventManagerTest, InnerCommonEventManager_1500, Level1)
{
    GTEST_LOG_(INFO) << "InnerCommonEventManager_1500 start";
    std::shared_ptr<InnerCommonEventManager> innerCommonEventManager = std::make_shared<InnerCommonEventManager>();
    ASSERT_NE(nullptr, innerCommonEventManager);
    std::u16string aa = u"aa";
    std::u16string bb = u"bb";
    std::u16string cc = u"cc";
    std::vector<std::u16string> args;
    args.emplace_back(aa);
    args.emplace_back(bb);
    args.emplace_back(cc);
    std::string result = "";
    innerCommonEventManager->HiDump(args, result);
    GTEST_LOG_(INFO) << "InnerCommonEventManager_1500 end";
}

/**
 * @tc.name: InnerCommonEventManager_1600
 * @tc.desc: test HiDump function.
 * @tc.type: FUNC
 */
HWTEST_F(InnerCommonEventManagerTest, InnerCommonEventManager_1600, Level1)
{
    GTEST_LOG_(INFO) << "InnerCommonEventManager_1600 start";
    std::shared_ptr<InnerCommonEventManager> innerCommonEventManager = std::make_shared<InnerCommonEventManager>();
    ASSERT_NE(nullptr, innerCommonEventManager);
    std::u16string aa = u"aa";
    std::vector<std::u16string> args;
    args.emplace_back(aa);
    std::string result = "";
    innerCommonEventManager->HiDump(args, result);
    GTEST_LOG_(INFO) << "InnerCommonEventManager_1600 end";
}

/**
 * @tc.name: InnerCommonEventManager_1700
 * @tc.desc: test HiDump function.
 * @tc.type: FUNC
 */
HWTEST_F(InnerCommonEventManagerTest, InnerCommonEventManager_1700, Level1)
{
    GTEST_LOG_(INFO) << "InnerCommonEventManager_1700 start";
    std::shared_ptr<InnerCommonEventManager> innerCommonEventManager = std::make_shared<InnerCommonEventManager>();
    ASSERT_NE(nullptr, innerCommonEventManager);
    std::u16string aa = u"-h";
    std::vector<std::u16string> args;
    args.emplace_back(aa);
    std::string result = "";
    innerCommonEventManager->HiDump(args, result);
    GTEST_LOG_(INFO) << "InnerCommonEventManager_1700 end";
}

/**
 * @tc.name: InnerCommonEventManager_1800
 * @tc.desc: test HiDump function.
 * @tc.type: FUNC
 */
HWTEST_F(InnerCommonEventManagerTest, InnerCommonEventManager_1800, Level1)
{
    GTEST_LOG_(INFO) << "InnerCommonEventManager_1800 start";
    std::shared_ptr<InnerCommonEventManager> innerCommonEventManager = std::make_shared<InnerCommonEventManager>();
    ASSERT_NE(nullptr, innerCommonEventManager);
    std::u16string aa = u"-h";
    std::u16string bb = u"-a";
    std::vector<std::u16string> args;
    args.emplace_back(aa);
    args.emplace_back(bb);
    std::string result = "";
    innerCommonEventManager->HiDump(args, result);
    GTEST_LOG_(INFO) << "InnerCommonEventManager_1800 end";
}

/**
 * @tc.name: InnerCommonEventManager_1900
 * @tc.desc: test HiDump function.
 * @tc.type: FUNC
 */
HWTEST_F(InnerCommonEventManagerTest, InnerCommonEventManager_1900, Level1)
{
    GTEST_LOG_(INFO) << "InnerCommonEventManager_1900 start";
    std::shared_ptr<InnerCommonEventManager> innerCommonEventManager = std::make_shared<InnerCommonEventManager>();
    ASSERT_NE(nullptr, innerCommonEventManager);
    std::u16string aa = u"-a";
    std::vector<std::u16string> args;
    args.emplace_back(aa);
    std::string result = "";
    innerCommonEventManager->HiDump(args, result);
    GTEST_LOG_(INFO) << "InnerCommonEventManager_1900 end";
}

/**
 * @tc.name: InnerCommonEventManager_2000
 * @tc.desc: test HiDump function.
 * @tc.type: FUNC
 */
HWTEST_F(InnerCommonEventManagerTest, InnerCommonEventManager_2000, Level1)
{
    GTEST_LOG_(INFO) << "InnerCommonEventManager_2000 start";
    std::shared_ptr<InnerCommonEventManager> innerCommonEventManager = std::make_shared<InnerCommonEventManager>();
    ASSERT_NE(nullptr, innerCommonEventManager);
    std::u16string aa = u"-e";
    std::vector<std::u16string> args;
    args.emplace_back(aa);
    std::string result = "";
    innerCommonEventManager->HiDump(args, result);
    GTEST_LOG_(INFO) << "InnerCommonEventManager_2000 end";
}

/**
 * @tc.name: InnerCommonEventManager_2100
 * @tc.desc: test HiDump function.
 * @tc.type: FUNC
 */
HWTEST_F(InnerCommonEventManagerTest, InnerCommonEventManager_2100, Level1)
{
    GTEST_LOG_(INFO) << "InnerCommonEventManager_2100 start";
    std::shared_ptr<InnerCommonEventManager> innerCommonEventManager = std::make_shared<InnerCommonEventManager>();
    ASSERT_NE(nullptr, innerCommonEventManager);
    std::u16string aa = u"-e";
    std::u16string bb = u"-a";
    std::vector<std::u16string> args;
    args.emplace_back(aa);
    args.emplace_back(bb);
    std::string result = "";
    innerCommonEventManager->HiDump(args, result);
    GTEST_LOG_(INFO) << "InnerCommonEventManager_2100 end";
}

/**
 * @tc.name: SetStaticSubscriberStateWithTwoParameters_0100
 * @tc.desc: Failed to call SetStaticSubscriberState API to obtain commonEventproxy.
 * @tc.type: FUNC
 */
HWTEST_F(InnerCommonEventManagerTest, SetStaticSubscriberStateWithTwoParameters_0100, Level1)
{
    auto innerCommonEventManager = std::make_shared<InnerCommonEventManager>();
    ASSERT_NE(nullptr, innerCommonEventManager);
    innerCommonEventManager->staticSubscriberManager_ = nullptr;
    std::vector<std::string> events;
    events.push_back("StaticCommonEventA");
    const int32_t ERR_NOTIFICATION_CESM_ERROR = 1500008;
    int32_t result = innerCommonEventManager->SetStaticSubscriberState(events, true);
    EXPECT_EQ(result, ERR_NOTIFICATION_CESM_ERROR);
}
