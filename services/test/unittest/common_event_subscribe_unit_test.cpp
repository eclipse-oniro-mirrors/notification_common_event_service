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

#include <gtest/gtest.h>

#define private public
#define protected public
#include "bundle_manager_helper.h"
#include "common_event_subscriber_manager.h"
#undef private
#undef protected

#include "common_event_listener.h"
#include "common_event_stub.h"
#include "common_event_subscriber.h"
#include "inner_common_event_manager.h"
#include "mock_bundle_manager.h"

using namespace testing::ext;
using namespace OHOS::EventFwk;
using namespace OHOS::AppExecFwk;

namespace {
const std::string EVENT = "com.ces.test.event";
const std::string ENTITY = "com.ces.test.entity";
const std::string SCHEME = "com.ces.test.scheme";
const std::string PERMISSION = "com.ces.test.permission";
const std::string DEVICEDID = "deviceId";
}  // namespace

static OHOS::sptr<OHOS::IRemoteObject> bundleObject = nullptr;
class CommonEventSubscribeUnitTest : public testing::Test {
public:
    CommonEventSubscribeUnitTest()
    {}
    ~CommonEventSubscribeUnitTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

class SubscriberTest : public CommonEventSubscriber {
public:
    SubscriberTest(const CommonEventSubscribeInfo &sp) : CommonEventSubscriber(sp)
    {}

    ~SubscriberTest()
    {}

    virtual void OnReceiveEvent(const CommonEventData &data)
    {}
};

class CommonEventStubTest : public CommonEventStub {
public:
    CommonEventStubTest()
    {}

    virtual bool PublishCommonEvent(const CommonEventData &event, const CommonEventPublishInfo &publishinfo,
        const OHOS::sptr<OHOS::IRemoteObject> &commonEventListener, const int32_t &userId)
    {
        return false;
    }

    virtual bool SubscribeCommonEvent(
        const CommonEventSubscribeInfo &subscribeInfo, const OHOS::sptr<OHOS::IRemoteObject> &commonEventListener)
    {
        return false;
    }

    virtual bool UnsubscribeCommonEvent(const OHOS::sptr<OHOS::IRemoteObject> &commonEventListener)
    {
        return false;
    }

    virtual bool DumpState(const uint8_t &dumpType, const std::string &event, const int32_t &userId,
        std::vector<std::string> &state)
    {
        return false;
    }

    virtual ~CommonEventStubTest()
    {}

    virtual bool FinishReceiver(const OHOS::sptr<OHOS::IRemoteObject> &proxy, const int &code,
        const std::string &receiverData, const bool &abortEvent)
    {
        return false;
    }
};

class EventReceiveStubTest : public EventReceiveStub {
public:
    EventReceiveStubTest()
    {}

    ~EventReceiveStubTest()
    {}

    virtual void NotifyEvent(const CommonEventData &commonEventData, const bool &ordered, const bool &sticky)
    {}
};

void CommonEventSubscribeUnitTest::SetUpTestCase(void)
{
    bundleObject = new MockBundleMgrService();
    OHOS::DelayedSingleton<BundleManagerHelper>::GetInstance()->sptrBundleMgr_ =
        OHOS::iface_cast<OHOS::AppExecFwk::IBundleMgr>(bundleObject);
}

void CommonEventSubscribeUnitTest::TearDownTestCase(void)
{}

void CommonEventSubscribeUnitTest::SetUp(void)
{}

void CommonEventSubscribeUnitTest::TearDown(void)
{}

/*
 * @tc.number: CommonEventSubscribeUnitTest_0300
 * @tc.name: test subscribe event
 * @tc.desc: InnerCommonEventManager subscribe common event success
 */
HWTEST_F(CommonEventSubscribeUnitTest, CommonEventSubscribeUnitTest_0300, Function | MediumTest | Level1)
{
    // make subscriber info
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    // make subscriber
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);

    // make common event listener
    OHOS::sptr<CommonEventListener> commonEventListener = new CommonEventListener(subscriber);
    OHOS::sptr<OHOS::IRemoteObject> commonEventListenerPtr(commonEventListener);

    // SubscribeCommonEvent
    struct tm curTime {0};
    OHOS::Security::AccessToken::AccessTokenID tokenID = 0;
    InnerCommonEventManager innerCommonEventManager;
    EXPECT_TRUE(innerCommonEventManager.SubscribeCommonEvent(
        subscribeInfo, commonEventListenerPtr, curTime, 0, 0, tokenID, ""));
}

/*
 * @tc.number: CommonEventSubscribeUnitTest_0400
 * @tc.name: test subscribe event
 * @tc.desc: InnerCommonEventManager subscribe common event fail because subscribeInfo has not event
 */
HWTEST_F(CommonEventSubscribeUnitTest, CommonEventSubscribeUnitTest_0400, Function | MediumTest | Level1)
{
    // make subscriber info
    MatchingSkills matchingSkills;
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    // make subscriber
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);

    // make common event listener
    OHOS::sptr<CommonEventListener> commonEventListener = new CommonEventListener(subscriber);
    OHOS::sptr<OHOS::IRemoteObject> commonEventListenerPtr(commonEventListener);

    // SubscribeCommonEvent
    struct tm curTime {0};
    OHOS::Security::AccessToken::AccessTokenID tokenID = 0;
    InnerCommonEventManager innerCommonEventManager;
    EXPECT_FALSE(innerCommonEventManager.SubscribeCommonEvent(
        subscribeInfo, commonEventListenerPtr, curTime, 0, 0, tokenID, ""));
}

/*
 * @tc.number: CommonEventSubscribeUnitTest_0500
 * @tc.name: test subscribe event
 * @tc.desc: 1. subscribe common event
 *                      2. fail subscribe common event, inner common event manager
 *                          common event listener is null
 */
HWTEST_F(CommonEventSubscribeUnitTest, CommonEventSubscribeUnitTest_0500, Function | MediumTest | Level1)
{
    // make subscriber info
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    // SubscribeCommonEvent
    OHOS::sptr<OHOS::IRemoteObject> sp(nullptr);
    struct tm curTime {0};
    OHOS::Security::AccessToken::AccessTokenID tokenID = 0;
    InnerCommonEventManager innerCommonEventManager;
    EXPECT_FALSE(innerCommonEventManager.SubscribeCommonEvent(subscribeInfo, sp, curTime, 0, 0, tokenID, ""));
}

/*
 * @tc.number: CommonEventSubscribeUnitTest_0600
 * @tc.name: test subscribe event
 * @tc.desc: subscribe common event success
 */
HWTEST_F(CommonEventSubscribeUnitTest, CommonEventSubscribeUnitTest_0600, Function | MediumTest | Level1)
{
    // make subscriber info
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<CommonEventSubscribeInfo> subscribeInfoPtr =
        std::make_shared<CommonEventSubscribeInfo>(subscribeInfo);

    // make subscriber
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);

    // make common event listener
    OHOS::sptr<CommonEventListener> commonEventListener = new CommonEventListener(subscriber);
    OHOS::sptr<OHOS::IRemoteObject> commonEventListenerPtr(commonEventListener);

    // InsertSubscriber
    struct tm curTime {0};
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.pid = 0;
    eventRecordInfo.uid = 0;
    eventRecordInfo.bundleName = "bundleName";
    CommonEventSubscriberManager commonEventSubscriberManager;
    auto result = commonEventSubscriberManager.InsertSubscriber(
        subscribeInfoPtr, commonEventListener, curTime, eventRecordInfo);
    EXPECT_NE(nullptr, result);
}

/*
 * @tc.number: CommonEventSubscribeUnitTest_0700
 * @tc.name: test subscribe event
 * @tc.desc: 1. subscribe common event
 *                      2. fail subscribe common event , common event subscriber manager
 *                          event subscriber info is null
 */
HWTEST_F(CommonEventSubscribeUnitTest, CommonEventSubscribeUnitTest_0700, Function | MediumTest | Level1)
{
    // make subscriber info
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    // make subscriber
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);

    // make common event listener
    OHOS::sptr<CommonEventListener> commonEventListener = new CommonEventListener(subscriber);
    OHOS::sptr<OHOS::IRemoteObject> commonEventListenerPtr(commonEventListener);

    // InsertSubscriber
    struct tm curTime {0};
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.pid = 0;
    eventRecordInfo.uid = 0;
    eventRecordInfo.bundleName = "bundleName";
    CommonEventSubscriberManager commonEventSubscriberManager;
    auto result =
        commonEventSubscriberManager.InsertSubscriber(nullptr, commonEventListenerPtr, curTime, eventRecordInfo);
    EXPECT_EQ(nullptr, result);
}

/*
 * @tc.number: CommonEventSubscribeUnitTest_0800
 * @tc.name: test subscribe event
 * @tc.desc: 1. subscribe common event
 *                      2. fail subscribe common event , common event subscriber manager
 *                          event common event listener is null
 */
HWTEST_F(CommonEventSubscribeUnitTest, CommonEventSubscribeUnitTest_0800, Function | MediumTest | Level1)
{
    // make subscriber info
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<CommonEventSubscribeInfo> subscribeInfoPtr =
        std::make_shared<CommonEventSubscribeInfo>(subscribeInfo);

    // make subscriber
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);

    // InsertSubscriber
    struct tm curTime {0};
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.pid = 0;
    eventRecordInfo.uid = 0;
    eventRecordInfo.bundleName = "bundleName";
    CommonEventSubscriberManager commonEventSubscriberManager;
    auto result = commonEventSubscriberManager.InsertSubscriber(subscribeInfoPtr, nullptr, curTime, eventRecordInfo);
    EXPECT_EQ(nullptr, result);
}

/*
 * @tc.number: CommonEventSubscribeUnitTest_0900
 * @tc.name: test subscribe event
 * @tc.desc: 1. subscribe common event
 *                      2. fail subscribe common event , common event subscriber manager
 *                          event size is null
 */
HWTEST_F(CommonEventSubscribeUnitTest, CommonEventSubscribeUnitTest_0900, Function | MediumTest | Level1)
{
    // make subscriber info
    MatchingSkills matchingSkills;
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<CommonEventSubscribeInfo> subscribeInfoPtr =
        std::make_shared<CommonEventSubscribeInfo>(subscribeInfo);

    // make subscriber
    CommonEventStubTest CommonEventStubTest;
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);

    // make common event listener
    OHOS::sptr<CommonEventListener> commonEventListener = new CommonEventListener(subscriber);
    std::shared_ptr<InnerCommonEventManager> innerCommonEventManager = std::make_shared<InnerCommonEventManager>();
    OHOS::sptr<OHOS::IRemoteObject> commonEventListenerPtr(commonEventListener);

    // InsertSubscriber
    struct tm curTime {0};
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.pid = 0;
    eventRecordInfo.uid = 0;
    eventRecordInfo.bundleName = "bundleName";
    CommonEventSubscriberManager commonEventSubscriberManager;
    auto result = commonEventSubscriberManager.InsertSubscriber(
        subscribeInfoPtr, commonEventListenerPtr, curTime, eventRecordInfo);
    EXPECT_EQ(nullptr, result);
}

/*
 * @tc.number: CommonEventSubscribeUnitTest_1000
 * @tc.name: ttest subscribe event
 * @tc.desc:  insert subscriber record locked success
 */
HWTEST_F(CommonEventSubscribeUnitTest, CommonEventSubscribeUnitTest_1000, Function | MediumTest | Level1)
{
    // make subscriber info
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT);
    matchingSkills.AddEvent(ENTITY);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    // make subscriber
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);

    // make common event listener
    OHOS::sptr<CommonEventListener> commonEventListener = new CommonEventListener(subscriber);
    OHOS::sptr<OHOS::IRemoteObject> commonEventListenerPtr(commonEventListener);

    // make events
    std::vector<std::string> events = subscribeInfo.GetMatchingSkills().GetEvents();

    // make record
    struct tm recordTime {0};
    auto record = std::make_shared<EventSubscriberRecord>();
    record->eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>(subscribeInfo);
    record->commonEventListener = commonEventListenerPtr;
    record->recordTime = recordTime;
    record->eventRecordInfo.pid = 0;
    record->eventRecordInfo.uid = 0;
    record->eventRecordInfo.bundleName = "bundleName";

    // InsertSubscriberRecordLocked
    CommonEventSubscriberManager commonEventSubscriberManager;
    EXPECT_TRUE(commonEventSubscriberManager.InsertSubscriberRecordLocked(events, record));
}

/*
 * @tc.number: CommonEventSubscribeUnitTest_1100
 * @tc.name: test subscribe event
 * @tc.desc:  insert subscriber record locked fail because events size is 0
 */
HWTEST_F(CommonEventSubscribeUnitTest, CommonEventSubscribeUnitTest_1100, Function | MediumTest | Level1)
{
    // make subscriber info
    MatchingSkills matchingSkills;
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    // make subscriber
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);

    // make common event listener
    OHOS::sptr<CommonEventListener> commonEventListener = new CommonEventListener(subscriber);
    OHOS::sptr<OHOS::IRemoteObject> commonEventListenerPtr(commonEventListener);

    // make events
    std::vector<std::string> events = subscribeInfo.GetMatchingSkills().GetEvents();

    // make record
    struct tm recordTime {0};
    auto record = std::make_shared<EventSubscriberRecord>();
    record->eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>(subscribeInfo);
    record->commonEventListener = commonEventListenerPtr;
    record->recordTime = recordTime;
    record->eventRecordInfo.pid = 0;
    record->eventRecordInfo.uid = 0;
    record->eventRecordInfo.bundleName = "bundleName";

    // InsertSubscriberRecordLocked
    CommonEventSubscriberManager commonEventSubscriberManager;
    EXPECT_FALSE(commonEventSubscriberManager.InsertSubscriberRecordLocked(events, record));
}

/*
 * @tc.number: CommonEventSubscribeUnitTest_1200
 * @tc.name: test subscribe event
 * @tc.desc:  insert subscriber record locked fail because record is nullptr
 */
HWTEST_F(CommonEventSubscribeUnitTest, CommonEventSubscribeUnitTest_1200, Function | MediumTest | Level1)
{
    // make subscriber info
    MatchingSkills matchingSkills;
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    // make events
    std::vector<std::string> events = subscribeInfo.GetMatchingSkills().GetEvents();
    CommonEventSubscriberManager commonEventSubscriberManager;

    // InsertSubscriberRecordLocked
    EXPECT_FALSE(commonEventSubscriberManager.InsertSubscriberRecordLocked(events, nullptr));
}
