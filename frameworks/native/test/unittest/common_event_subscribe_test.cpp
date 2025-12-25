/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include <thread>
#include <chrono>

#include <sys/time.h>

// redefine private and protected since testcase need to invoke and test private function
#define private public
#define protected public
#include "common_event.h"
#include "common_event_manager.h"
#include "common_event_stub.h"
#include "common_event_subscriber_manager.h"
#include "inner_common_event_manager.h"
#include "common_event_publish_info.h"
#include "common_event_subscribe_info.h"
#include "matching_skills.h"
#undef private
#undef protected

#include "datetime_ex.h"

#include <gtest/gtest.h>

using namespace testing::ext;
using namespace OHOS::EventFwk;
using OHOS::Parcel;
using OHOS::ErrCode;

namespace {
const std::string EVENT = "com.ces.test.event";
std::mutex mtx;
const time_t TIME_OUT_SECONDS_LIMIT = 5;
constexpr uint16_t SYSTEM_UID = 1000;
constexpr int32_t ERR_COMMON = -1;
}  // namespace

class SubscriberTest;

class CommonEventSubscribeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

public:
    static constexpr int TEST_WAIT_TIME = 100000;
    CommonEventManager commonEventManager;
    MatchingSkills matchingSkills;
};

class SubscriberTest : public CommonEventSubscriber {
public:
    explicit SubscriberTest(const CommonEventSubscribeInfo &sp) : CommonEventSubscriber(sp)
    {}

    ~SubscriberTest()
    {}

    virtual void OnReceiveEvent(const CommonEventData &data)
    {
        mtx.unlock();
    }
};

class EventReceiveStubTest : public EventReceiveStub {
public:
    EventReceiveStubTest()
    {}

    ~EventReceiveStubTest()
    {}

    OHOS::ErrCode NotifyEvent(const CommonEventData& data, bool ordered, bool sticky) override
    {
        return OHOS::ERR_OK;
    }
};

class CommonEventStubTest : public CommonEventStub {
public:
    CommonEventStubTest()
    {}

    virtual ErrCode PublishCommonEvent(const CommonEventData& event, const CommonEventPublishInfo& publishInfo,
        const OHOS::sptr<IRemoteObject>& commonEventListener, int32_t userId, int32_t& funcResult)
    {
        return ERR_COMMON;
    }

    virtual ErrCode SubscribeCommonEvent(const CommonEventSubscribeInfo& subscribeInfo,
        const OHOS::sptr<IRemoteObject>& commonEventListener, int32_t instanceKey, int32_t& funcResult)
    {
        return ERR_COMMON;
    }

    virtual ErrCode UnsubscribeCommonEvent(const OHOS::sptr<IRemoteObject>& commonEventListener, int32_t& funcResult)
    {
        return ERR_COMMON;
    }

    virtual ErrCode DumpState(uint8_t dumpType, const std::string& event, int32_t userId,
        std::vector<std::string>& state, bool& funcResult)
    {
        funcResult = false;
        return OHOS::ERR_OK;
    }

    virtual ~CommonEventStubTest()
    {}

    virtual ErrCode FinishReceiver(const OHOS::sptr<IRemoteObject>& proxy, int32_t code,
        const std::string& receiverData, bool abortEvent, bool& funcResult)
    {
        funcResult = false;
        return OHOS::ERR_OK;
    }
};

void CommonEventSubscribeTest::SetUpTestCase(void)
{}

void CommonEventSubscribeTest::TearDownTestCase(void)
{}

void CommonEventSubscribeTest::SetUp(void)
{}

void CommonEventSubscribeTest::TearDown(void)
{}

/*
 * Feature: CommonEventSubscribeTest
 * Function:CommonEvent SubscribeCommonEvent
 * SubFunction: Subscribe common event
 * FunctionPoints: test subscribe event
 * EnvConditions: system run normally
 * CaseDescription:  1. subscribe common event
 *                   2. success subscribe common event with right parameters
 */

HWTEST_F(CommonEventSubscribeTest, CommonEventSubscribe_001, TestSize.Level0)
{
    /* Subscribe */
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);
    bool subscribeResult = CommonEventManager::SubscribeCommonEvent(subscriber);

    EXPECT_EQ(true, subscribeResult);

    /* Publish */

    // make a want
    Want want;
    want.SetAction(EVENT);

    // make common event data
    CommonEventData data;
    data.SetWant(want);

    // lock the mutex
    mtx.lock();

    // publish a common event
    bool publishResult = CommonEventManager::PublishCommonEvent(data);

    EXPECT_EQ(true, publishResult);

    // record start time of publishing
    struct tm startTime = {0};
    EXPECT_EQ(OHOS::GetSystemCurrentTime(&startTime), true);

    // record current time
    struct tm doingTime = {0};
    int64_t seconds = 0;

    while (!mtx.try_lock()) {
        // get current time and compare it with the start time
        EXPECT_EQ(OHOS::GetSystemCurrentTime(&doingTime), true);
        seconds = OHOS::GetSecondsBetween(startTime, doingTime);
        if (seconds >= TIME_OUT_SECONDS_LIMIT) {
            break;
        }
    }

    // expect the subscriber could receive the event within 5 seconds.
    EXPECT_LT(seconds, TIME_OUT_SECONDS_LIMIT);
    mtx.unlock();
}

/*
 * Feature: CommonEventSubscribeTest
 * Function:CommonEventSubscriberManager InsertSubscriber
 * SubFunction: Subscribe common event
 * FunctionPoints: test subscribe event
 * EnvConditions: system run normally
 * CaseDescription:  1. subscribe common event
 *                   2. different subscriber subscribe event
 *                   3. success subscribe common event with right parameters
 */
HWTEST_F(CommonEventSubscribeTest, CommonEventSubscribe_002, TestSize.Level0)
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<SubscriberTest> subscribera = std::make_shared<SubscriberTest>(subscribeInfo);
    std::shared_ptr<SubscriberTest> subscriberb = std::make_shared<SubscriberTest>(subscribeInfo);

    bool subscribeResulta = CommonEventManager::SubscribeCommonEvent(subscribera);

    EXPECT_EQ(true, subscribeResulta);

    bool subscribeResultb = CommonEventManager::SubscribeCommonEvent(subscriberb);

    EXPECT_EQ(true, subscribeResultb);
}

/*
 * Feature: CommonEventSubscribeTest
 * Function:CommonEvent SubscribeCommonEvent
 * SubFunction: Subscribe common event
 * FunctionPoints: test subscribe event
 * EnvConditions: system run normally
 * CaseDescription:  1. subscribe common event
 *                   2. fail subscribe common event kit with null subscriber
 */

HWTEST_F(CommonEventSubscribeTest, CommonEventSubscribe_003, TestSize.Level0)
{
    bool subscribeResult = CommonEventManager::SubscribeCommonEvent(nullptr);

    EXPECT_EQ(false, subscribeResult);
}

/*
 * Feature: CommonEventSubscribeTest
 * Function:CommonEvent SubscribeCommonEvent
 * SubFunction: Subscribe common event
 * FunctionPoints: test subscribe event
 * EnvConditions: system run normally
 * CaseDescription:  1. subscribe common event
 *                   2. fail subscribe common event with no event
 */
HWTEST_F(CommonEventSubscribeTest, CommonEventSubscribe_004, TestSize.Level0)
{
    MatchingSkills matchingSkills;
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);

    bool subscribeResult = CommonEventManager::SubscribeCommonEvent(subscriber);

    EXPECT_EQ(false, subscribeResult);
}

/*
 * Feature: CommonEventSubscribeTest
 * Function:CommonEvent SubscribeCommonEvent
 * SubFunction: Subscribe common event
 * FunctionPoints: test subscribe event
 * EnvConditions: system run normally
 * CaseDescription:  1. subscribe common event
 *                   2. fail subscribe common event because common event listener has subsrciber
 */
HWTEST_F(CommonEventSubscribeTest, CommonEventSubscribe_005, TestSize.Level0)
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);

    CommonEventManager::SubscribeCommonEvent(subscriber);

    bool subscribeResult = CommonEventManager::SubscribeCommonEvent(subscriber);

    EXPECT_EQ(true, subscribeResult);
}

/*
 * Feature: CommonEventSubscribeTest
 * Function: InnerCommonEventManager SubscribeCommonEvent
 * SubFunction: Subscribe common event
 * FunctionPoints: test subscribe event
 * EnvConditions: system run normally
 * CaseDescription:  1. subscribe common event
 *                   2. fail subscribe common event, inner common event manager
 *                      common event listener is null
 */
HWTEST_F(CommonEventSubscribeTest, CommonEventSubscribe_009, TestSize.Level0)
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<InnerCommonEventManager> innerCommonEventManager = std::make_shared<InnerCommonEventManager>();
    OHOS::sptr<OHOS::IRemoteObject> sp(nullptr);

    struct tm curTime {0};
    OHOS::Security::AccessToken::AccessTokenID tokenID = 1;

    EXPECT_EQ(false, innerCommonEventManager->SubscribeCommonEvent(subscribeInfo, sp, curTime, 0, 0, tokenID, ""));
}

/*
 * Feature: CommonEventSubscribeTest
 * Function: CommonEventSubscriberManager InsertSubscriber
 * SubFunction: Subscribe common event
 * FunctionPoints: test subscribe event
 * EnvConditions: system run normally
 * CaseDescription:  1. subscribe common event
 *                   2. fail subscribe common event , common event subscriber manager
 *                      event subscriber info is null
 */
HWTEST_F(CommonEventSubscribeTest, CommonEventSubscribe_010, TestSize.Level0)
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);
    OHOS::sptr<CommonEventListener> commonEventListener = new CommonEventListener(subscriber);
    std::shared_ptr<InnerCommonEventManager> innerCommonEventManager = std::make_shared<InnerCommonEventManager>();
    OHOS::sptr<OHOS::IRemoteObject> commonEventListenerPtr(commonEventListener);

    struct tm curTime {0};
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.pid = 0;
    eventRecordInfo.uid = 0;
    eventRecordInfo.bundleName = "bundleName";

    auto result = OHOS::DelayedSingleton<CommonEventSubscriberManager>::GetInstance()->InsertSubscriber(
        nullptr, commonEventListenerPtr, curTime, eventRecordInfo);

    EXPECT_EQ(nullptr, result);
}

/*
 * Feature: CommonEventSubscribeTest
 * Function: CommonEventSubscriberManager InsertSubscriber
 * SubFunction: Subscribe common event
 * FunctionPoints: test subscribe event
 * EnvConditions: system run normally
 * CaseDescription:  1. subscribe common event
 *                   2. fail subscribe common event , common event subscriber manager
 *                      event common event listener is null
 */
HWTEST_F(CommonEventSubscribeTest, CommonEventSubscribe_011, TestSize.Level0)
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<CommonEventSubscribeInfo> commonEventSubscribeInfo =
        std::make_shared<CommonEventSubscribeInfo>(subscribeInfo);

    struct tm curTime {0};
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.pid = 0;
    eventRecordInfo.uid = 0;
    eventRecordInfo.bundleName = "bundleName";

    auto result = OHOS::DelayedSingleton<CommonEventSubscriberManager>::GetInstance()->InsertSubscriber(
        commonEventSubscribeInfo, nullptr, curTime, eventRecordInfo);

    EXPECT_EQ(nullptr, result);
}

/*
 * Feature: CommonEventSubscribeTest
 * Function: CommonEventSubscriberManager InsertSubscriber
 * SubFunction: Subscribe common event
 * FunctionPoints: test subscribe event
 * EnvConditions: system run normally
 * CaseDescription:  1. subscribe common event
 *                   2. fail subscribe common event , common event subscriber manager
 *                      event size is null
 */
HWTEST_F(CommonEventSubscribeTest, CommonEventSubscribe_012, TestSize.Level0)
{
    MatchingSkills matchingSkills;
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<CommonEventSubscribeInfo> commonEventSubscribeInfo =
        std::make_shared<CommonEventSubscribeInfo>(subscribeInfo);
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);
    OHOS::sptr<CommonEventListener> commonEventListener = new CommonEventListener(subscriber);
    std::shared_ptr<InnerCommonEventManager> innerCommonEventManager = std::make_shared<InnerCommonEventManager>();
    OHOS::sptr<OHOS::IRemoteObject> commonEventListenerSp(commonEventListener);

    struct tm curTime {0};
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.pid = 0;
    eventRecordInfo.uid = 0;
    eventRecordInfo.bundleName = "bundleName";

    auto result = OHOS::DelayedSingleton<CommonEventSubscriberManager>::GetInstance()->InsertSubscriber(
        commonEventSubscribeInfo, nullptr, curTime, eventRecordInfo);

    EXPECT_EQ(nullptr, result);
}

/*
 * Feature: CommonEventSubscribeTest
 * Function: CommonEventListener IsReady
 * SubFunction: Subscribe common event
 * FunctionPoints: test is ready
 * EnvConditions: system run normally
 * CaseDescription:  1. ready true because handler is null but ThreadMode is not handler
 */
HWTEST_F(CommonEventSubscribeTest, CommonEventSubscribe_014, TestSize.Level0)
{
    MatchingSkills matchingSkills;
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<CommonEventSubscribeInfo> commonEventSubscribeInfo =
        std::make_shared<CommonEventSubscribeInfo>(subscribeInfo);
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);
    CommonEventListener commonEventListener(subscriber);
    commonEventListener.runner_ = nullptr;

    bool result = commonEventListener.IsReady();

    EXPECT_EQ(true, result);
}

/*
 * Feature: CommonEventSubscribeTest
 * Function: CommonEventListener IsReady
 * SubFunction: Subscribe common event
 * FunctionPoints: test is ready
 * EnvConditions: system run normally
 * CaseDescription:  1. ready fail because handler is null and threadMode is handler
 */
HWTEST_F(CommonEventSubscribeTest, CommonEventSubscribe_015, TestSize.Level0)
{
    MatchingSkills matchingSkills;
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetThreadMode(CommonEventSubscribeInfo::HANDLER);
    std::shared_ptr<CommonEventSubscribeInfo> commonEventSubscribeInfo =
        std::make_shared<CommonEventSubscribeInfo>(subscribeInfo);
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);
    CommonEventListener commonEventListener(subscriber);
    commonEventListener.handler_ = nullptr;

    bool result = commonEventListener.IsReady();

    EXPECT_EQ(false, result);
}

/*
 * Feature: CommonEventSubscribeTest
 * Function: CommonEvent Subscribe
 * SubFunction: Subscribe common event
 * FunctionPoints: test subscribe event
 * EnvConditions: system run normally
 * CaseDescription:  1. subscribe common event
 *                   2. success subscribe common event with right parameters
 */
HWTEST_F(CommonEventSubscribeTest, CommonEventSubscribe_016, TestSize.Level0)
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);
    int32_t subscribeResult = CommonEventManager::Subscribe(subscriber);
    EXPECT_EQ(0, subscribeResult);
    Want want;
    want.SetAction(EVENT);
    CommonEventData data;
    data.SetWant(want);

    mtx.lock();
    bool publishResult = CommonEventManager::PublishCommonEvent(data);

    EXPECT_EQ(true, publishResult);

    struct tm startTime = {0};
    EXPECT_EQ(OHOS::GetSystemCurrentTime(&startTime), true);

    struct tm doingTime = {0};
    int64_t seconds = 0;

    while (!mtx.try_lock()) {
        EXPECT_EQ(OHOS::GetSystemCurrentTime(&doingTime), true);
        seconds = OHOS::GetSecondsBetween(startTime, doingTime);
        if (seconds >= TIME_OUT_SECONDS_LIMIT) {
            break;
        }
    }
    EXPECT_LT(seconds, TIME_OUT_SECONDS_LIMIT);
    mtx.unlock();
}

/*
 * Feature: CommonEventSubscribeTest
 * Function: CommonEvent Subscribe
 * SubFunction: Subscribe common event
 * FunctionPoints: test subscribe event
 * EnvConditions: system run normally
 * CaseDescription:  1. subscribe common event
 *                   2. different subscriber subscribe event
 *                   3. success subscribe common event with right parameters
 */
HWTEST_F(CommonEventSubscribeTest, CommonEventSubscribe_017, TestSize.Level0)
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<SubscriberTest> subscribera = std::make_shared<SubscriberTest>(subscribeInfo);
    std::shared_ptr<SubscriberTest> subscriberb = std::make_shared<SubscriberTest>(subscribeInfo);

    int32_t subscribeResulta = CommonEventManager::Subscribe(subscribera);

    EXPECT_EQ(0, subscribeResulta);

    int32_t subscribeResultb = CommonEventManager::Subscribe(subscriberb);

    EXPECT_EQ(0, subscribeResultb);
}

/*
 * Feature: CommonEventSubscribeTest
 * Function: CommonEvent Subscribe
 * SubFunction: Subscribe common event
 * FunctionPoints: test subscribe event
 * EnvConditions: system run normally
 * CaseDescription:  1. subscribe common event
 *                   2. fail subscribe common event kit with null subscriber
 */
HWTEST_F(CommonEventSubscribeTest, CommonEventSubscribe_018, TestSize.Level0)
{
    int32_t subscribeResult = CommonEventManager::Subscribe(nullptr);

    EXPECT_EQ(401, subscribeResult);
}

/*
 * Feature: CommonEventSubscribeTest
 * Function: CommonEvent Subscribe
 * SubFunction: Subscribe common event
 * FunctionPoints: test subscribe event
 * EnvConditions: system run normally
 * CaseDescription:  1. subscribe common event
 *                   2. fail subscribe common event with no event
 */
HWTEST_F(CommonEventSubscribeTest, CommonEventSubscribe_019, TestSize.Level0)
{
    MatchingSkills matchingSkills;
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);

    int32_t subscribeResult = CommonEventManager::Subscribe(subscriber);

    EXPECT_EQ(401, subscribeResult);
}

/*
 * Feature: CommonEventSubscribeTest
 * Function:CommonEvent Subscribe
 * SubFunction: Subscribe common event
 * FunctionPoints: test subscribe event
 * EnvConditions: system run normally
 * CaseDescription:  1. subscribe common event
 *                   2. fail subscribe common event because common event listener has subsrciber
 */
HWTEST_F(CommonEventSubscribeTest, CommonEventSubscribe_020, TestSize.Level0)
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);

    CommonEventManager::Subscribe(subscriber);

    std::string event1 = "test2";
    matchingSkills.RemoveEvent(EVENT);
    matchingSkills.AddEvent(event1);
    CommonEventSubscribeInfo subscribeInfo1(matchingSkills);
    subscriber->SetSubscribeInfo(subscribeInfo1);

    int32_t subscribeResult = CommonEventManager::Subscribe(subscriber);

    EXPECT_EQ(0, subscribeResult);
}

/*
 * tc.number: CommonEventManager_001
 * tc.name: test Freeze
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke Freeze interface verify whether it is normal
 */
HWTEST_F(CommonEventSubscribeTest, CommonEventManager_001, TestSize.Level0)
{
    CommonEventManager commonEventManager;
    bool freeze = commonEventManager.Freeze(SYSTEM_UID);
    EXPECT_EQ(false, freeze);
}

/*
 * tc.number: CommonEventManager_002
 * tc.name: test Unfreeze
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke Unfreeze interface verify whether it is normal
 */
HWTEST_F(CommonEventSubscribeTest, CommonEventManager_002, TestSize.Level0)
{
    CommonEventManager commonEventManager;
    bool unfreeze = commonEventManager.Unfreeze(SYSTEM_UID);
    EXPECT_EQ(false, unfreeze);
}

/*
 * tc.number: CommonEventManager_003
 * tc.name: test UnfreezeAll
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke UnfreezeAll interface verify whether it is normal
 */
HWTEST_F(CommonEventSubscribeTest, CommonEventManager_003, TestSize.Level0)
{
    CommonEventManager commonEventManager;
    bool unfreezeAll = commonEventManager.UnfreezeAll();
    EXPECT_EQ(false, unfreezeAll);
}

/*
 * tc.number: CommonEventManager_004
 * tc.name: test Freeze
 * tc.type: FUNC
 * tc.require: issue
 * tc.desc: Invoke PublishCommonEventAsUser interface verify whether it is normal
 */
HWTEST_F(CommonEventSubscribeTest, CommonEventManager_004, TestSize.Level0)
{
    CommonEventManager commonEventManager;
    CommonEventData data;
    int32_t userId = 10;
    bool result = commonEventManager.PublishCommonEventAsUser(data, userId);
    EXPECT_EQ(result, false);
}

/*
 * tc.number: CommonEventManager_005
 * tc.name: test Freeze
 * tc.type: FUNC
 * tc.require: issue
 * tc.desc: Invoke PublishCommonEventAsUser interface verify whether it is normal
 */
HWTEST_F(CommonEventSubscribeTest, CommonEventManager_005, TestSize.Level0)
{
    CommonEventManager commonEventManager;
    CommonEventData data;
    int32_t userId = 10;
    CommonEventPublishInfo publishInfo;
    bool result = commonEventManager.PublishCommonEventAsUser(data, publishInfo, userId);
    EXPECT_EQ(result, false);
}

/*
 * tc.number: CommonEventManager_006
 * tc.name: test SetStaticSubscriberState
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke Unfreeze interface verify whether it is normal
 */
HWTEST_F(CommonEventSubscribeTest, CommonEventManager_006, TestSize.Level0)
{
    CommonEventManager commonEventManager;
    int32_t ret = commonEventManager.SetStaticSubscriberState(true);
    EXPECT_NE(ret, OHOS::ERR_OK);
}

/*
 * tc.number: CommonEventManager_007
 * tc.name: test SetFreezeStatus
 * tc.type: FUNC
 * tc.desc: Invoke SetFreezeStatus interface verify whether it is normal
 */
HWTEST_F(CommonEventSubscribeTest, CommonEventManager_007, TestSize.Level0)
{
    CommonEventManager commonEventManager;
    std::set<int> pidList = {1000};
    bool result = commonEventManager.SetFreezeStatus(pidList, true);
    EXPECT_EQ(false, result);
}

/*
 * tc.number: CommonEventSubscribeInfo_001
 * tc.name: test ReadFromParcel
 * tc.type: FUNC
 * tc.require: issueI5RULW
 * tc.desc: Invoke ReadFromParcel interface verify whether it is normal
 */
HWTEST_F(CommonEventSubscribeTest, CommonEventSubscribeInfo_001, TestSize.Level0)
{
    Parcel parcel;
    CommonEventSubscribeInfo commonEventSubscribeInfo;
    bool result = commonEventSubscribeInfo.ReadFromParcel(parcel);
    EXPECT_EQ(result, false);
}

/*
 * tc.number: MatchingSkills_001
 * tc.name: test ReadFromParcel
 * tc.type: FUNC
 * tc.require: issueI5RULW
 * tc.desc: Invoke ReadFromParcel interface verify whether it is normal
 */
HWTEST_F(CommonEventSubscribeTest, MatchingSkills_001, TestSize.Level0)
{
    Parcel parcel;
    MatchingSkills matchingSkills;

    // write entity
    int32_t value = 1;
    parcel.WriteInt32(value);
    std::vector<std::u16string> actionU16Entity;
    for (std::vector<std::string>::size_type i = 0; i < 3; i++) {
        actionU16Entity.emplace_back(OHOS::Str8ToStr16("test"));
    }
    matchingSkills.WriteVectorInfo(parcel, actionU16Entity);

    //write event
    parcel.WriteInt32(value);
    std::vector<std::u16string> actionU16Event;
    for (std::vector<std::string>::size_type i = 0; i < 3; i++) {
        actionU16Event.emplace_back(OHOS::Str8ToStr16("test"));
    }
    matchingSkills.WriteVectorInfo(parcel, actionU16Event);

    // write scheme
    parcel.WriteInt32(value);
    std::vector<std::u16string> actionU16Scheme;
    for (std::vector<std::string>::size_type i = 0; i < 3; i++) {
        actionU16Scheme.emplace_back(OHOS::Str8ToStr16("test"));
    }
    matchingSkills.WriteVectorInfo(parcel, actionU16Scheme);

    bool result = matchingSkills.ReadFromParcel(parcel);
    EXPECT_EQ(result, true);
}

/*
 * tc.number: CommonEventSubscriber_001
 * tc.name: test SetCode
 * tc.type: FUNC
 * tc.require: issue
 * tc.desc: when SetCode return false
 */
HWTEST_F(CommonEventSubscribeTest, CommonEventSubscriber_001, TestSize.Level0)
{
    MatchingSkills matchingSkills;
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);

    subscriber->SetAsyncCommonEventResult(nullptr);
    EXPECT_EQ(subscriber->CheckSynchronous(), false);
    const int code = 1;
    bool result = subscriber->SetCode(code);
    EXPECT_EQ(result, false);
}

/*
 * tc.number: CommonEventSubscriber_002
 * tc.name: test GetCode
 * tc.type: FUNC
 * tc.require: issue
 * tc.desc: when GetCode return false
 */
HWTEST_F(CommonEventSubscribeTest, CommonEventSubscriber_002, TestSize.Level0)
{
    MatchingSkills matchingSkills;
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);

    subscriber->SetAsyncCommonEventResult(nullptr);
    EXPECT_EQ(subscriber->CheckSynchronous(), false);
    bool result = subscriber->GetCode();
    EXPECT_EQ(result, false);
}

/*
 * tc.number: CommonEventSubscriber_003
 * tc.name: test SetData
 * tc.type: FUNC
 * tc.require: issue
 * tc.desc: when SetData return false
 */
HWTEST_F(CommonEventSubscribeTest, CommonEventSubscriber_003, TestSize.Level0)
{
    MatchingSkills matchingSkills;
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);

    subscriber->SetAsyncCommonEventResult(nullptr);
    EXPECT_EQ(subscriber->CheckSynchronous(), false);
    const std::string data = "this is data";
    bool result = subscriber->SetData(data);
    EXPECT_EQ(result, false);
}

/*
 * tc.number: CommonEventSubscriber_004
 * tc.name: test GetData
 * tc.type: FUNC
 * tc.require: issue
 * tc.desc: when GetData return null
 */
HWTEST_F(CommonEventSubscribeTest, CommonEventSubscriber_004, TestSize.Level0)
{
    MatchingSkills matchingSkills;
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);

    subscriber->SetAsyncCommonEventResult(nullptr);
    EXPECT_EQ(subscriber->CheckSynchronous(), false);
    std::string result = subscriber->GetData();
    std::string ret = "";
    EXPECT_EQ(result, ret);
}

/*
 * tc.number: CommonEventSubscriber_005
 * tc.name: test SetCodeAndData
 * tc.type: FUNC
 * tc.require: issue
 * tc.desc: when SetCodeAndData return false
 */
HWTEST_F(CommonEventSubscribeTest, CommonEventSubscriber_005, TestSize.Level0)
{
    MatchingSkills matchingSkills;
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);

    subscriber->SetAsyncCommonEventResult(nullptr);
    EXPECT_EQ(subscriber->CheckSynchronous(), false);
    const int32_t code = 1;
    const std::string data = "this is data";
    bool result = subscriber->SetCodeAndData(code, data);
    EXPECT_EQ(result, false);
}

/*
 * tc.number: CommonEventSubscriber_006
 * tc.name: test ClearAbortCommonEvent and AbortCommonEvent
 * tc.type: FUNC
 * tc.require: issue
 * tc.desc: when ClearAbortCommonEvent
 */
HWTEST_F(CommonEventSubscribeTest, CommonEventSubscriber_006, TestSize.Level0)
{
    MatchingSkills matchingSkills;
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);
    std::shared_ptr<AsyncCommonEventResult> result =
        std::make_shared<AsyncCommonEventResult>(12, "data", true, false, nullptr);
    subscriber->SetAsyncCommonEventResult(result);
    EXPECT_EQ(subscriber->CheckSynchronous(), true);

    EXPECT_EQ(subscriber->AbortCommonEvent(), true);
    EXPECT_EQ(subscriber->GetAbortCommonEvent(), true);

    EXPECT_EQ(subscriber->ClearAbortCommonEvent(), true);
    EXPECT_EQ(subscriber->GetAbortCommonEvent(), false);
}