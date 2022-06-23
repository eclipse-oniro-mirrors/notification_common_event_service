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
#include "common_event_control_manager.h"
#include "common_event_subscriber_manager.h"
#undef private
#undef protected
#include "common_event_listener.h"
#include "common_event_subscriber.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EventFwk;
namespace {
const std::string EVENT = "com.ces.test.event";
const static uid_t TEST_UID = 10101;

class SubscriberTest : public CommonEventSubscriber {
public:
    explicit SubscriberTest(const CommonEventSubscribeInfo &sp) : CommonEventSubscriber(sp) {}

    virtual ~SubscriberTest() {}

    void OnReceiveEvent(const CommonEventData &data) override {}
};

class CommonEventFreezeUnitTest : public testing::Test {
public:
    CommonEventFreezeUnitTest() {}

    virtual ~CommonEventFreezeUnitTest() {}

    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
protected:
    MatchingSkills matchingSkills_;
    EventRecordInfo eventRecordInfo_;
};

void CommonEventFreezeUnitTest::SetUpTestCase() {}

void CommonEventFreezeUnitTest::TearDownTestCase() {}

void CommonEventFreezeUnitTest::SetUp()
{
    matchingSkills_.AddEvent(EVENT);
    eventRecordInfo_.pid = 0;
    eventRecordInfo_.uid = TEST_UID;
    eventRecordInfo_.bundleName = "bundleName";
}

void CommonEventFreezeUnitTest::TearDown() {}

/*
 * @tc.number: CommonEventFreezeUnitTest_0100
 * @tc.name: test CommonEventSubscriberManager UpdateFreezeInfo set freeze state to true.
 */
HWTEST_F(CommonEventFreezeUnitTest, CommonEventFreezeUnitTest_0100,
    Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "CommonEventFreezeUnitTest, CommonEventFreezeUnitTest_0100, TestSize.Level1";

    // make subscribeInfoPtr
    std::shared_ptr<CommonEventSubscribeInfo> subscribeInfoPtr =
        std::make_shared<CommonEventSubscribeInfo>(matchingSkills_);
    // make subscriber
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(*subscribeInfoPtr);
    // make commonEventListener
    OHOS::sptr<CommonEventListener> commonEventListener = new CommonEventListener(subscriber);
    struct tm curTime {0};
    // insert subscriber
    CommonEventSubscriberManager commonEventSubscriberManager;
    auto result = commonEventSubscriberManager.InsertSubscriber(
        subscribeInfoPtr, commonEventListener, curTime, eventRecordInfo_);
    EXPECT_NE(nullptr, result);
    // update freeze info
    commonEventSubscriberManager.UpdateFreezeInfo(TEST_UID, true);
    size_t expectSize = 1;
    ASSERT_EQ(expectSize, commonEventSubscriberManager.subscribers_.size());
    // get freeze records info
    EXPECT_EQ(true, commonEventSubscriberManager.subscribers_[0]->isFreeze);
    GTEST_LOG_(INFO)
        << "CommonEventFreezeUnitTest, CommonEventFreezeUnitTest_0100, TestSize.Level1 end";
}

/*
 * @tc.number: CommonEventFreezeUnitTest_0200
 * @tc.name: test CommonEventSubscriberManager UpdateFreezeInfo set freeze state to false.
 */
HWTEST_F(CommonEventFreezeUnitTest, CommonEventFreezeUnitTest_0200,
    Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "CommonEventFreezeUnitTest, CommonEventFreezeUnitTest_0200, TestSize.Level1";
    // make subscribeInfoPtr
    std::shared_ptr<CommonEventSubscribeInfo> subscribeInfoPtr =
        std::make_shared<CommonEventSubscribeInfo>(matchingSkills_);
    // make subscriber
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(*subscribeInfoPtr);
    // make common event listener
    OHOS::sptr<CommonEventListener> commonEventListener = new CommonEventListener(subscriber);
    struct tm curTime {0};
    // InsertSubscriber
    CommonEventSubscriberManager commonEventSubscriberManager;
    auto result = commonEventSubscriberManager.InsertSubscriber(
        subscribeInfoPtr, commonEventListener, curTime, eventRecordInfo_);
    EXPECT_NE(nullptr, result);
    // update freeze info
    commonEventSubscriberManager.UpdateFreezeInfo(TEST_UID, false);
    size_t expectSize = 1;
    ASSERT_EQ(expectSize, commonEventSubscriberManager.subscribers_.size());
    // get freeze records info
    EXPECT_EQ(false, commonEventSubscriberManager.subscribers_[0]->isFreeze);
    GTEST_LOG_(INFO)
        << "CommonEventFreezeUnitTest, CommonEventFreezeUnitTest_0200, TestSize.Level1 end";
}

/*
 * @tc.number: CommonEventFreezeUnitTest_0300
 * @tc.name: test CommonEventSubscriberManager insert frozen event record.
 */
HWTEST_F(CommonEventFreezeUnitTest, CommonEventFreezeUnitTest_0300,
    Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "CommonEventFreezeUnitTest, CommonEventFreezeUnitTest_0300, TestSize.Level1";
    // make subscriber info
    std::shared_ptr<CommonEventSubscribeInfo> subscribeInfoPtr =
        std::make_shared<CommonEventSubscribeInfo>(matchingSkills_);
    // make subscriber
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(*subscribeInfoPtr);
    // make common event listener
    OHOS::sptr<CommonEventListener> commonEventListener = new CommonEventListener(subscriber);
    struct tm curTime {0};
    // InsertSubscriber
    CommonEventSubscriberManager commonEventSubscriberManager;
    auto result = commonEventSubscriberManager.InsertSubscriber(
        subscribeInfoPtr, commonEventListener, curTime, eventRecordInfo_);
    EXPECT_NE(nullptr, result);
    // clear frozen events
    std::map<uid_t, FrozenRecords> allFrozenRecords = commonEventSubscriberManager.GetAllFrozenEvents();
    size_t expectSize = 0;
    EXPECT_EQ(expectSize, allFrozenRecords.size());
    // make SubscriberRecordPtr
    SubscriberRecordPtr eventSubscriberRecord = std::make_shared<EventSubscriberRecord>();
    eventSubscriberRecord->eventSubscribeInfo = subscribeInfoPtr;
    eventSubscriberRecord->commonEventListener = commonEventListener;
    eventSubscriberRecord->eventRecordInfo = eventRecordInfo_;
    eventSubscriberRecord->isFreeze = true;
    // make commonEventData
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    // make commonEventPublishInfo
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    // make commonEventRecord
    CommonEventRecord commonEventRecord;
    commonEventRecord.commonEventData = commonEventData;
    commonEventRecord.publishInfo = publishInfo;
    commonEventRecord.eventRecordInfo = eventRecordInfo_;
    // insert frozen events
    commonEventSubscriberManager.InsertFrozenEvents(eventSubscriberRecord, commonEventRecord);
    std::map<uid_t, FrozenRecords> allFrozenRecords1 = commonEventSubscriberManager.GetAllFrozenEvents();
    expectSize = 1;
    EXPECT_EQ(expectSize, allFrozenRecords1.size());
    GTEST_LOG_(INFO)
        << "CommonEventFreezeUnitTest, CommonEventFreezeUnitTest_0300, TestSize.Level1 end";
}

/*
 * @tc.number: CommonEventFreezeUnitTest_0400
 * @tc.name: test CommonEventSubscriberManager insert frozen event record.
 */
HWTEST_F(CommonEventFreezeUnitTest, CommonEventFreezeUnitTest_0400,
    Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "CommonEventFreezeUnitTest, CommonEventFreezeUnitTest_0400, TestSize.Level1";
    // make subscriber info
    std::shared_ptr<CommonEventSubscribeInfo> subscribeInfoPtr =
        std::make_shared<CommonEventSubscribeInfo>(matchingSkills_);
    // make subscriber
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(*subscribeInfoPtr);
    // make common event listener
    OHOS::sptr<CommonEventListener> commonEventListener = new CommonEventListener(subscriber);
    struct tm curTime {0};
    // InsertSubscriber
    CommonEventSubscriberManager commonEventSubscriberManager;
    auto result = commonEventSubscriberManager.InsertSubscriber(
        subscribeInfoPtr, commonEventListener, curTime, eventRecordInfo_);
    EXPECT_NE(nullptr, result);
    // clear frozen events
    std::map<uid_t, FrozenRecords> allFrozenRecords = commonEventSubscriberManager.GetAllFrozenEvents();
    size_t expectSize = 0;
    EXPECT_EQ(expectSize, allFrozenRecords.size());
    // make SubscriberRecordPtr
    SubscriberRecordPtr eventSubscriberRecord = std::make_shared<EventSubscriberRecord>();
    eventSubscriberRecord->eventSubscribeInfo = subscribeInfoPtr;
    eventSubscriberRecord->commonEventListener = commonEventListener;
    eventSubscriberRecord->eventRecordInfo = eventRecordInfo_;
    eventSubscriberRecord->isFreeze = true;
    // make commonEventData
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    // make commonEventPublishInfo
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    // make commonEventRecord
    CommonEventRecord commonEventRecord;
    commonEventRecord.commonEventData = commonEventData;
    commonEventRecord.publishInfo = publishInfo;
    commonEventRecord.eventRecordInfo = eventRecordInfo_;
    // insert frozen events
    commonEventSubscriberManager.InsertFrozenEvents(eventSubscriberRecord, commonEventRecord);
    commonEventSubscriberManager.InsertFrozenEvents(eventSubscriberRecord, commonEventRecord);
    std::map<uid_t, FrozenRecords> allFrozenRecords1 = commonEventSubscriberManager.GetAllFrozenEvents();
    expectSize = 1;
    EXPECT_EQ(expectSize, allFrozenRecords1.size());
    GTEST_LOG_(INFO)
        << "CommonEventFreezeUnitTest, CommonEventFreezeUnitTest_0400, TestSize.Level1 end";
}

/*
 * @tc.number: CommonEventFreezeUnitTest_0500
 * @tc.name: test CommonEventControlManager NotifyUnorderedEvent with frozen subscriber.
 */
HWTEST_F(CommonEventFreezeUnitTest, CommonEventFreezeUnitTest_0500,
    Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "CommonEventFreezeUnitTest, CommonEventFreezeUnitTest_0500, TestSize.Level1";
    // make subscriber info
    std::shared_ptr<CommonEventSubscribeInfo> subscribeInfoPtr =
        std::make_shared<CommonEventSubscribeInfo>(matchingSkills_);
    // make subscriber
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(*subscribeInfoPtr);
    // make common event listener
    OHOS::sptr<CommonEventListener> commonEventListener = new CommonEventListener(subscriber);
    // make eventSubscriberRecord
    SubscriberRecordPtr eventSubscriberRecord = std::make_shared<EventSubscriberRecord>();
    eventSubscriberRecord->eventSubscribeInfo = subscribeInfoPtr;
    eventSubscriberRecord->commonEventListener = commonEventListener;
    eventSubscriberRecord->eventRecordInfo = eventRecordInfo_;
    eventSubscriberRecord->isFreeze = true;
    // make commonEventData
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    // make publishInfo
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    // make eventRecord
    std::shared_ptr<OrderedEventRecord> eventRecord = std::make_shared<OrderedEventRecord>();
    eventRecord->commonEventData = commonEventData;
    eventRecord->publishInfo = publishInfo;
    eventRecord->resultTo = nullptr;
    eventRecord->state = OrderedEventRecord::IDLE;
    eventRecord->nextReceiver = 0;
    eventRecord->receivers.emplace_back(eventSubscriberRecord);
    eventRecord->deliveryState.emplace_back(OrderedEventRecord::PENDING);
    // NotifyUnorderedEvent
    CommonEventControlManager controlManager;
    controlManager.NotifyUnorderedEvent(eventRecord);
    EXPECT_EQ(OrderedEventRecord::DeliveryState::SKIPPED, eventRecord->deliveryState[0]);
    GTEST_LOG_(INFO)
        << "CommonEventFreezeUnitTest, CommonEventFreezeUnitTest_0500, TestSize.Level1 end";
}

/*
 * @tc.number: CommonEventFreezeUnitTest_0600
 * @tc.name: test CommonEventControlManager NotifyUnorderedEvent without frozen subscriber.
 */
HWTEST_F(CommonEventFreezeUnitTest, CommonEventFreezeUnitTest_0600,
    Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "CommonEventFreezeUnitTest, CommonEventFreezeUnitTest_0600, TestSize.Level1";
    // make subscribeInfoPtr
    std::shared_ptr<CommonEventSubscribeInfo> subscribeInfoPtr =
        std::make_shared<CommonEventSubscribeInfo>(matchingSkills_);
    // make subscriber
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(*subscribeInfoPtr);
    // make commonEventListener
    OHOS::sptr<CommonEventListener> commonEventListener = new CommonEventListener(subscriber);
    // make eventSubscriberRecord
    SubscriberRecordPtr eventSubscriberRecord = std::make_shared<EventSubscriberRecord>();
    eventSubscriberRecord->eventSubscribeInfo = subscribeInfoPtr;
    eventSubscriberRecord->commonEventListener = commonEventListener;
    eventSubscriberRecord->eventRecordInfo = eventRecordInfo_;
    eventSubscriberRecord->isFreeze = false;
    // make commonEventData
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    // make publishInfo
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    // make eventRecord
    std::shared_ptr<OrderedEventRecord> eventRecord = std::make_shared<OrderedEventRecord>();
    eventRecord->commonEventData = commonEventData;
    eventRecord->publishInfo = publishInfo;
    eventRecord->resultTo = nullptr;
    eventRecord->state = OrderedEventRecord::IDLE;
    eventRecord->nextReceiver = 0;
    eventRecord->receivers.emplace_back(eventSubscriberRecord);
    eventRecord->deliveryState.emplace_back(OrderedEventRecord::PENDING);
    // NotifyUnorderedEvent
    CommonEventControlManager controlManager;
    controlManager.NotifyUnorderedEvent(eventRecord);
    EXPECT_NE(OrderedEventRecord::DeliveryState::SKIPPED, eventRecord->deliveryState[0]);
    GTEST_LOG_(INFO)
        << "CommonEventFreezeUnitTest, CommonEventFreezeUnitTest_0600, TestSize.Level1 end";
}

/*
 * @tc.number: CommonEventFreezeUnitTest_0700
 * @tc.name: test CommonEventControlManager NotifyOrderedEvent with frozen subscriber.
 */
HWTEST_F(CommonEventFreezeUnitTest, CommonEventFreezeUnitTest_0700,
    Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "CommonEventFreezeUnitTest, CommonEventFreezeUnitTest_0700, TestSize.Level1";
    // make subscribeInfoPtr
    std::shared_ptr<CommonEventSubscribeInfo> subscribeInfoPtr =
        std::make_shared<CommonEventSubscribeInfo>(matchingSkills_);
    // make subscriber
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(*subscribeInfoPtr);
    // make commonEventListener
    OHOS::sptr<CommonEventListener> commonEventListener = new CommonEventListener(subscriber);
    // make eventSubscriberRecord
    SubscriberRecordPtr eventSubscriberRecord = std::make_shared<EventSubscriberRecord>();
    eventSubscriberRecord->eventSubscribeInfo = subscribeInfoPtr;
    eventSubscriberRecord->commonEventListener = commonEventListener;
    eventSubscriberRecord->eventRecordInfo = eventRecordInfo_;
    eventSubscriberRecord->isFreeze = true;
    // make commonEventData
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    // make publishInfo
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    // make eventRecord
    std::shared_ptr<OrderedEventRecord> eventRecord = std::make_shared<OrderedEventRecord>();
    eventRecord->commonEventData = commonEventData;
    eventRecord->publishInfo = publishInfo;
    eventRecord->resultTo = nullptr;
    eventRecord->state = OrderedEventRecord::IDLE;
    eventRecord->nextReceiver = 0;
    eventRecord->receivers.emplace_back(eventSubscriberRecord);
    eventRecord->deliveryState.emplace_back(OrderedEventRecord::PENDING);
    // NotifyOrderedEvent
    CommonEventControlManager controlManager;
    controlManager.NotifyOrderedEvent(eventRecord, 0);
    EXPECT_EQ(OrderedEventRecord::DeliveryState::SKIPPED, eventRecord->deliveryState[0]);
    GTEST_LOG_(INFO)
        << "CommonEventFreezeUnitTest, CommonEventFreezeUnitTest_0700, TestSize.Level1 end";
}

/*
 * @tc.number: CommonEventFreezeUnitTest_0800
 * @tc.name: test CommonEventControlManager NotifyOrderedEvent without frozen subscriber.
 */
HWTEST_F(CommonEventFreezeUnitTest, CommonEventFreezeUnitTest_0800,
    Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "CommonEventFreezeUnitTest, CommonEventFreezeUnitTest_0800, TestSize.Level1";
    // make subscribeInfoPtr
    std::shared_ptr<CommonEventSubscribeInfo> subscribeInfoPtr =
        std::make_shared<CommonEventSubscribeInfo>(matchingSkills_);
    // make subscriber
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(*subscribeInfoPtr);
    // make commonEventListener
    OHOS::sptr<CommonEventListener> commonEventListener = new CommonEventListener(subscriber);
    // make eventSubscriberRecord
    SubscriberRecordPtr eventSubscriberRecord = std::make_shared<EventSubscriberRecord>();
    eventSubscriberRecord->eventSubscribeInfo = subscribeInfoPtr;
    eventSubscriberRecord->commonEventListener = commonEventListener;
    eventSubscriberRecord->eventRecordInfo = eventRecordInfo_;
    eventSubscriberRecord->isFreeze = false;
    // make commonEventData
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    // make publishInfo
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    // make eventRecord
    std::shared_ptr<OrderedEventRecord> eventRecord = std::make_shared<OrderedEventRecord>();
    eventRecord->commonEventData = commonEventData;
    eventRecord->publishInfo = publishInfo;
    eventRecord->resultTo = nullptr;
    eventRecord->state = OrderedEventRecord::IDLE;
    eventRecord->nextReceiver = 0;
    eventRecord->receivers.emplace_back(eventSubscriberRecord);
    eventRecord->deliveryState.emplace_back(OrderedEventRecord::PENDING);
    // NotifyOrderedEvent
    CommonEventControlManager controlManager;
    controlManager.NotifyOrderedEvent(eventRecord, 0);
    EXPECT_NE(OrderedEventRecord::DeliveryState::SKIPPED, eventRecord->deliveryState[0]);
    GTEST_LOG_(INFO)
        << "CommonEventFreezeUnitTest, CommonEventFreezeUnitTest_0800, TestSize.Level1 end";
}
}  // namespace
