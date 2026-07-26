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
#include <numeric>
#define private public
#include "common_event_control_manager.h"
#undef private
#include "mock_common_event_stub.h"

extern void MockGetAction(bool mockRet);

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace EventFwk {

class CommonEventControlManagerBranchTest : public testing::Test {
public:
    CommonEventControlManagerBranchTest()
    {}
    ~CommonEventControlManagerBranchTest()
    {}

    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void CommonEventControlManagerBranchTest::SetUpTestCase(void)
{}

void CommonEventControlManagerBranchTest::TearDownTestCase(void)
{}

void CommonEventControlManagerBranchTest::SetUp(void)
{}

void CommonEventControlManagerBranchTest::TearDown(void)
{}

/**
 * @tc.name: CommonEventControlManager_0100
 * @tc.desc: test PublishStickyCommonEvent function record.first is nullptr and record.second is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_0100, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_0100 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::map<EventSubscriberRecord, std::vector<std::shared_ptr<CommonEventRecord>>> frozenRecords;
    EventSubscriberRecord rec;
    std::vector<std::shared_ptr<CommonEventRecord>> com;
    std::shared_ptr<CommonEventRecord> eve = nullptr;
    com.emplace_back(eve);
    frozenRecords.emplace(rec, com);
    commonEventControlManager->PublishFrozenEventsInner(frozenRecords);
    GTEST_LOG_(INFO) << "CommonEventControlManager_0100 end";
}

/**
 * @tc.name: CommonEventControlManager_0600
 * @tc.desc: test NotifyFreezeEvents and CheckPermission is OrderedEventRecord::SKIPPED.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_0600, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_0600 start";
    CommonEventControlManager commonEventControlManager;
    EventSubscriberRecord subscriberRecord;
    std::shared_ptr<CommonEventSubscribeInfo> eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>();
    subscriberRecord.eventSubscribeInfo = eventSubscribeInfo;
    subscriberRecord.eventRecordInfo.isProxy = true;
    subscriberRecord.eventRecordInfo.isSubsystem = true;
    subscriberRecord.eventRecordInfo.isSystemApp = true;
    subscriberRecord.commonEventListener = sptr<IRemoteObject>(new MockCommonEventStub());
    CommonEventRecord eventRecord;
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    eventRecord.commonEventData = commonEventData;
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    eventRecord.publishInfo = publishInfo;
    EXPECT_EQ(false, commonEventControlManager.NotifyFreezeEvents(subscriberRecord, eventRecord));
    GTEST_LOG_(INFO) << "CommonEventControlManager_0600 end";
}

/**
 * @tc.name: CommonEventControlManager_0700
 * @tc.desc: test FinishReceiverAction and doNext is false.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_0700, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_0700 start";
    CommonEventControlManager commonEventControlManager;
    std::shared_ptr<OrderedEventRecord> recordPtr = std::make_shared<OrderedEventRecord>();
    recordPtr->state = OrderedEventRecord::IDLE;
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    recordPtr->commonEventData = commonEventData;
    int32_t code = 1;
    std::string receiverData = "aa";
    bool abortEvent = true;
    EXPECT_EQ(true, commonEventControlManager.FinishReceiverAction(recordPtr, code, receiverData, abortEvent));
    GTEST_LOG_(INFO) << "CommonEventControlManager_0700 end";
}


/**
 * @tc.name: CommonEventControlManager_1000
 * @tc.desc: test GetUnorderedEventRecords and GetAction == event.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_1000, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_1000 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::vector<std::shared_ptr<OrderedEventRecord>> records;
    std::shared_ptr<OrderedEventRecord> rec = std::make_shared<OrderedEventRecord>();
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    rec->commonEventData = commonEventData;
    commonEventControlManager->unorderedEventQueue_.emplace_back(rec);
    std::string event = "aa";
    int32_t userId = ALL_USER;
    // set GetAction == event
    MockGetAction(false);
    commonEventControlManager->GetUnorderedEventRecords(event, userId, records);
    GTEST_LOG_(INFO) << "CommonEventControlManager_1000 end";
}

/**
 * @tc.name: CommonEventControlManager_1100
 * @tc.desc: test GetUnorderedEventRecords and GetAction == event and vec->userId == userId.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_1100, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_1100 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::vector<std::shared_ptr<OrderedEventRecord>> records;
    std::shared_ptr<OrderedEventRecord> rec = std::make_shared<OrderedEventRecord>();
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    rec->commonEventData = commonEventData;
    rec->userId = 100;
    commonEventControlManager->unorderedEventQueue_.emplace_back(rec);
    std::string event = "aa";
    int32_t userId = 100;
    // set GetAction == event
    MockGetAction(false);
    commonEventControlManager->GetUnorderedEventRecords(event, userId, records);
    GTEST_LOG_(INFO) << "CommonEventControlManager_1100 end";
}

/**
 * @tc.name: CommonEventControlManager_1200
 * @tc.desc: test GetUnorderedEventRecords and GetAction != event and vec->userId != userId.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_1200, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_1200 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::vector<std::shared_ptr<OrderedEventRecord>> records;
    std::shared_ptr<OrderedEventRecord> rec = std::make_shared<OrderedEventRecord>();
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    rec->commonEventData = commonEventData;
    rec->userId = 99;
    commonEventControlManager->unorderedEventQueue_.emplace_back(rec);
    std::string event = "aa";
    int32_t userId = 100;
    // set GetAction != event
    MockGetAction(true);
    commonEventControlManager->GetUnorderedEventRecords(event, userId, records);
    GTEST_LOG_(INFO) << "CommonEventControlManager_1200 end";
}

/**
 * @tc.name: CommonEventControlManager_1300
 * @tc.desc: test GetOrderedEventRecords and vec->userId != userId.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_1300, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_1300 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::vector<std::shared_ptr<OrderedEventRecord>> records;
    std::shared_ptr<OrderedEventRecord> rec = std::make_shared<OrderedEventRecord>();
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    rec->commonEventData = commonEventData;
    rec->userId = 99;
    commonEventControlManager->orderedEventQueue_.emplace_back(rec);
    std::string event = "";
    int32_t userId = 100;
    commonEventControlManager->GetOrderedEventRecords(event, userId, records);
    GTEST_LOG_(INFO) << "CommonEventControlManager_1300 end";
}

/**
 * @tc.name: CommonEventControlManager_1400
 * @tc.desc: test GetOrderedEventRecords and vec->userId == userId.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_1400, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_1400 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::vector<std::shared_ptr<OrderedEventRecord>> records;
    std::shared_ptr<OrderedEventRecord> rec = std::make_shared<OrderedEventRecord>();
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    rec->commonEventData = commonEventData;
    rec->userId = 100;
    commonEventControlManager->orderedEventQueue_.emplace_back(rec);
    std::string event = "";
    int32_t userId = 100;
    commonEventControlManager->GetOrderedEventRecords(event, userId, records);
    GTEST_LOG_(INFO) << "CommonEventControlManager_1400 end";
}

/**
 * @tc.name: CommonEventControlManager_1500
 * @tc.desc: test GetOrderedEventRecords and GetAction == event.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_1500, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_1500 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::vector<std::shared_ptr<OrderedEventRecord>> records;
    std::shared_ptr<OrderedEventRecord> rec = std::make_shared<OrderedEventRecord>();
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    rec->commonEventData = commonEventData;
    rec->userId = 100;
    commonEventControlManager->orderedEventQueue_.emplace_back(rec);
    std::string event = "aa";
    int32_t userId = ALL_USER;
    // set GetAction == event
    MockGetAction(false);
    commonEventControlManager->GetOrderedEventRecords(event, userId, records);
    GTEST_LOG_(INFO) << "CommonEventControlManager_1500 end";
}

/**
 * @tc.name: CommonEventControlManager_1600
 * @tc.desc: test GetOrderedEventRecords and GetAction != event.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_1600, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_1600 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::vector<std::shared_ptr<OrderedEventRecord>> records;
    std::shared_ptr<OrderedEventRecord> rec = std::make_shared<OrderedEventRecord>();
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    rec->commonEventData = commonEventData;
    rec->userId = 100;
    commonEventControlManager->orderedEventQueue_.emplace_back(rec);
    std::string event = "aa";
    int32_t userId = ALL_USER;
    // set GetAction != event
    MockGetAction(true);
    commonEventControlManager->GetOrderedEventRecords(event, userId, records);
    GTEST_LOG_(INFO) << "CommonEventControlManager_1600 end";
}

/**
 * @tc.name: CommonEventControlManager_1700
 * @tc.desc: test GetOrderedEventRecords and GetAction != event and GetAction != event.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_1700, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_1700 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::vector<std::shared_ptr<OrderedEventRecord>> records;
    std::shared_ptr<OrderedEventRecord> rec = std::make_shared<OrderedEventRecord>();
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    rec->commonEventData = commonEventData;
    rec->userId = 99;
    commonEventControlManager->orderedEventQueue_.emplace_back(rec);
    std::string event = "aa";
    int32_t userId = 100;
    // set GetAction != event
    MockGetAction(true);
    commonEventControlManager->GetOrderedEventRecords(event, userId, records);
    GTEST_LOG_(INFO) << "CommonEventControlManager_1700 end";
}

/**
 * @tc.name: CommonEventControlManager_1800
 * @tc.desc: test GetOrderedEventRecords and GetAction == event and GetAction == event.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_1800, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_1800 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::vector<std::shared_ptr<OrderedEventRecord>> records;
    std::shared_ptr<OrderedEventRecord> rec = std::make_shared<OrderedEventRecord>();
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    rec->commonEventData = commonEventData;
    rec->userId = 100;
    commonEventControlManager->orderedEventQueue_.emplace_back(rec);
    std::string event = "aa";
    int32_t userId = 100;
    // set GetAction == event
    MockGetAction(false);
    commonEventControlManager->GetOrderedEventRecords(event, userId, records);
    GTEST_LOG_(INFO) << "CommonEventControlManager_1800 end";
}
#ifdef CEM_SUPPORT_DUMP
/**
 * @tc.name: CommonEventControlManager_2200
 * @tc.desc: test DumpStateByCommonEventRecord and record->userId is UNDEFINED_USER.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_2200, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_2200 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    record->userId = UNDEFINED_USER;
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    record->publishInfo = publishInfo;
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    record->commonEventData = commonEventData;
    std::string dumpInfo = "aa";
    commonEventControlManager->DumpStateByCommonEventRecord(record, dumpInfo);
    GTEST_LOG_(INFO) << "CommonEventControlManager_2200 end";
}

/**
 * @tc.name: CommonEventControlManager_2300
 * @tc.desc: test DumpStateByCommonEventRecord and record->userId is default.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_2300, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_2300 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    record->userId = 100;
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    record->publishInfo = publishInfo;
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    record->commonEventData = commonEventData;
    std::string dumpInfo = "aa";
    commonEventControlManager->DumpStateByCommonEventRecord(record, dumpInfo);
    GTEST_LOG_(INFO) << "CommonEventControlManager_2300 end";
}

/**
 * @tc.name: CommonEventControlManager_2400
 * @tc.desc: test DumpStateByCommonEventRecord and permissionNum == 0 and permissionNum == 1.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_2400, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_2400 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    record->userId = 100;
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    record->publishInfo = publishInfo;
    // set subscriberPermissions_
    std::vector<std::string> subscriberPermissions;
    std::string bb = "bb";
    std::string cc = "cc";
    subscriberPermissions.emplace_back(bb);
    subscriberPermissions.emplace_back(cc);
    record->publishInfo->SetSubscriberPermissions(subscriberPermissions);
    // set record->commonEventData
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    record->commonEventData = commonEventData;
    std::string dumpInfo = "aa";
    // test DumpStateByCommonEventRecord
    commonEventControlManager->DumpStateByCommonEventRecord(record, dumpInfo);
    GTEST_LOG_(INFO) << "CommonEventControlManager_2400 end";
}

/**
 * @tc.name: CommonEventControlManager_2500
 * @tc.desc: test DumpStateByCommonEventRecord and record->publishInfo->IsSticky is true.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_2500, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_2500 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    record->userId = 100;
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    record->publishInfo = publishInfo;
    // set sticky_ is true
    record->publishInfo->SetSticky(true);
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    record->commonEventData = commonEventData;
    std::string dumpInfo = "aa";
    commonEventControlManager->DumpStateByCommonEventRecord(record, dumpInfo);
    GTEST_LOG_(INFO) << "CommonEventControlManager_2500 end";
}

/**
 * @tc.name: CommonEventControlManager_2600
 * @tc.desc: test DumpStateByCommonEventRecord and record->state is OrderedEventRecord::RECEIVING.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_2600, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_2600 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    record->userId = 100;
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    record->publishInfo = publishInfo;
    // set sticky_ is true
    record->publishInfo->SetSticky(true);
    record->state = OrderedEventRecord::RECEIVING;
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    record->commonEventData = commonEventData;
    std::string dumpInfo = "aa";
    commonEventControlManager->DumpStateByCommonEventRecord(record, dumpInfo);
    GTEST_LOG_(INFO) << "CommonEventControlManager_2600 end";
}

/**
 * @tc.name: CommonEventControlManager_2700
 * @tc.desc: test DumpStateByCommonEventRecord and record->state is default.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_2700, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_2700 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    record->userId = 100;
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    record->publishInfo = publishInfo;
    // set sticky_ is true
    record->publishInfo->SetSticky(true);
    record->state = 100;
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    record->commonEventData = commonEventData;
    std::string dumpInfo = "aa";
    commonEventControlManager->DumpStateByCommonEventRecord(record, dumpInfo);
    GTEST_LOG_(INFO) << "CommonEventControlManager_2700 end";
}

/**
 * @tc.name: CommonEventControlManager_3400
 * @tc.desc: test DumpStateBySubscriberRecord and record->receivers is empty.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_3400, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_3400 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    std::string dumpInfo = "aa";
    commonEventControlManager->DumpStateBySubscriberRecord(record, dumpInfo);
    GTEST_LOG_(INFO) << "CommonEventControlManager_3400 end";
}

/**
 * @tc.name: CommonEventControlManager_3500
 * @tc.desc: test DumpStateBySubscriberRecord and record->deliveryState[num - 1] is OrderedEventRecord::PENDING.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_3500, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_3500 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    // set record->receivers is not empty
    std::shared_ptr<EventSubscriberRecord> rec = std::make_shared<EventSubscriberRecord>();
    record->receivers.emplace_back(rec);
    // set record->deliveryState is OrderedEventRecord::PENDING
    record->deliveryState.emplace_back(OrderedEventRecord::PENDING);
    std::string dumpInfo = "aa";
    commonEventControlManager->DumpStateBySubscriberRecord(record, dumpInfo);
    GTEST_LOG_(INFO) << "CommonEventControlManager_3500 end";
}

/**
 * @tc.name: CommonEventControlManager_3600
 * @tc.desc: test DumpStateBySubscriberRecord and record->deliveryState[num - 1] is OrderedEventRecord::SKIPPED.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_3600, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_3600 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    // set record->receivers is not empty
    std::shared_ptr<EventSubscriberRecord> rec = std::make_shared<EventSubscriberRecord>();
    record->receivers.emplace_back(rec);
    // set record->deliveryState is OrderedEventRecord::SKIPPED
    record->deliveryState.emplace_back(OrderedEventRecord::SKIPPED);
    std::string dumpInfo = "aa";
    commonEventControlManager->DumpStateBySubscriberRecord(record, dumpInfo);
    GTEST_LOG_(INFO) << "CommonEventControlManager_3600 end";
}

/**
 * @tc.name: CommonEventControlManager_3700
 * @tc.desc: test DumpStateBySubscriberRecord and record->deliveryState[num - 1] is OrderedEventRecord::TIMEOUT.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_3700, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_3700 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    // set record->receivers is not empty
    std::shared_ptr<EventSubscriberRecord> rec = std::make_shared<EventSubscriberRecord>();
    record->receivers.emplace_back(rec);
    // set record->deliveryState is OrderedEventRecord::TIMEOUT
    record->deliveryState.emplace_back(OrderedEventRecord::TIMEOUT);
    std::string dumpInfo = "aa";
    commonEventControlManager->DumpStateBySubscriberRecord(record, dumpInfo);
    GTEST_LOG_(INFO) << "CommonEventControlManager_3700 end";
}

/**
 * @tc.name: CommonEventControlManager_3800
 * @tc.desc: test DumpStateBySubscriberRecord and record->deliveryState[num - 1] is default.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_3800, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_3800 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    // set record->receivers is not empty
    std::shared_ptr<EventSubscriberRecord> rec = std::make_shared<EventSubscriberRecord>();
    record->receivers.emplace_back(rec);
    // set record->deliveryState is default
    record->deliveryState.emplace_back(100);
    std::string dumpInfo = "aa";
    commonEventControlManager->DumpStateBySubscriberRecord(record, dumpInfo);
    GTEST_LOG_(INFO) << "CommonEventControlManager_3800 end";
}
#endif
/**
 * @tc.name: CommonEventControlManager_4200
 * @tc.desc: test SendOrderedEventProcTimeoutHiSysEvent and subscriberRecord is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_4200, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_4200 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::shared_ptr<EventSubscriberRecord> subscriberRecord = nullptr;
    std::string eventName = "aa";
    commonEventControlManager->SendOrderedEventProcTimeoutHiSysEvent(subscriberRecord, eventName);
    GTEST_LOG_(INFO) << "CommonEventControlManager_4200 end";
}

/**
 * @tc.name: CommonEventControlManager_4300
 * @tc.desc: test SendOrderedEventProcTimeoutHiSysEvent and subscriberRecord->eventSubscribeInfo != nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_4300, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_4300 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::shared_ptr<EventSubscriberRecord> subscriberRecord = std::make_shared<EventSubscriberRecord>();
    std::shared_ptr<CommonEventSubscribeInfo> eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>();
    subscriberRecord->eventSubscribeInfo = eventSubscribeInfo;
    std::string eventName = "aa";
    commonEventControlManager->SendOrderedEventProcTimeoutHiSysEvent(subscriberRecord, eventName);
    GTEST_LOG_(INFO) << "CommonEventControlManager_4300 end";
}

/**
 * @tc.name: CommonEventControlManager_4400
 * @tc.desc: test LogUnorderedEventResult with null eventRecord should not crash.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_4400, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_4400 start";
    std::shared_ptr<CommonEventControlManager> manager = std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, manager);
    std::shared_ptr<OrderedEventRecord> nullRecord = nullptr;
    int32_t succCnt = 0;
    int32_t failCnt = 0;
    int32_t freezeCnt = 0;
    std::string freezedPidsLogger;
    manager->LogUnorderedEventResult(nullRecord, succCnt, failCnt, freezeCnt, freezedPidsLogger);
    GTEST_LOG_(INFO) << "CommonEventControlManager_4400 end";
}

/**
 * @tc.name: CommonEventControlManager_4500
 * @tc.desc: test LogUnorderedEventResult with null commonEventData should not crash.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_4500, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_4500 start";
    std::shared_ptr<CommonEventControlManager> manager = std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, manager);
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    record->commonEventData = nullptr;
    int32_t succCnt = 0;
    int32_t failCnt = 0;
    int32_t freezeCnt = 0;
    std::string freezedPidsLogger;
    manager->LogUnorderedEventResult(record, succCnt, failCnt, freezeCnt, freezedPidsLogger);
    GTEST_LOG_(INFO) << "CommonEventControlManager_4500 end";
}

/**
 * @tc.name: CommonEventControlManager_4600
 * @tc.desc: test FinishReceiver with null commonEventData should return false.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_4600, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_4600 start";
    std::shared_ptr<CommonEventControlManager> manager = std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, manager);
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    record->commonEventData = nullptr;
    int32_t code = 0;
    std::string receiverData = "test";
    bool abortEvent = false;
    EXPECT_FALSE(manager->FinishReceiver(record, code, receiverData, abortEvent));
    GTEST_LOG_(INFO) << "CommonEventControlManager_4600 end";
}

/**
 * @tc.name: CommonEventControlManager_4700
 * @tc.desc: test HandleTimeoutReceiver with null commonEventData should not crash.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_4700, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_4700 start";
    std::shared_ptr<CommonEventControlManager> manager = std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, manager);
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    record->commonEventData = nullptr;
    int64_t nowSysTime = 0;
    manager->HandleTimeoutReceiver(record, nowSysTime);
    GTEST_LOG_(INFO) << "CommonEventControlManager_4700 end";
}

/**
 * @tc.name: CommonEventControlManager_4800
 * @tc.desc: test HandleFinalSubscriber with non-null resultTo but null commonEventData.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_4800, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_4800 start";
    std::shared_ptr<CommonEventControlManager> manager = std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, manager);
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    record->resultTo = sptr<IRemoteObject>(new MockCommonEventStub());
    record->commonEventData = nullptr;
    record->publishInfo = nullptr;
    bool result = manager->HandleFinalSubscriber(record);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "CommonEventControlManager_4800 end";
}

/**
 * @tc.name: CommonEventControlManager_4810
 * @tc.desc: test HandleOrderedNotifyResult with null eventRecordPtr should return false.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_4810, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_4810 start";
    std::shared_ptr<CommonEventControlManager> manager = std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, manager);
    std::shared_ptr<OrderedEventRecord> nullRecord = nullptr;
    bool result = manager->HandleOrderedNotifyResult(nullRecord, 0, OHOS::ERR_OK);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "CommonEventControlManager_4810 end";
}

/**
 * @tc.name: CommonEventControlManager_4820
 * @tc.desc: test HandleOrderedNotifyResult error path with null commonEventData (conditional log skip).
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_4820, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_4820 start";
    std::shared_ptr<CommonEventControlManager> manager = std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, manager);
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    record->commonEventData = nullptr;
    record->deliveryState.emplace_back(OrderedEventRecord::PENDING);
    record->receivers.emplace_back(std::make_shared<EventSubscriberRecord>());
    bool result = manager->HandleOrderedNotifyResult(record, 0, -1);
    EXPECT_FALSE(result);
    EXPECT_EQ(record->state.load(), OrderedEventRecord::SKIPPED);
    GTEST_LOG_(INFO) << "CommonEventControlManager_4820 end";
}

/**
 * @tc.name: CommonEventControlManager_4830
 * @tc.desc: test NotifySingleUnorderedSubscriber with null commonEventData should return false.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_4830, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_4830 start";
    std::shared_ptr<CommonEventControlManager> manager = std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, manager);
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    record->commonEventData = nullptr;
    record->publishInfo = nullptr;
    record->deliveryState.emplace_back(OrderedEventRecord::PENDING);
    std::shared_ptr<EventSubscriberRecord> vec = std::make_shared<EventSubscriberRecord>();
    vec->isFreeze = false;
    int32_t succCnt = 0;
    int32_t failCnt = 0;
    int32_t freezeCnt = 0;
    std::string freezedPidsLogger;
    bool result = manager->NotifySingleUnorderedSubscriber(record, vec, 0, succCnt, failCnt, freezeCnt,
        freezedPidsLogger);
    EXPECT_FALSE(result);
    EXPECT_EQ(1, failCnt);
    GTEST_LOG_(INFO) << "CommonEventControlManager_4830 end";
}

/**
 * @tc.name: CommonEventControlManager_4840
 * @tc.desc: test NotifySingleUnorderedSubscriber with isFreeze=true should call HandleFrozenUnorderedSubscriber.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_4840, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_4840 start";
    std::shared_ptr<CommonEventControlManager> manager = std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, manager);
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    std::shared_ptr<CommonEventData> data = std::make_shared<CommonEventData>();
    record->commonEventData = data;
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    record->publishInfo = publishInfo;
    record->deliveryState.emplace_back(OrderedEventRecord::PENDING);
    std::shared_ptr<EventSubscriberRecord> vec = std::make_shared<EventSubscriberRecord>();
    vec->isFreeze = true;
    int32_t succCnt = 0;
    int32_t failCnt = 0;
    int32_t freezeCnt = 0;
    std::string freezedPidsLogger;
    bool result = manager->NotifySingleUnorderedSubscriber(record, vec, 0, succCnt, failCnt, freezeCnt,
        freezedPidsLogger);
    EXPECT_TRUE(result);
    EXPECT_EQ(1, freezeCnt);
    GTEST_LOG_(INFO) << "CommonEventControlManager_4840 end";
}

/**
 * @tc.name: CommonEventControlManager_4900
 * @tc.desc: test NotifyOrderedEvent with null commonEventData should return false.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_4900, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_4900 start";
    std::shared_ptr<CommonEventControlManager> manager = std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, manager);
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    record->commonEventData = nullptr;
    record->publishInfo = nullptr;
    record->deliveryState.emplace_back(OrderedEventRecord::PENDING);
    record->receivers.emplace_back(std::make_shared<EventSubscriberRecord>());
    bool result = manager->NotifyOrderedEvent(record, 0);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "CommonEventControlManager_4900 end";
}

#ifdef CEM_SUPPORT_DUMP
/**
 * @tc.name: CommonEventControlManager_5000
 * @tc.desc: test DumpStateByCommonEventRecord with null record should not crash.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_5000, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_5000 start";
    std::shared_ptr<CommonEventControlManager> manager = std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, manager);
    std::shared_ptr<OrderedEventRecord> record = nullptr;
    std::string dumpInfo;
    manager->DumpStateByCommonEventRecord(record, dumpInfo);
    EXPECT_TRUE(dumpInfo.empty());
    GTEST_LOG_(INFO) << "CommonEventControlManager_5000 end";
}

/**
 * @tc.name: CommonEventControlManager_5100
 * @tc.desc: test DumpStateByCommonEventRecord with null publishInfo should not crash.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_5100, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_5100 start";
    std::shared_ptr<CommonEventControlManager> manager = std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, manager);
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    record->publishInfo = nullptr;
    record->commonEventData = nullptr;
    std::string dumpInfo;
    manager->DumpStateByCommonEventRecord(record, dumpInfo);
    EXPECT_TRUE(dumpInfo.empty());
    GTEST_LOG_(INFO) << "CommonEventControlManager_5100 end";
}

/**
 * @tc.name: CommonEventControlManager_5200
 * @tc.desc: test DumpStateByCommonEventRecord strftime fallback when recordTime is zero.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerBranchTest, CommonEventControlManager_5200, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_5200 start";
    std::shared_ptr<CommonEventControlManager> manager = std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, manager);
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    record->publishInfo = publishInfo;
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    record->commonEventData = commonEventData;
    struct tm zeroTime {0};
    record->recordTime = zeroTime;
    std::string dumpInfo;
    manager->DumpStateByCommonEventRecord(record, dumpInfo);
    EXPECT_FALSE(dumpInfo.empty());
    GTEST_LOG_(INFO) << "CommonEventControlManager_5200 end";
}
#endif

}
}
