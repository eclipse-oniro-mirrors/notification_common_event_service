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

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
namespace OHOS {
namespace EventFwk {

class CommonEventControlManagerTest : public testing::Test {
public:
    CommonEventControlManagerTest()
    {}
    ~CommonEventControlManagerTest()
    {}

    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void CommonEventControlManagerTest::SetUpTestCase(void)
{}

void CommonEventControlManagerTest::TearDownTestCase(void)
{}

void CommonEventControlManagerTest::SetUp(void)
{}

void CommonEventControlManagerTest::TearDown(void)
{}

/**
 * @tc.name: CommonEventControlManager_0100
 * @tc.desc: test PublishStickyCommonEvent function and subscriberRecord is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerTest, CommonEventControlManager_0100, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_0100 start";
    CommonEventControlManager commonEventControlManager;
    CommonEventRecord eventRecord;
    std::shared_ptr<EventSubscriberRecord> subscriberRecord = nullptr;
    bool sticky = commonEventControlManager.PublishStickyCommonEvent(eventRecord, subscriberRecord);
    EXPECT_EQ(false, sticky);
    GTEST_LOG_(INFO) << "CommonEventControlManager_0100 end";
}

/**
 * @tc.name: CommonEventControlManager_0200
 * @tc.desc: test NotifyUnorderedEvent function and eventRecord is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerTest, CommonEventControlManager_0200, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_0200 start";
    CommonEventControlManager commonEventControlManager;
    std::shared_ptr<OrderedEventRecord> eventRecord = nullptr;
    bool sticky = commonEventControlManager.NotifyUnorderedEvent(eventRecord);
    EXPECT_EQ(false, sticky);
    GTEST_LOG_(INFO) << "CommonEventControlManager_0200 end";
}

/**
 * @tc.name: CommonEventControlManager_0300
 * @tc.desc: test EnqueueUnorderedRecord function and eventRecordPtr is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerTest, CommonEventControlManager_0300, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_0300 start";
    CommonEventControlManager commonEventControlManager;
    std::shared_ptr<OrderedEventRecord> eventRecordPtr = nullptr;
    bool sticky = commonEventControlManager.EnqueueUnorderedRecord(eventRecordPtr);
    EXPECT_EQ(false, sticky);
    GTEST_LOG_(INFO) << "CommonEventControlManager_0300 end";
}

/**
 * @tc.name: CommonEventControlManager_0500
 * @tc.desc: test NotifyOrderedEvent function and eventRecordPtr is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerTest, CommonEventControlManager_0500, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_0500 start";
    CommonEventControlManager commonEventControlManager;
    std::shared_ptr<OrderedEventRecord> eventRecordPtr = nullptr;
    size_t index = 1;
    EXPECT_EQ(false, commonEventControlManager.NotifyOrderedEvent(eventRecordPtr, index));
    GTEST_LOG_(INFO) << "CommonEventControlManager_0500 end";
}

/**
 * @tc.name: CommonEventControlManager_0600
 * @tc.desc: test NotifyOrderedEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerTest, CommonEventControlManager_0600, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_0600 start";
    CommonEventControlManager commonEventControlManager;
    std::shared_ptr<OrderedEventRecord> eventRecordPtr = std::make_shared<OrderedEventRecord>();
    size_t index = -1;
    EXPECT_EQ(false, commonEventControlManager.NotifyOrderedEvent(eventRecordPtr, index));
    GTEST_LOG_(INFO) << "CommonEventControlManager_0600 end";
}

/**
 * @tc.name: CommonEventControlManager_0700
 * @tc.desc: test NotifyOrderedEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerTest, CommonEventControlManager_0700, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_0700 start";
    CommonEventControlManager commonEventControlManager;
    std::shared_ptr<OrderedEventRecord> eventRecordPtr = std::make_shared<OrderedEventRecord>();
    size_t index = 0;
    EXPECT_EQ(false, commonEventControlManager.NotifyOrderedEvent(eventRecordPtr, index));
    GTEST_LOG_(INFO) << "CommonEventControlManager_0700 end";
}

/**
 * @tc.name: CommonEventControlManager_0800
 * @tc.desc: test SetTimeout function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerTest, CommonEventControlManager_0800, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_0800 start";
    CommonEventControlManager commonEventControlManager;
    commonEventControlManager.pendingTimeoutMessage_ = true;
    EXPECT_EQ(true, commonEventControlManager.SetTimeout());
    GTEST_LOG_(INFO) << "CommonEventControlManager_0800 end";
}

/**
 * @tc.name: CommonEventControlManager_0900
 * @tc.desc: test FinishReceiverAction function and recordPtr is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerTest, CommonEventControlManager_0900, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_0900 start";
    CommonEventControlManager commonEventControlManager;
    std::shared_ptr<OrderedEventRecord> recordPtr = nullptr;
    int32_t code = 1;
    std::string receiverData = "aa";
    bool abortEvent = false;
    EXPECT_EQ(false, commonEventControlManager.FinishReceiverAction(recordPtr, code, receiverData, abortEvent));
    GTEST_LOG_(INFO) << "CommonEventControlManager_0900 end";
}

/**
 * @tc.name: CommonEventControlManager_1300
 * @tc.desc: test GetUnorderedEventRecords function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerTest, CommonEventControlManager_1300, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_1300 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::string event = "";
    int32_t userId = ALL_USER;
    std::vector<std::shared_ptr<OrderedEventRecord>> records;
    commonEventControlManager->GetUnorderedEventRecords(event, userId, records);
    GTEST_LOG_(INFO) << "CommonEventControlManager_1300 end";
}

/**
 * @tc.name: CommonEventControlManager_1400
 * @tc.desc: test GetUnorderedEventRecords function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerTest, CommonEventControlManager_1400, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_1400 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::string event = "";
    int32_t userId = ALL_USER + 1;
    std::vector<std::shared_ptr<OrderedEventRecord>> records;
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    record->userId = ALL_USER + 1;
    commonEventControlManager->unorderedEventQueue_.emplace_back(record);
    commonEventControlManager->GetUnorderedEventRecords(event, userId, records);
    GTEST_LOG_(INFO) << "CommonEventControlManager_1400 end";
}

/**
 * @tc.name: CommonEventControlManager_1500
 * @tc.desc: test GetUnorderedEventRecords function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerTest, CommonEventControlManager_1500, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_1500 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::string event = "";
    int32_t userId = ALL_USER + 1;
    std::vector<std::shared_ptr<OrderedEventRecord>> records;
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    record->userId = ALL_USER + 2;
    commonEventControlManager->unorderedEventQueue_.emplace_back(record);
    commonEventControlManager->GetUnorderedEventRecords(event, userId, records);
    GTEST_LOG_(INFO) << "CommonEventControlManager_1500 end";
}

/**
 * @tc.name: CommonEventControlManager_1600
 * @tc.desc: test GetUnorderedEventRecords function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerTest, CommonEventControlManager_1600, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_1600 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::string event = "aa";
    int32_t userId = ALL_USER;
    std::vector<std::shared_ptr<OrderedEventRecord>> records;
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    record->commonEventData = commonEventData;
    commonEventControlManager->unorderedEventQueue_.emplace_back(record);
    commonEventControlManager->GetUnorderedEventRecords(event, userId, records);
    GTEST_LOG_(INFO) << "CommonEventControlManager_1600 end";
}

/**
 * @tc.name: CommonEventControlManager_1700
 * @tc.desc: test GetUnorderedEventRecords function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerTest, CommonEventControlManager_1700, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_1700 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::string event = "aa";
    int32_t userId = ALL_USER + 1;
    std::vector<std::shared_ptr<OrderedEventRecord>> records;
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    record->commonEventData = commonEventData;
    record->userId = ALL_USER + 1;
    commonEventControlManager->unorderedEventQueue_.emplace_back(record);
    commonEventControlManager->GetUnorderedEventRecords(event, userId, records);
    GTEST_LOG_(INFO) << "CommonEventControlManager_1700 end";
}

/**
 * @tc.name: CommonEventControlManager_1800
 * @tc.desc: test GetUnorderedEventRecords function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerTest, CommonEventControlManager_1800, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_1800 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::string event = "aa";
    int32_t userId = ALL_USER + 1;
    std::vector<std::shared_ptr<OrderedEventRecord>> records;
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    record->commonEventData = commonEventData;
    record->userId = ALL_USER;
    commonEventControlManager->unorderedEventQueue_.emplace_back(record);
    commonEventControlManager->GetUnorderedEventRecords(event, userId, records);
    GTEST_LOG_(INFO) << "CommonEventControlManager_1800 end";
}

/**
 * @tc.name: CommonEventControlManager_1900
 * @tc.desc: test GetOrderedEventRecords function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerTest, CommonEventControlManager_1900, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_1900 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::string event = "";
    int32_t userId = ALL_USER;
    std::vector<std::shared_ptr<OrderedEventRecord>> records;
    commonEventControlManager->GetOrderedEventRecords(event, userId, records);
    GTEST_LOG_(INFO) << "CommonEventControlManager_1900 end";
}

/**
 * @tc.name: CommonEventControlManager_2000
 * @tc.desc: test GetOrderedEventRecords function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerTest, CommonEventControlManager_2000, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_2000 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::string event = "";
    int32_t userId = ALL_USER + 1;
    std::vector<std::shared_ptr<OrderedEventRecord>> records;
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    record->userId = ALL_USER + 1;
    commonEventControlManager->unorderedEventQueue_.emplace_back(record);
    commonEventControlManager->GetOrderedEventRecords(event, userId, records);
    GTEST_LOG_(INFO) << "CommonEventControlManager_2000 end";
}

/**
 * @tc.name: CommonEventControlManager_2100
 * @tc.desc: test GetOrderedEventRecords function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerTest, CommonEventControlManager_2100, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_2100 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::string event = "";
    int32_t userId = ALL_USER + 1;
    std::vector<std::shared_ptr<OrderedEventRecord>> records;
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    record->userId = ALL_USER + 2;
    commonEventControlManager->unorderedEventQueue_.emplace_back(record);
    commonEventControlManager->GetOrderedEventRecords(event, userId, records);
    GTEST_LOG_(INFO) << "CommonEventControlManager_2100 end";
}

/**
 * @tc.name: CommonEventControlManager_2200
 * @tc.desc: test GetOrderedEventRecords function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerTest, CommonEventControlManager_2200, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_2200 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::string event = "aa";
    int32_t userId = ALL_USER;
    std::vector<std::shared_ptr<OrderedEventRecord>> records;
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    record->commonEventData = commonEventData;
    commonEventControlManager->unorderedEventQueue_.emplace_back(record);
    commonEventControlManager->GetOrderedEventRecords(event, userId, records);
    GTEST_LOG_(INFO) << "CommonEventControlManager_2200 end";
}

/**
 * @tc.name: CommonEventControlManager_2300
 * @tc.desc: test GetOrderedEventRecords function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerTest, CommonEventControlManager_2300, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_2300 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::string event = "aa";
    int32_t userId = ALL_USER + 1;
    std::vector<std::shared_ptr<OrderedEventRecord>> records;
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    record->commonEventData = commonEventData;
    record->userId = ALL_USER + 1;
    commonEventControlManager->unorderedEventQueue_.emplace_back(record);
    commonEventControlManager->GetOrderedEventRecords(event, userId, records);
    GTEST_LOG_(INFO) << "CommonEventControlManager_2300 end";
}

/**
 * @tc.name: CommonEventControlManager_2400
 * @tc.desc: test GetOrderedEventRecords function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventControlManagerTest, CommonEventControlManager_2400, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_2400 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    std::string event = "aa";
    int32_t userId = ALL_USER + 1;
    std::vector<std::shared_ptr<OrderedEventRecord>> records;
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    record->commonEventData = commonEventData;
    record->userId = ALL_USER + 2;
    commonEventControlManager->unorderedEventQueue_.emplace_back(record);
    commonEventControlManager->GetOrderedEventRecords(event, userId, records);
    GTEST_LOG_(INFO) << "CommonEventControlManager_2400 end";
}

HWTEST_F(CommonEventControlManagerTest, CanLogUnorderedEvent_ShouldReturnTrue_WhenEventNotInCache, Level1) {
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    std::string testEvent = "test_event";
    EXPECT_TRUE(commonEventControlManager->CanLogUnorderedEvent(testEvent));
    EXPECT_EQ(commonEventControlManager->unorderedEventLogCache_.size(), 1);
    EXPECT_EQ(commonEventControlManager->unorderedEventLogCache_[0]->event_, testEvent);
    EXPECT_EQ(commonEventControlManager->unorderedEventLogCache_[0]->missingCount_, 0);
}

HWTEST_F(CommonEventControlManagerTest,
    CanLogUnorderedEvent_ShouldReturnTrueAndClearCache_WhenEventInCacheAndTimeout, Level1) {
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    std::string testEvent = "test_event";
    auto now = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
    auto oldCache = std::make_shared<CommonEventControlManager::EventLogCache>(testEvent,
        now - std::chrono::seconds(11), 5);
    commonEventControlManager->unorderedEventLogCache_.push_back(oldCache);
    
    EXPECT_TRUE(commonEventControlManager->CanLogUnorderedEvent(testEvent));
    EXPECT_EQ(commonEventControlManager->unorderedEventLogCache_.size(), 1);
}

HWTEST_F(CommonEventControlManagerTest,
    CanLogUnorderedEvent_ShouldReturnFalseAndIncreaseSuppressed_WhenEventInCacheAndNotTimeout, Level1) {
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    std::string testEvent = "test_event";
    auto now = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
    auto oldCache = std::make_shared<CommonEventControlManager::EventLogCache>(testEvent,
        now - std::chrono::milliseconds(9), 5);
    commonEventControlManager->unorderedEventLogCache_.push_back(oldCache);
    
    EXPECT_FALSE(commonEventControlManager->CanLogUnorderedEvent(testEvent));
    EXPECT_EQ(commonEventControlManager->unorderedEventLogCache_.size(), 1);
    EXPECT_EQ(commonEventControlManager->unorderedEventLogCache_[0]->missingCount_, 6);
}

HWTEST_F(CommonEventControlManagerTest, CanLogUnorderedEvent_ShouldHandleMultipleEventsCorrectly, Level1) {
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    std::string event1 = "event1";
    std::string event2 = "event2";
    auto now = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
    auto oldCache1 = std::make_shared<CommonEventControlManager::EventLogCache>(event1,
        now - std::chrono::seconds(11), 5);
    auto oldCache2 = std::make_shared<CommonEventControlManager::EventLogCache>(event2,
        now - std::chrono::milliseconds(9), 5);
    commonEventControlManager->unorderedEventLogCache_.push_back(oldCache1);
    commonEventControlManager->unorderedEventLogCache_.push_back(oldCache2);
    
    EXPECT_TRUE(commonEventControlManager->CanLogUnorderedEvent(event1));
    EXPECT_EQ(commonEventControlManager->unorderedEventLogCache_.size(), 2);
    EXPECT_EQ(commonEventControlManager->unorderedEventLogCache_[0]->event_, event1);
    EXPECT_EQ(commonEventControlManager->unorderedEventLogCache_[0]->missingCount_, 0);
    
    EXPECT_FALSE(commonEventControlManager->CanLogUnorderedEvent(event2));
    EXPECT_EQ(commonEventControlManager->unorderedEventLogCache_.size(), 2);
    EXPECT_EQ(commonEventControlManager->unorderedEventLogCache_[1]->event_, event2);
    EXPECT_EQ(commonEventControlManager->unorderedEventLogCache_[1]->missingCount_, 6);
}

HWTEST_F(CommonEventControlManagerTest, CanLogUnorderedEvent_ShouldClearOtherEvents_WhenAllEventTimeout, Level1) {
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    std::string event1 = "event1";
    std::string event2 = "event2";
    auto now = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());

    auto oldCache1 = std::make_shared<CommonEventControlManager::EventLogCache>(event1,
        now - std::chrono::seconds(11), 5);
    auto oldCache2 = std::make_shared<CommonEventControlManager::EventLogCache>(event2,
        now - std::chrono::seconds(9), 5);
    commonEventControlManager->unorderedEventLogCache_.push_back(oldCache1);
    commonEventControlManager->unorderedEventLogCache_.push_back(oldCache2);

    EXPECT_TRUE(commonEventControlManager->CanLogUnorderedEvent(event1));
    EXPECT_EQ(commonEventControlManager->unorderedEventLogCache_.size(), 1);
    EXPECT_EQ(commonEventControlManager->unorderedEventLogCache_[0]->event_, event1);
    EXPECT_EQ(commonEventControlManager->unorderedEventLogCache_[0]->missingCount_, 0);
}
}
}
