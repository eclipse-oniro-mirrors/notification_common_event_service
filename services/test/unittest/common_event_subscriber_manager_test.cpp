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
#include "common_event.h"
#include "common_event_manager.h"
#include "common_event_sticky_manager.h"
#include "common_event_stub.h"
#include "common_event_subscriber_manager.h"
#include "inner_common_event_manager.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EventFwk;
using namespace OHOS::AppExecFwk;

class CommonEventSubscriberManagerTest : public testing::Test {
public:
    CommonEventSubscriberManagerTest()
    {}
    ~CommonEventSubscriberManagerTest()
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

void CommonEventSubscriberManagerTest::SetUpTestCase(void)
{}

void CommonEventSubscriberManagerTest::TearDownTestCase(void)
{}

void CommonEventSubscriberManagerTest::SetUp(void)
{}

void CommonEventSubscriberManagerTest::TearDown(void)
{}

/**
 * @tc.name: CommonEventSubscriberManager_0100
 * @tc.desc: test RemoveSubscriber function and commonEventListener is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventSubscriberManager_0100, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_0100 start";
    CommonEventSubscriberManager commonEventSubscriberManager;
    sptr<IRemoteObject> commonEventListener = nullptr;
    EXPECT_EQ(ERR_INVALID_VALUE, commonEventSubscriberManager.RemoveSubscriber(commonEventListener));
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_0100 end";
}

/**
 * @tc.name: CommonEventSubscriberManager_0200
 * @tc.desc: test RemoveSubscriber function and death_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventSubscriberManager_0200, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_0200 start";
    CommonEventSubscriberManager commonEventSubscriberManager;
    // set commonEventListener
    MatchingSkills matchingSkills_;
    CommonEventSubscribeInfo subscribeInfo(matchingSkills_);
    std::shared_ptr<DreivedSubscriber> subscriber = std::make_shared<DreivedSubscriber>(subscribeInfo);
    sptr<IRemoteObject> commonEventListener = new CommonEventListener(subscriber);
    commonEventSubscriberManager.death_ = nullptr;
    EXPECT_EQ(ERR_OK, commonEventSubscriberManager.RemoveSubscriber(commonEventListener));
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_0200 end";
}

/**
 * @tc.name: CommonEventSubscriberManager_0300
 * @tc.desc: test DumpDetailed function and record is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventSubscriberManager_0300, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_0300 start";
    std::shared_ptr<CommonEventSubscriberManager> commonEventSubscriberManager =
        std::make_shared<CommonEventSubscriberManager>();
    ASSERT_NE(nullptr, commonEventSubscriberManager);
    std::string title = "aa";
    SubscriberRecordPtr record = nullptr;
    std::string format = "aa";
    std::string dumpInfo = "aa";
    commonEventSubscriberManager->DumpDetailed(title, record, format, dumpInfo);
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_0300 end";
}

/**
 * @tc.name: CommonEventSubscriberManager_0400
 * @tc.desc: test DumpDetailed function and record->eventSubscribeInfo is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventSubscriberManager_0400, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_0400 start";
    std::shared_ptr<CommonEventSubscriberManager> commonEventSubscriberManager =
        std::make_shared<CommonEventSubscriberManager>();
    ASSERT_NE(nullptr, commonEventSubscriberManager);
    std::string title = "aa";
    SubscriberRecordPtr record = std::make_shared<EventSubscriberRecord>();
    record->eventSubscribeInfo = nullptr;
    std::string format = "aa";
    std::string dumpInfo = "aa";
    commonEventSubscriberManager->DumpDetailed(title, record, format, dumpInfo);
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_0400 end";
}

/**
 * @tc.name: CommonEventSubscriberManager_0500
 * @tc.desc: test DumpDetailed function and userId is UNDEFINED_USER.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventSubscriberManager_0500, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_0500 start";
    std::shared_ptr<CommonEventSubscriberManager> commonEventSubscriberManager =
        std::make_shared<CommonEventSubscriberManager>();
    ASSERT_NE(nullptr, commonEventSubscriberManager);
    std::string title = "aa";
    SubscriberRecordPtr record = std::make_shared<EventSubscriberRecord>();
    MatchingSkills matchingSkills_;
    record->eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>(matchingSkills_);
    int32_t userId = UNDEFINED_USER;
    record->eventSubscribeInfo->SetUserId(userId);
    std::string format = "aa";
    std::string dumpInfo = "aa";
    commonEventSubscriberManager->DumpDetailed(title, record, format, dumpInfo);
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_0500 end";
}

/**
 * @tc.name: CommonEventSubscriberManager_0501
 * @tc.desc: test DumpDetailed function and userId is ALL_USER.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventSubscriberManager_0501, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_0501 start";
    std::shared_ptr<CommonEventSubscriberManager> commonEventSubscriberManager =
        std::make_shared<CommonEventSubscriberManager>();
    ASSERT_NE(nullptr, commonEventSubscriberManager);
    std::string title = "aa";
    SubscriberRecordPtr record = std::make_shared<EventSubscriberRecord>();
    MatchingSkills matchingSkills_;
    record->eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>(matchingSkills_);
    int32_t userId = ALL_USER;
    record->eventSubscribeInfo->SetUserId(userId);

    MatchingSkills matchSkills;
    std::string event = "event.unit.test";
    matchSkills.AddEvent(event);
    EXPECT_EQ(1, matchSkills.CountEvent());
    std::string entity = "event.unit.test";
    matchSkills.AddEntity(entity);
    EXPECT_EQ(1, matchSkills.CountEntities());
    std::string shceme = "event.unit.test";
    matchSkills.AddScheme(shceme);
    EXPECT_EQ(1, matchSkills.CountSchemes());
    std::string format = "aa";
    std::string dumpInfo = "aa";
    commonEventSubscriberManager->DumpDetailed(title, record, format, dumpInfo);
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_0501 end";
}

/**
 * @tc.name: CommonEventSubscriberManager_0600
 * @tc.desc: test DumpDetailed function and userId is 100.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventSubscriberManager_0600, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_0600 start";
    std::shared_ptr<CommonEventSubscriberManager> commonEventSubscriberManager =
        std::make_shared<CommonEventSubscriberManager>();
    ASSERT_NE(nullptr, commonEventSubscriberManager);
    std::string title = "aa";
    SubscriberRecordPtr record = std::make_shared<EventSubscriberRecord>();
    MatchingSkills matchingSkills_;
    record->eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>(matchingSkills_);
    int32_t userId = 100;
    record->eventSubscribeInfo->SetUserId(userId);
    std::string format = "aa";
    std::string dumpInfo = "aa";
    commonEventSubscriberManager->DumpDetailed(title, record, format, dumpInfo);
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_0600 end";
}

/**
 * @tc.name: CommonEventSubscriberManager_0700
 * @tc.desc: test InsertSubscriberRecordLocked function and record is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventSubscriberManager_0700, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_0700 start";
    CommonEventSubscriberManager commonEventSubscriberManager;
    std::string event = "aa";
    std::vector<std::string> events;
    events.emplace_back(event);
    SubscriberRecordPtr record = nullptr;
    EXPECT_EQ(false, commonEventSubscriberManager.InsertSubscriberRecordLocked(events, record));
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_0700 end";
}

/**
 * @tc.name: CommonEventSubscriberManager_0800
 * @tc.desc: test InsertSubscriberRecordLocked function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventSubscriberManager_0800, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_0800 start";
    CommonEventSubscriberManager commonEventSubscriberManager;
    std::string event = "aa";
    std::vector<std::string> events;
    events.emplace_back(event);
    SubscriberRecordPtr record = std::make_shared<EventSubscriberRecord>();
    MatchingSkills matchingSkills_;
    record->eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>(matchingSkills_);
    std::multiset<SubscriberRecordPtr> mults;
    mults.insert(record);
    commonEventSubscriberManager.eventSubscribers_.emplace(event, mults);
    EXPECT_EQ(true, commonEventSubscriberManager.InsertSubscriberRecordLocked(events, record));
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_0800 end";
}

/**
 * @tc.name: CommonEventSubscriberManager_0900
 * @tc.desc: test RemoveSubscriberRecordLocked function and commonEventListener is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventSubscriberManager_0900, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_0900 start";
    CommonEventSubscriberManager commonEventSubscriberManager;
    sptr<IRemoteObject> commonEventListener = nullptr;
    EXPECT_EQ(ERR_INVALID_VALUE, commonEventSubscriberManager.RemoveSubscriberRecordLocked(commonEventListener));
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_0900 end";
}

/**
 * @tc.name: CommonEventSubscriberManager_1000
 * @tc.desc: test CheckSubscriberByUserId function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventSubscriberManager_1000, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_1000 start";
    CommonEventSubscriberManager commonEventSubscriberManager;
    int32_t subscriberUserId = UNDEFINED_USER;
    bool isSystemApp = true;
    int32_t userId = UNDEFINED_USER;
    EXPECT_EQ(true, commonEventSubscriberManager.CheckSubscriberByUserId(subscriberUserId, isSystemApp, userId));
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_1000 end";
}

/**
 * @tc.name: CommonEventSubscriberManager_1100
 * @tc.desc: test CheckSubscriberByUserId function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventSubscriberManager_1100, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_1100 start";
    CommonEventSubscriberManager commonEventSubscriberManager;
    int32_t subscriberUserId = UNDEFINED_USER;
    bool isSystemApp = true;
    int32_t userId = ALL_USER;
    EXPECT_EQ(true, commonEventSubscriberManager.CheckSubscriberByUserId(subscriberUserId, isSystemApp, userId));
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_1100 end";
}

/**
 * @tc.name: CommonEventSubscriberManager_1200
 * @tc.desc: test CheckSubscriberByUserId function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventSubscriberManager_1200, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_1200 start";
    CommonEventSubscriberManager commonEventSubscriberManager;
    int32_t subscriberUserId = 100;
    bool isSystemApp = false;
    int32_t userId = 100;
    EXPECT_EQ(true, commonEventSubscriberManager.CheckSubscriberByUserId(subscriberUserId, isSystemApp, userId));
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_1200 end";
}

/**
 * @tc.name: CommonEventSubscriberManager_1300
 * @tc.desc: test CheckSubscriberByUserId function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventSubscriberManager_1300, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_1300 start";
    CommonEventSubscriberManager commonEventSubscriberManager;
    int32_t subscriberUserId = 100;
    bool isSystemApp = true;
    int32_t userId = 99;
    EXPECT_EQ(false, commonEventSubscriberManager.CheckSubscriberByUserId(subscriberUserId, isSystemApp, userId));
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_1300 end";
}

/**
 * @tc.name: CommonEventSubscriberManager_1400
 * @tc.desc: test CheckSubscriberByUserId function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventSubscriberManager_1400, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_1400 start";
    CommonEventSubscriberManager commonEventSubscriberManager;
    int32_t subscriberUserId = 98;
    bool isSystemApp = true;
    int32_t userId = 98;
    EXPECT_EQ(true, commonEventSubscriberManager.CheckSubscriberByUserId(subscriberUserId, isSystemApp, userId));
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_1400 end";
}

/**
 * @tc.name: CommonEventSubscriberManager_1500
 * @tc.desc: test CheckSubscriberByUserId function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventSubscriberManager_1500, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_1500 start";
    CommonEventSubscriberManager commonEventSubscriberManager;
    int32_t subscriberUserId = 101;
    bool isSystemApp = false;
    int32_t userId = 99;
    EXPECT_EQ(false, commonEventSubscriberManager.CheckSubscriberByUserId(subscriberUserId, isSystemApp, userId));
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_1500 end";
}

/**
 * @tc.name: CommonEventSubscriberManager_1600
 * @tc.desc: test GetSubscriberRecordsByEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventSubscriberManager_1600, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_1600 start";
    std::shared_ptr<CommonEventSubscriberManager> commonEventSubscriberManager =
        std::make_shared<CommonEventSubscriberManager>();
    ASSERT_NE(nullptr, commonEventSubscriberManager);
    std::string event = "";
    int32_t userId = ALL_USER;
    std::vector<SubscriberRecordPtr> records;
    commonEventSubscriberManager->GetSubscriberRecordsByEvent(event, userId, records);
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_1600 end";
}

/**
 * @tc.name: CommonEventSubscriberManager_1700
 * @tc.desc: test GetSubscriberRecordsByEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventSubscriberManager_1700, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_1700 start";
    std::shared_ptr<CommonEventSubscriberManager> commonEventSubscriberManager =
        std::make_shared<CommonEventSubscriberManager>();
    ASSERT_NE(nullptr, commonEventSubscriberManager);
    std::string event = "";
    int32_t userId = 100;
    std::vector<SubscriberRecordPtr> records;
    SubscriberRecordPtr record = std::make_shared<EventSubscriberRecord>();
    MatchingSkills matchingSkills_;
    record->eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>(matchingSkills_);
    record->eventSubscribeInfo->SetUserId(userId);
    commonEventSubscriberManager->subscribers_.emplace_back(record);
    commonEventSubscriberManager->GetSubscriberRecordsByEvent(event, userId, records);
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_1700 end";
}

/**
 * @tc.name: CommonEventSubscriberManager_1800
 * @tc.desc: test GetSubscriberRecordsByEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventSubscriberManager_1800, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_1800 start";
    std::shared_ptr<CommonEventSubscriberManager> commonEventSubscriberManager =
        std::make_shared<CommonEventSubscriberManager>();
    ASSERT_NE(nullptr, commonEventSubscriberManager);
    std::string event = "";
    int32_t userId = 100;
    std::vector<SubscriberRecordPtr> records;
    SubscriberRecordPtr record = std::make_shared<EventSubscriberRecord>();
    MatchingSkills matchingSkills_;
    record->eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>(matchingSkills_);
    int32_t userIds = 90;
    record->eventSubscribeInfo->SetUserId(userIds);
    commonEventSubscriberManager->subscribers_.emplace_back(record);
    commonEventSubscriberManager->GetSubscriberRecordsByEvent(event, userId, records);
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_1800 end";
}

/**
 * @tc.name: CommonEventSubscriberManager_1900
 * @tc.desc: test GetSubscriberRecordsByEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventSubscriberManager_1900, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_1900 start";
    std::shared_ptr<CommonEventSubscriberManager> commonEventSubscriberManager =
        std::make_shared<CommonEventSubscriberManager>();
    ASSERT_NE(nullptr, commonEventSubscriberManager);
    std::string event = "aa";
    int32_t userId = 99;
    std::vector<SubscriberRecordPtr> records;
    commonEventSubscriberManager->GetSubscriberRecordsByEvent(event, userId, records);
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_1900 end";
}

/**
 * @tc.name: CommonEventSubscriberManager_2000
 * @tc.desc: test GetSubscriberRecordsByEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventSubscriberManager_2000, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_2000 start";
    std::shared_ptr<CommonEventSubscriberManager> commonEventSubscriberManager =
        std::make_shared<CommonEventSubscriberManager>();
    ASSERT_NE(nullptr, commonEventSubscriberManager);
    std::string event = "aa";
    int32_t userId = 99;
    std::vector<SubscriberRecordPtr> records;
    std::multiset<SubscriberRecordPtr> sub;
    SubscriberRecordPtr record = std::make_shared<EventSubscriberRecord>();
    sub.insert(record);
    MatchingSkills matchingSkills_;
    record->eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>(matchingSkills_);
    int32_t userIds = -1;
    record->eventSubscribeInfo->SetUserId(userIds);
    commonEventSubscriberManager->eventSubscribers_.emplace(event, sub);
    commonEventSubscriberManager->GetSubscriberRecordsByEvent(event, userId, records);
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_2000 end";
}

/**
 * @tc.name: CommonEventSubscriberManager_2100
 * @tc.desc: test GetSubscriberRecordsByEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventSubscriberManager_2100, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_2100 start";
    std::shared_ptr<CommonEventSubscriberManager> commonEventSubscriberManager =
        std::make_shared<CommonEventSubscriberManager>();
    ASSERT_NE(nullptr, commonEventSubscriberManager);
    std::string event = "aa";
    int32_t userId = 99;
    std::vector<SubscriberRecordPtr> records;
    std::multiset<SubscriberRecordPtr> sub;
    SubscriberRecordPtr record = std::make_shared<EventSubscriberRecord>();
    sub.insert(record);
    MatchingSkills matchingSkills_;
    record->eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>(matchingSkills_);
    int32_t userIds = 101;
    record->eventSubscribeInfo->SetUserId(userIds);
    commonEventSubscriberManager->eventSubscribers_.emplace(event, sub);
    commonEventSubscriberManager->GetSubscriberRecordsByEvent(event, userId, records);
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_2100 end";
}

/**
 * @tc.name: CommonEventSubscriberManager_2200
 * @tc.desc: test RemoveFrozenEventsBySubscriber function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventSubscriberManager_2200, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_2200 start";
    std::shared_ptr<CommonEventSubscriberManager> commonEventSubscriberManager =
        std::make_shared<CommonEventSubscriberManager>();
    ASSERT_NE(nullptr, commonEventSubscriberManager);
    SubscriberRecordPtr subscriberRecord = std::make_shared<EventSubscriberRecord>();
    uid_t uids = 1;
    subscriberRecord->eventRecordInfo.uid = uids;
    // set frozenEvents_
    FrozenRecords frozenRecord;
    commonEventSubscriberManager->frozenEvents_.emplace(uids, frozenRecord);
    commonEventSubscriberManager->RemoveFrozenEventsBySubscriber(subscriberRecord);
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_2200 end";
}

/**
 * @tc.name: CommonEventSubscriberManager_2300
 * @tc.desc: test DumpState function when records.size()>0.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventSubscriberManager_2300, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_2300 start";
    std::shared_ptr<CommonEventSubscriberManager> commonEventSubscriberManager =
        std::make_shared<CommonEventSubscriberManager>();
    ASSERT_NE(nullptr, commonEventSubscriberManager);
    std::string event = "";
    int32_t userId = 100;
    std::vector<SubscriberRecordPtr> records;
    SubscriberRecordPtr record = std::make_shared<EventSubscriberRecord>();
    MatchingSkills matchingSkills_;
    record->eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>(matchingSkills_);
    record->eventSubscribeInfo->SetUserId(userId);
    commonEventSubscriberManager->subscribers_.emplace_back(record);
    commonEventSubscriberManager->GetSubscriberRecordsByEvent(event, userId, records);
    EXPECT_EQ(1, records.size());
    std::vector<std::string> state;
    commonEventSubscriberManager->DumpState(event, userId, state);
    commonEventSubscriberManager->UpdateAllFreezeInfos(true, 1);
    commonEventSubscriberManager->UpdateAllFreezeInfos(false, 1);
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_2300 end";
}

/**
 * @tc.name: CommonEventSubscriberManager_2400
 * @tc.desc: test DumpState function when record is nullptr..
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventSubscriberManager_2400, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_2400 start";
    std::shared_ptr<CommonEventSubscriberManager> commonEventSubscriberManager =
        std::make_shared<CommonEventSubscriberManager>();
    ASSERT_NE(nullptr, commonEventSubscriberManager);
    SubscriberRecordPtr subscriberRecord = std::make_shared<EventSubscriberRecord>();
    CommonEventRecord eventRecord;
    commonEventSubscriberManager->InsertFrozenEvents(subscriberRecord, eventRecord);
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_2400 end";
}

/**
 * @tc.name: CommonEventSubscriberManager_2500
 * @tc.desc: test DumpState function when record not nullptr..
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventSubscriberManager_2500, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_2500 start";
    std::shared_ptr<CommonEventSubscriberManager> commonEventSubscriberManager =
        std::make_shared<CommonEventSubscriberManager>();
    ASSERT_NE(nullptr, commonEventSubscriberManager);
    SubscriberRecordPtr subscriberRecord = nullptr;
    CommonEventRecord eventRecord;
    commonEventSubscriberManager->InsertFrozenEvents(subscriberRecord, eventRecord);
    GTEST_LOG_(INFO) << "CommonEventSubscriberManager_2500 end";
}

/**
 * @tc.name: CommonEventStickyManager_0100
 * @tc.desc: test UpdateStickyEventLocked function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventStickyManager_0100, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventStickyManager_0100 start";
    CommonEventStickyManager commonEventStickyManager;
    std::string event = "";
    std::shared_ptr<CommonEventRecord> record = nullptr;
    EXPECT_EQ(ERR_INVALID_VALUE, commonEventStickyManager.UpdateStickyEventLocked(event, record));
    GTEST_LOG_(INFO) << "CommonEventStickyManager_0100 end";
}

/**
 * @tc.name: CommonEventStickyManager_0200
 * @tc.desc: test UpdateStickyEventLocked function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventStickyManager_0200, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventStickyManager_0200 start";
    CommonEventStickyManager commonEventStickyManager;
    std::string event = "aa";
    std::shared_ptr<CommonEventRecord> record = nullptr;
    EXPECT_EQ(ERR_INVALID_VALUE, commonEventStickyManager.UpdateStickyEventLocked(event, record));
    GTEST_LOG_(INFO) << "CommonEventStickyManager_0200 end";
}

/**
 * @tc.name: CommonEventStickyManager_0300
 * @tc.desc: test GetStickyCommonEventRecords function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventStickyManager_0300, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventStickyManager_0300 start";
    std::shared_ptr<CommonEventStickyManager> commonEventStickyManager =
        std::make_shared<CommonEventStickyManager>();
    ASSERT_NE(nullptr, commonEventStickyManager);
    std::string event = "";
    int32_t userId = ALL_USER;
    std::vector<std::shared_ptr<CommonEventRecord>> records;
    // set commonEventRecords_
    std::shared_ptr<CommonEventRecord> comm = std::make_shared<CommonEventRecord>();
    comm->userId = ALL_USER;
    commonEventStickyManager->commonEventRecords_.emplace(event, comm);
    commonEventStickyManager->GetStickyCommonEventRecords(event, userId, records);
    GTEST_LOG_(INFO) << "CommonEventStickyManager_0300 end";
}

/**
 * @tc.name: CommonEventStickyManager_0400
 * @tc.desc: test GetStickyCommonEventRecords function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventStickyManager_0400, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventStickyManager_0400 start";
    std::shared_ptr<CommonEventStickyManager> commonEventStickyManager =
        std::make_shared<CommonEventStickyManager>();
    ASSERT_NE(nullptr, commonEventStickyManager);
    std::string event = "";
    int32_t userId = 100;
    std::vector<std::shared_ptr<CommonEventRecord>> records;
    // set commonEventRecords_
    std::shared_ptr<CommonEventRecord> comm = std::make_shared<CommonEventRecord>();
    comm->userId = 101;
    commonEventStickyManager->commonEventRecords_.emplace(event, comm);
    commonEventStickyManager->GetStickyCommonEventRecords(event, userId, records);
    GTEST_LOG_(INFO) << "CommonEventStickyManager_0400 end";
}

/**
 * @tc.name: CommonEventStickyManager_0500
 * @tc.desc: test GetStickyCommonEventRecords function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventStickyManager_0500, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventStickyManager_0500 start";
    std::shared_ptr<CommonEventStickyManager> commonEventStickyManager =
        std::make_shared<CommonEventStickyManager>();
    ASSERT_NE(nullptr, commonEventStickyManager);
    std::string event = "aa";
    int32_t userId = 100;
    std::vector<std::shared_ptr<CommonEventRecord>> records;
    // set commonEventRecords_
    std::shared_ptr<CommonEventRecord> comm = std::make_shared<CommonEventRecord>();
    comm->userId = 101;
    commonEventStickyManager->commonEventRecords_.emplace(event, comm);
    commonEventStickyManager->GetStickyCommonEventRecords(event, userId, records);
    GTEST_LOG_(INFO) << "CommonEventStickyManager_0500 end";
}

/**
 * @tc.name: CommonEventStickyManager_0600
 * @tc.desc: test GetStickyCommonEventRecords function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CommonEventStickyManager_0600, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventStickyManager_0600 start";
    std::shared_ptr<CommonEventStickyManager> commonEventStickyManager =
        std::make_shared<CommonEventStickyManager>();
    ASSERT_NE(nullptr, commonEventStickyManager);
    std::string event = "aa";
    int32_t userId = ALL_USER;
    std::vector<std::shared_ptr<CommonEventRecord>> records;
    // set commonEventRecords_
    std::shared_ptr<CommonEventRecord> comm = std::make_shared<CommonEventRecord>();
    comm->userId = ALL_USER;
    commonEventStickyManager->commonEventRecords_.emplace(event, comm);
    commonEventStickyManager->GetStickyCommonEventRecords(event, userId, records);
    GTEST_LOG_(INFO) << "CommonEventStickyManager_0600 end";
}

