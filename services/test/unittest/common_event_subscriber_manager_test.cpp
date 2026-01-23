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
#include "common_event_permission_manager.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EventFwk;
using namespace OHOS::AppExecFwk;
namespace OHOS {
namespace EventFwk {

extern void MockGetEventPermission(bool mockRet, PermissionState mockState = PermissionState::AND,
    int32_t permissionSize = 1);
extern void MockIsVerfyPermisson(bool isVerify);
extern void MockIsSystemApp(bool mockRet);

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

#ifdef CEM_SUPPORT_DUMP
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
#endif
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
    std::set<SubscriberRecordPtr> mults;
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
    std::set<SubscriberRecordPtr> sub;
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
    std::set<SubscriberRecordPtr> sub;
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
#ifdef CEM_SUPPORT_DUMP
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
#endif
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
 * @tc.name: UpdateSubscriberRecordLocked_0100
 * @tc.desc: test UpdateSubscriberRecordLocked function and record is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, UpdateSubscriberRecordLocked_0100, Level1)
{
    GTEST_LOG_(INFO) << "UpdateSubscriberRecordLocked_0100 start";
    std::string event1 = "test1";
    struct tm curTime {0};
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(event1);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<CommonEventSubscribeInfo> commonEventSubscribeInfo =
        std::make_shared<CommonEventSubscribeInfo>(subscribeInfo);
    CommonEventSubscriberManager commonEventSubscriberManager;
    std::string event = "aa";
    std::vector<std::string> events;
    events.emplace_back(event);
    SubscriberRecordPtr record = nullptr;

    EventRecordInfo eventRecordInfo;
    eventRecordInfo.pid = 0;
    eventRecordInfo.uid = 0;
    eventRecordInfo.bundleName = "bundleName";
    EXPECT_EQ(false, commonEventSubscriberManager.UpdateSubscriberRecordLocked(commonEventSubscribeInfo,
        curTime, eventRecordInfo, record));
    GTEST_LOG_(INFO) << "UpdateSubscriberRecordLocked_0100 end";
}

/**
 * @tc.name: UpdateSubscriberRecordLocked_0200
 * @tc.desc: test UpdateSubscriberRecordLocked function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, UpdateSubscriberRecordLocked_0200, Level1)
{
    std::string event1 = "test1";
    std::string event2 = "test2";
    struct tm curTime {0};
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(event1);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<CommonEventSubscribeInfo> commonEventSubscribeInfo =
        std::make_shared<CommonEventSubscribeInfo>(subscribeInfo);

    EventRecordInfo eventRecordInfo;
    eventRecordInfo.pid = 0;
    eventRecordInfo.uid = 0;
    eventRecordInfo.bundleName = "bundleName";

    CommonEventSubscriberManager commonEventSubscriberManager;
    SubscriberRecordPtr record = std::make_shared<EventSubscriberRecord>();
    MatchingSkills matchingSkills_;
    matchingSkills.AddEvent(event2);
    record->eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>(matchingSkills_);
    std::set<SubscriberRecordPtr> mults;
    mults.insert(record);
    commonEventSubscriberManager.eventSubscribers_.emplace(event1, mults);
    commonEventSubscriberManager.eventSubscribers_.emplace(event2, mults);
    EXPECT_EQ(true, commonEventSubscriberManager.UpdateSubscriberRecordLocked(commonEventSubscribeInfo,
        curTime, eventRecordInfo, record));
    GTEST_LOG_(INFO) << "UpdateSubscriberRecordLocked_0200 end";
}

/**
 * @tc.name: UpdateSubscriberRecordLocked_0300
 * @tc.desc: test UpdateSubscriberRecordLocked function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, UpdateSubscriberRecordLocked_0300, Level1)
{
    std::string eventName1 = "atest1";
    std::string eventName2 = "btest1";
    std::string eventName3 = "ctest1";
    std::string eventName4 = "dtest1";
    struct tm curTime {0};
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(eventName3);
    matchingSkills.AddEvent(eventName1);
    matchingSkills.AddEvent(eventName2);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<CommonEventSubscribeInfo> commonEventSubscribeInfo =
        std::make_shared<CommonEventSubscribeInfo>(subscribeInfo);

    EventRecordInfo eventRecordInfo;
    eventRecordInfo.pid = 0;
    eventRecordInfo.uid = 0;
    eventRecordInfo.bundleName = "bundleName";

    CommonEventSubscriberManager commonEventSubscriberManager;
    SubscriberRecordPtr record = std::make_shared<EventSubscriberRecord>();
    MatchingSkills matchingSkills_;
    matchingSkills_.AddEvent(eventName4);
    matchingSkills_.AddEvent(eventName3);
    matchingSkills_.AddEvent(eventName1);
    record->eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>(matchingSkills_);
    std::set<SubscriberRecordPtr> mults;
    mults.insert(record);
    commonEventSubscriberManager.eventSubscribers_.emplace(eventName1, mults);
    commonEventSubscriberManager.eventSubscribers_.emplace(eventName2, mults);
    EXPECT_EQ(true, commonEventSubscriberManager.UpdateSubscriberRecordLocked(commonEventSubscribeInfo,
        curTime, eventRecordInfo, record));
    GTEST_LOG_(INFO) << "UpdateSubscriberRecordLocked_0300 end";
}

/**
 * @tc.name: InsertEventSubscribers_0100
 * @tc.desc: test InsertEventSubscribers function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, InsertEventSubscribers_0100, Level1)
{
    std::string event1 = "test1";
    std::string event2 = "test2";
    std::vector<std::string> events;
    events.push_back(event1);
    events.push_back(event2);
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(event1);
    matchingSkills.AddEvent(event2);
    CommonEventSubscriberManager commonEventSubscriberManager;
    SubscriberRecordPtr record = std::make_shared<EventSubscriberRecord>();
    record->eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>(matchingSkills);
    std::set<SubscriberRecordPtr> mults;
    mults.insert(record);
    commonEventSubscriberManager.eventSubscribers_.emplace(event1, mults);
    commonEventSubscriberManager.InsertEventSubscribers(events, record);
    EXPECT_EQ(commonEventSubscriberManager.eventSubscribers_.size(), 2);
}

/**
 * @tc.name: InsertEventSubscribers_0200
 * @tc.desc: test InsertEventSubscribers function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, InsertEventSubscribers_0200, Level1)
{
    std::string event1 = "test1";
    std::vector<std::string> events;
    events.push_back(event1);
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(event1);

    std::set<SubscriberRecordPtr> mults;
    for (int32_t i = 0; i < 255; i++) {
        SubscriberRecordPtr record = std::make_shared<EventSubscriberRecord>();
        mults.insert(record);
    }
    
    SubscriberRecordPtr record1 = std::make_shared<EventSubscriberRecord>();
    record1->eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>(matchingSkills);
    mults.insert(record1);

    CommonEventSubscriberManager commonEventSubscriberManager;
    commonEventSubscriberManager.eventSubscribers_.emplace(event1, mults);
    commonEventSubscriberManager.InsertEventSubscribers(events, record1);
    EXPECT_EQ(commonEventSubscriberManager.eventSubscribers_[event1].size(), 256);
}

/**
 * @tc.name: RemoveEventSubscribers_0100
 * @tc.desc: test RemoveEventSubscribers function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, RemoveEventSubscribers_0100, Level1)
{
    std::string event1 = "test1";
    std::string event2 = "test2";
    std::vector<std::string> events;
    events.push_back(event1);
    events.push_back(event2);
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(event1);

    std::set<SubscriberRecordPtr> mults;
    SubscriberRecordPtr record = std::make_shared<EventSubscriberRecord>();
    record->eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>(matchingSkills);
    mults.insert(record);

    CommonEventSubscriberManager commonEventSubscriberManager;
    commonEventSubscriberManager.eventSubscribers_.emplace(event1, mults);
    commonEventSubscriberManager.RemoveEventSubscribers(events, record);
    EXPECT_EQ(commonEventSubscriberManager.eventSubscribers_.size(), 0);
}

/**
 * @tc.name: RemoveEventSubscribers_0200
 * @tc.desc: test RemoveEventSubscribers function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, RemoveEventSubscribers_0200, Level1)
{
    std::string event1 = "test1";
    std::string event2 = "test2";
    std::vector<std::string> events;
    events.push_back(event1);
    events.push_back(event2);
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(event1);

    std::set<SubscriberRecordPtr> mults;
    SubscriberRecordPtr record = std::make_shared<EventSubscriberRecord>();
    SubscriberRecordPtr record1 = std::make_shared<EventSubscriberRecord>();
    record->eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>(matchingSkills);
    mults.insert(record);

    CommonEventSubscriberManager commonEventSubscriberManager;
    commonEventSubscriberManager.eventSubscribers_.emplace(event1, mults);
    commonEventSubscriberManager.RemoveEventSubscribers(events, record1);
    EXPECT_EQ(commonEventSubscriberManager.eventSubscribers_.size(), 1);
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

/**
 * @tc.name: CheckSubscriberPermission_1000
 * @tc.desc: test CheckSubscriberPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CheckSubscriberPermission_1000, Level0)
{
    GTEST_LOG_(INFO) << "CheckSubscriberPermission_1000 start";
    std::shared_ptr<CommonEventSubscriberManager> commonEventSubscriberManager =
        std::make_shared<CommonEventSubscriberManager>();
    auto subscriberRecord = std::make_shared<EventSubscriberRecord>();
    subscriberRecord->eventRecordInfo.isProxy = false;
    subscriberRecord->eventRecordInfo.isSubsystem = true;
    subscriberRecord->eventRecordInfo.isSystemApp = true;
    CommonEventRecord eventRecord;
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    eventRecord.commonEventData = commonEventData;
    MockGetEventPermission(true);
    EXPECT_EQ(true, commonEventSubscriberManager->CheckSubscriberPermission(subscriberRecord, eventRecord));
    GTEST_LOG_(INFO) << "CheckSubscriberPermission_1000 end";
}

/**
 * @tc.name: CheckSubscriberPermission_1100
 * @tc.desc: test CheckSubscriberPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CheckSubscriberPermission_1100, Level0)
{
    GTEST_LOG_(INFO) << "CheckSubscriberPermission_1100 start";
    std::shared_ptr<CommonEventSubscriberManager> commonEventSubscriberManager =
        std::make_shared<CommonEventSubscriberManager>();
    auto subscriberRecord = std::make_shared<EventSubscriberRecord>();
    subscriberRecord->eventRecordInfo.isProxy = true;
    subscriberRecord->eventRecordInfo.isSubsystem = false;
    subscriberRecord->eventRecordInfo.isSystemApp = false;
    CommonEventRecord eventRecord;
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    eventRecord.commonEventData = commonEventData;
    MockGetEventPermission(true);
    MockIsVerfyPermisson(true);
    EXPECT_EQ(true, commonEventSubscriberManager->CheckSubscriberPermission(subscriberRecord, eventRecord));
    GTEST_LOG_(INFO) << "CheckSubscriberPermission_1100 end";
}

/**
 * @tc.name: CheckSubscriberPermission_1200
 * @tc.desc: test CheckSubscriberPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CheckSubscriberPermission_1200, Level0)
{
    GTEST_LOG_(INFO) << "CheckSubscriberPermission_1200 start";
    std::shared_ptr<CommonEventSubscriberManager> commonEventSubscriberManager =
        std::make_shared<CommonEventSubscriberManager>();
    auto subscriberRecord = std::make_shared<EventSubscriberRecord>();
    subscriberRecord->eventRecordInfo.isProxy = true;
    subscriberRecord->eventRecordInfo.isSubsystem = false;
    subscriberRecord->eventRecordInfo.isSystemApp = false;
    subscriberRecord->eventRecordInfo.subId = "xxxx";
    CommonEventRecord eventRecord;
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    OHOS::AAFwk::Want want;
    want.SetAction("usual.event.USER_LOCKED");
    commonEventData->SetWant(want);
    eventRecord.commonEventData = commonEventData;
    MockGetEventPermission(true);
    MockIsVerfyPermisson(false);
    EXPECT_EQ(false, commonEventSubscriberManager->CheckSubscriberPermission(subscriberRecord, eventRecord));
    GTEST_LOG_(INFO) << "CheckSubscriberPermission_1200 end";
}

/**
 * @tc.name: CheckSubscriberPermission_0200
 * @tc.desc: test CheckSubscriberPermission permission.names.size is 2 and permission.state is PermissionState::AND.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CheckSubscriberPermission_1300, Level0)
{
    GTEST_LOG_(INFO) << "CheckSubscriberPermission_0200 start";
    std::shared_ptr<CommonEventSubscriberManager> commonEventSubscriberManager =
        std::make_shared<CommonEventSubscriberManager>();
    auto subscriberRecord = std::make_shared<EventSubscriberRecord>();
    std::shared_ptr<CommonEventSubscribeInfo> eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>();
    subscriberRecord->eventSubscribeInfo = eventSubscribeInfo;
    subscriberRecord->eventRecordInfo.isProxy = true;
    subscriberRecord->eventRecordInfo.isSubsystem = true;
    subscriberRecord->eventRecordInfo.isSystemApp = true;
    subscriberRecord->eventRecordInfo.subId = "xxxx";
    subscriberRecord->eventRecordInfo.uid = 1001;
    CommonEventRecord eventRecord;
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    eventRecord.publishInfo = publishInfo;

    OHOS::AAFwk::Want want;
    want.SetAction("usual.event.USER_LOCKED");
    commonEventData->SetWant(want);
    eventRecord.commonEventData = commonEventData;

    // set VerifyAccessToken is false
    MockIsVerfyPermisson(false);
    MockIsSystemApp(false);
    EXPECT_EQ(false, commonEventSubscriberManager->CheckSubscriberPermission(subscriberRecord, eventRecord));
    GTEST_LOG_(INFO) << "CheckSubscriberPermission_0200 end";
}

/**
 * @tc.name: CheckSubscriberPermission_0300
 * @tc.desc: test CheckSubscriberPermission permission.names.size is 2 and permission.state is PermissionState::AND.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CheckSubscriberPermission_1400, Level0)
{
    GTEST_LOG_(INFO) << "CheckSubscriberPermission_0300 start";
    std::shared_ptr<CommonEventSubscriberManager> commonEventSubscriberManager =
        std::make_shared<CommonEventSubscriberManager>();
    auto subscriberRecord = std::make_shared<EventSubscriberRecord>();
    std::shared_ptr<CommonEventSubscribeInfo> eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>();
    subscriberRecord->eventSubscribeInfo = eventSubscribeInfo;
    subscriberRecord->eventRecordInfo.isProxy = true;
    subscriberRecord->eventRecordInfo.isSubsystem = true;
    subscriberRecord->eventRecordInfo.isSystemApp = true;
    CommonEventRecord eventRecord;
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    eventRecord.commonEventData = commonEventData;
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    eventRecord.publishInfo = publishInfo;
    // set VerifyAccessToken is true
    MockIsVerfyPermisson(true);
    EXPECT_EQ(true, commonEventSubscriberManager->CheckSubscriberPermission(subscriberRecord, eventRecord));
    GTEST_LOG_(INFO) << "CheckSubscriberPermission_0300 end";
}

/**
 * @tc.name: CheckSubscriberPermission_0300
 * @tc.desc: test CheckSubscriberPermission permission.names.size is 2 and permission.state is PermissionState::AND.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CheckSubscriberPermission_1500, Level0)
{
    GTEST_LOG_(INFO) << "CheckSubscriberPermission_0300 start";
    std::shared_ptr<CommonEventSubscriberManager> commonEventSubscriberManager =
        std::make_shared<CommonEventSubscriberManager>();
    auto subscriberRecord = std::make_shared<EventSubscriberRecord>();
    std::shared_ptr<CommonEventSubscribeInfo> eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>();
    subscriberRecord->eventSubscribeInfo = eventSubscribeInfo;
    subscriberRecord->eventRecordInfo.isProxy = true;
    subscriberRecord->eventRecordInfo.isSubsystem = false;
    subscriberRecord->eventRecordInfo.isSystemApp = true;
    CommonEventRecord eventRecord;
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    eventRecord.commonEventData = commonEventData;
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    eventRecord.publishInfo = publishInfo;
    OHOS::AAFwk::Want want;
    want.SetAction("usual.event.USER_LOCKED");
    commonEventData->SetWant(want);
    eventRecord.commonEventData = commonEventData;
    // set VerifyAccessToken is true
    MockGetEventPermission(true, PermissionState::AND, 2);
    MockIsVerfyPermisson(true);

    EXPECT_EQ(true, commonEventSubscriberManager->CheckSubscriberPermission(subscriberRecord, eventRecord));
    GTEST_LOG_(INFO) << "CheckSubscriberPermission_0300 end";
}

/**
 * @tc.name: CheckSubscriberPermission_0300
 * @tc.desc: test CheckSubscriberPermission permission.names.size is 2 and permission.state is PermissionState::AND.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CheckSubscriberPermission_1600, Level0)
{
    GTEST_LOG_(INFO) << "CheckSubscriberPermission_0300 start";
    std::shared_ptr<CommonEventSubscriberManager> commonEventSubscriberManager =
        std::make_shared<CommonEventSubscriberManager>();
    auto subscriberRecord = std::make_shared<EventSubscriberRecord>();
    std::shared_ptr<CommonEventSubscribeInfo> eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>();
    subscriberRecord->eventSubscribeInfo = eventSubscribeInfo;
    subscriberRecord->eventRecordInfo.isProxy = true;
    subscriberRecord->eventRecordInfo.isSubsystem = false;
    subscriberRecord->eventRecordInfo.isSystemApp = false;
    subscriberRecord->eventRecordInfo.subId = "xxxx";
    CommonEventRecord eventRecord;
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    eventRecord.commonEventData = commonEventData;
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    eventRecord.publishInfo = publishInfo;
    OHOS::AAFwk::Want want;
    want.SetAction("usual.event.USER_LOCKED");
    commonEventData->SetWant(want);
    eventRecord.commonEventData = commonEventData;

    EXPECT_EQ(false, commonEventSubscriberManager->CheckSubscriberPermission(subscriberRecord, eventRecord));
    GTEST_LOG_(INFO) << "CheckSubscriberPermission_0300 end";
}

/**
 * @tc.name: CheckSubscriberPermission_0300
 * @tc.desc: test CheckSubscriberPermission permission.names.size is 2 and permission.state is PermissionState::AND.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CheckSubscriberPermission_1700, Level0)
{
    GTEST_LOG_(INFO) << "CheckSubscriberPermission_0300 start";
    std::shared_ptr<CommonEventSubscriberManager> commonEventSubscriberManager =
        std::make_shared<CommonEventSubscriberManager>();
    auto subscriberRecord = std::make_shared<EventSubscriberRecord>();
    std::shared_ptr<CommonEventSubscribeInfo> eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>();
    subscriberRecord->eventSubscribeInfo = eventSubscribeInfo;
    subscriberRecord->eventRecordInfo.isProxy = true;
    subscriberRecord->eventRecordInfo.isSubsystem = false;
    subscriberRecord->eventRecordInfo.isSystemApp = true;
    subscriberRecord->eventRecordInfo.subId = "xxxx";
    subscriberRecord->eventRecordInfo.uid = 1001;
    CommonEventRecord eventRecord;
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    eventRecord.commonEventData = commonEventData;
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    eventRecord.publishInfo = publishInfo;
    OHOS::AAFwk::Want want;
    want.SetAction("usual.event.BOOT_COMPLETED");
    commonEventData->SetWant(want);
    eventRecord.commonEventData = commonEventData;
    // set VerifyAccessToken is true
    MockGetEventPermission(true, PermissionState::AND, 2);
    MockIsVerfyPermisson(false);

    EXPECT_EQ(false, commonEventSubscriberManager->CheckSubscriberPermission(subscriberRecord, eventRecord));
    GTEST_LOG_(INFO) << "CheckSubscriberPermission_0300 end";
}

/**
 * @tc.name: CheckSubscriberPermission_0300
 * @tc.desc: test CheckSubscriberPermission permission.names.size is 2 and permission.state is PermissionState::AND.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CheckSubscriberPermission_1800, Level0)
{
    GTEST_LOG_(INFO) << "CheckSubscriberPermission_0300 start";
    std::shared_ptr<CommonEventSubscriberManager> commonEventSubscriberManager =
        std::make_shared<CommonEventSubscriberManager>();
    auto subscriberRecord = std::make_shared<EventSubscriberRecord>();
    std::shared_ptr<CommonEventSubscribeInfo> eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>();
    subscriberRecord->eventSubscribeInfo = eventSubscribeInfo;
    subscriberRecord->eventRecordInfo.isProxy = true;
    subscriberRecord->eventRecordInfo.isSubsystem = false;
    subscriberRecord->eventRecordInfo.isSystemApp = true;
    subscriberRecord->eventRecordInfo.subId = "xxxx";
    subscriberRecord->eventRecordInfo.uid = 1001;
    CommonEventRecord eventRecord;
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    eventRecord.commonEventData = commonEventData;
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    eventRecord.publishInfo = publishInfo;
    OHOS::AAFwk::Want want;
    want.SetAction("usual.event.BOOT_COMPLETED");
    commonEventData->SetWant(want);
    eventRecord.commonEventData = commonEventData;
    // set VerifyAccessToken is true
    MockGetEventPermission(true, PermissionState::OR, 2);
    MockIsVerfyPermisson(false);

    EXPECT_EQ(false, commonEventSubscriberManager->CheckSubscriberPermission(subscriberRecord, eventRecord));
    GTEST_LOG_(INFO) << "CheckSubscriberPermission_0300 end";
}

/**
 * @tc.name: CheckSubscriberPermission_0300
 * @tc.desc: test CheckSubscriberPermission permission.names.size is 2 and permission.state is PermissionState::AND.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CheckSubscriberPermission_1900, Level0)
{
    GTEST_LOG_(INFO) << "CheckSubscriberPermission_0300 start";
    std::shared_ptr<CommonEventSubscriberManager> commonEventSubscriberManager =
        std::make_shared<CommonEventSubscriberManager>();
    auto subscriberRecord = std::make_shared<EventSubscriberRecord>();
    std::shared_ptr<CommonEventSubscribeInfo> eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>();
    subscriberRecord->eventSubscribeInfo = eventSubscribeInfo;
    subscriberRecord->eventRecordInfo.isProxy = true;
    subscriberRecord->eventRecordInfo.isSubsystem = false;
    subscriberRecord->eventRecordInfo.isSystemApp = true;
    CommonEventRecord eventRecord;
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    eventRecord.commonEventData = commonEventData;
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    eventRecord.publishInfo = publishInfo;
    OHOS::AAFwk::Want want;
    want.SetAction("usual.event.USER_LOCKED");
    commonEventData->SetWant(want);
    eventRecord.commonEventData = commonEventData;
    // set VerifyAccessToken is true
    MockGetEventPermission(true, PermissionState::OR, 2);
    MockIsVerfyPermisson(true);

    EXPECT_EQ(true, commonEventSubscriberManager->CheckSubscriberPermission(subscriberRecord, eventRecord));
    GTEST_LOG_(INFO) << "CheckSubscriberPermission_0300 end";
}

/**
 * @tc.name: CommonEventControlManager_0800
 * @tc.desc: test CheckPublisherRequiredPermissions and VerifyAccessToken is false.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CheckPublisherRequiredPermissions_0800, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_0800 start";
    std::shared_ptr<CommonEventSubscriberManager> commonEventSubscriberManager =
        std::make_shared<CommonEventSubscriberManager>();
    std::string publisherRequiredPermission = "aa";
    std::vector<std::string> publisherRequiredPermissions;
    publisherRequiredPermissions.emplace_back(publisherRequiredPermission);
    auto subscriberRecord = std::make_shared<EventSubscriberRecord>();
    std::shared_ptr<CommonEventSubscribeInfo> eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>();
    subscriberRecord->eventSubscribeInfo = eventSubscribeInfo;
    subscriberRecord->eventRecordInfo.subId = "xxx";
    subscriberRecord->eventRecordInfo.uid = 100;
    CommonEventRecord eventRecord;
    eventRecord.eventRecordInfo.uid = 1001;
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    eventRecord.commonEventData = commonEventData;
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    publishInfo->SetSubscriberPermissions(publisherRequiredPermissions);
    eventRecord.publishInfo = publishInfo;
    // set VerifyAccessToken is false
    MockIsVerfyPermisson(false);
    EXPECT_EQ(false, commonEventSubscriberManager->CheckPublisherRequiredPermissions(subscriberRecord, eventRecord));
    GTEST_LOG_(INFO) << "CommonEventControlManager_0800 end";
}

/**
 * @tc.name: CommonEventControlManager_0900
 * @tc.desc: test CheckPublisherRequiredPermissions and VerifyAccessToken is true.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CheckPublisherRequiredPermissions_0900, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_0900 start";
    std::shared_ptr<CommonEventSubscriberManager> commonEventSubscriberManager =
        std::make_shared<CommonEventSubscriberManager>();
    std::string publisherRequiredPermission = "aa";
    std::vector<std::string> publisherRequiredPermissions;
    publisherRequiredPermissions.emplace_back(publisherRequiredPermission);
    auto subscriberRecord = std::make_shared<EventSubscriberRecord>();
    std::shared_ptr<CommonEventSubscribeInfo> eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>();
    subscriberRecord->eventSubscribeInfo = eventSubscribeInfo;
    subscriberRecord->eventRecordInfo.uid = 100;
    CommonEventRecord eventRecord;
    eventRecord.eventRecordInfo.uid = 1001;
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    eventRecord.commonEventData = commonEventData;
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    publishInfo->SetSubscriberPermissions(publisherRequiredPermissions);
    eventRecord.publishInfo = publishInfo;
    // set VerifyAccessToken is true
    MockIsVerfyPermisson(true);
    EXPECT_EQ(true, commonEventSubscriberManager->CheckPublisherRequiredPermissions(subscriberRecord, eventRecord));
    GTEST_LOG_(INFO) << "CommonEventControlManager_0900 end";
}

/**
 * @tc.name: CommonEventControlManager_0900
 * @tc.desc: test CheckPublisherRequiredPermissions and VerifyAccessToken is true.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerTest, CheckPublisherRequiredPermissions_1000, Level0)
{
    GTEST_LOG_(INFO) << "CommonEventControlManager_0900 start";
    std::shared_ptr<CommonEventSubscriberManager> commonEventSubscriberManager =
        std::make_shared<CommonEventSubscriberManager>();
    std::string publisherRequiredPermission = "aa";
    std::vector<std::string> publisherRequiredPermissions;
    publisherRequiredPermissions.emplace_back(publisherRequiredPermission);
    auto subscriberRecord = std::make_shared<EventSubscriberRecord>();
    std::shared_ptr<CommonEventSubscribeInfo> eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>();
    subscriberRecord->eventSubscribeInfo = eventSubscribeInfo;
    subscriberRecord->eventRecordInfo.uid = 100;
    CommonEventRecord eventRecord;
    eventRecord.eventRecordInfo.uid = 100;
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    eventRecord.commonEventData = commonEventData;
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    publishInfo->SetSubscriberPermissions(publisherRequiredPermissions);
    eventRecord.publishInfo = publishInfo;
    // set VerifyAccessToken is true
    MockIsVerfyPermisson(false);

    EXPECT_EQ(true, commonEventSubscriberManager->CheckPublisherRequiredPermissions(subscriberRecord, eventRecord));
    GTEST_LOG_(INFO) << "CommonEventControlManager_0900 end";
}

HWTEST_F(CommonEventSubscriberManagerTest, CheckPublisherWhetherMatched_BundleNameNotMatched_ReturnFalse, Level0)
{
    // Arrange
    std::shared_ptr<CommonEventSubscriberManager> manager = std::make_shared<CommonEventSubscriberManager>();
    std::shared_ptr<EventSubscriberRecord> subscriberRecord = std::make_shared<EventSubscriberRecord>();
    std::shared_ptr<CommonEventSubscribeInfo> eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>();
    eventSubscribeInfo->SetPublisherBundleName("Bundle2");
    subscriberRecord->eventSubscribeInfo = eventSubscribeInfo;

    CommonEventRecord eventRecord;
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.bundleName = "Bundle1";
    eventRecord.eventRecordInfo = eventRecordInfo;

    // Act
    bool result = manager->CheckPublisherWhetherMatched(subscriberRecord, eventRecord);

    // Assert
    EXPECT_FALSE(result);
}

HWTEST_F(CommonEventSubscriberManagerTest, CheckPublisherWhetherMatched_UidNotMatched_ReturnFalse, Level0)
{
    // Arrange
    std::shared_ptr<CommonEventSubscriberManager> manager = std::make_shared<CommonEventSubscriberManager>();
    std::shared_ptr<EventSubscriberRecord> subscriberRecord = std::make_shared<EventSubscriberRecord>();
    std::shared_ptr<CommonEventSubscribeInfo> eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>();
    eventSubscribeInfo->SetPublisherUid(1002);
    subscriberRecord->eventSubscribeInfo = eventSubscribeInfo;

    CommonEventRecord eventRecord;
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.uid = 1001;
    eventRecord.eventRecordInfo = eventRecordInfo;

    // Act
    bool result = manager->CheckPublisherWhetherMatched(subscriberRecord, eventRecord);

    // Assert
    EXPECT_FALSE(result);
}

HWTEST_F(CommonEventSubscriberManagerTest, CheckPublisherWhetherMatched_PermissionNotMatched_ReturnFalse, Level0)
{
    // Arrange
    std::shared_ptr<CommonEventSubscriberManager> manager = std::make_shared<CommonEventSubscriberManager>();
    std::shared_ptr<EventSubscriberRecord> subscriberRecord = std::make_shared<EventSubscriberRecord>();
    std::shared_ptr<CommonEventSubscribeInfo> eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>();
    eventSubscribeInfo->SetPublisherBundleName("Bundle1");
    eventSubscribeInfo->SetPublisherUid(1001);
    eventSubscribeInfo->SetPermission("xxxxx");
    subscriberRecord->eventSubscribeInfo = eventSubscribeInfo;

    CommonEventRecord eventRecord;
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.uid = 1001;
    eventRecordInfo.bundleName = "Bundle1";
    eventRecordInfo.subId = "xxxx";
    eventRecord.eventRecordInfo = eventRecordInfo;
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    OHOS::AAFwk::Want want;
    want.SetAction("usual.event.BOOT_COMPLETED");
    commonEventData->SetWant(want);
    eventRecord.commonEventData = commonEventData;
    MockIsVerfyPermisson(false);

    // Act
    bool result = manager->CheckPublisherWhetherMatched(subscriberRecord, eventRecord);
    // Assert
    EXPECT_FALSE(result);
}

HWTEST_F(CommonEventSubscriberManagerTest, CheckPublisherWhetherMatched_AllMatched_ReturnTrue, Level0)
{
    // Arrange
    std::shared_ptr<CommonEventSubscriberManager> manager = std::make_shared<CommonEventSubscriberManager>();
    std::shared_ptr<EventSubscriberRecord> subscriberRecord = std::make_shared<EventSubscriberRecord>();
    std::shared_ptr<CommonEventSubscribeInfo> eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>();
    eventSubscribeInfo->SetPublisherBundleName("Bundle1");
    eventSubscribeInfo->SetPublisherUid(1001);
    eventSubscribeInfo->SetPermission("xxxxx");
    subscriberRecord->eventSubscribeInfo = eventSubscribeInfo;
    subscriberRecord->eventRecordInfo.uid = 1001;

    CommonEventRecord eventRecord;
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.bundleName = "Bundle1";
    eventRecordInfo.uid = 1001;
    eventRecord.eventRecordInfo = eventRecordInfo;
    MockIsVerfyPermisson(true);

    // Act
    bool result = manager->CheckPublisherWhetherMatched(subscriberRecord, eventRecord);
    // Assert
    EXPECT_TRUE(result);
}

HWTEST_F(CommonEventSubscriberManagerTest, CheckSubscriberWhetherMatched_NoFilter, Level0)
{
    // Arrange
    std::shared_ptr<CommonEventSubscriberManager> manager = std::make_shared<CommonEventSubscriberManager>();
    CommonEventRecord eventRecord;
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    eventRecord.publishInfo = publishInfo;

    SubscriberRecordPtr subscriberRecord = std::make_shared<EventSubscriberRecord>();
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.bundleName = "bundleName2";
    subscriberRecord->eventRecordInfo = eventRecordInfo;

    // Act
    bool result = manager->CheckSubscriberWhetherMatched(subscriberRecord, eventRecord);

    // Assert
    EXPECT_TRUE(result);
}

HWTEST_F(CommonEventSubscriberManagerTest, CheckSubscriberWhetherMatched_BundleNameNotMatched, Level0)
{
    // Arrange
    std::shared_ptr<CommonEventSubscriberManager> manager = std::make_shared<CommonEventSubscriberManager>();
    CommonEventRecord eventRecord;
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    publishInfo->SetBundleName("bundleName1");
    eventRecord.publishInfo = publishInfo;

    SubscriberRecordPtr subscriberRecord = std::make_shared<EventSubscriberRecord>();
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.bundleName = "bundleName2";
    subscriberRecord->eventRecordInfo = eventRecordInfo;

    // Act
    bool result = manager->CheckSubscriberWhetherMatched(subscriberRecord, eventRecord);

    // Assert
    EXPECT_FALSE(result);
}

HWTEST_F(CommonEventSubscriberManagerTest, CheckSubscriberWhetherMatched_SubscriberTypeNotMatched, Level0)
{
    // Arrange
    std::shared_ptr<CommonEventSubscriberManager> manager = std::make_shared<CommonEventSubscriberManager>();
    CommonEventRecord eventRecord;
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    publishInfo->SetSubscriberType(SubscriberType::SYSTEM_SUBSCRIBER_TYPE);
    eventRecord.publishInfo = publishInfo;

    SubscriberRecordPtr subscriberRecord = std::make_shared<EventSubscriberRecord>();
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.isSystemApp = false;
    subscriberRecord->eventRecordInfo = eventRecordInfo;

    // Act
    bool result = manager->CheckSubscriberWhetherMatched(subscriberRecord, eventRecord);

    // Assert
    EXPECT_FALSE(result);
}

HWTEST_F(CommonEventSubscriberManagerTest, CheckSubscriberWhetherMatched_SubscriberUidNotMatched, Level0)
{
    // Arrange
    std::shared_ptr<CommonEventSubscriberManager> manager = std::make_shared<CommonEventSubscriberManager>();
    CommonEventRecord eventRecord;
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    publishInfo->SetSubscriberUid({1, 2, 3});
    eventRecord.publishInfo = publishInfo;

    SubscriberRecordPtr subscriberRecord = std::make_shared<EventSubscriberRecord>();
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.uid = 4;
    subscriberRecord->eventRecordInfo = eventRecordInfo;

    // Act
    bool result = manager->CheckSubscriberWhetherMatched(subscriberRecord, eventRecord);

    // Assert
    EXPECT_FALSE(result);
}

HWTEST_F(CommonEventSubscriberManagerTest, CheckSubscriberWhetherMatched_PublisherRequiredPermissionsNotMatched, Level0)
{
    // Arrange
    std::shared_ptr<CommonEventSubscriberManager> manager = std::make_shared<CommonEventSubscriberManager>();
    SubscriberRecordPtr subscriberRecord = std::make_shared<EventSubscriberRecord>();
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.uid = 4;
    eventRecordInfo.bundleName = "xxx";
    eventRecordInfo.subId = "xxxx";
    subscriberRecord->eventRecordInfo = eventRecordInfo;
    auto eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>();
    eventSubscribeInfo->SetUserId(100);
    subscriberRecord->eventSubscribeInfo = eventSubscribeInfo;
    subscriberRecord->eventRecordInfo.uid = 1001;

    CommonEventRecord eventRecord;
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    publishInfo->SetValidationRule(ValidationRule::AND);
    std::vector<std::string> publisherRequiredPermissions;
    publisherRequiredPermissions.emplace_back("publisherRequiredPermission");
    publishInfo->SetSubscriberPermissions(publisherRequiredPermissions);
    eventRecord.publishInfo = publishInfo;
    eventRecord.eventRecordInfo.uid = 1002;
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    OHOS::AAFwk::Want want;
    want.SetAction("usual.event.BOOT_COMPLETED");
    commonEventData->SetWant(want);
    eventRecord.commonEventData = commonEventData;
    MockIsVerfyPermisson(false);

    // Act
    bool result = manager->CheckSubscriberWhetherMatched(subscriberRecord, eventRecord);

    // Assert
    EXPECT_FALSE(result);
}

HWTEST_F(CommonEventSubscriberManagerTest, CheckSubscriberWhetherMatched_AllConditionsMatched, Level0)
{
    // Arrange
    std::shared_ptr<CommonEventSubscriberManager> manager = std::make_shared<CommonEventSubscriberManager>();
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    CommonEventRecord eventRecord;
    publishInfo->SetBundleName("bundleName1");
    publishInfo->SetSubscriberType(SubscriberType::SYSTEM_SUBSCRIBER_TYPE);
    publishInfo->SetSubscriberUid({1});
    publishInfo->SetValidationRule(ValidationRule::AND);
    eventRecord.publishInfo = publishInfo;
    eventRecord.eventRecordInfo.uid = 1;

    SubscriberRecordPtr subscriberRecord = std::make_shared<EventSubscriberRecord>();
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.bundleName = "bundleName1";
    eventRecordInfo.isSystemApp = true;
    eventRecordInfo.uid = 1;
    subscriberRecord->eventRecordInfo = eventRecordInfo;
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    OHOS::AAFwk::Want want;
    want.SetAction("usual.event.BOOT_COMPLETED");
    commonEventData->SetWant(want);
    eventRecord.commonEventData = commonEventData;
    MockIsVerfyPermisson(true);

    // Act
    bool result = manager->CheckSubscriberWhetherMatched(subscriberRecord, eventRecord);

    // Assert
    EXPECT_TRUE(result);
}

HWTEST_F(CommonEventSubscriberManagerTest, CheckSubscriberWhetherMatched_UidNotMatchedAndRuleIsAnd, Level0)
{
    // Arrange
    std::shared_ptr<CommonEventSubscriberManager> manager = std::make_shared<CommonEventSubscriberManager>();
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    CommonEventRecord eventRecord;
    publishInfo->SetBundleName("bundleName1");
    publishInfo->SetSubscriberType(SubscriberType::SYSTEM_SUBSCRIBER_TYPE);
    publishInfo->SetSubscriberUid({2});
    publishInfo->SetValidationRule(ValidationRule::AND);
    eventRecord.publishInfo = publishInfo;

    SubscriberRecordPtr subscriberRecord = std::make_shared<EventSubscriberRecord>();
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.bundleName = "bundleName1";
    eventRecordInfo.isSystemApp = true;
    eventRecordInfo.uid = 1;
    subscriberRecord->eventRecordInfo = eventRecordInfo;

    // Act
    bool result = manager->CheckSubscriberWhetherMatched(subscriberRecord, eventRecord);

    // Assert
    EXPECT_FALSE(result);
}

HWTEST_F(CommonEventSubscriberManagerTest, CheckSubscriberWhetherMatched_PermissionNotMatchedAndRuleIsAnd, Level0)
{
    // Arrange
    std::shared_ptr<CommonEventSubscriberManager> manager = std::make_shared<CommonEventSubscriberManager>();
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    CommonEventRecord eventRecord;
    publishInfo->SetBundleName("bundleName1");
    publishInfo->SetSubscriberType(SubscriberType::SYSTEM_SUBSCRIBER_TYPE);
    publishInfo->SetSubscriberUid({1});
    publishInfo->SetValidationRule(ValidationRule::AND);
    eventRecord.publishInfo = publishInfo;
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    OHOS::AAFwk::Want want;
    want.SetAction("usual.event.BOOT_COMPLETED");
    commonEventData->SetWant(want);
    eventRecord.commonEventData = commonEventData;

    SubscriberRecordPtr subscriberRecord = std::make_shared<EventSubscriberRecord>();
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.bundleName = "bundleName1";
    eventRecordInfo.isSystemApp = true;
    eventRecordInfo.uid = 1;
    eventRecordInfo.subId = "xxxx";
    subscriberRecord->eventRecordInfo = eventRecordInfo;
    auto eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>();
    eventSubscribeInfo->SetUserId(100);
    subscriberRecord->eventSubscribeInfo = eventSubscribeInfo;
    MockIsVerfyPermisson(false);

    // Act
    bool result = manager->CheckSubscriberWhetherMatched(subscriberRecord, eventRecord);

    // Assert
    EXPECT_TRUE(result);
}

HWTEST_F(CommonEventSubscriberManagerTest, CheckSubscriberWhetherMatched_OneOfConditionsNotMatchedAndRuleIsOr, Level0)
{
    // Arrange
    std::shared_ptr<CommonEventSubscriberManager> manager = std::make_shared<CommonEventSubscriberManager>();
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    CommonEventRecord eventRecord;
    publishInfo->SetBundleName("bundleName1");
    publishInfo->SetSubscriberType(SubscriberType::SYSTEM_SUBSCRIBER_TYPE);
    publishInfo->SetSubscriberUid({2});
    publishInfo->SetValidationRule(ValidationRule::OR);
    std::vector<std::string> publisherRequiredPermissions;
    publisherRequiredPermissions.emplace_back("publisherRequiredPermission");
    publishInfo->SetSubscriberPermissions(publisherRequiredPermissions);
    eventRecord.publishInfo = publishInfo;

    SubscriberRecordPtr subscriberRecord = std::make_shared<EventSubscriberRecord>();
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.bundleName = "bundleName1";
    eventRecordInfo.isSystemApp = true;
    eventRecordInfo.uid = 1;
    subscriberRecord->eventRecordInfo = eventRecordInfo;
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    OHOS::AAFwk::Want want;
    want.SetAction("usual.event.BOOT_COMPLETED");
    commonEventData->SetWant(want);
    eventRecord.commonEventData = commonEventData;
    MockIsVerfyPermisson(true);

    // Act
    bool result = manager->CheckSubscriberWhetherMatched(subscriberRecord, eventRecord);

    // Assert
    EXPECT_TRUE(result);
}

HWTEST_F(CommonEventSubscriberManagerTest, CheckSubscriberWhetherMatched_AllConditionsNotMatchedAndRuleIsOr, Level0)
{
    // Arrange
    std::shared_ptr<CommonEventSubscriberManager> manager = std::make_shared<CommonEventSubscriberManager>();
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    CommonEventRecord eventRecord;
    publishInfo->SetBundleName("bundleName1");
    publishInfo->SetSubscriberType(SubscriberType::SYSTEM_SUBSCRIBER_TYPE);
    publishInfo->SetSubscriberUid({2});
    publishInfo->SetValidationRule(ValidationRule::OR);
    eventRecord.publishInfo = publishInfo;

    SubscriberRecordPtr subscriberRecord = std::make_shared<EventSubscriberRecord>();
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.bundleName = "bundleName12";
    eventRecordInfo.isSystemApp = false;
    eventRecordInfo.uid = 1;
    subscriberRecord->eventRecordInfo = eventRecordInfo;

    // Act
    bool result = manager->CheckSubscriberWhetherMatched(subscriberRecord, eventRecord);

    // Assert
    EXPECT_FALSE(result);
}

HWTEST_F(CommonEventSubscriberManagerTest, CheckWhetherIsAppIndexSubscribed_AllBundleIsEmpty, Level0)
{
    // Arrange
    std::shared_ptr<CommonEventSubscriberManager> manager = std::make_shared<CommonEventSubscriberManager>();
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    CommonEventRecord eventRecord;
    EventRecordInfo publisherEventRecordInfo;
    publisherEventRecordInfo.bundleName = "";
    publisherEventRecordInfo.uid = 10000;
    eventRecord.eventRecordInfo = publisherEventRecordInfo;

    SubscriberRecordPtr subscriberRecord = std::make_shared<EventSubscriberRecord>();
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.bundleName = "";
    eventRecordInfo.uid = 10000;
    subscriberRecord->eventRecordInfo = eventRecordInfo;

    // Act
    bool result = manager->CheckWhetherIsAppIndexSubscribed(subscriberRecord, eventRecord);

    // Assert
    EXPECT_TRUE(result);
}

HWTEST_F(CommonEventSubscriberManagerTest, CheckWhetherIsAppIndexSubscribed_SubscreiberBundleIsEmpty, Level0)
{
    // Arrange
    std::shared_ptr<CommonEventSubscriberManager> manager = std::make_shared<CommonEventSubscriberManager>();
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    CommonEventRecord eventRecord;
    EventRecordInfo publisherEventRecordInfo;
    publisherEventRecordInfo.bundleName = "publisherBundle";
    publisherEventRecordInfo.uid = 10000;
    eventRecord.eventRecordInfo = publisherEventRecordInfo;

    SubscriberRecordPtr subscriberRecord = std::make_shared<EventSubscriberRecord>();
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.bundleName = "";
    eventRecordInfo.uid = 10000;
    subscriberRecord->eventRecordInfo = eventRecordInfo;

    // Act
    bool result = manager->CheckWhetherIsAppIndexSubscribed(subscriberRecord, eventRecord);

    // Assert
    EXPECT_TRUE(result);
}

HWTEST_F(CommonEventSubscriberManagerTest, CheckWhetherIsAppIndexSubscribed_PublisherBundleIsEmpty, Level0)
{
    // Arrange
    std::shared_ptr<CommonEventSubscriberManager> manager = std::make_shared<CommonEventSubscriberManager>();
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    CommonEventRecord eventRecord;
    EventRecordInfo publisherEventRecordInfo;
    publisherEventRecordInfo.bundleName = "";
    publisherEventRecordInfo.uid = 10000;
    eventRecord.eventRecordInfo = publisherEventRecordInfo;

    SubscriberRecordPtr subscriberRecord = std::make_shared<EventSubscriberRecord>();
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.bundleName = "subscriber";
    eventRecordInfo.uid = 10000;
    subscriberRecord->eventRecordInfo = eventRecordInfo;

    // Act
    bool result = manager->CheckWhetherIsAppIndexSubscribed(subscriberRecord, eventRecord);

    // Assert
    EXPECT_TRUE(result);
}

HWTEST_F(CommonEventSubscriberManagerTest, CheckWhetherIsAppIndexSubscribed_BundleIsNotEqual, Level0)
{
    // Arrange
    std::shared_ptr<CommonEventSubscriberManager> manager = std::make_shared<CommonEventSubscriberManager>();
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    CommonEventRecord eventRecord;
    EventRecordInfo publisherEventRecordInfo;
    publisherEventRecordInfo.bundleName = "publisher";
    publisherEventRecordInfo.uid = 10000;
    eventRecord.eventRecordInfo = publisherEventRecordInfo;

    SubscriberRecordPtr subscriberRecord = std::make_shared<EventSubscriberRecord>();
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.bundleName = "subscriber";
    eventRecordInfo.uid = 10000;
    subscriberRecord->eventRecordInfo = eventRecordInfo;

    // Act
    bool result = manager->CheckWhetherIsAppIndexSubscribed(subscriberRecord, eventRecord);

    // Assert
    EXPECT_TRUE(result);
}

HWTEST_F(CommonEventSubscriberManagerTest, CheckWhetherIsAppIndexSubscribed_BundleIsEqualButUidIsNotEqual, Level0)
{
    // Arrange
    std::shared_ptr<CommonEventSubscriberManager> manager = std::make_shared<CommonEventSubscriberManager>();
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    CommonEventRecord eventRecord;
    EventRecordInfo publisherEventRecordInfo;
    publisherEventRecordInfo.bundleName = "publisher";
    publisherEventRecordInfo.uid = 10001;
    eventRecord.eventRecordInfo = publisherEventRecordInfo;

    SubscriberRecordPtr subscriberRecord = std::make_shared<EventSubscriberRecord>();
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.bundleName = "publisher";
    eventRecordInfo.uid = 10000;
    subscriberRecord->eventRecordInfo = eventRecordInfo;

    // Act
    bool result = manager->CheckWhetherIsAppIndexSubscribed(subscriberRecord, eventRecord);

    // Assert
    EXPECT_FALSE(result);
}

HWTEST_F(CommonEventSubscriberManagerTest, CheckWhetherIsAppIndexSubscribed_BundleIsEqualAndUidIsEqual, Level0)
{
    // Arrange
    std::shared_ptr<CommonEventSubscriberManager> manager = std::make_shared<CommonEventSubscriberManager>();
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    CommonEventRecord eventRecord;
    EventRecordInfo publisherEventRecordInfo;
    publisherEventRecordInfo.bundleName = "publisher";
    publisherEventRecordInfo.uid = 10000;
    eventRecord.eventRecordInfo = publisherEventRecordInfo;

    SubscriberRecordPtr subscriberRecord = std::make_shared<EventSubscriberRecord>();
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.bundleName = "publisher";
    eventRecordInfo.uid = 10000;
    subscriberRecord->eventRecordInfo = eventRecordInfo;

    // Act
    bool result = manager->CheckWhetherIsAppIndexSubscribed(subscriberRecord, eventRecord);

    // Assert
    EXPECT_TRUE(result);
}
}
}