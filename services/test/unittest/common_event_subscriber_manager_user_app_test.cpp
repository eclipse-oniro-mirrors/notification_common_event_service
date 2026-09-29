/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#define private public  // NOLINT
#include "common_event_constant.h"
#include "common_event_publish_info.h"
#include "common_event_subscriber_manager.h"
#include "os_account_manager_helper.h"
#undef private

#include "user_app_test_mock_apis.h"
#include "want.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EventFwk;

class CommonEventSubscriberManagerUserAppTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

namespace {
constexpr uid_t UID_USER_100_NORMAL = 20010001;   // 100 * 200000 + 10001
constexpr uid_t UID_USER_100_SYSTEM = 20011002;
constexpr uid_t UID_USER_100_WILDCARD = 20012003;
constexpr uid_t UID_SUBSYSTEM_NATIVE = 5523;      // host user 0
constexpr uid_t UID_USER_0_SYSTEM = 3057;         // host user 0
constexpr uid_t UID_USER_101_WILDCARD = 20201001;
constexpr uid_t UID_USER_101_CONCRETE = 20202002;
constexpr uid_t UID_USER_99 = 19801001;           // 99 * 200000 + 10001

SubscriberRecordPtr CreateUserAppMatrixRecord(const std::string &event, int32_t subUserId, uid_t uid,
    bool isSubsystem, const std::string &bundleName)
{
    SubscriberRecordPtr record = std::make_shared<EventSubscriberRecord>();
    MatchingSkills skills;
    skills.AddEvent(event);
    record->eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>(skills);
    record->eventSubscribeInfo->SetUserId(subUserId);
    record->eventRecordInfo.uid = uid;
    record->eventRecordInfo.isSubsystem = isSubsystem;
    record->eventRecordInfo.bundleName = bundleName;
    return record;
}

bool ContainsBundle(const std::vector<SubscriberRecordPtr> &records, const std::string &bundleName)
{
    for (auto &record : records) {
        if (record->eventRecordInfo.bundleName == bundleName) {
            return true;
        }
    }
    return false;
}
} // namespace

/**
 * @tc.name: IsSubscriberSystemSide_001
 * @tc.desc: test IsSystemSideSubscriber with null record and subsystem record.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerUserAppTest, IsSubscriberSystemSide_001, Level0)
{
    GTEST_LOG_(INFO) << "IsSubscriberSystemSide_001 start";
    EXPECT_TRUE(IsSubscriberSystemSide(nullptr));

    SubscriberRecordPtr record = std::make_shared<EventSubscriberRecord>();
    record->eventRecordInfo.isSubsystem = true;
    record->eventRecordInfo.uid = UID_SUBSYSTEM_NATIVE;
    EXPECT_TRUE(IsSubscriberSystemSide(record));
    GTEST_LOG_(INFO) << "IsSubscriberSystemSide_001 end";
}

/**
 * @tc.name: IsSubscriberSystemSide_002
 * @tc.desc: test IsSystemSideSubscriber with subscriber hosted in system user space [0, 99].
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerUserAppTest, IsSubscriberSystemSide_002, Level0)
{
    GTEST_LOG_(INFO) << "IsSubscriberSystemSide_002 start";
    SubscriberRecordPtr user0Record = std::make_shared<EventSubscriberRecord>();
    user0Record->eventRecordInfo.uid = UID_USER_0_SYSTEM;
    EXPECT_TRUE(IsSubscriberSystemSide(user0Record));

    SubscriberRecordPtr user99Record = std::make_shared<EventSubscriberRecord>();
    user99Record->eventRecordInfo.uid = UID_USER_99;
    EXPECT_TRUE(IsSubscriberSystemSide(user99Record));
    GTEST_LOG_(INFO) << "IsSubscriberSystemSide_002 end";
}

/**
 * @tc.name: IsSubscriberSystemSide_003
 * @tc.desc: test IsSystemSideSubscriber with subscriber hosted in normal user space (>= 100).
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerUserAppTest, IsSubscriberSystemSide_003, Level0)
{
    GTEST_LOG_(INFO) << "IsSubscriberSystemSide_003 start";
    SubscriberRecordPtr user100Record = std::make_shared<EventSubscriberRecord>();
    user100Record->eventRecordInfo.uid = UID_USER_100_NORMAL;
    EXPECT_FALSE(IsSubscriberSystemSide(user100Record));

    SubscriberRecordPtr user101Record = std::make_shared<EventSubscriberRecord>();
    user101Record->eventRecordInfo.uid = UID_USER_101_WILDCARD;
    EXPECT_FALSE(IsSubscriberSystemSide(user101Record));
    GTEST_LOG_(INFO) << "IsSubscriberSystemSide_003 end";
}

/**
 * @tc.name: CheckSubscriberBySpecifiedType_UserApp
 * @tc.desc: test CheckSubscriberBySpecifiedType with USER_APP_SUBSCRIBER_TYPE.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerUserAppTest, CheckSubscriberBySpecifiedType_UserApp, Level0)
{
    GTEST_LOG_(INFO) << "CheckSubscriberBySpecifiedType_UserApp start";
    CommonEventSubscriberManager manager;

    SubscriberRecordPtr systemSideRecord = std::make_shared<EventSubscriberRecord>();
    systemSideRecord->eventRecordInfo.isSubsystem = true;
    systemSideRecord->eventRecordInfo.uid = UID_SUBSYSTEM_NATIVE;
    EXPECT_FALSE(manager.CheckSubscriberBySpecifiedType(
        static_cast<int32_t>(SubscriberType::USER_APP_SUBSCRIBER_TYPE), false, systemSideRecord));

    SubscriberRecordPtr userAppRecord = std::make_shared<EventSubscriberRecord>();
    userAppRecord->eventRecordInfo.uid = UID_USER_100_NORMAL;
    EXPECT_TRUE(manager.CheckSubscriberBySpecifiedType(
        static_cast<int32_t>(SubscriberType::USER_APP_SUBSCRIBER_TYPE), false, userAppRecord));

    EXPECT_TRUE(manager.CheckSubscriberBySpecifiedType(
        static_cast<int32_t>(SubscriberType::ALL_SUBSCRIBER_TYPE), false, systemSideRecord));
    GTEST_LOG_(INFO) << "CheckSubscriberBySpecifiedType_UserApp end";
}

/**
 * @tc.name: CheckSubscriberWhetherMatched_UserAppType
 * @tc.desc: test CheckSubscriberWhetherMatched with USER_APP type under AND rule.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerUserAppTest, CheckSubscriberWhetherMatched_UserAppType, Level0)
{
    GTEST_LOG_(INFO) << "CheckSubscriberWhetherMatched_UserAppType start";
    std::shared_ptr<CommonEventSubscriberManager> manager = std::make_shared<CommonEventSubscriberManager>();
    CommonEventRecord eventRecord;
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    publishInfo->SetSubscriberType(static_cast<int32_t>(SubscriberType::USER_APP_SUBSCRIBER_TYPE));
    eventRecord.publishInfo = publishInfo;

    SubscriberRecordPtr systemSideRecord = std::make_shared<EventSubscriberRecord>();
    EventRecordInfo systemSideInfo;
    systemSideInfo.isSubsystem = true;
    systemSideInfo.uid = UID_SUBSYSTEM_NATIVE;
    systemSideRecord->eventRecordInfo = systemSideInfo;
    EXPECT_FALSE(manager->CheckSubscriberWhetherMatched(systemSideRecord, eventRecord));

    SubscriberRecordPtr userAppRecord = std::make_shared<EventSubscriberRecord>();
    EventRecordInfo userAppInfo;
    userAppInfo.uid = UID_USER_100_NORMAL;
    userAppRecord->eventRecordInfo = userAppInfo;
    EXPECT_TRUE(manager->CheckSubscriberWhetherMatched(userAppRecord, eventRecord));
    GTEST_LOG_(INFO) << "CheckSubscriberWhetherMatched_UserAppType end";
}

/**
 * @tc.name: GetSubscriberRecordsByWantLocked_UserAppMatrix
 * @tc.desc: test USER_APP subscriber type full delivery matrix for event published to user 100.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerUserAppTest, GetSubscriberRecordsByWantLocked_UserAppMatrix, Level0)
{
    GTEST_LOG_(INFO) << "GetSubscriberRecordsByWantLocked_UserAppMatrix start";
    const std::string event = "test.event.userapp.matrix";
    CommonEventSubscriberManager manager;
    std::vector<SubscriberRecordPtr> subs;
    subs.push_back(CreateUserAppMatrixRecord(event, 100, UID_USER_100_NORMAL, false, "app.user100.normal"));
    subs.push_back(CreateUserAppMatrixRecord(event, 100, UID_USER_100_SYSTEM, false, "app.user100.system"));
    subs.push_back(CreateUserAppMatrixRecord(event, ALL_USER, UID_USER_100_WILDCARD, false, "app.user100.wildcard"));
    subs.push_back(CreateUserAppMatrixRecord(event, ALL_USER, UID_SUBSYSTEM_NATIVE, true, "subsystem.native"));
    subs.push_back(CreateUserAppMatrixRecord(event, ALL_USER, UID_USER_0_SYSTEM, false, "app.user0.system"));
    subs.push_back(CreateUserAppMatrixRecord(event, ALL_USER, UID_USER_101_WILDCARD, false, "app.user101.wildcard"));
    subs.push_back(CreateUserAppMatrixRecord(event, 101, UID_USER_101_CONCRETE, false, "app.user101.concrete"));
    subs.push_back(CreateUserAppMatrixRecord(event, 99, UID_USER_99, false, "app.user99"));
    manager.eventSubscribers_.emplace(event, subs);
    MockIsVerfyPermisson(true);

    CommonEventRecord eventRecord;
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    publishInfo->SetSubscriberType(static_cast<int32_t>(SubscriberType::USER_APP_SUBSCRIBER_TYPE));
    eventRecord.publishInfo = publishInfo;
    eventRecord.userId = 100;
    eventRecord.eventRecordInfo.isSystemApp = true;
    eventRecord.eventRecordInfo.bundleName = "publisher.bundle";
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    AAFwk::Want want;
    want.SetAction(event);
    commonEventData->SetWant(want);
    eventRecord.commonEventData = commonEventData;

    std::vector<SubscriberRecordPtr> records;
    manager.GetSubscriberRecordsByWantLocked(eventRecord, records);
    EXPECT_EQ(records.size(), 4);
    EXPECT_TRUE(ContainsBundle(records, "app.user100.normal"));
    EXPECT_TRUE(ContainsBundle(records, "app.user100.system"));
    EXPECT_TRUE(ContainsBundle(records, "app.user100.wildcard"));
    EXPECT_TRUE(ContainsBundle(records, "app.user101.wildcard"));
    EXPECT_FALSE(ContainsBundle(records, "subsystem.native"));
    EXPECT_FALSE(ContainsBundle(records, "app.user0.system"));
    EXPECT_FALSE(ContainsBundle(records, "app.user101.concrete"));
    EXPECT_FALSE(ContainsBundle(records, "app.user99"));
    GTEST_LOG_(INFO) << "GetSubscriberRecordsByWantLocked_UserAppMatrix end";
}

/**
 * @tc.name: GetSubscriberRecordsByWantLocked_UserAppAllUserEvent
 * @tc.desc: test USER_APP subscriber type with ALL_USER event broadcast.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerUserAppTest, GetSubscriberRecordsByWantLocked_UserAppAllUserEvent, Level0)
{
    GTEST_LOG_(INFO) << "GetSubscriberRecordsByWantLocked_UserAppAllUserEvent start";
    const std::string event = "test.event.userapp.alluser";
    CommonEventSubscriberManager manager;
    std::vector<SubscriberRecordPtr> subs;
    subs.push_back(CreateUserAppMatrixRecord(event, 100, UID_USER_100_NORMAL, false, "app.user100.normal"));
    subs.push_back(CreateUserAppMatrixRecord(event, ALL_USER, UID_USER_100_WILDCARD, false, "app.user100.wildcard"));
    subs.push_back(CreateUserAppMatrixRecord(event, ALL_USER, UID_SUBSYSTEM_NATIVE, true, "subsystem.native"));
    subs.push_back(CreateUserAppMatrixRecord(event, ALL_USER, UID_USER_0_SYSTEM, false, "app.user0.system"));
    subs.push_back(CreateUserAppMatrixRecord(event, ALL_USER, UID_USER_101_WILDCARD, false, "app.user101.wildcard"));
    subs.push_back(CreateUserAppMatrixRecord(event, 101, UID_USER_101_CONCRETE, false, "app.user101.concrete"));
    subs.push_back(CreateUserAppMatrixRecord(event, 99, UID_USER_99, false, "app.user99"));
    manager.eventSubscribers_.emplace(event, subs);
    MockIsVerfyPermisson(true);

    CommonEventRecord eventRecord;
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    publishInfo->SetSubscriberType(static_cast<int32_t>(SubscriberType::USER_APP_SUBSCRIBER_TYPE));
    eventRecord.publishInfo = publishInfo;
    eventRecord.userId = ALL_USER;
    eventRecord.eventRecordInfo.isSystemApp = true;
    eventRecord.eventRecordInfo.bundleName = "publisher.bundle";
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    AAFwk::Want want;
    want.SetAction(event);
    commonEventData->SetWant(want);
    eventRecord.commonEventData = commonEventData;

    std::vector<SubscriberRecordPtr> records;
    manager.GetSubscriberRecordsByWantLocked(eventRecord, records);
    EXPECT_EQ(records.size(), 4);
    EXPECT_TRUE(ContainsBundle(records, "app.user100.normal"));
    EXPECT_TRUE(ContainsBundle(records, "app.user100.wildcard"));
    EXPECT_TRUE(ContainsBundle(records, "app.user101.wildcard"));
    EXPECT_TRUE(ContainsBundle(records, "app.user101.concrete"));
    EXPECT_FALSE(ContainsBundle(records, "subsystem.native"));
    EXPECT_FALSE(ContainsBundle(records, "app.user0.system"));
    EXPECT_FALSE(ContainsBundle(records, "app.user99"));
    GTEST_LOG_(INFO) << "GetSubscriberRecordsByWantLocked_UserAppAllUserEvent end";
}

/**
 * @tc.name: GetSubscriberRecordsByWantLocked_UserAppOrRule
 * @tc.desc: test system side subscriber cannot bypass USER_APP exclusion via OR rule with permissions.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerUserAppTest, GetSubscriberRecordsByWantLocked_UserAppOrRule, Level0)
{
    GTEST_LOG_(INFO) << "GetSubscriberRecordsByWantLocked_UserAppOrRule start";
    const std::string event = "test.event.userapp.orrule";
    CommonEventSubscriberManager manager;
    std::vector<SubscriberRecordPtr> subs;
    subs.push_back(CreateUserAppMatrixRecord(event, 100, UID_SUBSYSTEM_NATIVE, true, "subsystem.native"));
    subs.push_back(CreateUserAppMatrixRecord(event, 100, UID_USER_100_NORMAL, false, "app.user100.normal"));
    manager.eventSubscribers_.emplace(event, subs);
    MockIsVerfyPermisson(true);

    CommonEventRecord eventRecord;
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    publishInfo->SetSubscriberType(static_cast<int32_t>(SubscriberType::USER_APP_SUBSCRIBER_TYPE));
    publishInfo->SetValidationRule(ValidationRule::OR);
    std::vector<std::string> subscriberPermissions;
    subscriberPermissions.emplace_back("test.permission.userapp");
    publishInfo->SetSubscriberPermissions(subscriberPermissions);
    eventRecord.publishInfo = publishInfo;
    eventRecord.userId = 100;
    eventRecord.eventRecordInfo.isSystemApp = true;
    eventRecord.eventRecordInfo.bundleName = "publisher.bundle";
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    AAFwk::Want want;
    want.SetAction(event);
    commonEventData->SetWant(want);
    eventRecord.commonEventData = commonEventData;

    // subsystem holds the required permission, but hard precondition still excludes it
    MockIsVerfyPermisson(true);
    std::vector<SubscriberRecordPtr> records;
    manager.GetSubscriberRecordsByWantLocked(eventRecord, records);
    EXPECT_EQ(records.size(), 1);
    EXPECT_TRUE(ContainsBundle(records, "app.user100.normal"));
    EXPECT_FALSE(ContainsBundle(records, "subsystem.native"));
    MockIsVerfyPermisson(false);
    GTEST_LOG_(INFO) << "GetSubscriberRecordsByWantLocked_UserAppOrRule end";
}

/**
 * @tc.name: GetSubscriberRecordsByWantLocked_WithoutUserAppType
 * @tc.desc: test delivery behavior keeps unchanged when USER_APP type is not set.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerUserAppTest, GetSubscriberRecordsByWantLocked_WithoutUserAppType, Level0)
{
    GTEST_LOG_(INFO) << "GetSubscriberRecordsByWantLocked_WithoutUserAppType start";
    const std::string event = "test.event.userapp.notype";
    CommonEventSubscriberManager manager;
    std::vector<SubscriberRecordPtr> subs;
    subs.push_back(CreateUserAppMatrixRecord(event, 100, UID_USER_100_NORMAL, false, "app.user100.normal"));
    subs.push_back(CreateUserAppMatrixRecord(event, ALL_USER, UID_USER_100_WILDCARD, false, "app.user100.wildcard"));
    subs.push_back(CreateUserAppMatrixRecord(event, ALL_USER, UID_SUBSYSTEM_NATIVE, true, "subsystem.native"));
    subs.push_back(CreateUserAppMatrixRecord(event, ALL_USER, UID_USER_0_SYSTEM, false, "app.user0.system"));
    subs.push_back(CreateUserAppMatrixRecord(event, ALL_USER, UID_USER_101_WILDCARD, false, "app.user101.wildcard"));
    subs.push_back(CreateUserAppMatrixRecord(event, 101, UID_USER_101_CONCRETE, false, "app.user101.concrete"));
    subs.push_back(CreateUserAppMatrixRecord(event, 99, UID_USER_99, false, "app.user99"));
    manager.eventSubscribers_.emplace(event, subs);
    MockIsVerfyPermisson(true);

    CommonEventRecord eventRecord;
    std::shared_ptr<CommonEventPublishInfo> publishInfo = std::make_shared<CommonEventPublishInfo>();
    eventRecord.publishInfo = publishInfo;
    eventRecord.userId = 100;
    eventRecord.eventRecordInfo.isSystemApp = true;
    eventRecord.eventRecordInfo.bundleName = "publisher.bundle";
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>();
    AAFwk::Want want;
    want.SetAction(event);
    commonEventData->SetWant(want);
    eventRecord.commonEventData = commonEventData;

    std::vector<SubscriberRecordPtr> records;
    manager.GetSubscriberRecordsByWantLocked(eventRecord, records);
    EXPECT_EQ(records.size(), 6);
    EXPECT_TRUE(ContainsBundle(records, "app.user100.normal"));
    EXPECT_TRUE(ContainsBundle(records, "app.user100.wildcard"));
    EXPECT_TRUE(ContainsBundle(records, "subsystem.native"));
    EXPECT_TRUE(ContainsBundle(records, "app.user0.system"));
    EXPECT_TRUE(ContainsBundle(records, "app.user101.wildcard"));
    EXPECT_TRUE(ContainsBundle(records, "app.user99"));
    EXPECT_FALSE(ContainsBundle(records, "app.user101.concrete"));
    GTEST_LOG_(INFO) << "GetSubscriberRecordsByWantLocked_WithoutUserAppType end";
}

/**
 * @tc.name: IsInSystemUserSpace_Boundary
 * @tc.desc: test shared range predicate boundary values including negative user id.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventSubscriberManagerUserAppTest, IsInSystemUserSpace_Boundary, Level0)
{
    GTEST_LOG_(INFO) << "IsInSystemUserSpace_Boundary start";
    EXPECT_FALSE(OsAccountManagerHelper::IsInSystemUserSpace(-1));
    EXPECT_TRUE(OsAccountManagerHelper::IsInSystemUserSpace(0));
    EXPECT_TRUE(OsAccountManagerHelper::IsInSystemUserSpace(SUBSCRIBE_USER_SYSTEM_END));
    EXPECT_FALSE(OsAccountManagerHelper::IsInSystemUserSpace(SUBSCRIBE_USER_SYSTEM_END + 1));
    EXPECT_FALSE(OsAccountManagerHelper::IsInSystemUserSpace(101));
    GTEST_LOG_(INFO) << "IsInSystemUserSpace_Boundary end";
}
