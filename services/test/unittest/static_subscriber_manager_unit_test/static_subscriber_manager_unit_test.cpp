/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "bool_wrapper.h"
#include "ces_inner_error_code.h"
#include "common_event_support.h"
#include "double_wrapper.h"
#include "int_wrapper.h"
#include "string_wrapper.h"
#include "want.h"
#define private public
#define protected public
#include "static_subscriber_manager.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EventFwk;
using StaticSubscriber = OHOS::EventFwk::StaticSubscriberManager::StaticSubscriber;

extern void MockVerifyAccessToken(bool mockRet, int8_t times = 0);
extern void MockGetHapTokenID(Security::AccessToken::AccessTokenID mockRet);
extern void MockQueryExtensionInfos(bool mockRet, uint8_t mockCase);
extern void MockGetResConfigFile(bool mockRet, uint8_t mockCase);
extern void MockQueryActiveOsAccountIds(bool mockRet, uint8_t mockCase);
extern void MockGetOsAccountLocalIdFromUid(bool mockRet, uint8_t mockCase = 0);
extern void MockGetApplicationInfos(uint8_t mockCase = 1);
extern bool IsConnectAbilityCalled();
extern void ResetAbilityManagerHelperState();
extern void ResetAccountMock();
extern void ResetBundleManagerHelperMock();
extern void ResetAccessTokenHelperMock();
extern void SetBundleNameMock();
extern void SetUidMock(int32_t uid);
extern void SetSystemMock(bool mockRet);

namespace {
    constexpr uint8_t TEST_MUL_SIZE = 2;
    constexpr uint8_t MOCK_CASE_2 = 2;
    constexpr uint8_t MOCK_CASE_3 = 3;
    constexpr uint8_t MOCK_CASE_4 = 4;
    constexpr uint8_t MOCK_CASE_5 = 5;
    const int VALID_CODE = 100;
    const std::string VALID_DATA = "testData";
    const std::string PARAM_1 = "param1";
    const std::string PARAM_2 = "param2";
    const std::string PARAM_3 = "param3";
    const std::string PARAM_4 = "param4";
    const std::string EVENT_NAME = "eventName";
    const bool PARAM_VALUE_1 = true;
    const int PARAM_VALUE_2 = 101;
    const double PARAM_VALUE_3 = 101.01;
    const std::string PARAM_VALUE_4 = "value";
    const bool INVALID_PARAM_VALUE_1 = false;
    const int INVALID_PARAM_VALUE_2 = 102;
    const double INVALID_PARAM_VALUE_3 = 102.01;
    const std::string INVALID_PARAM_VALUE_4 = "differentValue";
}

class StaticSubscriberManagerUnitTest : public testing::Test {
public:
    StaticSubscriberManagerUnitTest() {}

    virtual ~StaticSubscriberManagerUnitTest() {}

    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};

void StaticSubscriberManagerUnitTest::SetUpTestCase()
{
    SetSystemMock(true);
}

void StaticSubscriberManagerUnitTest::TearDownTestCase() {}

void StaticSubscriberManagerUnitTest::SetUp() {}

void StaticSubscriberManagerUnitTest::TearDown()
{
    ResetBundleManagerHelperMock();
    ResetAccountMock();
    ResetAccessTokenHelperMock();
}

/*
 * @tc.name: InitAllowListTest_0100
 * @tc.desc: test if StaticSubscriberManager's InitAllowList function executed as expected in normal case.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, InitAllowListTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, InitAllowListTest_0100, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    bool initResult = manager->InitAllowList();
    // expect init success
    EXPECT_TRUE(initResult);
    // expect hasInit true
    EXPECT_TRUE(manager->hasInitAllowList_);
}

/*
 * @tc.name: ParseEventsTest_0100
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function executed as expected with
 *           valid params when profile only has one element.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, ParseEventsTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, ParseEventsTest_0100, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string testExtensionName = "StaticSubscriber";
    std::string testExtensionBundleName = "default";
    int testExtensionUserId = 100;
    std::string testProfile =
        "{"
        "    \"commonEvents\":["
        "        {"
        "            \"events\":[\"usual.event.TIME_TICK\"],"
        "            \"name\":\"StaticSubscriber\","
        "            \"permission\":\"\""
        "        }"
        "    ]"
        "}";
    // set staticSubscribers_ value
    string expectEventName = "usual.event.TIME_TICK";
    std::set<std::string> events;
    events.insert(expectEventName);
    StaticSubscriber subscribers = { .events = events };
    std::string keyMock = std::to_string(testExtensionUserId) + "_" + testExtensionBundleName;
    manager->staticSubscribers_.emplace(keyMock, subscribers);
    // Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is not empty
    EXPECT_EQ(1, manager->validSubscribers_.size());
    // expect map content is correct
    auto it = manager->validSubscribers_.find(expectEventName);
    ASSERT_NE(manager->validSubscribers_.end(), it);
    std::vector<StaticSubscriberManager::StaticSubscriberInfo> infos = it->second;
    ASSERT_EQ(1, infos.size());
    auto info = infos[0];
    EXPECT_EQ(testExtensionName, info.name);
    EXPECT_EQ(testExtensionBundleName, info.bundleName);
    EXPECT_EQ(testExtensionUserId, info.userId);
}

/*
 * @tc.name: ParseEventsTest_0200
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function executed as expected with
 *           invalid empty profile when profile only has one element.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, ParseEventsTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, ParseEventsTest_0200, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string testExtensionName = "StaticSubscriber";
    std::string testExtensionBundleName = "default";
    int testExtensionUserId = 100;
    std::string testProfile ="";
    // Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is not empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: ParseEventsTest_0300
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function executed as expected with
 *           invalid non-object profile when profile only has one element.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, ParseEventsTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, ParseEventsTest_0300, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string testExtensionName = "StaticSubscriber";
    std::string testExtensionBundleName = "default";
    int testExtensionUserId = 100;
    std::string testProfile = "test";
    // Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: ParseEventsTest_0400
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function executed as expected with
 *           invalid empty 'commonEvents' element when profile only has one element.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, ParseEventsTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, ParseEventsTest_0400, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string testExtensionName = "StaticSubscriber";
    std::string testExtensionBundleName = "default";
    int testExtensionUserId = 100;
    std::string testProfile =
        "{"
        "    \"commonEvents\":["
        "    ]"
        "}";
    // Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: ParseEventsTest_0500
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function executed as expected with
 *           invalid non-object 'commonEvents' element when profile only has one element.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, ParseEventsTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, ParseEventsTest_0500, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string testExtensionName = "StaticSubscriber";
    std::string testExtensionBundleName = "default";
    int testExtensionUserId = 100;
    std::string testProfile =
        "{"
        "    \"commonEvents\":true"
        "}";
    // Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: ParseEventsTest_0600
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function executed as expected with
 *           invalid empty 'name' element when profile only has one element.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, ParseEventsTest_0600, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, ParseEventsTest_0600, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string testExtensionName = "StaticSubscriber";
    std::string testExtensionBundleName = "default";
    int testExtensionUserId = 100;
    std::string testProfile =
        "{"
        "    \"commonEvents\":["
        "        {"
        "            \"events\":[\"usual.event.TIME_TICK\"],"
        "            \"name\":\"\","
        "            \"permission\":\"\""
        "        }"
        "    ]"
        "}";
    // Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: ParseEventsTest_0700
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function executed as expected with
 *           invalid non-string 'name' element when profile only has one element.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, ParseEventsTest_0700, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, ParseEventsTest_0700, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string testExtensionName = "StaticSubscriber";
    std::string testExtensionBundleName = "default";
    int testExtensionUserId = 100;
    std::string testProfile =
        "{"
        "    \"commonEvents\":["
        "        {"
        "            \"events\":[\"usual.event.TIME_TICK\"],"
        "            \"name\":true,"
        "            \"permission\":\"\""
        "        }"
        "    ]"
        "}";
    // Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: ParseEventsTest_0800
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function executed as expected with
 *           invalid non-string 'name' element when profile only has one element.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, ParseEventsTest_0800, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, ParseEventsTest_0800, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string testExtensionName = "StaticSubscriber";
    std::string testExtensionBundleName = "default";
    int testExtensionUserId = 100;
    std::string testProfile =
        "{"
        "    \"commonEvents\":["
        "        {"
        "            \"events\":[\"usual.event.TIME_TICK\"],"
        "            \"name\":\"fakeName\","
        "            \"permission\":\"\""
        "        }"
        "    ]"
        "}";
    // Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: ParseEventsTest_0900
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function executed as expected with
 *           invalid json string when profile only has one element.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, ParseEventsTest_0900, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, ParseEventsTest_0900, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string testExtensionName = "StaticSubscriber";
    std::string testExtensionBundleName = "default";
    int testExtensionUserId = 100;
    std::string testProfile =
        "{"
        "    \"commonEvents\":["
        "        {"
        "            \"events\":[\"usual.event.TIME_TICK\"],"
        "            \"name\":\"StaticSubscriber\","
        "            \"permission\""
        "        }"
        "    ]"
        "}";
    // Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: ParseEventsTest_1000
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function executed as expected with
 *           invalid nonm-string 'permission' element when profile only has one element.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, ParseEventsTest_1000, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, ParseEventsTest_1000, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string testExtensionName = "StaticSubscriber";
    std::string testExtensionBundleName = "default";
    int testExtensionUserId = 100;
    std::string testProfile =
        "{"
        "    \"commonEvents\":["
        "        {"
        "            \"events\":[\"usual.event.TIME_TICK\"],"
        "            \"name\":\"StaticSubscriber\","
        "            \"permission\":true"
        "        }"
        "    ]"
        "}";
    // Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: ParseEventsTest_1100
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function executed as expected with
 *           invalid null type 'events' element when profile only has one element.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, ParseEventsTest_1100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, ParseEventsTest_1100, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string testExtensionName = "StaticSubscriber";
    std::string testExtensionBundleName = "default";
    int testExtensionUserId = 100;
    std::string testProfile =
        "{"
        "    \"commonEvents\":["
        "        {"
        "            \"events\":null,"
        "            \"name\":\"StaticSubscriber\","
        "            \"permission\":\"\""
        "        }"
        "    ]"
        "}";
    // Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: ParseEventsTest_1200
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function executed as expected with
 *           invalid non-array 'events' element when profile only has one element.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, ParseEventsTest_1200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, ParseEventsTest_1200, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string testExtensionName = "StaticSubscriber";
    std::string testExtensionBundleName = "default";
    int testExtensionUserId = 100;
    std::string testProfile =
        "{"
        "    \"commonEvents\":["
        "        {"
        "            \"events\":123,"
        "            \"name\":\"StaticSubscriber\","
        "            \"permission\":true"
        "        }"
        "    ]"
        "}";
    // Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: ParseEventsTest_1300
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function executed as expected with
 *           invalid empty 'events' element when profile only has one element.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, ParseEventsTest_1300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, ParseEventsTest_1300, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string testExtensionName = "StaticSubscriber";
    std::string testExtensionBundleName = "default";
    int testExtensionUserId = 100;
    std::string testProfile =
        "{"
        "    \"commonEvents\":["
        "        {"
        "            \"events\":[],"
        "            \"name\":\"StaticSubscriber\","
        "            \"permission\":true"
        "        }"
        "    ]"
        "}";
    // Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: ParseEventsTest_1400
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function executed as expected with
 *           invalid null 'event' element when profile only has one element.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, ParseEventsTest_1400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, ParseEventsTest_1400, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string testExtensionName = "StaticSubscriber";
    std::string testExtensionBundleName = "default";
    int testExtensionUserId = 100;
    std::string testProfile =
        "{"
        "    \"commonEvents\":["
        "        {"
        "            \"events\":[null],"
        "            \"name\":\"StaticSubscriber\","
        "            \"permission\":true"
        "        }"
        "    ]"
        "}";
    // Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: ParseEventsTest_1500
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function executed as expected with
 *           invalid non-string 'event' element when profile only has one element.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, ParseEventsTest_1500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, ParseEventsTest_1500, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string testExtensionName = "StaticSubscriber";
    std::string testExtensionBundleName = "default";
    int testExtensionUserId = 100;
    std::string testProfile =
        "{"
        "    \"commonEvents\":["
        "        {"
        "            \"events\":[123],"
        "            \"name\":\"StaticSubscriber\","
        "            \"permission\":true"
        "        }"
        "    ]"
        "}";
    // Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: ParseEventsTest_1600
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function executed as expected
 *            when profile has two elements.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, ParseEventsTest_1600, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, ParseEventsTest_1600, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string testExtensionName = "StaticSubscriber";
    std::string testExtensionBundleName = "default";
    int testExtensionUserId = 100;
    std::string testProfile =
        "{"
        "    \"commonEvents\":["
        "        {"
        "            \"events\":[\"usual.event.TIME_TICK0\"],"
        "            \"name\":\"StaticSubscriber\","
        "            \"permission\":\"\""
        "        },"
        "        {"
        "            \"events\":[\"usual.event.TIME_TICK1\"],"
        "            \"name\":\"StaticSubscriber\","
        "            \"permission\":\"permission1\""
        "        }"
        "    ]"
        "}";
    // set staticSubscribers_ value
    string expectEventName0 = "usual.event.TIME_TICK0";
    string expectEventName1 = "usual.event.TIME_TICK1";
    std::set<std::string> events;
    events.insert(expectEventName0);
    events.insert(expectEventName1);
    StaticSubscriber subscribers = { .events = events };
    std::string keyMock = std::to_string(testExtensionUserId) + "_" + testExtensionBundleName;
    manager->staticSubscribers_.emplace(keyMock, subscribers);
    // Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is not empty
    EXPECT_EQ(TEST_MUL_SIZE, manager->validSubscribers_.size());
    // expect map content is correct
    auto it0 = manager->validSubscribers_.find(expectEventName0);
    ASSERT_NE(manager->validSubscribers_.end(), it0);
    std::vector<StaticSubscriberManager::StaticSubscriberInfo> infos0 = it0->second;
    ASSERT_EQ(1, infos0.size());
    auto info0 = infos0[0];
    EXPECT_EQ(testExtensionName, info0.name);
    EXPECT_EQ(testExtensionBundleName, info0.bundleName);
    EXPECT_EQ(testExtensionUserId, info0.userId);
    EXPECT_EQ("", info0.permission);
    // expect map content is correct
    auto it1 = manager->validSubscribers_.find(expectEventName1);
    ASSERT_NE(manager->validSubscribers_.end(), it1);
    std::vector<StaticSubscriberManager::StaticSubscriberInfo> infos1 = it1->second;
    ASSERT_EQ(1, infos1.size());
    auto info1 = infos1[0];
    EXPECT_EQ(testExtensionName, info1.name);
    EXPECT_EQ(testExtensionBundleName, info1.bundleName);
    EXPECT_EQ(testExtensionUserId, info1.userId);
    string expectPermission = "permission1";
    EXPECT_EQ(expectPermission, info1.permission);
}

/*
 * @tc.name: ParseEventsTest_1700
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function executed as expected with
 *           one invalid element when profile has two elements.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, ParseEventsTest_1700, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, ParseEventsTest_1700, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string testExtensionName = "StaticSubscriber";
    std::string testExtensionBundleName = "default";
    int testExtensionUserId = 100;
    std::string testProfile =
        "{"
        "    \"commonEvents\":["
        "        {"
        "            \"events\":true,"
        "            \"name\":\"StaticSubscriber\","
        "            \"permission\":\"permission1\""
        "        },"
        "        {"
        "            \"events\":[\"usual.event.TIME_TICK1\"],"
        "            \"name\":\"StaticSubscriber\","
        "            \"permission\":\"permission1\""
        "        }"
        "    ]"
        "}";
    // set staticSubscribers_ value
    string expectEventName1 = "usual.event.TIME_TICK1";
    std::set<std::string> events;
    events.insert(expectEventName1);
    StaticSubscriber subscribers = { .events = events };
    std::string keyMock = std::to_string(testExtensionUserId) + "_" + testExtensionBundleName;
    manager->staticSubscribers_.emplace(keyMock, subscribers);
    // Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is not empty
    EXPECT_EQ(1, manager->validSubscribers_.size());
    // expect map content is correct
    string expectEventName0 = "usual.event.TIME_TICK0";
    auto it0 = manager->validSubscribers_.find(expectEventName0);
    EXPECT_EQ(manager->validSubscribers_.end(), it0);
    // expect map content is correct
    auto it1 = manager->validSubscribers_.find(expectEventName1);
    ASSERT_NE(manager->validSubscribers_.end(), it1);
    std::vector<StaticSubscriberManager::StaticSubscriberInfo> infos = it1->second;
    ASSERT_EQ(1, infos.size());
    auto info = infos[0];
    EXPECT_EQ(testExtensionName, info.name);
    EXPECT_EQ(testExtensionBundleName, info.bundleName);
    EXPECT_EQ(testExtensionUserId, info.userId);
    string expectPermission = "permission1";
    EXPECT_EQ(expectPermission, info.permission);
}

/*
 * @tc.name: ParseEventsTest_1800
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function executed as expected with
 *           two invalid elements when profile has two elements.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, ParseEventsTest_1800, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, ParseEventsTest_1800, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string testExtensionName = "StaticSubscriber";
    std::string testExtensionBundleName = "default";
    int testExtensionUserId = 100;
    std::string testProfile =
        "{"
        "    \"commonEvents\":["
        "        {"
        "            \"events\":[0\"],"
        "            \"name\":\"StaticSubscriber\","
        "            \"permission\":\"\""
        "        },"
        "        {"
        "            \"events\":[\"usual.event.TIME_TICK1\"],"
        "            \"name\"icSubscriber\","
        "            \"permission\":\"permission1\""
        "        }"
        "    ]"
        "}";
    // Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is not empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
    // expect map content is correct
    string expectEventName0 = "usual.event.TIME_TICK0";
    auto it0 = manager->validSubscribers_.find(expectEventName0);
    EXPECT_EQ(manager->validSubscribers_.end(), it0);
    // expect map content is correct
    string expectEventName1 = "usual.event.TIME_TICK1";
    auto it1 = manager->validSubscribers_.find(expectEventName1);
    EXPECT_EQ(manager->validSubscribers_.end(), it1);
}

/*
 * @tc.name: ParseEventsTest_1900
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function executed as expected with
 * duplicated elements when profile has two elements.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, ParseEventsTest_1900, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, ParseEventsTest_1900, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string testExtensionName = "StaticSubscriber";
    std::string testExtensionBundleName = "default";
    int testExtensionUserId = 100;
    std::string testProfile =
        "{"
        "    \"commonEvents\":["
        "        {"
        "            \"events\":[\"usual.event.TIME_TICK0\"],"
        "            \"name\":\"StaticSubscriber\","
        "            \"permission\":\"\""
        "        },"
        "        {"
        "            \"events\":[\"usual.event.TIME_TICK0\"],"
        "            \"name\":\"StaticSubscriber\","
        "            \"permission\":\"\""
        "        }"
        "    ]"
        "}";
    // set staticSubscribers_ value
    string expectEventName0 = "usual.event.TIME_TICK0";
    std::set<std::string> events;
    events.insert(expectEventName0);
    StaticSubscriber subscribers = { .events = events };
    std::string keyMock = std::to_string(testExtensionUserId) + "_" + testExtensionBundleName;
    manager->staticSubscribers_.emplace(keyMock, subscribers);
    // Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is not empty
    EXPECT_EQ(1, manager->validSubscribers_.size());
    // expect map content is correct
    auto it = manager->validSubscribers_.find(expectEventName0);
    ASSERT_NE(manager->validSubscribers_.end(), it);
    std::vector<StaticSubscriberManager::StaticSubscriberInfo> infos = it->second;
    ASSERT_EQ(1, infos.size());
    auto info = infos[0];
    EXPECT_EQ(testExtensionName, info.name);
    EXPECT_EQ(testExtensionBundleName, info.bundleName);
    EXPECT_EQ(testExtensionUserId, info.userId);
    EXPECT_EQ("", info.permission);
}

/*
 * @tc.name: ParseEventsTest_2000
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function executed as expected with
 * almost duplicated elements when profile has two elements.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, ParseEventsTest_2000, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, ParseEventsTest_2000, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string testExtensionName = "StaticSubscriber";
    std::string testExtensionBundleName = "default";
    int testExtensionUserId = 100;
    std::string testProfile =
        "{"
        "    \"commonEvents\":["
        "        {"
        "            \"events\":[\"usual.event.TIME_TICK0\"],"
        "            \"name\":\"StaticSubscriber\","
        "            \"permission\":\"\""
        "        },"
        "        {"
        "            \"events\":[\"usual.event.TIME_TICK0\"],"
        "            \"name\":\"StaticSubscriber\","
        "            \"permission\":\"permission1\""
        "        }"
        "    ]"
        "}";
    // set staticSubscribers_ value
    string expectEventName0 = "usual.event.TIME_TICK0";
    std::set<std::string> events;
    events.insert(expectEventName0);
    StaticSubscriber subscribers = { .events = events };
    std::string keyMock = std::to_string(testExtensionUserId) + "_" + testExtensionBundleName;
    manager->staticSubscribers_.emplace(keyMock, subscribers);
    // Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is not empty
    EXPECT_EQ(1, manager->validSubscribers_.size());
    // expect map content is correct
    auto it = manager->validSubscribers_.find(expectEventName0);
    ASSERT_NE(manager->validSubscribers_.end(), it);
    std::vector<StaticSubscriberManager::StaticSubscriberInfo> infos = it->second;
    ASSERT_EQ(1, infos.size());
    auto info = infos[0];
    EXPECT_EQ(testExtensionName, info.name);
    EXPECT_EQ(testExtensionBundleName, info.bundleName);
    EXPECT_EQ(testExtensionUserId, info.userId);
    EXPECT_EQ("", info.permission);
}

/*
 * @tc.name: ParseEventsTest_2100
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function executed as expected with
 *           no 'name' element when profile only has one element.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, ParseEventsTest_2100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, ParseEventsTest_2100, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string testExtensionName = "StaticSubscriber";
    std::string testExtensionBundleName = "default";
    int testExtensionUserId = 100;
    std::string testProfile =
        "{"
        "    \"commonEvents\":["
        "        {"
        "            \"events\":[\"usual.event.TIME_TICK\"],"
        "            \"permission\":\"\""
        "        }"
        "    ]"
        "}";
    // Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: ParseEventsTest_2200
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function executed as expected with
 *           no 'events' element when profile only has one element.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, ParseEventsTest_2200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, ParseEventsTest_2200, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string testExtensionName = "StaticSubscriber";
    std::string testExtensionBundleName = "default";
    int testExtensionUserId = 100;
    std::string testProfile =
        "{"
        "    \"commonEvents\":["
        "        {"
        "            \"name\":\"StaticSubscriber\","
        "            \"permission\":\"\""
        "        }"
        "    ]"
        "}";
    // Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: AddToValidSubsribersTest_0100
 * @tc.desc: test if StaticSubscriberManager's AddToValidSubsribers function executed as expected in normal case.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, AddToValidSubsribersTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, AddToValidSubsribersTest_0100, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    std::string testEventName = "testEvent";
    StaticSubscriberManager::StaticSubscriberInfo testInfo = {
        .name = "testName",
        .bundleName = "testBundleName",
        .userId = 100,
        .permission = ""
    };
    manager->AddToValidSubscribers(testEventName, testInfo);
    // expect valid subscribers map is empty
    EXPECT_EQ(1, manager->validSubscribers_.size());
}

/*
 * @tc.name: AddToValidSubsribersTest_0200
 * @tc.desc: test if StaticSubscriberManager's AddToValidSubsribers function executed as expected when add 
 *           duplicated subscriber with same event.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, AddToValidSubsribersTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, AddToValidSubsribersTest_0200, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    std::string testEventName = "testEvent";
    StaticSubscriberManager::StaticSubscriberInfo testInfo0 = {
        .name = "testName",
        .bundleName = "testBundleName",
        .userId = 100,
        .permission = ""
    };
    manager->AddToValidSubscribers(testEventName, testInfo0);
    EXPECT_EQ(1, manager->validSubscribers_.size());
    StaticSubscriberManager::StaticSubscriberInfo testInfo1 = {
        .name = "testName",
        .bundleName = "testBundleName",
        .userId = 100,
        .permission = ""
    };
    manager->AddToValidSubscribers(testEventName, testInfo1);
    EXPECT_EQ(1, manager->validSubscribers_.size());
}

/*
 * @tc.name: AddToValidSubsribersTest_0300
 * @tc.desc: test if StaticSubscriberManager's AddToValidSubsribers function executed as expected when add 
 *           different subscribers with same event.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, AddToValidSubsribersTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, AddToValidSubsribersTest_0300, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    std::string testEventName = "testEvent";
    StaticSubscriberManager::StaticSubscriberInfo testInfo0 = {
        .name = "testName",
        .bundleName = "testBundleName",
        .userId = 100,
        .permission = ""
    };
    manager->AddToValidSubscribers(testEventName, testInfo0);
    EXPECT_EQ(1, manager->validSubscribers_.size());
    StaticSubscriberManager::StaticSubscriberInfo testInfo1 = {
        .name = "testName1",
        .bundleName = "testBundleName1",
        .userId = 100,
        .permission = ""
    };
    manager->AddToValidSubscribers(testEventName, testInfo1);
    EXPECT_EQ(1, manager->validSubscribers_.size());
    auto subcriberList = manager->validSubscribers_[testEventName];
    EXPECT_EQ(TEST_MUL_SIZE, subcriberList.size());
}

/*
 * @tc.name: AddToValidSubsribersTest_0400
 * @tc.desc: test if StaticSubscriberManager's AddToValidSubsribers function executed as expected when add 
 *           same subscriber with diffrernt events.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, AddToValidSubsribersTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, AddToValidSubsribersTest_0400, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    std::string testEventName0 = "testEvent0";
    StaticSubscriberManager::StaticSubscriberInfo testInfo = {
        .name = "testName",
        .bundleName = "testBundleName",
        .userId = 100,
        .permission = ""
    };
    manager->AddToValidSubscribers(testEventName0, testInfo);
    EXPECT_EQ(1, manager->validSubscribers_.size());
    std::string testEventName1 = "testEvent1";
    manager->AddToValidSubscribers(testEventName1, testInfo);
    EXPECT_EQ(TEST_MUL_SIZE, manager->validSubscribers_.size());
    auto subcriberList1 = manager->validSubscribers_[testEventName0];
    EXPECT_EQ(1, subcriberList1.size());
    auto subcriberList2 = manager->validSubscribers_[testEventName1];
    EXPECT_EQ(1, subcriberList2.size());
}

/*
 * @tc.name: AddToValidSubsribersTest_0500
 * @tc.desc: test if StaticSubscriberManager's AddToValidSubsribers function executed as expected when add 
 *           different subscribers with diffrernt events.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, AddToValidSubsribersTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, AddToValidSubsribersTest_0500, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    std::string testEventName0 = "testEvent0";
    StaticSubscriberManager::StaticSubscriberInfo testInfo0 = {
        .name = "testName",
        .bundleName = "testBundleName",
        .userId = 100,
        .permission = ""
    };
    manager->AddToValidSubscribers(testEventName0, testInfo0);
    EXPECT_EQ(1, manager->validSubscribers_.size());
    std::string testEventName1 = "testEvent1";
    StaticSubscriberManager::StaticSubscriberInfo testInfo1 = {
        .name = "testName",
        .bundleName = "testBundleName",
        .userId = 100,
        .permission = ""
    };
    manager->AddToValidSubscribers(testEventName1, testInfo1);
    EXPECT_EQ(TEST_MUL_SIZE, manager->validSubscribers_.size());
}

/*
 * @tc.name: RemoveSubscriberWithBundleNameTest_0100
 * @tc.desc: test if StaticSubscriberManager's RemoveSubscriberWithBundleName function executed as expected
 *           in normal case.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, RemoveSubscriberWithBundleNameTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, RemoveSubscriberWithBundleNameTest_0100, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    std::string testEventName = "testEvent";
    StaticSubscriberManager::StaticSubscriberInfo testInfo = {
        .name = "testName",
        .bundleName = "testBundleName",
        .userId = 100,
        .permission = ""
    };
    manager->AddToValidSubscribers(testEventName, testInfo);
    // expect valid subscribers map is empty
    EXPECT_EQ(1, manager->validSubscribers_.size());
    std::string testBundleName = "testBundleName";
    int testUserId = 100;
    manager->RemoveSubscriberWithBundleName(testBundleName, testUserId);
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: RemoveSubscriberWithBundleNameTest_0200
 * @tc.desc: test if StaticSubscriberManager's RemoveSubscriberWithBundleName function executed as expected
 *           when userId not match.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, RemoveSubscriberWithBundleNameTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, RemoveSubscriberWithBundleNameTest_0200, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    std::string testEventName = "testEvent";
    StaticSubscriberManager::StaticSubscriberInfo testInfo = {
        .name = "testName",
        .bundleName = "testBundleName",
        .userId = 100,
        .permission = ""
    };
    manager->AddToValidSubscribers(testEventName, testInfo);
    // expect valid subscribers map is empty
    EXPECT_EQ(1, manager->validSubscribers_.size());
    std::string testBundleName = "testBundleName";
    int testUserId = 101;
    manager->RemoveSubscriberWithBundleName(testBundleName, testUserId);
    EXPECT_EQ(1, manager->validSubscribers_.size());
}

/*
 * @tc.name: RemoveSubscriberWithBundleNameTest_0300
 * @tc.desc: test if StaticSubscriberManager's RemoveSubscriberWithBundleName function executed as expected
 *           when bundleName not match.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, RemoveSubscriberWithBundleNameTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, RemoveSubscriberWithBundleNameTest_0300, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    std::string testEventName = "testEvent";
    StaticSubscriberManager::StaticSubscriberInfo testInfo = {
        .name = "testName",
        .bundleName = "testBundleName",
        .userId = 100,
        .permission = ""
    };
    manager->AddToValidSubscribers(testEventName, testInfo);
    // expect valid subscribers map is empty
    EXPECT_EQ(1, manager->validSubscribers_.size());
    std::string testBundleName = "testBundleName1";
    int testUserId = 100;
    manager->RemoveSubscriberWithBundleName(testBundleName, testUserId);
    EXPECT_EQ(1, manager->validSubscribers_.size());
}

/*
 * @tc.name: RemoveSubscriberWithBundleNameTest_0400
 * @tc.desc: test if StaticSubscriberManager's RemoveSubscriberWithBundleName function executed as expected
 *           when multiple bundlename and userid matched.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, RemoveSubscriberWithBundleNameTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, RemoveSubscriberWithBundleNameTest_0400, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    std::string testEventName0 = "testEvent0";
    StaticSubscriberManager::StaticSubscriberInfo testInfo = {
        .name = "testName",
        .bundleName = "testBundleName",
        .userId = 100,
        .permission = ""
    };
    manager->AddToValidSubscribers(testEventName0, testInfo);
    // expect valid subscribers map is empty
    EXPECT_EQ(1, manager->validSubscribers_.size());
    std::string testEventName1 = "testEvent1";
    manager->AddToValidSubscribers(testEventName1, testInfo);
    // expect valid subscribers map is empty
    EXPECT_EQ(TEST_MUL_SIZE, manager->validSubscribers_.size());
    std::string testBundleName = "testBundleName";
    int testUserId = 100;
    manager->RemoveSubscriberWithBundleName(testBundleName, testUserId);
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: VerifyPublisherPermissionTest_0100
 * @tc.desc: test if StaticSubscriberManager's VerifyPublisherPermission function executed as expected
 *           when in normal case.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, VerifyPublisherPermissionTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, VerifyPublisherPermissionTest_0100, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    Security::AccessToken::AccessTokenID id = 100;
    std::string permission = "permission";
    MockVerifyAccessToken(true);
    EXPECT_TRUE(manager->VerifyPublisherPermission(id, permission));
}

/*
 * @tc.name: VerifyPublisherPermissionTest_0200
 * @tc.desc: test if StaticSubscriberManager's VerifyPublisherPermission function executed as expected
 *           when permission is null.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, VerifyPublisherPermissionTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, VerifyPublisherPermissionTest_0200, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    Security::AccessToken::AccessTokenID id = 100;
    std::string permission = "";
    EXPECT_TRUE(manager->VerifyPublisherPermission(id, permission));
}

/*
 * @tc.name: VerifyPublisherPermissionTest_0300
 * @tc.desc: test if StaticSubscriberManager's VerifyPublisherPermission function executed as expected
 *           when permission verify failed.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, VerifyPublisherPermissionTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, VerifyPublisherPermissionTest_0300, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    Security::AccessToken::AccessTokenID id = 100;
    std::string permission = "permission";
    MockVerifyAccessToken(false);
    EXPECT_FALSE(manager->VerifyPublisherPermission(id, permission));
}

/*
 * @tc.name: InitValidSubscribersTest_0100
 * @tc.desc: test if StaticSubscriberManager's InitValidSubscribers function executed as expected
 *           in normal case.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, InitValidSubscribersTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, InitValidSubscribersTest_0100, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    // init subscriberList
    MockQueryExtensionInfos(true, 1);
    MockGetResConfigFile(true, 1);
    // set staticSubscribers_ value
    std::string testEventName = "usual.event.TIME_TICK";
    std::string bundleName = "com.ohos.systemui";
    std::set<std::string> events;
    events.insert(testEventName);
    StaticSubscriber subscribers = { .events = events };
    int32_t userId = 100;
    manager->staticSubscribers_.emplace(std::to_string(userId) + "_" + bundleName, subscribers);
    EXPECT_TRUE(manager->InitValidSubscribers());
    EXPECT_TRUE(manager->hasInitValidSubscribers_);
    EXPECT_EQ(1, manager->validSubscribers_.size());
    auto validSubscribers = manager->validSubscribers_[testEventName];
    EXPECT_EQ(1, validSubscribers.size());
}

/*
 * @tc.name: InitValidSubscribersTest_0200
 * @tc.desc: test if StaticSubscriberManager's InitValidSubscribers function executed as expected
 *           when valid list is not empty.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, InitValidSubscribersTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, InitValidSubscribersTest_0200, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    // mock that query extension info with one extension
    MockQueryExtensionInfos(true, 1);
    MockGetResConfigFile(true, 1);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    // init subscriberList
    std::string eventName = "eventName0";
    std::vector<StaticSubscriberManager::StaticSubscriberInfo> info0;
    manager->validSubscribers_.insert(make_pair(eventName, info0));
    EXPECT_EQ(1, manager->validSubscribers_.size());
    // set staticSubscribers_ value
    std::string testEventName = "usual.event.TIME_TICK";
    std::string bundleName = "com.ohos.systemui";
    std::set<std::string> events;
    events.insert(testEventName);
    StaticSubscriber subscribers = { .events = events };
    int32_t userId = 100;
    manager->staticSubscribers_.emplace(std::to_string(userId) + "_" + bundleName, subscribers);
    EXPECT_TRUE(manager->InitValidSubscribers());
    EXPECT_TRUE(manager->hasInitValidSubscribers_);
    EXPECT_EQ(1, manager->validSubscribers_.size());
    auto validSubscribers = manager->validSubscribers_[testEventName];
    EXPECT_EQ(1, validSubscribers.size());
}

/*
 * @tc.name: InitValidSubscribersTest_0300
 * @tc.desc: test if StaticSubscriberManager's InitValidSubscribers function executed as expected
 *           when query extension info failed.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, InitValidSubscribersTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, InitValidSubscribersTest_0300, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    MockQueryExtensionInfos(false, 0);
    std::string eventName = "eventName0";
    EXPECT_FALSE(manager->InitValidSubscribers());
}

/*
 * @tc.name: InitValidSubscribersTest_0400
 * @tc.desc: test if StaticSubscriberManager's InitValidSubscribers function executed as expected
 *           when one invalid extensions were found.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, InitValidSubscribersTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, InitValidSubscribersTest_0400, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    // init subscriberList
    MockQueryExtensionInfos(true, MOCK_CASE_2);
    MockGetResConfigFile(true, 1);
    EXPECT_TRUE(manager->InitValidSubscribers());
    EXPECT_TRUE(manager->hasInitValidSubscribers_);
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: InitValidSubscribersTest_0500
 * @tc.desc: test if StaticSubscriberManager's InitValidSubscribers function executed as expected
 *           when two valid extensions were found, profile different.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, InitValidSubscribersTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, InitValidSubscribersTest_0500, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    // init subscriberList
    MockQueryExtensionInfos(true, MOCK_CASE_3);
    MockGetResConfigFile(true, MOCK_CASE_2);
    // set staticSubscribers_ value
    std::string testEventName0 = "usual.event.TIME_TICK";
    std::string bundleName = "com.ohos.systemui";
    std::set<std::string> events;
    events.insert(testEventName0);
    StaticSubscriber subscribers = { .events = events };
    int32_t userId = 100;
    std::string keyMock = std::to_string(userId) + "_" + bundleName;
    manager->staticSubscribers_.emplace(keyMock, subscribers);
    EXPECT_TRUE(manager->InitValidSubscribers());
    EXPECT_TRUE(manager->hasInitValidSubscribers_);
    EXPECT_EQ(1, manager->validSubscribers_.size());
    auto validSubscribers0 = manager->validSubscribers_[testEventName0];
    EXPECT_EQ(1, validSubscribers0.size());
}

/*
 * @tc.name: InitValidSubscribersTest_0600
 * @tc.desc: test if StaticSubscriberManager's InitValidSubscribers function executed as expected
 *           when two valid extensions were found, profile same.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, InitValidSubscribersTest_0600, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, InitValidSubscribersTest_0600, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    // init subscriberList
    MockQueryExtensionInfos(true, MOCK_CASE_3);
    MockGetResConfigFile(true, MOCK_CASE_3);
    // set staticSubscribers_ value
    std::string testEventName = "usual.event.TIME_TICK";
    std::string bundleName = "com.ohos.systemui";
    std::set<std::string> events;
    events.insert(testEventName);
    StaticSubscriber subscribers = { .events = events };
    int32_t userId = 100;
    std::string keyMock = std::to_string(userId) + "_" + bundleName;
    manager->staticSubscribers_.emplace(keyMock, subscribers);
    EXPECT_TRUE(manager->InitValidSubscribers());
    EXPECT_TRUE(manager->hasInitValidSubscribers_);
    EXPECT_EQ(1, manager->validSubscribers_.size());
    auto validSubscribers = manager->validSubscribers_[testEventName];
    EXPECT_EQ(1, validSubscribers.size());
}

/*
 * @tc.name: InitValidSubscribersTest_0700
 * @tc.desc: test if StaticSubscriberManager's InitValidSubscribers function executed as expected
 *           when one valid extension and one invalid extension were found.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, InitValidSubscribersTest_0700, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, InitValidSubscribersTest_0700, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    // init subscriberList
    MockQueryExtensionInfos(true, MOCK_CASE_3);
    MockGetResConfigFile(true, MOCK_CASE_3);
    // set staticSubscribers_ value
    std::string testEventName = "usual.event.TIME_TICK";
    std::string bundleName = "com.ohos.systemui";
    std::set<std::string> events;
    events.insert(testEventName);
    StaticSubscriber subscribers = { .events = events };
    int32_t userId = 100;
    std::string keyMock = std::to_string(userId) + "_" + bundleName;
    manager->staticSubscribers_.emplace(keyMock, subscribers);
    EXPECT_TRUE(manager->InitValidSubscribers());
    EXPECT_TRUE(manager->hasInitValidSubscribers_);
    EXPECT_EQ(1, manager->validSubscribers_.size());
    auto validSubscribers = manager->validSubscribers_[testEventName];
    EXPECT_EQ(1, validSubscribers.size());
}

/*
 * @tc.name: InitValidSubscribersTest_0800
 * @tc.desc: test if StaticSubscriberManager's InitValidSubscribers function executed as expected
 *           when two invalid extension were found.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, InitValidSubscribersTest_0800, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, InitValidSubscribersTest_0800, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    MockQueryExtensionInfos(true, MOCK_CASE_3);
    MockGetResConfigFile(true, MOCK_CASE_3);
    EXPECT_TRUE(manager->InitValidSubscribers());
    EXPECT_TRUE(manager->hasInitValidSubscribers_);
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: UpdateSubscriberTest_0100
 * @tc.desc: test if StaticSubscriberManager's UpdateSubscriber function executed as expected
 *           in normal case.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, UpdateSubscriberTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, UpdateSubscriberTest_0100, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    Want testWant;
    std::string testNormalEventName = "testEventName";
    testWant.SetAction(testNormalEventName);
    CommonEventData testEventData;
    testEventData.SetWant(testWant);
    manager->UpdateSubscriber(testEventData);
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: UpdateSubscriberTest_0200
 * @tc.desc: test if StaticSubscriberManager's UpdateSubscriber function executed as expected
 *           when add bundle event was sent.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, UpdateSubscriberTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, UpdateSubscriberTest_0200, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    // init subscriberList
    Want testWant;
    std::string testNormalEventName = CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED;
    testWant.SetAction(testNormalEventName);
    std::string testBundleName = "com.ohos.systemui";
    std::string testAbilityName = "StaticSubscriber";
    testWant.SetElementName(testBundleName, testAbilityName);
    CommonEventData testEventData;
    testEventData.SetWant(testWant);
    // mock that query extension info with one extension
    MockQueryExtensionInfos(true, 1);
    MockGetResConfigFile(true, 1);
    MockGetOsAccountLocalIdFromUid(true);
    MockQueryActiveOsAccountIds(true, 0);
    // set staticSubscribers_ value
    std::string testEventName = "usual.event.TIME_TICK";
    std::set<std::string> events;
    events.insert(testEventName);
    StaticSubscriber subscribers = { .events = events };
    int32_t userId = 100;
    std::string keyMock = std::to_string(userId) + "_" + testBundleName;
    manager->staticSubscribers_.emplace(keyMock, subscribers);
    manager->UpdateSubscriber(testEventData);
    EXPECT_EQ(1, manager->validSubscribers_.size());
}

/*
 * @tc.name: UpdateSubscriberTest_0300
 * @tc.desc: test if StaticSubscriberManager's UpdateSubscriber function executed as expected
 *           when change bundle event was sent.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, UpdateSubscriberTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, UpdateSubscriberTest_0300, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    // init subscriberList
    std::string eventName = "usual.event.TIME_TICK";
    StaticSubscriberManager::StaticSubscriberInfo testInfo = {
        .name = "StaticSubscriber",
        .bundleName = "com.ohos.systemui",
        .userId = 100,
        .permission = "permission1",
    };
    std::vector<StaticSubscriberManager::StaticSubscriberInfo> info0;
    info0.emplace_back(testInfo);
    manager->validSubscribers_.insert(make_pair(eventName, info0));
    auto validSubscribers0 = manager->validSubscribers_[eventName];
    EXPECT_EQ(1, validSubscribers0.size());
    std::string expectPermissionBefore = "permission1";
    EXPECT_EQ(expectPermissionBefore, validSubscribers0[0].permission);
    Want testWant;
    std::string testNormalEventName = CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED;
    testWant.SetAction(testNormalEventName);
    std::string testBundleName = "com.ohos.systemui";
    std::string testAbilityName = "StaticSubscriber";
    testWant.SetElementName(testBundleName, testAbilityName);
    CommonEventData testEventData;
    testEventData.SetWant(testWant);
    // mock that query extension info with one extension
    MockQueryExtensionInfos(true, 1);
    MockGetResConfigFile(true, 1);
    // set staticSubscribers_ value
    std::string testEventName = "usual.event.TIME_TICK";
    std::set<std::string> events;
    events.insert(testEventName);
    StaticSubscriber subscribers = { .events = events };
    int32_t userId = 100;
    std::string keyMock = std::to_string(userId) + "_" + testBundleName;
    manager->staticSubscribers_.emplace(keyMock, subscribers);
    manager->UpdateSubscriber(testEventData);
    EXPECT_EQ(1, manager->validSubscribers_.size());
    std::string expectPermissionAfter = "permission0";
    auto validSubscribers1 = manager->validSubscribers_[eventName];
    EXPECT_EQ(1, validSubscribers1.size());
}

/*
 * @tc.name: UpdateSubscriberTest_0400
 * @tc.desc: test if StaticSubscriberManager's UpdateSubscriber function executed as expected
 *           when remove bundle event was sent.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, UpdateSubscriberTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, UpdateSubscriberTest_0400, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    std::string eventName = "usual.event.TIME_TICK";
    StaticSubscriberManager::StaticSubscriberInfo testInfo = {
        .name = "StaticSubscriber",
        .bundleName = "com.ohos.systemui",
        .userId = 100,
        .permission = "permission1"
    };
    std::vector<StaticSubscriberManager::StaticSubscriberInfo> info0;
    info0.emplace_back(testInfo);
    manager->validSubscribers_.insert(make_pair(eventName, info0));
    auto validSubscribers0 = manager->validSubscribers_[eventName];
    EXPECT_EQ(1, validSubscribers0.size());
    std::string expectPermissionBefore = "permission1";
    EXPECT_EQ(expectPermissionBefore, validSubscribers0[0].permission);
    Want testWant;
    std::string testNormalEventName = CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED;
    testWant.SetAction(testNormalEventName);
    std::string testBundleName = "com.ohos.systemui";
    std::string testAbilityName = "StaticSubscriber";
    testWant.SetElementName(testBundleName, testAbilityName);
    CommonEventData testEventData;
    testEventData.SetWant(testWant);
    // mock that query extension info with one extension
    MockQueryExtensionInfos(true, 1);
    MockGetResConfigFile(true, 1);
    manager->UpdateSubscriber(testEventData);
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: UpdateSubscriberTest_0500
 * @tc.desc: test if StaticSubscriberManager's UpdateSubscriber function executed as expected
 *           when GetOsAccountLocalIdFromUid failed.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, UpdateSubscriberTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, UpdateSubscriberTest_0500, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    Want testWant;
    std::string testNormalEventName = CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED;
    testWant.SetAction(testNormalEventName);
    std::string testBundleName = "com.ohos.systemui";
    std::string testAbilityName = "StaticSubscriber";
    testWant.SetElementName(testBundleName, testAbilityName);
    CommonEventData testEventData;
    testEventData.SetWant(testWant);
    // mock that query extension info with one extension
    MockQueryExtensionInfos(true, 1);
    MockGetResConfigFile(true, 1);
    MockGetOsAccountLocalIdFromUid(false);
    manager->UpdateSubscriber(testEventData);
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: UpdateSubscriberTest_0600
 * @tc.desc: test if StaticSubscriberManager's UpdateSubscriber function executed as expected
 *           when QueryActiveOsAccountIds failed.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, UpdateSubscriberTest_0600, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, UpdateSubscriberTest_0600, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    Want testWant;
    std::string testNormalEventName = CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED;
    testWant.SetAction(testNormalEventName);
    std::string testBundleName = "com.ohos.systemui";
    std::string testAbilityName = "StaticSubscriber";
    testWant.SetElementName(testBundleName, testAbilityName);
    CommonEventData testEventData;
    testEventData.SetWant(testWant);
    // mock that query extension info with one extension
    MockQueryExtensionInfos(true, 1);
    MockGetResConfigFile(true, 1);
    MockQueryActiveOsAccountIds(false, 0);
    manager->UpdateSubscriber(testEventData);
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: UpdateSubscriberTest_0700
 * @tc.desc: test if StaticSubscriberManager's UpdateSubscriber function executed as expected
 *           when userId not match.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, UpdateSubscriberTest_0700, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, UpdateSubscriberTest_0700, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    Want testWant;
    std::string testNormalEventName = CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED;
    testWant.SetAction(testNormalEventName);
    std::string testBundleName = "com.ohos.systemui";
    std::string testAbilityName = "StaticSubscriber";
    testWant.SetElementName(testBundleName, testAbilityName);
    CommonEventData testEventData;
    testEventData.SetWant(testWant);
    // mock that query extension info with one extension
    MockQueryExtensionInfos(true, 1);
    MockGetResConfigFile(true, 1);
    MockGetOsAccountLocalIdFromUid(true);
    MockQueryActiveOsAccountIds(true, 1);
    manager->UpdateSubscriber(testEventData);
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: AddSubscriberTest_0100
 * @tc.desc: test if StaticSubscriberManager's AddSubscriber function executed as expected
 *           in normal case.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, AddSubscriberTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, AddSubscriberTest_0100, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    AppExecFwk::ExtensionAbilityInfo info0;
    info0.bundleName = "com.ohos.systemui";
    info0.name = "StaticSubscriber";
    MockGetResConfigFile(true, 1);
    // set staticSubscribers_ value
    string expectEventName = "usual.event.TIME_TICK";
    std::set<std::string> events;
    events.insert(expectEventName);
    StaticSubscriber subscribers = { .events = events };
    int32_t userId = 100;
    manager->staticSubscribers_.emplace(std::to_string(userId) + "_" + info0.bundleName, subscribers);
    manager->AddSubscriber(info0);
    EXPECT_EQ(1, manager->validSubscribers_.size());
}

/*
 * @tc.name: AddSubscriberTest_0200
 * @tc.desc: test if StaticSubscriberManager's AddSubscriber function executed as expected
 *           when GetResConfigFile failed.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, AddSubscriberTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, AddSubscriberTest_0200, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    AppExecFwk::ExtensionAbilityInfo info0;
    info0.bundleName = "com.ohos.systemui";
    info0.name = "StaticSubscriber";
    MockGetResConfigFile(false, 0);
    manager->AddSubscriber(info0);
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: AddSubscriberTest_0300
 * @tc.desc: test if StaticSubscriberManager's AddSubscriber function executed as expected
 *           when GetOsAccountLocalIdFromUid failed.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, AddSubscriberTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, AddSubscriberTest_0300, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    AppExecFwk::ExtensionAbilityInfo info0;
    info0.bundleName = "com.ohos.systemui";
    info0.name = "StaticSubscriber";
    MockGetResConfigFile(true, 1);
    MockGetOsAccountLocalIdFromUid(false);
    manager->AddSubscriber(info0);
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: AddSubscriberTest_0400
 * @tc.desc: test if StaticSubscriberManager's AddSubscriber function executed as expected
 *           when profiles has more than one profile.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, AddSubscriberTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, AddSubscriberTest_0400, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    AppExecFwk::ExtensionAbilityInfo info0;
    info0.bundleName = "com.ohos.systemui";
    info0.name = "StaticSubscriber";
    MockGetResConfigFile(true, MOCK_CASE_2);
    MockGetOsAccountLocalIdFromUid(true);
    // set staticSubscribers_ value
    string expectEventName = "usual.event.TIME_TICK";
    std::set<std::string> events;
    events.insert(expectEventName);
    StaticSubscriber subscribers = { .events = events };
    int32_t userId = 100;
    manager->staticSubscribers_.emplace(std::to_string(userId) + "_" + info0.bundleName, subscribers);
    manager->AddSubscriber(info0);
    EXPECT_EQ(1, manager->validSubscribers_.size());
}

/*
 * @tc.name: AddSubscriberWithBundleNameTest_0100
 * @tc.desc: test if StaticSubscriberManager's AddSubscriberWithBundleName function executed as expected
 *           in normal case.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, AddSubscriberWithBundleNameTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, AddSubscriberWithBundleNameTest_0100, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    // init subscriberList
    // mock that query extension info with one extension
    MockQueryExtensionInfos(true, 1);
    // mock that cet config file with one profile
    MockGetResConfigFile(true, 1);
    std::string testBundleName = "com.ohos.systemui";
    int32_t testUserId = 100;
    // set staticSubscribers_ value
    std::string testEventName = "usual.event.TIME_TICK";
    std::set<std::string> events;
    events.insert(testEventName);
    StaticSubscriber subscribers = { .events = events };
    int32_t userId = 100;
    manager->staticSubscribers_.emplace(std::to_string(userId) + "_" + testBundleName, subscribers);
    manager->AddSubscriberWithBundleName(testBundleName, testUserId);
    EXPECT_EQ(1, manager->validSubscribers_.size());
}

/*
 * @tc.name: AddSubscriberWithBundleNameTest_0200
 * @tc.desc: test if StaticSubscriberManager's AddSubscriberWithBundleName function executed as expected
 *           when QueryExtensionInfos failed.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, AddSubscriberWithBundleNameTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, AddSubscriberWithBundleNameTest_0200, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    // init subscriberList
    // mock that query extension info failed
    MockQueryExtensionInfos(false, 0);
    MockGetResConfigFile(true, 1);
    std::string testBundleName = "com.ohos.systemui";
    int32_t testUserId = 100;
    manager->AddSubscriberWithBundleName(testBundleName, testUserId);
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: AddSubscriberWithBundleNameTest_0300
 * @tc.desc: test if StaticSubscriberManager's AddSubscriberWithBundleName function executed as expected
 *           when bundleName not match.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, AddSubscriberWithBundleNameTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, AddSubscriberWithBundleNameTest_0300, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    // init subscriberList
    // mock that query extension info with one extension
    MockQueryExtensionInfos(true, 1);
    MockGetResConfigFile(true, 1);
    std::string testBundleName = "com.ohos.systemui1";
    int32_t testUserId = 100;
    manager->AddSubscriberWithBundleName(testBundleName, testUserId);
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: AddSubscriberWithBundleNameTest_0400
 * @tc.desc: test if StaticSubscriberManager's AddSubscriberWithBundleName function executed as expected
 *           when extension is not in allow list.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, AddSubscriberWithBundleNameTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, AddSubscriberWithBundleNameTest_0400, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    // init subscriberList
    // mock that query extension info with one extension
    MockQueryExtensionInfos(true, 1);
    MockGetResConfigFile(true, 1);
    std::string testBundleName = "com.ohos.systemui";
    int32_t testUserId = 100;
    manager->AddSubscriberWithBundleName(testBundleName, testUserId);
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: AddSubscriberWithBundleNameTest_0500
 * @tc.desc: test if StaticSubscriberManager's AddSubscriberWithBundleName function executed as expected
 *           when more than one extensions were queried.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, AddSubscriberWithBundleNameTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, AddSubscriberWithBundleNameTest_0500, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    MockQueryExtensionInfos(true, MOCK_CASE_4);
    MockGetResConfigFile(true, MOCK_CASE_4);
    std::string testBundleName = "com.ohos.systemui";
    int32_t testUserId = 100;
    // set staticSubscribers_ value
    string expectEventName = "usual.event.TIME_TICK";
    std::set<std::string> events;
    events.insert(expectEventName);
    StaticSubscriber subscriber = { .events = events };
    int32_t userId = 100;
    manager->staticSubscribers_.emplace(std::to_string(userId) + "_" + testBundleName, subscriber);
    manager->AddSubscriberWithBundleName(testBundleName, testUserId);
    EXPECT_EQ(1, manager->validSubscribers_.size());
    // expect that targer event has two subscribers
    std::string testEventName = "usual.event.TIME_TICK";
    auto subscribers = manager->validSubscribers_[testEventName];
    EXPECT_EQ(TEST_MUL_SIZE, subscribers.size());
}

/*
 * @tc.name: VerifySubscriberPermissionTest_0100
 * @tc.desc: test if StaticSubscriberManager's VerifySubscriberPermission function executed as expected
 *           in normal case.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, VerifySubscriberPermissionTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, VerifySubscriberPermissionTest_0100, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    MockGetHapTokenID(100);
    // mock that verify success
    MockVerifyAccessToken(true);
    std::string testBundleName = "com.ohos.systemui";
    int32_t testUserId = 100;
    std::string permission0 = "permission0";
    std::string permission1 = "permission1";
    std::vector<std::string> permissions;
    permissions.emplace_back(permission0);
    permissions.emplace_back(permission1);
    EXPECT_TRUE(manager->VerifySubscriberPermission(testBundleName, testUserId, permissions));
}

/*
 * @tc.name: VerifySubscriberPermissionTest_0200
 * @tc.desc: test if StaticSubscriberManager's VerifySubscriberPermission function executed as expected
 *           when permissions list is empty.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, VerifySubscriberPermissionTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, VerifySubscriberPermissionTest_0200, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    MockGetHapTokenID(100);
    // mock that verify success
    MockVerifyAccessToken(true);
    std::string testBundleName = "com.ohos.systemui";
    int32_t testUserId = 100;
    std::vector<std::string> permissions;
    EXPECT_TRUE(manager->VerifySubscriberPermission(testBundleName, testUserId, permissions));
}

/*
 * @tc.name: VerifySubscriberPermissionTest_0300
 * @tc.desc: test if StaticSubscriberManager's VerifySubscriberPermission function executed as expected
 *           when permissions list has empty permission.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, VerifySubscriberPermissionTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, VerifySubscriberPermissionTest_0300, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    MockGetHapTokenID(100);
    // mock that verify success
    MockVerifyAccessToken(true);
    std::string testBundleName = "com.ohos.systemui";
    int32_t testUserId = 100;
    std::string permission0 = "";
    std::string permission1 = "permission1";
    std::vector<std::string> permissions;
    permissions.emplace_back(permission0);
    permissions.emplace_back(permission1);
    EXPECT_TRUE(manager->VerifySubscriberPermission(testBundleName, testUserId, permissions));
}

/*
 * @tc.name: VerifySubscriberPermissionTest_0400
 * @tc.desc: test if StaticSubscriberManager's VerifySubscriberPermission function executed as expected
 *           when permissions partly verify failed.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, VerifySubscriberPermissionTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, VerifySubscriberPermissionTest_0400, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    MockGetHapTokenID(100);
    // mock that first time verify success, second tile verify failed
    MockVerifyAccessToken(false, 1);
    std::string testBundleName = "com.ohos.systemui";
    int32_t testUserId = 100;
    std::string permission0 = "permission0";
    std::string permission1 = "permission1";
    std::vector<std::string> permissions;
    permissions.emplace_back(permission0);
    permissions.emplace_back(permission1);
    EXPECT_FALSE(manager->VerifySubscriberPermission(testBundleName, testUserId, permissions));
}

/*
 * @tc.name: VerifySubscriberPermissionTest_0500
 * @tc.desc: test if StaticSubscriberManager's VerifySubscriberPermission function executed as expected
 *           when permissions all verify failed.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, VerifySubscriberPermissionTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, VerifySubscriberPermissionTest_0500, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    MockGetHapTokenID(100);
    // mock that verify failed
    MockVerifyAccessToken(false);
    std::string testBundleName = "com.ohos.systemui";
    int32_t testUserId = 100;
    std::string permission0 = "permission0";
    std::string permission1 = "permission1";
    std::vector<std::string> permissions;
    permissions.emplace_back(permission0);
    permissions.emplace_back(permission1);
    EXPECT_FALSE(manager->VerifySubscriberPermission(testBundleName, testUserId, permissions));
}

/*
 * @tc.name: PublishCommonEventTest_0100
 * @tc.desc: test if StaticSubscriberManager's PublishCommonEvent function executed as expected
 *           in when first time publish normal event.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, PublishCommonEventTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, PublishCommonEventTest_0100, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    // construct common event data
    Want testWant;
    std::string testNormalEventName = "usual.event.TIME_TICK";
    testWant.SetAction(testNormalEventName);
    std::string testBundleName = "com.ohos.systemui";
    std::string testAbilityName = "StaticSubscriber";
    testWant.SetElementName(testBundleName, testAbilityName);
    CommonEventData testEventData;
    testEventData.SetWant(testWant);
    // construct common event publish info,mock that publishinfo's bundlename is the same with subscriber
    // and permission verify successfully.
    CommonEventPublishInfo testPublishInfo;
    testPublishInfo.SetBundleName(testBundleName);
    // construct other params, not important
    Security::AccessToken::AccessTokenID testCallerToken = 100;
    int32_t testUserId = 100;
    sptr<IRemoteObject> service = nullptr;
    std::string bundleName = "com.ohos.systemui";
    // mock that QueryExtensionInfos success
    MockQueryExtensionInfos(true, 1);
    // mock that GetResConfigFile success
    MockGetResConfigFile(true, 1);
    // mock that all VerifyAccessToken operation success
    MockVerifyAccessToken(true);
    // mock that GetOsAccountLocalIdFromUid success
    MockGetOsAccountLocalIdFromUid(true, MOCK_CASE_2);
    manager->PublishCommonEvent(testEventData, testPublishInfo, testCallerToken, testUserId, service, bundleName);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    // expect that targer event has two subscribers
    auto subscribers = manager->validSubscribers_[testNormalEventName];
    EXPECT_EQ(0, subscribers.size());
    EXPECT_FALSE(IsConnectAbilityCalled());
    ResetAbilityManagerHelperState();
}

/*
 * @tc.name: PublishCommonEventTest_0200
 * @tc.desc: test if StaticSubscriberManager's PublishCommonEvent function executed as expected
 *           in when second time publish normal event.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, PublishCommonEventTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, PublishCommonEventTest_0200, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    // mock that allowlist has already inited
    manager->hasInitAllowList_ = true;
    // mock that valid subscribers has already inited
    manager->hasInitValidSubscribers_ = true;
    std::string eventName = "usual.event.TIME_TICK";
    StaticSubscriberManager::StaticSubscriberInfo testInfo = {
        .name = "StaticSubscriber",
        .bundleName = "com.ohos.systemui",
        .userId = 100,
        .permission = "permission1"
    };
    std::vector<StaticSubscriberManager::StaticSubscriberInfo> info0;
    info0.emplace_back(testInfo);
    manager->validSubscribers_.insert(make_pair(eventName, info0));
    // construct common event data
    Want testWant;
    std::string testNormalEventName = "usual.event.TIME_TICK";
    testWant.SetAction(testNormalEventName);
    std::string testBundleName = "com.ohos.systemui";
    std::string testAbilityName = "StaticSubscriber";
    testWant.SetElementName(testBundleName, testAbilityName);
    CommonEventData testEventData;
    testEventData.SetWant(testWant);
    // construct common event publish info,mock that publishinfo's bundlename is the same with subscriber
    // and permission verify successfully.
    CommonEventPublishInfo testPublishInfo;
    testPublishInfo.SetBundleName(testBundleName);
    // construct other params, not important
    Security::AccessToken::AccessTokenID testCallerToken = 100;
    int32_t testUserId = 100;
    sptr<IRemoteObject> service = nullptr;
    std::string bundleName = "com.ohos.systemui";
    // mock that QueryExtensionInfos success
    MockQueryExtensionInfos(true, 1);
    // mock that GetResConfigFile success
    MockGetResConfigFile(true, 1);
    // mock that all VerifyAccessToken operation success
    MockVerifyAccessToken(true);
    // mock that GetOsAccountLocalIdFromUid success
    MockGetOsAccountLocalIdFromUid(true, MOCK_CASE_2);
    manager->PublishCommonEvent(testEventData, testPublishInfo, testCallerToken, testUserId, service, bundleName);
    EXPECT_EQ(1, manager->validSubscribers_.size());
    // expect that targer event has two subscribers
    auto subscribers = manager->validSubscribers_[testNormalEventName];
    EXPECT_EQ(1, subscribers.size());
    EXPECT_TRUE(IsConnectAbilityCalled());
    ResetAbilityManagerHelperState();
}

/*
 * @tc.name: PublishCommonEventTest_0300
 * @tc.desc: test if StaticSubscriberManager's PublishCommonEvent function executed as expected
 *           in when first time publish and InitValidSubscribers failed.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, PublishCommonEventTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, PublishCommonEventTest_0300, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    // construct common event data
    Want testWant;
    std::string testNormalEventName = "usual.event.TIME_TICK";
    testWant.SetAction(testNormalEventName);
    std::string testBundleName = "com.ohos.systemui";
    std::string testAbilityName = "StaticSubscriber";
    testWant.SetElementName(testBundleName, testAbilityName);
    CommonEventData testEventData;
    testEventData.SetWant(testWant);
    // construct common event publish info,mock that publishinfo's bundlename is the same with subscriber
    // and permission verify successfully.
    CommonEventPublishInfo testPublishInfo;
    testPublishInfo.SetBundleName(testBundleName);
    // construct other params, not important
    Security::AccessToken::AccessTokenID testCallerToken = 100;
    int32_t testUserId = 100;
    sptr<IRemoteObject> service = nullptr;
    std::string bundleName = "com.ohos.systemui";
    // mock that QueryExtensionInfos failed
    MockQueryExtensionInfos(false, 0);
    // mock that GetResConfigFile success
    MockGetResConfigFile(true, 1);
    // mock that all VerifyAccessToken operation success
    MockVerifyAccessToken(true);
    // mock that GetOsAccountLocalIdFromUid success
    MockGetOsAccountLocalIdFromUid(true, MOCK_CASE_2);
    manager->PublishCommonEvent(testEventData, testPublishInfo, testCallerToken, testUserId, service, bundleName);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    EXPECT_FALSE(IsConnectAbilityCalled());
    ResetAbilityManagerHelperState();
}

/*
 * @tc.name: PublishCommonEventTest_0400
 * @tc.desc: test if StaticSubscriberManager's PublishCommonEvent function executed as expected
 *           in when publish a COMMON_EVENT_BOOT_COMPLETED and InitValidSubscriber success.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, PublishCommonEventTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, PublishCommonEventTest_0400, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    // construct common event data
    Want testWant;
    std::string testNormalEventName = CommonEventSupport::COMMON_EVENT_BOOT_COMPLETED;
    testWant.SetAction(testNormalEventName);
    std::string testBundleName = "com.ohos.systemui";
    std::string testAbilityName = "StaticSubscriber";
    testWant.SetElementName(testBundleName, testAbilityName);
    CommonEventData testEventData;
    testEventData.SetWant(testWant);
    // construct common event publish info,mock that publishinfo's bundlename is the same with subscriber
    // and permission verify successfully.
    CommonEventPublishInfo testPublishInfo;
    testPublishInfo.SetBundleName(testBundleName);
    // construct other params, not important
    Security::AccessToken::AccessTokenID testCallerToken = 100;
    int32_t testUserId = 100;
    sptr<IRemoteObject> service = nullptr;
    std::string bundleName = "com.ohos.systemui";
    // mock that QueryExtensionInfos success
    MockQueryExtensionInfos(true, 1);
    // mock that GetResConfigFile success
    MockGetResConfigFile(true, 1);
    // mock that all VerifyAccessToken operation success
    MockVerifyAccessToken(true);
    // mock that GetOsAccountLocalIdFromUid success
    MockGetOsAccountLocalIdFromUid(true, MOCK_CASE_2);
    manager->PublishCommonEvent(testEventData, testPublishInfo, testCallerToken, testUserId, service, bundleName);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    EXPECT_FALSE(IsConnectAbilityCalled());
    ResetAbilityManagerHelperState();
}

/*
 * @tc.name: PublishCommonEventTest_0500
 * @tc.desc: test if StaticSubscriberManager's PublishCommonEvent function executed as expected
 *           in when publish a COMMON_EVENT_BOOT_COMPLETED and InitValidSubscriber failed.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, PublishCommonEventTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, PublishCommonEventTest_0500, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    // construct common event data
    Want testWant;
    std::string testNormalEventName = CommonEventSupport::COMMON_EVENT_BOOT_COMPLETED;
    testWant.SetAction(testNormalEventName);
    std::string testBundleName = "com.ohos.systemui";
    std::string testAbilityName = "StaticSubscriber";
    testWant.SetElementName(testBundleName, testAbilityName);
    CommonEventData testEventData;
    testEventData.SetWant(testWant);
    // construct common event publish info,mock that publishinfo's bundlename is the same with subscriber
    // and permission verify successfully.
    CommonEventPublishInfo testPublishInfo;
    testPublishInfo.SetBundleName(testBundleName);
    // construct other params, not important
    Security::AccessToken::AccessTokenID testCallerToken = 100;
    int32_t testUserId = 100;
    sptr<IRemoteObject> service = nullptr;
    std::string bundleName = "com.ohos.systemui";
    // mock that QueryExtensionInfos failed
    MockQueryExtensionInfos(false, 0);
    // mock that GetResConfigFile success
    MockGetResConfigFile(true, 1);
    // mock that all VerifyAccessToken operation success
    MockVerifyAccessToken(true);
    // mock that GetOsAccountLocalIdFromUid success
    MockGetOsAccountLocalIdFromUid(true, MOCK_CASE_2);
    manager->PublishCommonEvent(testEventData, testPublishInfo, testCallerToken, testUserId, service, bundleName);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    EXPECT_FALSE(IsConnectAbilityCalled());
    ResetAbilityManagerHelperState();
}

/*
 * @tc.name: PublishCommonEventTest_0600
 * @tc.desc: test if StaticSubscriberManager's PublishCommonEvent function executed as expected
 *           in when publish a COMMON_EVENT_LOCKED_BOOT_COMPLETED and InitValidSubscriber success.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, PublishCommonEventTest_0600, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, PublishCommonEventTest_0600, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    // construct common event data
    Want testWant;
    std::string testNormalEventName = CommonEventSupport::COMMON_EVENT_LOCKED_BOOT_COMPLETED;
    testWant.SetAction(testNormalEventName);
    std::string testBundleName = "com.ohos.systemui";
    std::string testAbilityName = "StaticSubscriber";
    testWant.SetElementName(testBundleName, testAbilityName);
    CommonEventData testEventData;
    testEventData.SetWant(testWant);
    // construct common event publish info,mock that publishinfo's bundlename is the same with subscriber
    // and permission verify successfully.
    CommonEventPublishInfo testPublishInfo;
    testPublishInfo.SetBundleName(testBundleName);
    // construct other params, not important
    Security::AccessToken::AccessTokenID testCallerToken = 100;
    int32_t testUserId = 100;
    sptr<IRemoteObject> service = nullptr;
    std::string bundleName = "com.ohos.systemui";
    // mock that QueryExtensionInfos success
    MockQueryExtensionInfos(true, 1);
    // mock that GetResConfigFile success
    MockGetResConfigFile(true, 1);
    // mock that all VerifyAccessToken operation success
    MockVerifyAccessToken(true);
    // mock that GetOsAccountLocalIdFromUid success
    MockGetOsAccountLocalIdFromUid(true, MOCK_CASE_2);
    manager->PublishCommonEvent(testEventData, testPublishInfo, testCallerToken, testUserId, service, bundleName);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    EXPECT_FALSE(IsConnectAbilityCalled());
    ResetAbilityManagerHelperState();
}

/*
 * @tc.name: PublishCommonEventTest_0700
 * @tc.desc: test if StaticSubscriberManager's PublishCommonEvent function executed as expected
 *           in when publish a COMMON_EVENT_LOCKED_BOOT_COMPLETED and InitValidSubscriber failed.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, PublishCommonEventTest_0700, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, PublishCommonEventTest_0700, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    // construct common event data
    Want testWant;
    std::string testNormalEventName = CommonEventSupport::COMMON_EVENT_LOCKED_BOOT_COMPLETED;
    testWant.SetAction(testNormalEventName);
    std::string testBundleName = "com.ohos.systemui";
    std::string testAbilityName = "StaticSubscriber";
    testWant.SetElementName(testBundleName, testAbilityName);
    CommonEventData testEventData;
    testEventData.SetWant(testWant);
    // construct common event publish info,mock that publishinfo's bundlename is the same with subscriber
    // and permission verify successfully.
    CommonEventPublishInfo testPublishInfo;
    testPublishInfo.SetBundleName(testBundleName);
    // construct other params, not important
    Security::AccessToken::AccessTokenID testCallerToken = 100;
    int32_t testUserId = 100;
    sptr<IRemoteObject> service = nullptr;
    std::string bundleName = "com.ohos.systemui";
    // mock that QueryExtensionInfos failed
    MockQueryExtensionInfos(false, 0);
    // mock that GetResConfigFile success
    MockGetResConfigFile(true, 1);
    // mock that all VerifyAccessToken operation success
    MockVerifyAccessToken(true);
    // mock that GetOsAccountLocalIdFromUid success
    MockGetOsAccountLocalIdFromUid(true, MOCK_CASE_2);
    manager->PublishCommonEvent(testEventData, testPublishInfo, testCallerToken, testUserId, service, bundleName);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    EXPECT_FALSE(IsConnectAbilityCalled());
    ResetAbilityManagerHelperState();
}

/*
 * @tc.name: PublishCommonEventTest_0800
 * @tc.desc: test if StaticSubscriberManager's PublishCommonEvent function executed as expected
 *           in when publish a COMMON_EVENT_USER_SWITCHED and InitValidSubscriber success.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, PublishCommonEventTest_0800, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, PublishCommonEventTest_0800, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    // construct common event data
    Want testWant;
    std::string testNormalEventName = CommonEventSupport::COMMON_EVENT_USER_SWITCHED;
    testWant.SetAction(testNormalEventName);
    std::string testBundleName = "com.ohos.systemui";
    std::string testAbilityName = "StaticSubscriber";
    testWant.SetElementName(testBundleName, testAbilityName);
    CommonEventData testEventData;
    testEventData.SetWant(testWant);
    // construct common event publish info,mock that publishinfo's bundlename is the same with subscriber
    // and permission verify successfully.
    CommonEventPublishInfo testPublishInfo;
    testPublishInfo.SetBundleName(testBundleName);
    // construct other params, not important
    Security::AccessToken::AccessTokenID testCallerToken = 100;
    int32_t testUserId = 100;
    sptr<IRemoteObject> service = nullptr;
    std::string bundleName = "com.ohos.systemui";
    // mock that QueryExtensionInfos success
    MockQueryExtensionInfos(true, 1);
    // mock that GetResConfigFile success
    MockGetResConfigFile(true, 1);
    // mock that all VerifyAccessToken operation success
    MockVerifyAccessToken(true);
    // mock that GetOsAccountLocalIdFromUid success
    MockGetOsAccountLocalIdFromUid(true, MOCK_CASE_2);
    manager->PublishCommonEvent(testEventData, testPublishInfo, testCallerToken, testUserId, service, bundleName);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    EXPECT_FALSE(IsConnectAbilityCalled());
    ResetAbilityManagerHelperState();
}

/*
 * @tc.name: PublishCommonEventTest_0900
 * @tc.desc: test if StaticSubscriberManager's PublishCommonEvent function executed as expected
 *           in when publish a COMMON_EVENT_USER_SWITCHED and InitValidSubscriber failed.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, PublishCommonEventTest_0900, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, PublishCommonEventTest_0900, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    // construct common event data
    Want testWant;
    std::string testNormalEventName = CommonEventSupport::COMMON_EVENT_USER_SWITCHED;
    testWant.SetAction(testNormalEventName);
    std::string testBundleName = "com.ohos.systemui";
    std::string testAbilityName = "StaticSubscriber";
    testWant.SetElementName(testBundleName, testAbilityName);
    CommonEventData testEventData;
    testEventData.SetWant(testWant);
    // construct common event publish info,mock that publishinfo's bundlename is the same with subscriber
    // and permission verify successfully.
    CommonEventPublishInfo testPublishInfo;
    testPublishInfo.SetBundleName(testBundleName);
    // construct other params, not important
    Security::AccessToken::AccessTokenID testCallerToken = 100;
    int32_t testUserId = 100;
    sptr<IRemoteObject> service = nullptr;
    std::string bundleName = "com.ohos.systemui";
    // mock that QueryExtensionInfos failed
    MockQueryExtensionInfos(false, 0);
    // mock that GetResConfigFile success
    MockGetResConfigFile(true, 1);
    // mock that all VerifyAccessToken operation success
    MockVerifyAccessToken(true);
    // mock that GetOsAccountLocalIdFromUid success
    MockGetOsAccountLocalIdFromUid(true, MOCK_CASE_2);
    manager->PublishCommonEvent(testEventData, testPublishInfo, testCallerToken, testUserId, service, bundleName);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    EXPECT_FALSE(IsConnectAbilityCalled());
    ResetAbilityManagerHelperState();
}

/*
 * @tc.name: PublishCommonEventTest_1000
 * @tc.desc: test if StaticSubscriberManager's PublishCommonEvent function executed as expected
 *           in when publish a COMMON_EVENT_UID_REMOVED and InitValidSubscriber success.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, PublishCommonEventTest_1000, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, PublishCommonEventTest_1000, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    // construct common event data
    Want testWant;
    std::string testNormalEventName = CommonEventSupport::COMMON_EVENT_UID_REMOVED;
    testWant.SetAction(testNormalEventName);
    std::string testBundleName = "com.ohos.systemui";
    std::string testAbilityName = "StaticSubscriber";
    testWant.SetElementName(testBundleName, testAbilityName);
    CommonEventData testEventData;
    testEventData.SetWant(testWant);
    // construct common event publish info,mock that publishinfo's bundlename is the same with subscriber
    // and permission verify successfully.
    CommonEventPublishInfo testPublishInfo;
    testPublishInfo.SetBundleName(testBundleName);
    // construct other params, not important
    Security::AccessToken::AccessTokenID testCallerToken = 100;
    int32_t testUserId = 100;
    sptr<IRemoteObject> service = nullptr;
    std::string bundleName = "com.ohos.systemui";
    // mock that QueryExtensionInfos success
    MockQueryExtensionInfos(true, 1);
    // mock that GetResConfigFile success
    MockGetResConfigFile(true, 1);
    // mock that all VerifyAccessToken operation success
    MockVerifyAccessToken(true);
    // mock that GetOsAccountLocalIdFromUid success
    MockGetOsAccountLocalIdFromUid(true, MOCK_CASE_2);
    manager->PublishCommonEvent(testEventData, testPublishInfo, testCallerToken, testUserId, service, bundleName);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    EXPECT_FALSE(IsConnectAbilityCalled());
    ResetAbilityManagerHelperState();
}

/*
 * @tc.name: PublishCommonEventTest_1100
 * @tc.desc: test if StaticSubscriberManager's PublishCommonEvent function executed as expected
 *           in when publish a COMMON_EVENT_UID_REMOVED and InitValidSubscriber failed.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, PublishCommonEventTest_1100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, PublishCommonEventTest_1100, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    // construct common event data
    Want testWant;
    std::string testNormalEventName = CommonEventSupport::COMMON_EVENT_UID_REMOVED;
    testWant.SetAction(testNormalEventName);
    std::string testBundleName = "com.ohos.systemui";
    std::string testAbilityName = "StaticSubscriber";
    testWant.SetElementName(testBundleName, testAbilityName);
    CommonEventData testEventData;
    testEventData.SetWant(testWant);
    // construct common event publish info,mock that publishinfo's bundlename is the same with subscriber
    // and permission verify successfully.
    CommonEventPublishInfo testPublishInfo;
    testPublishInfo.SetBundleName(testBundleName);
    // construct other params, not important
    Security::AccessToken::AccessTokenID testCallerToken = 100;
    int32_t testUserId = 100;
    sptr<IRemoteObject> service = nullptr;
    std::string bundleName = "com.ohos.systemui";
    // mock that QueryExtensionInfos failed
    MockQueryExtensionInfos(false, 0);
    // mock that GetResConfigFile success
    MockGetResConfigFile(true, 1);
    // mock that all VerifyAccessToken operation success
    MockVerifyAccessToken(true);
    // mock that GetOsAccountLocalIdFromUid success
    MockGetOsAccountLocalIdFromUid(true, MOCK_CASE_2);
    manager->PublishCommonEvent(testEventData, testPublishInfo, testCallerToken, testUserId, service, bundleName);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    EXPECT_FALSE(IsConnectAbilityCalled());
    ResetAbilityManagerHelperState();
}

/*
 * @tc.name: PublishCommonEventTest_1200
 * @tc.desc: test if StaticSubscriberManager's PublishCommonEvent function executed as expected
 *           in when publish a COMMON_EVENT_USER_STARTED and InitValidSubscriber success.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, PublishCommonEventTest_1200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, PublishCommonEventTest_1200, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    // construct common event data
    Want testWant;
    std::string testNormalEventName = CommonEventSupport::COMMON_EVENT_USER_STARTED;
    testWant.SetAction(testNormalEventName);
    std::string testBundleName = "com.ohos.systemui";
    std::string testAbilityName = "StaticSubscriber";
    testWant.SetElementName(testBundleName, testAbilityName);
    CommonEventData testEventData;
    testEventData.SetWant(testWant);
    // construct common event publish info,mock that publishinfo's bundlename is the same with subscriber
    // and permission verify successfully.
    CommonEventPublishInfo testPublishInfo;
    testPublishInfo.SetBundleName(testBundleName);
    // construct other params, not important
    Security::AccessToken::AccessTokenID testCallerToken = 100;
    int32_t testUserId = 100;
    sptr<IRemoteObject> service = nullptr;
    std::string bundleName = "com.ohos.systemui";
    // mock that QueryExtensionInfos success
    MockQueryExtensionInfos(true, 1);
    // mock that GetResConfigFile success
    MockGetResConfigFile(true, 1);
    // mock that all VerifyAccessToken operation success
    MockVerifyAccessToken(true);
    // mock that GetOsAccountLocalIdFromUid success
    MockGetOsAccountLocalIdFromUid(true, MOCK_CASE_2);
    manager->PublishCommonEvent(testEventData, testPublishInfo, testCallerToken, testUserId, service, bundleName);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    EXPECT_FALSE(IsConnectAbilityCalled());
    ResetAbilityManagerHelperState();
}

/*
 * @tc.name: PublishCommonEventTest_1300
 * @tc.desc: test if StaticSubscriberManager's PublishCommonEvent function executed as expected
 *           in when publish a COMMON_EVENT_USER_STARTED and InitValidSubscriber failed.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, PublishCommonEventTest_1300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, PublishCommonEventTest_1300, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    // construct common event data
    Want testWant;
    std::string testNormalEventName = CommonEventSupport::COMMON_EVENT_USER_STARTED;
    testWant.SetAction(testNormalEventName);
    std::string testBundleName = "com.ohos.systemui";
    std::string testAbilityName = "StaticSubscriber";
    testWant.SetElementName(testBundleName, testAbilityName);
    CommonEventData testEventData;
    testEventData.SetWant(testWant);
    // construct common event publish info,mock that publishinfo's bundlename is the same with subscriber
    // and permission verify successfully.
    CommonEventPublishInfo testPublishInfo;
    testPublishInfo.SetBundleName(testBundleName);
    // construct other params, not important
    Security::AccessToken::AccessTokenID testCallerToken = 100;
    int32_t testUserId = 100;
    sptr<IRemoteObject> service = nullptr;
    std::string bundleName = "com.ohos.systemui";
    // mock that QueryExtensionInfos failed
    MockQueryExtensionInfos(false, 0);
    // mock that GetResConfigFile success
    MockGetResConfigFile(true, 1);
    // mock that all VerifyAccessToken operation success
    MockVerifyAccessToken(true);
    // mock that GetOsAccountLocalIdFromUid success
    MockGetOsAccountLocalIdFromUid(true, MOCK_CASE_2);
    manager->PublishCommonEvent(testEventData, testPublishInfo, testCallerToken, testUserId, service, bundleName);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    EXPECT_FALSE(IsConnectAbilityCalled());
    ResetAbilityManagerHelperState();
}

/*
 * @tc.name: PublishCommonEventTest_1400
 * @tc.desc: test if StaticSubscriberManager's PublishCommonEvent function executed as expected
 *           in when publish a COMMON_EVENT_PACKAGE_ADDED.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, PublishCommonEventTest_1400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, PublishCommonEventTest_1400, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    // mock that allowlist has already inited
    manager->hasInitAllowList_ = true;
    // mock that valid subscribers has already inited
    manager->hasInitValidSubscribers_ = true;
    std::string eventName = "usual.event.TIME_TICK";
    StaticSubscriberManager::StaticSubscriberInfo testInfo = {
        .name = "StaticSubscriber",
        .bundleName = "com.ohos.systemui",
        .userId = 100,
        .permission = "permission1"
    };
    std::vector<StaticSubscriberManager::StaticSubscriberInfo> info0;
    info0.emplace_back(testInfo);
    manager->validSubscribers_.insert(make_pair(eventName, info0));
    // construct common event data
    Want testWant;
    std::string testNormalEventName = CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED;
    testWant.SetAction(testNormalEventName);
    std::string testBundleName = "com.ohos.systemui1";
    std::string testAbilityName = "StaticSubscriber";
    testWant.SetElementName(testBundleName, testAbilityName);
    CommonEventData testEventData;
    testEventData.SetWant(testWant);

    // construct common event publish info,mock that publishinfo's bundlename is the same with subscriber
    // and permission verify successfully.
    CommonEventPublishInfo testPublishInfo;
    testPublishInfo.SetBundleName(testBundleName);
    // construct other params, not important
    Security::AccessToken::AccessTokenID testCallerToken = 100;
    int32_t testUserId = 100;
    sptr<IRemoteObject> service = nullptr;
    std::string bundleName = "com.ohos.systemui";
    // mock that QueryExtensionInfos success
    MockQueryExtensionInfos(true, MOCK_CASE_2);
    // mock that GetResConfigFile success
    MockGetResConfigFile(true, MOCK_CASE_5);
    // mock that all VerifyAccessToken operation success
    MockVerifyAccessToken(true);
    // mock that GetOsAccountLocalIdFromUid success
    MockGetOsAccountLocalIdFromUid(true);
    // set staticSubscribers_ value
    std::set<std::string> events;
    events.insert(eventName);
    StaticSubscriber subscribers = { .events = events };
    int32_t userId = 100;
    manager->staticSubscribers_.emplace(std::to_string(userId) + "_" + testBundleName, subscribers);
    manager->PublishCommonEvent(testEventData, testPublishInfo, testCallerToken, testUserId, service, bundleName);
    // expect time_tick and add event both have subscriber
    EXPECT_EQ(1, manager->validSubscribers_.size());
    auto subscribers0 = manager->validSubscribers_[eventName];
    EXPECT_EQ(TEST_MUL_SIZE, subscribers0.size());
    auto subscribers1 = manager->validSubscribers_[testNormalEventName];
    EXPECT_EQ(0, subscribers1.size());
    EXPECT_FALSE(IsConnectAbilityCalled());
    ResetAbilityManagerHelperState();
}

/*
 * @tc.name: PublishCommonEventTest_1500
 * @tc.desc: test if StaticSubscriberManager's PublishCommonEvent function executed as expected
 *           in when publish a COMMON_EVENT_PACKAGE_CHANGED.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, PublishCommonEventTest_1500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, PublishCommonEventTest_1500, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    // mock that allowlist has already inited
    manager->hasInitAllowList_ = true;
    // mock that valid subscribers has already inited
    manager->hasInitValidSubscribers_ = true;
    std::string eventName = "usual.event.TIME_TICK";
    StaticSubscriberManager::StaticSubscriberInfo testInfo = {
        .name = "StaticSubscriber",
        .bundleName = "com.ohos.systemui",
        .userId = 100,
        .permission = "permission1"
    };
    std::vector<StaticSubscriberManager::StaticSubscriberInfo> info0;
    info0.emplace_back(testInfo);
    manager->validSubscribers_.insert(make_pair(eventName, info0));
    // construct common event data
    Want testWant;
    std::string testNormalEventName = CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED;
    testWant.SetAction(testNormalEventName);
    std::string testBundleName = "com.ohos.systemui1";
    std::string testAbilityName = "StaticSubscriber";
    testWant.SetElementName(testBundleName, testAbilityName);
    CommonEventData testEventData;
    testEventData.SetWant(testWant);
    // construct common event publish info,mock that publishinfo's bundlename is the same with subscriber
    // and permission verify successfully.
    CommonEventPublishInfo testPublishInfo;
    testPublishInfo.SetBundleName(testBundleName);
    // construct other params, not important
    Security::AccessToken::AccessTokenID testCallerToken = 100;
    int32_t testUserId = 100;
    sptr<IRemoteObject> service = nullptr;
    std::string bundleName = "com.ohos.systemui";
    // mock that QueryExtensionInfos success
    MockQueryExtensionInfos(true, MOCK_CASE_2);
    // mock that GetResConfigFile success
    MockGetResConfigFile(true, MOCK_CASE_5);
    // mock that all VerifyAccessToken operation success
    MockVerifyAccessToken(true);
    // mock that GetOsAccountLocalIdFromUid success
    MockGetOsAccountLocalIdFromUid(true);
    // set staticSubscribers_ value
    std::set<std::string> events;
    events.insert(eventName);
    StaticSubscriber subscribers = { .events = events };
    int32_t userId = 100;
    manager->staticSubscribers_.emplace(std::to_string(userId) + "_" + testBundleName, subscribers);
    manager->PublishCommonEvent(testEventData, testPublishInfo, testCallerToken, testUserId, service, bundleName);
    // expect time_tick and add event both have subscriber
    EXPECT_EQ(1, manager->validSubscribers_.size());
    auto subscribers0 = manager->validSubscribers_[eventName];
    EXPECT_EQ(TEST_MUL_SIZE, subscribers0.size());
    auto subscribers1 = manager->validSubscribers_[CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED];
    EXPECT_EQ(0, subscribers1.size());
    EXPECT_FALSE(IsConnectAbilityCalled());
    ResetAbilityManagerHelperState();
}

/*
 * @tc.name: PublishCommonEventTest_1600
 * @tc.desc: test if StaticSubscriberManager's PublishCommonEvent function executed as expected
 *           in when publish a COMMON_EVENT_PACKAGE_REMOVED.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, PublishCommonEventTest_1600, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, PublishCommonEventTest_1600, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    // mock that allowlist has already inited
    manager->hasInitAllowList_ = true;
    // mock that valid subscribers has already inited
    manager->hasInitValidSubscribers_ = true;
    std::string eventName = "usual.event.TIME_TICK";
    StaticSubscriberManager::StaticSubscriberInfo testInfo = {
        .name = "StaticSubscriber",
        .bundleName = "com.ohos.systemui",
        .userId = 100,
        .permission = "permission1"
    };
    std::vector<StaticSubscriberManager::StaticSubscriberInfo> info0;
    info0.emplace_back(testInfo);
    manager->validSubscribers_.insert(make_pair(eventName, info0));
    // construct common event data
    Want testWant;
    std::string testNormalEventName = CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED;
    testWant.SetAction(testNormalEventName);
    std::string testBundleName = "com.ohos.systemui1";
    std::string testAbilityName = "StaticSubscriber";
    testWant.SetElementName(testBundleName, testAbilityName);
    CommonEventData testEventData;
    testEventData.SetWant(testWant);
    // construct common event publish info,mock that publishinfo's bundlename is the same with subscriber
    // and permission verify successfully.
    CommonEventPublishInfo testPublishInfo;
    testPublishInfo.SetBundleName(testBundleName);
    // construct other params, not important
    Security::AccessToken::AccessTokenID testCallerToken = 100;
    int32_t testUserId = 100;
    sptr<IRemoteObject> service = nullptr;
    std::string bundleName = "com.ohos.systemui";
    // mock that QueryExtensionInfos success
    MockQueryExtensionInfos(true, MOCK_CASE_2);
    // mock that GetResConfigFile success
    MockGetResConfigFile(true, MOCK_CASE_5);
    // mock that all VerifyAccessToken operation success
    MockVerifyAccessToken(true);
    // mock that GetOsAccountLocalIdFromUid success
    MockGetOsAccountLocalIdFromUid(true);
    manager->PublishCommonEvent(testEventData, testPublishInfo, testCallerToken, testUserId, service, bundleName);
    // expect time_tick and add event both have subscriber
    EXPECT_EQ(1, manager->validSubscribers_.size());
    auto subscribers0 = manager->validSubscribers_[eventName];
    EXPECT_EQ(1, subscribers0.size());
    EXPECT_FALSE(IsConnectAbilityCalled());
    ResetAbilityManagerHelperState();
}

/*
 * @tc.name: PublishCommonEventTest_1700
 * @tc.desc: test if StaticSubscriberManager's PublishCommonEvent function executed as expected
 *           in when subscriber userId smaller than min of valid userId.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, PublishCommonEventTest_1700, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, PublishCommonEventTest_1700, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    // construct common event data
    Want testWant;
    std::string testNormalEventName = "usual.event.TIME_TICK";
    testWant.SetAction(testNormalEventName);
    std::string testBundleName = "com.ohos.systemui";
    std::string testAbilityName = "StaticSubscriber";
    testWant.SetElementName(testBundleName, testAbilityName);
    CommonEventData testEventData;
    testEventData.SetWant(testWant);
    // construct common event publish info,mock that publishinfo's bundlename is the same with subscriber
    // and permission verify successfully.
    CommonEventPublishInfo testPublishInfo;
    testPublishInfo.SetBundleName(testBundleName);
    // construct other params, not important
    Security::AccessToken::AccessTokenID testCallerToken = 100;
    int32_t testUserId = 100;
    sptr<IRemoteObject> service = nullptr;
    std::string bundleName = "com.ohos.systemui";
    // mock that QueryExtensionInfos success
    MockQueryExtensionInfos(true, 1);
    // mock that GetResConfigFile success
    MockGetResConfigFile(true, 1);
    // mock that all VerifyAccessToken operation success
    MockVerifyAccessToken(true);
    // mock that GetOsAccountLocalIdFromUid success
    MockGetOsAccountLocalIdFromUid(true, 1);
    manager->PublishCommonEvent(testEventData, testPublishInfo, testCallerToken, testUserId, service, bundleName);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    // expect that targer event has two subscribers
    auto subscribers = manager->validSubscribers_[testNormalEventName];
    EXPECT_EQ(0, subscribers.size());
    EXPECT_FALSE(IsConnectAbilityCalled());
    ResetAbilityManagerHelperState();
}

/*
 * @tc.name: PublishCommonEventTest_1800
 * @tc.desc: test if StaticSubscriberManager's PublishCommonEvent function executed as expected
 *           in when userId param is ALL_USER.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, PublishCommonEventTest_1800, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, PublishCommonEventTest_1800, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    // construct common event data
    Want testWant;
    std::string testNormalEventName = "usual.event.TIME_TICK";
    testWant.SetAction(testNormalEventName);
    std::string testBundleName = "com.ohos.systemui";
    std::string testAbilityName = "StaticSubscriber";
    testWant.SetElementName(testBundleName, testAbilityName);
    CommonEventData testEventData;
    testEventData.SetWant(testWant);
    // construct common event publish info,mock that publishinfo's bundlename is the same with subscriber
    // and permission verify successfully.
    CommonEventPublishInfo testPublishInfo;
    testPublishInfo.SetBundleName(testBundleName);
    // construct ALL_USER userId
    int32_t testUserId = -1;
    // construct other params, not important
    Security::AccessToken::AccessTokenID testCallerToken = 100;
    sptr<IRemoteObject> service = nullptr;
    std::string bundleName = "com.ohos.systemui";
    // mock that QueryExtensionInfos success
    MockQueryExtensionInfos(true, 1);
    // mock that GetResConfigFile success
    MockGetResConfigFile(true, 1);
    // mock that all VerifyAccessToken operation success
    MockVerifyAccessToken(true);
    // mock that GetOsAccountLocalIdFromUid success
    MockGetOsAccountLocalIdFromUid(true);
    manager->PublishCommonEvent(testEventData, testPublishInfo, testCallerToken, testUserId, service, bundleName);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    // expect that targer event has two subscribers
    auto subscribers = manager->validSubscribers_[testNormalEventName];
    EXPECT_EQ(0, subscribers.size());
    EXPECT_FALSE(IsConnectAbilityCalled());
    ResetAbilityManagerHelperState();
}

/*
 * @tc.name: PublishCommonEventTest_1900
 * @tc.desc: test if StaticSubscriberManager's PublishCommonEvent function executed as expected
 *           in when subscriber userid dismatch param userId.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, PublishCommonEventTest_1900, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, PublishCommonEventTest_1900, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    // construct common event data
    Want testWant;
    std::string testNormalEventName = "usual.event.TIME_TICK";
    testWant.SetAction(testNormalEventName);
    std::string testBundleName = "com.ohos.systemui";
    std::string testAbilityName = "StaticSubscriber";
    testWant.SetElementName(testBundleName, testAbilityName);
    CommonEventData testEventData;
    testEventData.SetWant(testWant);
    // construct common event publish info,mock that publishinfo's bundlename is the same with subscriber
    // and permission verify successfully.
    CommonEventPublishInfo testPublishInfo;
    testPublishInfo.SetBundleName(testBundleName);
    // construct not match userId
    int32_t testUserId = 101;
    // construct other params, not important
    Security::AccessToken::AccessTokenID testCallerToken = 100;
    sptr<IRemoteObject> service = nullptr;
    std::string bundleName = "com.ohos.systemui";
    // mock that QueryExtensionInfos success
    MockQueryExtensionInfos(true, 1);
    // mock that GetResConfigFile success
    MockGetResConfigFile(true, 1);
    // mock that all VerifyAccessToken operation success
    MockVerifyAccessToken(true);
    // mock that GetOsAccountLocalIdFromUid success
    MockGetOsAccountLocalIdFromUid(true);
    manager->PublishCommonEvent(testEventData, testPublishInfo, testCallerToken, testUserId, service, bundleName);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    // expect that targer event has two subscribers
    auto subscribers = manager->validSubscribers_[testNormalEventName];
    EXPECT_EQ(0, subscribers.size());
    EXPECT_FALSE(IsConnectAbilityCalled());
    ResetAbilityManagerHelperState();
}

/*
 * @tc.name: PublishCommonEventTest_2000
 * @tc.desc: test if StaticSubscriberManager's PublishCommonEvent function executed as expected
 *           in when publisher permission verify failed.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, PublishCommonEventTest_2000, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, PublishCommonEventTest_2000, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    // construct common event data
    Want testWant;
    std::string testNormalEventName = "usual.event.TIME_TICK";
    testWant.SetAction(testNormalEventName);
    std::string testBundleName = "com.ohos.systemui";
    std::string testAbilityName = "StaticSubscriber";
    testWant.SetElementName(testBundleName, testAbilityName);
    CommonEventData testEventData;
    testEventData.SetWant(testWant);
    // construct common event publish info,mock that publishinfo's bundlename is the same with subscriber
    // and permission verify successfully.
    CommonEventPublishInfo testPublishInfo;
    testPublishInfo.SetBundleName(testBundleName);
    // construct not match userId
    int32_t testUserId = 100;
    // construct other params, not important
    Security::AccessToken::AccessTokenID testCallerToken = 100;
    sptr<IRemoteObject> service = nullptr;
    std::string bundleName = "com.ohos.systemui";
    // mock that QueryExtensionInfos success
    MockQueryExtensionInfos(true, 1);
    // mock that GetResConfigFile success
    MockGetResConfigFile(true, 1);
    // mock that first time verify permission failed, second time success
    MockVerifyAccessToken(true, 1);
    // mock that GetOsAccountLocalIdFromUid success
    MockGetOsAccountLocalIdFromUid(true, MOCK_CASE_2);
    manager->PublishCommonEvent(testEventData, testPublishInfo, testCallerToken, testUserId, service, bundleName);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    // expect that targer event has two subscribers
    auto subscribers = manager->validSubscribers_[testNormalEventName];
    EXPECT_EQ(0, subscribers.size());
    EXPECT_FALSE(IsConnectAbilityCalled());
    ResetAbilityManagerHelperState();
}

/*
 * @tc.name: PublishCommonEventTest_2100
 * @tc.desc: test if StaticSubscriberManager's PublishCommonEvent function executed as expected
 *           in when subscriber permission verify failed.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, PublishCommonEventTest_2100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, PublishCommonEventTest_2100, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    // construct common event data
    Want testWant;
    std::string testNormalEventName = "usual.event.TIME_TICK";
    testWant.SetAction(testNormalEventName);
    std::string testBundleName = "com.ohos.systemui";
    std::string testAbilityName = "StaticSubscriber";
    testWant.SetElementName(testBundleName, testAbilityName);
    CommonEventData testEventData;
    testEventData.SetWant(testWant);
    // construct common event publish info,mock that publishinfo's bundlename is the same with subscriber
    // and permission verify successfully.
    CommonEventPublishInfo testPublishInfo;
    testPublishInfo.SetBundleName(testBundleName);
    // assume that publisher require subscriber need has some permission
    std::vector<std::string> permissionsRequieredForSub;
    std::string permission1RequieredForSub = "permission1RequieredForSub";
    std::string permission2RequieredForSub = "permission2RequieredForSub";
    permissionsRequieredForSub.emplace_back(permission1RequieredForSub);
    permissionsRequieredForSub.emplace_back(permission2RequieredForSub);
    testPublishInfo.SetSubscriberPermissions(permissionsRequieredForSub);
    // construct not match userId
    int32_t testUserId = 100;
    // construct other params, not important
    Security::AccessToken::AccessTokenID testCallerToken = 100;
    sptr<IRemoteObject> service = nullptr;
    std::string bundleName = "com.ohos.systemui";
    // mock that QueryExtensionInfos success
    MockQueryExtensionInfos(true, 1);
    // mock that GetResConfigFile success
    MockGetResConfigFile(true, 1);
    // mock that first time verify permission failed, second time success
    MockVerifyAccessToken(false, 1);
    // mock that GetOsAccountLocalIdFromUid success
    MockGetOsAccountLocalIdFromUid(true, MOCK_CASE_2);
    manager->PublishCommonEvent(testEventData, testPublishInfo, testCallerToken, testUserId, service, bundleName);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    // expect that targer event has two subscribers
    auto subscribers = manager->validSubscribers_[testNormalEventName];
    EXPECT_EQ(0, subscribers.size());
    EXPECT_FALSE(IsConnectAbilityCalled());
    ResetAbilityManagerHelperState();
}

/*
 * @tc.name: PublishCommonEventTest_2200
 * @tc.desc: test if StaticSubscriberManager's PublishCommonEvent function executed as expected
 *           in when subscriber bundleName and publishInfo bundleName dismatch.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, PublishCommonEventTest_2200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, PublishCommonEventTest_2200, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    // construct common event data
    Want testWant;
    std::string testNormalEventName = "usual.event.TIME_TICK";
    testWant.SetAction(testNormalEventName);
    std::string testBundleName = "com.ohos.systemui1";
    std::string testAbilityName = "StaticSubscriber";
    testWant.SetElementName(testBundleName, testAbilityName);
    CommonEventData testEventData;
    testEventData.SetWant(testWant);
    // construct common event publish info,mock that publishinfo's bundlename is the same with subscriber
    // and permission verify successfully.
    CommonEventPublishInfo testPublishInfo;
    testPublishInfo.SetBundleName(testBundleName);
    // construct not match userId
    int32_t testUserId = 100;
    // construct other params, not important
    Security::AccessToken::AccessTokenID testCallerToken = 100;
    sptr<IRemoteObject> service = nullptr;
    std::string bundleName = "com.ohos.systemui";
    // mock that QueryExtensionInfos success
    MockQueryExtensionInfos(true, 1);
    // mock that GetResConfigFile success
    MockGetResConfigFile(true, 1);
    // mock that verify permission success
    MockVerifyAccessToken(true);
    // mock that GetOsAccountLocalIdFromUid success
    MockGetOsAccountLocalIdFromUid(true, MOCK_CASE_2);
    manager->PublishCommonEvent(testEventData, testPublishInfo, testCallerToken, testUserId, service, bundleName);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    // expect that targer event has two subscribers
    auto subscribers = manager->validSubscribers_[testNormalEventName];
    EXPECT_EQ(0, subscribers.size());
    EXPECT_FALSE(IsConnectAbilityCalled());
    ResetAbilityManagerHelperState();
}

/*
 * @tc.name: PublishCommonEventTest_2300
 * @tc.desc: test if StaticSubscriberManager's PublishCommonEvent function executed as expected
 *           test function isDisableEvent returns a value of false.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberManagerUnitTest, PublishCommonEventTest_2300, Function | MediumTest | Level1)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    // mock that allowlist has already inited
    manager->hasInitAllowList_ = true;
    // mock that valid subscribers has already inited
    manager->hasInitValidSubscribers_ = true;
    std::string eventName = "usual.event.TIME_TICK";
    StaticSubscriberManager::StaticSubscriberInfo testInfo = {
        .name = "StaticSubscriber",
        .bundleName = "com.ohos.systemui",
        .userId = 100,
        .permission = "permission1",
    };
    std::vector<StaticSubscriberManager::StaticSubscriberInfo> info0;
    info0.emplace_back(testInfo);
    manager->validSubscribers_.insert(make_pair(eventName, info0));
    // construct common event data
    Want testWant;
    std::string testNormalEventName = "usual.event.TIME_TICK";
    testWant.SetAction(testNormalEventName);
    std::string testBundleName = "com.ohos.systemui";
    std::string testAbilityName = "StaticSubscriber";
    testWant.SetElementName(testBundleName, testAbilityName);
    CommonEventData testEventData;
    testEventData.SetWant(testWant);
    // construct common event publish info,mock that publishinfo's bundlename is the same with subscriber
    // and permission verify successfully.
    CommonEventPublishInfo testPublishInfo;
    testPublishInfo.SetBundleName(testBundleName);
    // construct other params, not important
    Security::AccessToken::AccessTokenID testCallerToken = 100;
    int32_t testUserId = 100;
    sptr<IRemoteObject> service = nullptr;
    std::string bundleName = "com.ohos.systemui";
    // mock that QueryExtensionInfos success
    MockQueryExtensionInfos(true, 1);
    // mock that GetResConfigFile success
    MockGetResConfigFile(true, 1);
    // mock that all VerifyAccessToken operation success
    MockVerifyAccessToken(true);
    // mock that GetOsAccountLocalIdFromUid success
    MockGetOsAccountLocalIdFromUid(true, MOCK_CASE_2);
    manager->PublishCommonEvent(testEventData, testPublishInfo, testCallerToken, testUserId, service, bundleName);
    EXPECT_EQ(1, manager->validSubscribers_.size());
    // expect that targer event has two subscribers
    auto subscribers = manager->validSubscribers_[testNormalEventName];
    EXPECT_EQ(1, subscribers.size());
    EXPECT_TRUE(IsConnectAbilityCalled());
    ResetAbilityManagerHelperState();
}

/*
 * @tc.name: SetStaticSubscriberState_0100
 * @tc.desc: Test SetStaticSubscriberState function.
 * @tc.type: FUNC
 * @tc.require: #I70XI1
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, SetStaticSubscriberState_0100, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, SetStaticSubscriberState_0100, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    StaticSubscriber subscriber;
    subscriber.events.emplace("event1");
    int uidMockH = 1000;
    SetUidMock(uidMockH);
    manager->staticSubscribers_.emplace(std::to_string(uidMockH) + std::string("testBundleName"), subscriber);
    SetBundleNameMock();
    auto ret = manager->SetStaticSubscriberState(true);
    EXPECT_EQ(ERR_INVALID_OPERATION, ret);
}

/*
 * @tc.name: SetStaticSubscriberState_0200
 * @tc.desc: Test SetStaticSubscriberState function.
 * @tc.type: FUNC
 * @tc.require: #I70XI1
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, SetStaticSubscriberState_0200, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, SetStaticSubscriberState_0200, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    StaticSubscriber subscriber;
    subscriber.events.emplace("event1");
    int uidMockI = 1000;
    SetUidMock(uidMockI);
    manager->staticSubscribers_.emplace(std::to_string(uidMockI) + std::string("testBundleName"), subscriber);
    SetBundleNameMock();
    auto ret = manager->SetStaticSubscriberState(false);
    EXPECT_EQ(ERR_INVALID_OPERATION, ret);
}

/*
 * @tc.name: SetStaticSubscriberState_0300
 * @tc.desc: Test SetStaticSubscriberState function.
 * @tc.type: FUNC
 * @tc.require: #I70XI1
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, SetStaticSubscriberState_0300, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, SetStaticSubscriberState_0300, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    auto ret = manager->SetStaticSubscriberState(true);
    EXPECT_EQ(ERR_INVALID_OPERATION, ret);
}

/*
 * @tc.name: SetStaticSubscriberState_0400
 * @tc.desc: Test SetStaticSubscriberState function.
 * @tc.type: FUNC
 * @tc.require: #I70XI1
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, SetStaticSubscriberState_0400, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, SetStaticSubscriberState_0400, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    auto ret = manager->SetStaticSubscriberState(false);
    EXPECT_EQ(ERR_INVALID_OPERATION, ret);
}

/*
 * @tc.name: SetStaticSubscriberStateWithTwoParameters_0100
 * @tc.desc: Test SetStaticSubscriberState function to get bundlename successfully.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberManagerUnitTest, SetStaticSubscriberStateWithTwoParameters_0100, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::vector<std::string> events;
    events.emplace_back("event1");
    int callingUid = 1000;
    SetUidMock(callingUid);
    manager->disableEvents_.emplace(std::to_string(callingUid) + std::string("testBundleName"), events);
    SetBundleNameMock();
    auto ret = manager->SetStaticSubscriberState(events, true);
    EXPECT_EQ(0, ret);
}

/*
 * @tc.name: SetStaticSubscriberStateWithTwoParameters_0200
 * @tc.desc: Failed to test SetStaticSubscriberState function to get bundlename.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberManagerUnitTest, SetStaticSubscriberStateWithTwoParameters_0200, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::vector<std::string> events;
    events.emplace_back("event1");
    auto ret = manager->SetStaticSubscriberState(events, true);
    EXPECT_EQ(0, ret);
}

/*
 * @tc.name: UpdateDisableEvents_0100
 * @tc.desc: Test the UpdateDisableEvents function, disableEvents_ is empty and enable is true.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberManagerUnitTest, UpdateDisableEvents_0100, Function | MediumTest | Level1)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string bunaleName = "testBundleName";
    std::vector<std::string> events;
    events.emplace_back("event1");
    bool enable = true;
    int32_t uid = 1000;
    auto ret = manager->UpdateDisableEvents(bunaleName, events, enable, uid);
    EXPECT_EQ(0, ret);
}

/*
 * @tc.name: UpdateDisableEvents_0200
 * @tc.desc: Test the UpdateDisableEvents function, disableEvents_ is empty and add event.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberManagerUnitTest, UpdateDisableEvents_0200, Function | MediumTest | Level1)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string bunaleName = "testBundleName";
    std::vector<std::string> events;
    events.emplace_back("event1");
    bool enable = false;
    int32_t uid = 1000;
    auto ret = manager->UpdateDisableEvents(bunaleName, events, enable, uid);
    EXPECT_EQ(0, ret);
}

/*
 * @tc.name: UpdateDisableEvents_0300
 * @tc.desc: Test the UpdateDisableEvents function, disableEvents_ is not empty and delete event.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberManagerUnitTest, UpdateDisableEvents_0300, Function | MediumTest | Level1)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string bunaleName = "testBundleName";
    int32_t uid = 1000;
    std::string key = std::to_string(uid) + bunaleName;
    std::vector<std::string> events;
    events.emplace_back("event1");
    bool enable = true;
    manager->disableEvents_.emplace(key, events);
    auto ret = manager->UpdateDisableEvents(bunaleName, events, enable, uid);
    EXPECT_EQ(0, ret);
}

/*
 * @tc.name: UpdateDisableEvents_0400
 * @tc.desc: Test the UpdateDisableEvents function, disableEvents_ is not empty and delete events.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberManagerUnitTest, UpdateDisableEvents_0400, Function | MediumTest | Level1)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string bunaleName = "testBundleName";
    int32_t uid = 1000;
    std::string key = std::to_string(uid) + bunaleName;
    std::vector<std::string> events;
    events.emplace_back("event1");
    events.emplace_back("event2");
    bool enable = true;
    manager->disableEvents_.emplace(key, events);
    auto ret = manager->UpdateDisableEvents(bunaleName, events, enable, uid);
    EXPECT_EQ(0, ret);
}

/*
 * @tc.name: UpdateDisableEvents_0500
 * @tc.desc: Test the UpdateDisableEvents function, the events of disableEvents_ is empty and add events.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberManagerUnitTest, UpdateDisableEvents_0500, Function | MediumTest | Level1)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string bunaleName = "testBundleName";
    int32_t uid = 1000;
    std::string key = std::to_string(uid) + bunaleName;
    std::vector<std::string> events;
    std::vector<std::string> events1;
    events.emplace_back("event1");
    bool enable = false;
    manager->disableEvents_.emplace(key, events1);
    auto ret = manager->UpdateDisableEvents(bunaleName, events, enable, uid);
    EXPECT_EQ(0, ret);
}

/*
 * @tc.name: RemoveSubscriberWithBundleName_0100
 * @tc.desc: Test the RemoveSubscriberWithBundleName function, delete events disableEvents_ through bundlename
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberManagerUnitTest, RemoveSubscriberWithBundleName_0100, Function | MediumTest | Level1)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string bundleName = "testBundleName";
    int32_t userId = 1000;
    std::vector<std::string> events;
    events.emplace_back("event1");
    std::string key = std::to_string(userId) + "_" + bundleName;
    manager->disableEvents_.emplace(key, events);
    manager->RemoveSubscriberWithBundleName(bundleName, userId);
    EXPECT_EQ(manager->disableEvents_.end(), manager->disableEvents_.find(key));
}

/*
 * @tc.name: RemoveSubscriberWithBundleName_0200
 * @tc.desc: Test the RemoveSubscriberWithBundleName function, delete events disableEvents_ through bundlename,
 *           there is no bundlename.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberManagerUnitTest, RemoveSubscriberWithBundleName_0200, Function | MediumTest | Level1)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string bundleName = "testBundleName";
    int32_t userId = 1000;
    std::vector<std::string> events;
    events.emplace_back("event1");
    manager->RemoveSubscriberWithBundleName(bundleName, userId);
    EXPECT_EQ(manager->disableEvents_.end(), manager->disableEvents_.find(bundleName));
}

/*
 * @tc.name: IsDisableEvent_0100
 * @tc.desc: Test the isDisableEvent function, bundlename with input parameters in disableEvents_.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberManagerUnitTest, IsDisableEvent_0100, Function | MediumTest | Level1)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string bundleName = "testBundleName";
    std::string event = "event1";
    std::vector<std::string> events;
    events.emplace_back(event);
    int32_t uid = 100;
    std::string key = std::to_string(uid) + "_" + bundleName;
    manager->disableEvents_.emplace(key, events);
    int32_t userId = 100;
    auto ret = manager->IsDisableEvent(bundleName, event, uid);
    EXPECT_EQ(true, ret);
}

/*
 * @tc.name: IsDisableEvent_0200
 * @tc.desc: Test the isDisableEvent function, bundlename with no parameters passed in the disableEvents_.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberManagerUnitTest, IsDisableEvent_0200, Function | MediumTest | Level1)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string bundleName = "testBundleName";
    std::string event = "event1";
    int32_t userId = 100;
    auto ret = manager->IsDisableEvent(bundleName, event, userId);
    EXPECT_EQ(false, ret);
}

/*
 * @tc.name: ParseFilterObject_0100
 * @tc.desc: Test the ParseFilterObject function with valid input.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberManagerUnitTest, ParseFilterObject_0100, Function | MediumTest | Level1)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    nlohmann::json filterObj = { { { "event", EVENT_NAME },
        { "conditions", { { "parameters", { { PARAM_1, PARAM_VALUE_1 }, { PARAM_2, PARAM_VALUE_2 },
                                              { PARAM_3, PARAM_VALUE_3 }, { PARAM_4, PARAM_VALUE_4 } } },
                            { "code", VALID_CODE }, { "data", VALID_DATA } } } } };
    StaticSubscriberManager::StaticSubscriberInfo subscriber;
    manager->ParseFilterObject(filterObj, EVENT_NAME, subscriber);
    EXPECT_EQ(subscriber.filterCode.value(), VALID_CODE);
    EXPECT_EQ(subscriber.filterData.value(), VALID_DATA);
    EXPECT_EQ(std::get<bool>(subscriber.filterParameters[PARAM_1]), PARAM_VALUE_1);
    EXPECT_EQ(std::get<int32_t>(subscriber.filterParameters[PARAM_2]), PARAM_VALUE_2);
    EXPECT_EQ(std::get<double>(subscriber.filterParameters[PARAM_3]), PARAM_VALUE_3);
    EXPECT_EQ(std::get<std::string>(subscriber.filterParameters[PARAM_4]), PARAM_VALUE_4);
}

/*
 * @tc.name: ParseFilterObject_0200
 * @tc.desc: Test the ParseFilterObject function with invalid input.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberManagerUnitTest, ParseFilterObject_0200, Function | MediumTest | Level1)
{
    const std::string invalidCode = "invalidCode";
    const int invalidData = 12345;
    auto manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    nlohmann::json filterObj = { { { "event", EVENT_NAME },
        { "conditions", { { "parameters", { { PARAM_1, nullptr }, { PARAM_2, nlohmann::json::object() },
                                              { PARAM_3, nlohmann::json::array() } } },
                            { "code", invalidCode }, { "data", invalidData } } } } };
    StaticSubscriberManager::StaticSubscriberInfo subscriber;
    manager->ParseFilterObject(filterObj, EVENT_NAME, subscriber);
    EXPECT_FALSE(subscriber.filterCode.has_value());
    EXPECT_FALSE(subscriber.filterData.has_value());
    EXPECT_TRUE(subscriber.filterParameters.empty());
}

/*
 * @tc.name: AddFilterParameter_0100
 * @tc.desc: Test the AddFilterParameter function with various parameter types.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberManagerUnitTest, AddFilterParameter_0100, Function | MediumTest | Level1)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::map<std::string, StaticSubscriberManager::ParameterType> filterParameters;
    nlohmann::json paramValue = PARAM_VALUE_1;
    manager->AddFilterParameter(PARAM_1, paramValue, filterParameters);
    EXPECT_EQ(std::get<bool>(filterParameters[PARAM_1]), PARAM_VALUE_1);
    paramValue = PARAM_VALUE_2;
    manager->AddFilterParameter(PARAM_2, paramValue, filterParameters);
    EXPECT_EQ(std::get<int32_t>(filterParameters[PARAM_2]), PARAM_VALUE_2);
    paramValue = PARAM_VALUE_3;
    manager->AddFilterParameter(PARAM_3, paramValue, filterParameters);
    EXPECT_EQ(std::get<double>(filterParameters[PARAM_3]), PARAM_VALUE_3);
    paramValue = PARAM_VALUE_4;
    manager->AddFilterParameter(PARAM_4, paramValue, filterParameters);
    EXPECT_EQ(std::get<std::string>(filterParameters[PARAM_4]), PARAM_VALUE_4);
}

/*
 * @tc.name: AddFilterParameter_0200
 * @tc.desc: Test the AddFilterParameter function with invalid parameter types.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberManagerUnitTest, AddFilterParameter_0200, Function | MediumTest | Level1)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::map<std::string, StaticSubscriberManager::ParameterType> filterParameters;
    nlohmann::json paramValue = nullptr;
    manager->AddFilterParameter(PARAM_1, paramValue, filterParameters);
    EXPECT_TRUE(filterParameters.empty());
    paramValue = nlohmann::json::object();
    manager->AddFilterParameter(PARAM_2, paramValue, filterParameters);
    EXPECT_TRUE(filterParameters.empty());
    paramValue = nlohmann::json::array();
    manager->AddFilterParameter(PARAM_3, paramValue, filterParameters);
    EXPECT_TRUE(filterParameters.empty());
}

/*
 * @tc.name: IsFilterParameters_0100
 * @tc.desc: Test the IsFilterParameters function with matching parameters.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberManagerUnitTest, IsFilterParameters_0100, Function | MediumTest | Level1)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    StaticSubscriberManager::StaticSubscriberInfo subscriber;
    subscriber.filterParameters = { { PARAM_1, PARAM_VALUE_1 }, { PARAM_2, PARAM_VALUE_2 }, { PARAM_3, PARAM_VALUE_3 },
        { PARAM_4, PARAM_VALUE_4 } };
    Want want;
    OHOS::AAFwk::WantParams wantParams;
    wantParams.SetParam(PARAM_1, AAFwk::Boolean::Box(PARAM_VALUE_1));
    wantParams.SetParam(PARAM_2, AAFwk::Integer::Box(PARAM_VALUE_2));
    wantParams.SetParam(PARAM_3, AAFwk::Double::Box(PARAM_VALUE_3));
    wantParams.SetParam(PARAM_4, AAFwk::String::Box(PARAM_VALUE_4));
    want.SetParams(wantParams);
    CommonEventData data;
    data.SetWant(want);
    EXPECT_TRUE(manager->IsFilterParameters(subscriber, data));
}

/*
 * @tc.name: IsFilterParameters_0200
 * @tc.desc: Test the IsFilterParameters function with non-matching parameters.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberManagerUnitTest, IsFilterParameters_0200, Function | MediumTest | Level1)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    StaticSubscriberManager::StaticSubscriberInfo subscriber;
    subscriber.filterParameters = { { PARAM_1, PARAM_VALUE_1 }, { PARAM_2, PARAM_VALUE_2 }, { PARAM_3, PARAM_VALUE_3 },
        { PARAM_4, PARAM_VALUE_4 } };
    Want want;
    OHOS::AAFwk::WantParams wantParams;
    wantParams.SetParam(PARAM_1, AAFwk::Boolean::Box(INVALID_PARAM_VALUE_1));
    wantParams.SetParam(PARAM_2, AAFwk::Integer::Box(INVALID_PARAM_VALUE_2));
    wantParams.SetParam(PARAM_3, AAFwk::Double::Box(INVALID_PARAM_VALUE_3));
    wantParams.SetParam(PARAM_4, AAFwk::String::Box(INVALID_PARAM_VALUE_4));
    want.SetParams(wantParams);
    CommonEventData data;
    data.SetWant(want);
    EXPECT_FALSE(manager->IsFilterParameters(subscriber, data));
}

/*
 * @tc.name: CheckFilterCodeAndData_0100
 * @tc.desc: Test the CheckFilterCodeAndData function with matching code and data.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberManagerUnitTest, CheckFilterCodeAndData_0100, Function | MediumTest | Level1)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    StaticSubscriberManager::StaticSubscriberInfo subscriber;
    subscriber.filterCode = VALID_CODE;
    subscriber.filterData = VALID_DATA;
    CommonEventData data;
    data.SetCode(VALID_CODE);
    data.SetData(VALID_DATA);
    EXPECT_TRUE(manager->CheckFilterCodeAndData(subscriber, data));
}

/*
 * @tc.name: CheckFilterCodeAndData_0200
 * @tc.desc: Test the CheckFilterCodeAndData function with non-matching code and data.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberManagerUnitTest, CheckFilterCodeAndData_0200, Function | MediumTest | Level1)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    StaticSubscriberManager::StaticSubscriberInfo subscriber;
    subscriber.filterCode = VALID_CODE;
    subscriber.filterData = VALID_DATA;
    CommonEventData data;
    const int invalidCode = 200;
    const std::string invalidData = "differentData";
    data.SetCode(invalidCode);
    data.SetData(invalidData);
    EXPECT_FALSE(manager->CheckFilterCodeAndData(subscriber, data));
}

/*
 * @tc.name: CheckFilterParameters_0100
 * @tc.desc: Test the CheckFilterParameters function with matching parameters.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberManagerUnitTest, CheckFilterParameters_0100, Function | MediumTest | Level1)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::map<std::string, StaticSubscriberManager::ParameterType> filterParameters = { { PARAM_1, PARAM_VALUE_1 },
        { PARAM_2, PARAM_VALUE_2 }, { PARAM_3, PARAM_VALUE_3 }, { PARAM_4, PARAM_VALUE_4 } };
    Want want;
    OHOS::AAFwk::WantParams wantParams;
    wantParams.SetParam(PARAM_1, AAFwk::Boolean::Box(PARAM_VALUE_1));
    wantParams.SetParam(PARAM_2, AAFwk::Integer::Box(PARAM_VALUE_2));
    wantParams.SetParam(PARAM_3, AAFwk::Double::Box(PARAM_VALUE_3));
    wantParams.SetParam(PARAM_4, AAFwk::String::Box(PARAM_VALUE_4));
    want.SetParams(wantParams);
    EXPECT_TRUE(manager->CheckFilterParameters(filterParameters, want));
}

/*
 * @tc.name: CheckFilterParameters_0200
 * @tc.desc: Test the CheckFilterParameters function with non-matching parameters.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberManagerUnitTest, CheckFilterParameters_0200, Function | MediumTest | Level1)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::map<std::string, StaticSubscriberManager::ParameterType> filterParameters = { { PARAM_1, PARAM_VALUE_1 },
        { PARAM_2, PARAM_VALUE_2 }, { PARAM_3, PARAM_VALUE_3 }, { PARAM_4, PARAM_VALUE_4 } };
    Want want;
    OHOS::AAFwk::WantParams wantParams;
    wantParams.SetParam(PARAM_1, AAFwk::Boolean::Box(INVALID_PARAM_VALUE_1));
    wantParams.SetParam(PARAM_2, AAFwk::Integer::Box(INVALID_PARAM_VALUE_2));
    wantParams.SetParam(PARAM_3, AAFwk::Double::Box(INVALID_PARAM_VALUE_3));
    wantParams.SetParam(PARAM_4, AAFwk::String::Box(INVALID_PARAM_VALUE_4));
    want.SetParams(wantParams);
    EXPECT_FALSE(manager->CheckFilterParameters(filterParameters, want));
}


HWTEST_F(StaticSubscriberManagerUnitTest, ATC_CheckSubscriberBySpecifiedUids_EmptyList, Level0)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    std::vector<int32_t> emptyList;
    EXPECT_FALSE(manager->CheckSubscriberBySpecifiedUids(1, emptyList));
}

HWTEST_F(StaticSubscriberManagerUnitTest, ATC_CheckSubscriberBySpecifiedUids_SubscriberNotInList, Level0)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    std::vector<int32_t> list = {2, 3, 4};
    EXPECT_FALSE(manager->CheckSubscriberBySpecifiedUids(1, list));
}

HWTEST_F(StaticSubscriberManagerUnitTest, ATC_CheckSubscriberBySpecifiedUids_SubscriberInList, Level0)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    std::vector<int32_t> list = {1, 2, 3};
    EXPECT_TRUE(manager->CheckSubscriberBySpecifiedUids(1, list));
}

HWTEST_F(StaticSubscriberManagerUnitTest, ATC_CheckSubscriberWhetherMatched_AllConditionsMatched_ReturnTrue, Level0)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    StaticSubscriberManager::StaticSubscriberInfo subscriber;
    subscriber.bundleName = "testBundle";
    subscriber.userId = 1;
    CommonEventPublishInfo publishInfo;
    publishInfo.SetBundleName("testBundle");
    publishInfo.SetSubscriberType(static_cast<int32_t>(SubscriberType::ALL_SUBSCRIBER_TYPE));
    publishInfo.SetSubscriberUid({1});
    publishInfo.SetSubscriberPermissions({"permission"});
    publishInfo.SetValidationRule(ValidationRule::AND);
    SetUidMock(1);
    MockGetHapTokenID(100);
    MockVerifyAccessToken(true);

    EXPECT_TRUE(manager->CheckSubscriberWhetherMatched(subscriber, publishInfo));
}

HWTEST_F(StaticSubscriberManagerUnitTest, ATC_CheckSubscriberWhetherMatched_BundleNameNotMatched_ReturnFalse, Level0)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    StaticSubscriberManager::StaticSubscriberInfo subscriber;
    subscriber.bundleName = "testBundle";
    subscriber.userId = 1;
    CommonEventPublishInfo publishInfo;
    publishInfo.SetBundleName("otherBundle");
    publishInfo.SetSubscriberType(static_cast<int32_t>(SubscriberType::ALL_SUBSCRIBER_TYPE));
    publishInfo.SetSubscriberUid({1});
    publishInfo.SetSubscriberPermissions({"permission"});
    publishInfo.SetValidationRule(ValidationRule::AND);
    SetUidMock(1);
    MockGetHapTokenID(100);
    MockVerifyAccessToken(true);

    EXPECT_FALSE(manager->CheckSubscriberWhetherMatched(subscriber, publishInfo));
}

HWTEST_F(StaticSubscriberManagerUnitTest, ATC_CheckSubscriberWhetherMatched_SubscriberTypeNotMatched_ReturnFalse,
    Level0)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    StaticSubscriberManager::StaticSubscriberInfo subscriber;
    subscriber.bundleName = "testBundle";
    subscriber.userId = 1;
    CommonEventPublishInfo publishInfo;
    publishInfo.SetBundleName("testBundle");
    publishInfo.SetSubscriberType(static_cast<int32_t>(SubscriberType::SYSTEM_SUBSCRIBER_TYPE));
    publishInfo.SetSubscriberUid({1});
    publishInfo.SetValidationRule(ValidationRule::AND);
    SetSystemMock(false);
    MockGetHapTokenID(100);
    MockVerifyAccessToken(true);
    SetUidMock(1);

    EXPECT_FALSE(manager->CheckSubscriberWhetherMatched(subscriber, publishInfo));
}

HWTEST_F(StaticSubscriberManagerUnitTest, ATC_CheckSubscriberWhetherMatched_SubscriberUidNotMatched_ReturnFalse,
    Level0)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    StaticSubscriberManager::StaticSubscriberInfo subscriber;
    subscriber.bundleName = "testBundle";
    subscriber.userId = 1;
    CommonEventPublishInfo publishInfo;
    publishInfo.SetBundleName("testBundle");
    publishInfo.SetSubscriberType(static_cast<int32_t>(SubscriberType::ALL_SUBSCRIBER_TYPE));
    publishInfo.SetSubscriberUid({1});
    publishInfo.SetValidationRule(ValidationRule::AND);
    SetSystemMock(true);
    MockGetHapTokenID(100);
    MockVerifyAccessToken(true);
    SetUidMock(2);

    EXPECT_FALSE(manager->CheckSubscriberWhetherMatched(subscriber, publishInfo));
}

HWTEST_F(StaticSubscriberManagerUnitTest, ATC_CheckSubscriberWhetherMatched_PermissionNotMatched_ReturnFalse, Level0)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    StaticSubscriberManager::StaticSubscriberInfo subscriber;
    subscriber.bundleName = "testBundle";
    subscriber.userId = 1;
    CommonEventPublishInfo publishInfo;
    publishInfo.SetBundleName("testBundle");
    publishInfo.SetSubscriberType(static_cast<int32_t>(SubscriberType::ALL_SUBSCRIBER_TYPE));
    publishInfo.SetSubscriberUid({1});
    publishInfo.SetValidationRule(ValidationRule::AND);
    publishInfo.SetSubscriberPermissions({"permission"});
    SetSystemMock(true);
    MockGetHapTokenID(100);
    MockVerifyAccessToken(false);
    SetUidMock(1);

    EXPECT_FALSE(manager->CheckSubscriberWhetherMatched(subscriber, publishInfo));
}

HWTEST_F(StaticSubscriberManagerUnitTest, CheckSubscriberWhetherMatched_ShouldReturnTrue_WhenFilterSettingsIsZero,
    Level0)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    StaticSubscriberManager::StaticSubscriberInfo subscriber;
    CommonEventPublishInfo publishInfo;

    EXPECT_TRUE(manager->CheckSubscriberWhetherMatched(subscriber, publishInfo));
}

/**
* @tc.name  : CheckSubscriberWhetherMatched_ShouldReturnTrue_WhenBundleNameMatches
* @tc.number: CheckSubscriberWhetherMatched_Test_002
* @tc.desc  : 当订阅者的bundleName与发布的事件信息中的bundleName匹配时，函数应返回true
*/
HWTEST_F(StaticSubscriberManagerUnitTest, CheckSubscriberWhetherMatched_ShouldReturnTrue_WhenBundleNameMatches, Level0)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    StaticSubscriberManager::StaticSubscriberInfo subscriber;
    subscriber.bundleName = "com.example.app";
    CommonEventPublishInfo publishInfo;
    publishInfo.SetBundleName("com.example.app");

    EXPECT_TRUE(manager->CheckSubscriberWhetherMatched(subscriber, publishInfo));
}

/**
* @tc.name  : CheckSubscriberWhetherMatched_ShouldReturnTrue_WhenSubscriberTypeMatches
* @tc.number: CheckSubscriberWhetherMatched_Test_003
* @tc.desc  : 当订阅者类型匹配时，函数应返回true
*/
HWTEST_F(StaticSubscriberManagerUnitTest, CheckSubscriberWhetherMatched_ShouldReturnTrue_WhenSubscriberTypeMatches,
    Level0)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    StaticSubscriberManager::StaticSubscriberInfo subscriber;
    subscriber.bundleName = "com.example.app";
    subscriber.userId = 0;
    CommonEventPublishInfo publishInfo;
    publishInfo.SetSubscriberType(static_cast<int32_t>(SubscriberType::SYSTEM_SUBSCRIBER_TYPE));
    SetSystemMock(true);

    EXPECT_TRUE(manager->CheckSubscriberWhetherMatched(subscriber, publishInfo));
}

/**
* @tc.name  : CheckSubscriberWhetherMatched_ShouldReturnTrue_WhenSubscriberUidMatches
* @tc.number: CheckSubscriberWhetherMatched_Test_004
* @tc.desc  : 当订阅者UID匹配时，函数应返回true
*/
HWTEST_F(StaticSubscriberManagerUnitTest, CheckSubscriberWhetherMatched_ShouldReturnTrue_WhenSubscriberUidMatches,
    Level0)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    StaticSubscriberManager::StaticSubscriberInfo subscriber;
    subscriber.bundleName = "com.example.app";
    subscriber.userId = 0;
    CommonEventPublishInfo publishInfo;
    publishInfo.SetSubscriberUid({12345});
    SetUidMock(12345);

    EXPECT_TRUE(manager->CheckSubscriberWhetherMatched(subscriber, publishInfo));
}

/**
* @tc.name  : CheckSubscriberWhetherMatched_ShouldReturnTrue_WhenSubscriberPermissionsMatch
* @tc.number: CheckSubscriberWhetherMatched_Test_005
* @tc.desc  : 当订阅者权限匹配时，函数应返回true
*/
HWTEST_F(StaticSubscriberManagerUnitTest,
    CheckSubscriberWhetherMatched_ShouldReturnTrue_WhenSubscriberPermissionsMatch, Level0)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    StaticSubscriberManager::StaticSubscriberInfo subscriber;
    subscriber.bundleName = "com.example.app";
    subscriber.userId = 0;
    CommonEventPublishInfo publishInfo;
    publishInfo.SetSubscriberPermissions({"permission1"});
    MockGetHapTokenID(100);
    MockVerifyAccessToken(true);

    EXPECT_TRUE(manager->CheckSubscriberWhetherMatched(subscriber, publishInfo));
}

HWTEST_F(StaticSubscriberManagerUnitTest,
    CheckSubscriberWhetherMatched_ShouldReturnTrue_WhenValidationRuleIsORAndBundleNameMatches, Level0)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    StaticSubscriberManager::StaticSubscriberInfo subscriber;
    subscriber.bundleName = "testBundle";
    subscriber.userId = 1;
    CommonEventPublishInfo publishInfo;
    publishInfo.SetBundleName("testBundle");
    publishInfo.SetSubscriberType(static_cast<int32_t>(SubscriberType::ALL_SUBSCRIBER_TYPE));
    publishInfo.SetSubscriberUid({1});
    publishInfo.SetSubscriberPermissions({"permission"});
    publishInfo.SetValidationRule(ValidationRule::OR);
    SetUidMock(2);
    SetSystemMock(false);
    MockGetHapTokenID(100);
    MockVerifyAccessToken(false);

    EXPECT_TRUE(manager->CheckSubscriberWhetherMatched(subscriber, publishInfo));
}

HWTEST_F(StaticSubscriberManagerUnitTest,
    CheckSubscriberWhetherMatched_ShouldReturnTrue_WhenValidationRuleIsORAndUidMatches, Level0)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    StaticSubscriberManager::StaticSubscriberInfo subscriber;
    subscriber.bundleName = "testBundle";
    subscriber.userId = 1;
    CommonEventPublishInfo publishInfo;
    publishInfo.SetBundleName("otherBundle");
    publishInfo.SetSubscriberType(static_cast<int32_t>(SubscriberType::ALL_SUBSCRIBER_TYPE));
    publishInfo.SetSubscriberUid({1});
    publishInfo.SetSubscriberPermissions({"permission"});
    publishInfo.SetValidationRule(ValidationRule::OR);
    SetUidMock(1);
    SetSystemMock(false);
    MockGetHapTokenID(100);
    MockVerifyAccessToken(false);

    EXPECT_TRUE(manager->CheckSubscriberWhetherMatched(subscriber, publishInfo));
}

HWTEST_F(StaticSubscriberManagerUnitTest,
    CheckSubscriberWhetherMatched_ShouldReturnTrue_WhenValidationRuleIsORAndPermissionMatches, Level0)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    StaticSubscriberManager::StaticSubscriberInfo subscriber;
    subscriber.bundleName = "testBundle";
    subscriber.userId = 1;
    CommonEventPublishInfo publishInfo;
    publishInfo.SetBundleName("otherBundle");
    publishInfo.SetSubscriberType(static_cast<int32_t>(SubscriberType::ALL_SUBSCRIBER_TYPE));
    publishInfo.SetSubscriberUid({1});
    publishInfo.SetSubscriberPermissions({"permission"});
    publishInfo.SetValidationRule(ValidationRule::OR);
    SetUidMock(2);
    SetSystemMock(false);
    MockGetHapTokenID(100);
    MockVerifyAccessToken(true);

    EXPECT_TRUE(manager->CheckSubscriberWhetherMatched(subscriber, publishInfo));
}

HWTEST_F(StaticSubscriberManagerUnitTest,
    CheckSubscriberWhetherMatched_ShouldReturnTrue_WhenValidationRuleIsORAndTypeMatches, Level0)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    StaticSubscriberManager::StaticSubscriberInfo subscriber;
    subscriber.bundleName = "testBundle";
    subscriber.userId = 1;
    CommonEventPublishInfo publishInfo;
    publishInfo.SetBundleName("otherBundle");
    publishInfo.SetSubscriberType(static_cast<int32_t>(SubscriberType::ALL_SUBSCRIBER_TYPE));
    publishInfo.SetSubscriberUid({1});
    publishInfo.SetSubscriberPermissions({"permission"});
    publishInfo.SetValidationRule(ValidationRule::OR);
    SetUidMock(2);
    SetSystemMock(true);
    MockGetHapTokenID(100);
    MockVerifyAccessToken(false);

    EXPECT_TRUE(manager->CheckSubscriberWhetherMatched(subscriber, publishInfo));
}

HWTEST_F(StaticSubscriberManagerUnitTest,
    CheckSubscriberWhetherMatched_ShouldReturnTrue_WhenValidationRuleIsORAndAllConditionsNotMatched, Level0)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    StaticSubscriberManager::StaticSubscriberInfo subscriber;
    subscriber.bundleName = "testBundle";
    subscriber.userId = 1;
    CommonEventPublishInfo publishInfo;
    publishInfo.SetBundleName("otherBundle");
    publishInfo.SetSubscriberType(static_cast<int32_t>(SubscriberType::SYSTEM_SUBSCRIBER_TYPE));
    publishInfo.SetSubscriberUid({1});
    publishInfo.SetSubscriberPermissions({"permission"});
    publishInfo.SetValidationRule(ValidationRule::OR);
    SetSystemMock(false);
    SetUidMock(2);
    MockGetHapTokenID(100);
    MockVerifyAccessToken(false);

    EXPECT_FALSE(manager->CheckSubscriberWhetherMatched(subscriber, publishInfo));
}

HWTEST_F(StaticSubscriberManagerUnitTest,
    CheckSubscriberWhetherMatched_ShouldReturnTrue_WhenValidationRuleIsORAndAllConditionsNotMatchedAndNoType, Level0)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    StaticSubscriberManager::StaticSubscriberInfo subscriber;
    subscriber.bundleName = "testBundle";
    subscriber.userId = 1;
    CommonEventPublishInfo publishInfo;
    publishInfo.SetBundleName("otherBundle");
    publishInfo.SetSubscriberUid({1});
    publishInfo.SetSubscriberPermissions({"permission"});
    publishInfo.SetValidationRule(ValidationRule::OR);
    SetUidMock(2);
    MockGetHapTokenID(100);
    MockVerifyAccessToken(false);

    EXPECT_FALSE(manager->CheckSubscriberWhetherMatched(subscriber, publishInfo));
}

/*
 * @tc.name: InitValidSubscribersTest_0900
 * @tc.desc: test if StaticSubscriberManager's InitValidSubscribers function executed as expected
 *           when two invalid extension were found.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, InitValidSubscribersTest_0900, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "StaticSubscriberManagerUnitTest, InitValidSubscribersTest_0900, TestSize.Level1";
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    EXPECT_EQ(0, manager->validSubscribers_.size());
    MockQueryExtensionInfos(true, MOCK_CASE_3);
    MockGetResConfigFile(true, MOCK_CASE_3);
    MockGetOsAccountLocalIdFromUid(false);
    EXPECT_TRUE(manager->InitValidSubscribers());
    EXPECT_TRUE(manager->hasInitValidSubscribers_);
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: InitAllowListTest_0200
 * @tc.desc: test if StaticSubscriberManager's InitAllowList function executed as expected in normal case.
 * @tc.type: FUNC
 * @tc.require: #I5RLKK
 * 
 */
HWTEST_F(StaticSubscriberManagerUnitTest, InitAllowListTest_0200, Function | MediumTest | Level1)
{
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    MockGetApplicationInfos();
    MockGetOsAccountLocalIdFromUid(true);
    bool initResult = manager->InitAllowList();
    EXPECT_TRUE(initResult);
    EXPECT_TRUE(manager->hasInitAllowList_);
    MockGetOsAccountLocalIdFromUid(false);
    initResult = manager->InitAllowList();
    EXPECT_TRUE(initResult);
}

/*
 * @tc.name: SetStaticSubscriberState_0500
 * @tc.desc: Test SetStaticSubscriberState function.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberManagerUnitTest, SetStaticSubscriberState_0500, Function | SmallTest | Level1)
{
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    MockGetOsAccountLocalIdFromUid(false);
    auto ret = manager->SetStaticSubscriberState(false);
    EXPECT_EQ(ERR_INVALID_OPERATION, ret);
    std::vector<std::string> events;
    ret = manager->SetStaticSubscriberState(events, true);
    EXPECT_EQ(ERR_INVALID_OPERATION, ret);
}