/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "static_subscriber_manager.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EventFwk;

namespace {
    constexpr uint8_t TEST_ALLOWLIST_SIZE = 3;
    constexpr uint8_t TEST_PARSE_EVENTS_MUL_SIZE = 2;
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

void StaticSubscriberManagerUnitTest::SetUpTestCase() {}

void StaticSubscriberManagerUnitTest::TearDownTestCase() {}

void StaticSubscriberManagerUnitTest::SetUp() {}

void StaticSubscriberManagerUnitTest::TearDown() {}

/*
 * @tc.name: InitAllowListTest_0100
 * @tc.desc: test if StaticSubscriberManager's InitAllowList function excuted as expected in normal case.
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
    //Init
    bool initResult = manager->InitAllowList();
    // expect init success
    EXPECT_TRUE(initResult);
    // expect allow list has apps
    EXPECT_EQ(TEST_ALLOWLIST_SIZE, manager->subscriberList_.size());
    // expect hasInit true
    EXPECT_TRUE(manager->hasInitAllowList_);
}

/*
 * @tc.name: ParseEventsTest_0100
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function excuted as expected with
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
    //Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is not empty
    EXPECT_EQ(1, manager->validSubscribers_.size());
    // expect map content is correct
    string expectEventName = "usual.event.TIME_TICK";
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
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function excuted as expected with
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
    //Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is not empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: ParseEventsTest_0300
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function excuted as expected with
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
    //Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: ParseEventsTest_0400
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function excuted as expected with
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
    //Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: ParseEventsTest_0500
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function excuted as expected with
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
    //Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: ParseEventsTest_0600
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function excuted as expected with
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
    //Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: ParseEventsTest_0700
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function excuted as expected with
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
    //Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: ParseEventsTest_0800
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function excuted as expected with
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
    //Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: ParseEventsTest_0900
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function excuted as expected with
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
    //Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: ParseEventsTest_1000
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function excuted as expected with
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
    //Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: ParseEventsTest_1100
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function excuted as expected with
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
    //Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: ParseEventsTest_1200
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function excuted as expected with
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
    //Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: ParseEventsTest_1300
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function excuted as expected with
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
    //Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: ParseEventsTest_1400
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function excuted as expected with
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
    //Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: ParseEventsTest_1500
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function excuted as expected with
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
    //Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: ParseEventsTest_1600
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function excuted as expected
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
    //Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is not empty
    EXPECT_EQ(TEST_PARSE_EVENTS_MUL_SIZE, manager->validSubscribers_.size());
    // expect map content is correct
    string expectEventName0 = "usual.event.TIME_TICK0";
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
    string expectEventName1 = "usual.event.TIME_TICK1";
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
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function excuted as expected with
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
    //Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is not empty
    EXPECT_EQ(1, manager->validSubscribers_.size());
    // expect map content is correct
    string expectEventName0 = "usual.event.TIME_TICK0";
    auto it0 = manager->validSubscribers_.find(expectEventName0);
    EXPECT_EQ(manager->validSubscribers_.end(), it0);
    // expect map content is correct
    string expectEventName1 = "usual.event.TIME_TICK1";
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
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function excuted as expected with
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
    //Init
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
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function excuted as expected with
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
    //Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is not empty
    EXPECT_EQ(1, manager->validSubscribers_.size());
    // expect map content is correct
    string expectEventName0 = "usual.event.TIME_TICK0";
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
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function excuted as expected with
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
    //Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is not empty
    EXPECT_EQ(1, manager->validSubscribers_.size());
    // expect map content is correct
    string expectEventName0 = "usual.event.TIME_TICK0";
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
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function excuted as expected with
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
    //Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}

/*
 * @tc.name: ParseEventsTest_2200
 * @tc.desc: test if StaticSubscriberManager's ParseEvents function excuted as expected with
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
    //Init
    manager->ParseEvents(testExtensionName, testExtensionBundleName, testExtensionUserId, testProfile);
    // expect valid subscribers map is empty
    EXPECT_EQ(0, manager->validSubscribers_.size());
}





