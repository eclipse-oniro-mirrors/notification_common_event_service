/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "ces_inner_error_code.h"
#include "nlohmann/json.hpp"
#define private public
#define protected public
#include "static_subscriber_data_manager.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EventFwk;
class StaticSubscriberDataManagerUnitTest : public testing::Test {
public:
    StaticSubscriberDataManagerUnitTest() {}
    virtual ~StaticSubscriberDataManagerUnitTest() {}

    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void StaticSubscriberDataManagerUnitTest::SetUpTestCase() {}

void StaticSubscriberDataManagerUnitTest::TearDownTestCase() {}

void StaticSubscriberDataManagerUnitTest::SetUp() {}

void StaticSubscriberDataManagerUnitTest::TearDown() {}

/*
 * @tc.name: UpdateStaticSubscriberState_0100
 * @tc.desc: Test UpdateStaticSubscriberState function, the parameter disableEvents passed in is empty.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberDataManagerUnitTest, UpdateStaticSubscriberState_0100, Function | MediumTest | Level1)
{
    auto dataManager = std::make_shared<StaticSubscriberDataManager>();
    ASSERT_NE(nullptr, dataManager);
    std::map<std::string, std::vector<std::string>> disableEvents;
    auto ret = dataManager->UpdateStaticSubscriberState(disableEvents);
    EXPECT_EQ(ERR_OK, ret);
}

/*
 * @tc.name: QueryStaticSubscriberStateData_0100
 * @tc.desc: Test QueryStaticSubscriberStateData function, the parameter disableEvents passed in is empty.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberDataManagerUnitTest, QueryStaticSubscriberStateData_0100, Function | MediumTest | Level1)
{
    auto dataManager = std::make_shared<StaticSubscriberDataManager>();
    ASSERT_NE(nullptr, dataManager);
    std::map<std::string, std::vector<std::string>> disableEvents;
    std::set<std::string> bundleList;
    auto ret = dataManager->QueryStaticSubscriberStateData(disableEvents, bundleList);
    EXPECT_EQ(ERR_OK, ret);
}

/*
 * @tc.name: QueryStaticSubscriberStateData_0200
 * @tc.desc: Test QueryStaticSubscriberStateData function, the value of database data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberDataManagerUnitTest, QueryStaticSubscriberStateData_0200, Function | MediumTest | Level1)
{
    auto dataManager = std::make_shared<StaticSubscriberDataManager>();
    ASSERT_NE(nullptr, dataManager);
    std::map<std::string, std::vector<std::string>> disableEvents;
    std::set<std::string> bundleList;
    std::string bundleName = "testBundleName";
    DistributedKv::Key key(bundleName);
    DistributedKv::Value value("0");
    dataManager->CheckKvStore();
    EXPECT_NE(dataManager->kvStorePtr_, nullptr);
    EXPECT_EQ(dataManager->kvStorePtr_->Put(key, value), DistributedKv::Status::SUCCESS);
    auto ret = dataManager->QueryStaticSubscriberStateData(disableEvents, bundleList);
    EXPECT_EQ(ERR_OK, ret);
}

/*
 * @tc.name: QueryStaticSubscriberStateData_0300
 * @tc.desc: Test QueryStaticSubscriberStateData function, the value of database data is events.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberDataManagerUnitTest, QueryStaticSubscriberStateData_0300, Function | MediumTest | Level1)
{
    auto dataManager = std::make_shared<StaticSubscriberDataManager>();
    ASSERT_NE(nullptr, dataManager);
    std::map<std::string, std::vector<std::string>> disableEvents;
    std::set<std::string> bundleList;
    std::string bundleName = "testBundleName";
    DistributedKv::Key key(bundleName);
    DistributedKv::Value value{"events1"};
    dataManager->CheckKvStore();
    EXPECT_NE(dataManager->kvStorePtr_, nullptr);
    EXPECT_EQ(dataManager->kvStorePtr_->Put(key, value), DistributedKv::Status::SUCCESS);
    auto ret = dataManager->QueryStaticSubscriberStateData(disableEvents, bundleList);
    EXPECT_EQ(ERR_INVALID_OPERATION, ret);
}

/*
 * @tc.name: DeleteElementByBundleName_0100
 * @tc.desc: Test DeleteDisableEventElementByBundleName function, the parameter disableEvents passed in is empty.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberDataManagerUnitTest, DeleteElementByBundleName_0100, Function | MediumTest | Level1)
{
    auto dataManager = std::make_shared<StaticSubscriberDataManager>();
    ASSERT_NE(nullptr, dataManager);
    std::string bundleName;
    auto ret = dataManager->DeleteDisableEventElementByBundleName(bundleName);
    EXPECT_EQ(ERR_INVALID_VALUE, ret);
}

/*
 * @tc.name: DeleteElementByBundleName_0200
 * @tc.desc: Test the DeleteDisableEventElementByBundleName function,
 *           The parameter disableEvents passed in is not empty.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberDataManagerUnitTest, DeleteElementByBundleName_0200, Function | MediumTest | Level1)
{
    auto dataManager = std::make_shared<StaticSubscriberDataManager>();
    ASSERT_NE(nullptr, dataManager);
    std::string bundleName = "testBundleName";
    DistributedKv::Key key(bundleName);
    DistributedKv::Value value ("events1");
    dataManager->CheckKvStore();
    EXPECT_NE(dataManager->kvStorePtr_, nullptr);
    EXPECT_EQ(dataManager->kvStorePtr_->Put(key, value), DistributedKv::Status::SUCCESS);
    auto ret = dataManager->DeleteDisableEventElementByBundleName(bundleName);
    EXPECT_EQ(ERR_OK, ret);
}

/*
 * @tc.name: ConvertEventsToValue_0100
 * @tc.desc: Test the ConvertEventsToValue function and whether the value conversion is as expected.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberDataManagerUnitTest, ConvertEventsToValue_0100, Function | MediumTest | Level1)
{
    auto dataManager = std::make_shared<StaticSubscriberDataManager>();
    ASSERT_NE(nullptr, dataManager);
    std::vector<std::string> events;
    events.emplace_back("event1");
    nlohmann::json jsonNodes = nlohmann::json::array();
    jsonNodes.emplace_back("event1");
    auto value = jsonNodes.dump();
    auto ret = dataManager->ConvertEventsToValue(events);
    EXPECT_EQ(static_cast<DistributedKv::Value>(value), ret);
}

/*
 * @tc.name: ConvertValueToEvents_0100
 * @tc.desc: Test the ConvertValueToEvents function, passing in error parameters.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberDataManagerUnitTest, ConvertValueToEvents_0100, Function | MediumTest | Level1)
{
    auto dataManager = std::make_shared<StaticSubscriberDataManager>();
    ASSERT_NE(nullptr, dataManager);
    std::vector<std::string> events;
    DistributedKv::Value value("event1");
    auto ret = dataManager->ConvertValueToEvents(value, events);
    EXPECT_EQ(false, ret);
}

/*
 * @tc.name: ConvertValueToEvents_0200
 * @tc.desc: Test the ConvertValueToEvents function, passing in the correct parameters.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberDataManagerUnitTest, ConvertValueToEvents_0200, Function | MediumTest | Level1)
{
    auto dataManager = std::make_shared<StaticSubscriberDataManager>();
    ASSERT_NE(nullptr, dataManager);
    std::vector<std::string> events;
    nlohmann::json jsonNodes = nlohmann::json::array();
    jsonNodes.emplace_back("event1");
    jsonNodes.emplace_back("event2");
    auto value = jsonNodes.dump();
    auto ret = dataManager->ConvertValueToEvents(value, events);
    EXPECT_EQ(true, ret);
}