/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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
#include "ability_manager_helper.h"
#undef private
#include "mock_iabilitymanager.h"
#include "static_subscriber_connection.h"
#include "mock_service_registry.h"
#include "static_subscriber_stub.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EventFwk;
using namespace OHOS::AppExecFwk;

class AbilityManagerHelperTest : public testing::Test {
public:
    AbilityManagerHelperTest()
    {}
    ~AbilityManagerHelperTest()
    {}

    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AbilityManagerHelperTest::SetUpTestCase(void)
{}

void AbilityManagerHelperTest::TearDownTestCase(void)
{}

void AbilityManagerHelperTest::SetUp(void)
{}

void AbilityManagerHelperTest::TearDown(void)
{}

class MockStaticSubscriber : public StaticSubscriberStub {
public:
    explicit MockStaticSubscriber() {}
    ~MockStaticSubscriber() = default;

    ErrCode OnReceiveEvent(const CommonEventData& data, int32_t& funcResult) override
    {
        return ERR_OK;
    }
};
/**
* @tc.name: AbilityManagerHelper_0100
* @tc.desc: test GetAbilityMgrProxy function and abilityMgr_ is not nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_0100, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0100 start";
    AbilityManagerHelper abilityManagerHelper;
    sptr<IRemoteObject> mockAbilityManager = new (std::nothrow) MockIAbilityManager();
    MockSaProxy(mockAbilityManager);

    EXPECT_NE(nullptr, abilityManagerHelper.GetAbilityMgrProxy());
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0100 end";
}

/**
* @tc.name: AbilityManagerHelper_0200
* @tc.desc: test GetAbilityMgrProxy function and abilityMgr_ is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_0200, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0200 start";
    AbilityManagerHelper abilityManagerHelper;
    sptr<IRemoteObject> mockAbilityManager = nullptr;
    MockSaProxy(mockAbilityManager);

    EXPECT_EQ(nullptr, abilityManagerHelper.GetAbilityMgrProxy());
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0200 end";
}

/**
* @tc.name: AbilityManagerHelper_0300
* @tc.desc: test ConnectAbility function and GetAbilityMgrProxy is false.
* @tc.type: FUNC
*/
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_0300, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0300 start";
    AbilityManagerHelper abilityManagerHelper;
    sptr<IRemoteObject> mockAbilityManager = nullptr;
    MockSaProxy(mockAbilityManager);
    Want want;
    CommonEventData event;
    sptr<IRemoteObject> callerToken = nullptr;
    const int32_t userId = 1;
    EXPECT_EQ(-1, abilityManagerHelper.ConnectAbility(want, event, callerToken, userId));
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0300 end";
}

/**
* @tc.name  : test SetEventHandler
* @tc.number: AbilityManagerHelper_0600
* @tc.desc  : Test SetEventHandler succeeded.
*/
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_0600, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0600 start";
    auto abilityManagerHelper = std::make_shared<AbilityManagerHelper>();
    CommonEventData data;
    sptr<StaticSubscriberConnection> connection = new (std::nothrow) StaticSubscriberConnection(data, "");
    abilityManagerHelper->subscriberConnection_.emplace("test_key", connection);
    EXPECT_NE(abilityManagerHelper->subscriberConnection_.size(), 0);
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0600 end";
}

/**
* @tc.name  : test DisconnectAbility
* @tc.number: AbilityManagerHelper_0700
* @tc.desc  : Test the DisconnectAbility function when the connection is nullptr.
*/
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_0700, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0700 start";
    auto abilityManagerHelper = std::make_shared<AbilityManagerHelper>();
    CommonEventData data;
    sptr<StaticSubscriberConnection> connection = new (std::nothrow) StaticSubscriberConnection(data, "");
    abilityManagerHelper->subscriberConnection_.emplace("test_key", connection);
    abilityManagerHelper->DisconnectAbility(nullptr, "");
    EXPECT_NE(abilityManagerHelper->subscriberConnection_.size(), 0);
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0700 end";
}

/**
* @tc.name  : test DisconnectAbility
* @tc.number: AbilityManagerHelper_0800
* @tc.desc  : Test the DisconnectAbility function when the connection is not nullptr.
*/
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_0800, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0800 start";
    auto abilityManagerHelper = std::make_shared<AbilityManagerHelper>();
    CommonEventData data;
    sptr<StaticSubscriberConnection> connection = new (std::nothrow) StaticSubscriberConnection(data, "");
    abilityManagerHelper->subscriberConnection_.emplace("test_key", connection);
    sptr<StaticSubscriberConnection> connectionOne = new (std::nothrow) StaticSubscriberConnection(data, "");
    abilityManagerHelper->DisconnectAbility(connectionOne, "test_action");
    EXPECT_NE(abilityManagerHelper->subscriberConnection_.size(), 0);
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0800 end";
}

/**
* @tc.name  : test DisconnectServiceAbilityDelay
* @tc.number: AbilityManagerHelper_0900
* @tc.desc  : Test the DisconnectServiceAbilityDelay function when the connection is nullptr.
*/
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_0900, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0900 start";
    auto abilityManagerHelper = std::make_shared<AbilityManagerHelper>();
    CommonEventData data;
    sptr<StaticSubscriberConnection> connection = new (std::nothrow) StaticSubscriberConnection(data, "");
    abilityManagerHelper->subscriberConnection_.emplace("test_key", connection);
    abilityManagerHelper->DisconnectServiceAbilityDelay(nullptr, "");
    EXPECT_NE(abilityManagerHelper->subscriberConnection_.size(), 0);
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0900 end";
}

/**
* @tc.name  : test DisconnectServiceAbilityDelay
* @tc.number: AbilityManagerHelper_1000
* @tc.desc  : Test the DisconnectServiceAbilityDelay function when the eventHandler_ is nullptr.
*/
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_1000, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_1000 start";
    auto abilityManagerHelper = std::make_shared<AbilityManagerHelper>();
    CommonEventData data;
    sptr<StaticSubscriberConnection> connection = new (std::nothrow) StaticSubscriberConnection(data, "");
    abilityManagerHelper->subscriberConnection_.emplace("test_key", connection);
    abilityManagerHelper->DisconnectServiceAbilityDelay(connection, "test_action");
    EXPECT_NE(abilityManagerHelper->subscriberConnection_.size(), 0);
    GTEST_LOG_(INFO) << "AbilityManagerHelper_1000 end";
}

/**
* @tc.name  : test DisconnectServiceAbilityDelay
* @tc.number: AbilityManagerHelper_1100
* @tc.desc  : Test the DisconnectServiceAbilityDelay function when the input parameters meet the requirements.
*/
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_1100, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_1100 start";
    auto abilityManagerHelper = std::make_shared<AbilityManagerHelper>();
    CommonEventData data;
    sptr<StaticSubscriberConnection> firstConnection = new (std::nothrow) StaticSubscriberConnection(data, "");
    abilityManagerHelper->subscriberConnection_.emplace("test_key", firstConnection);
    sptr<StaticSubscriberConnection> SecondConnection = new (std::nothrow) StaticSubscriberConnection(data, "");
    abilityManagerHelper->DisconnectServiceAbilityDelay(SecondConnection, "test_action");
    EXPECT_NE(abilityManagerHelper->subscriberConnection_.size(), 0);
    GTEST_LOG_(INFO) << "AbilityManagerHelper_1100 end";
}

/**
* @tc.name  : test ConnectAbility multiple times
* @tc.number: AbilityManagerHelper_1200
* @tc.desc  : When calling the connection multiple times, the proxy_ is empty
*/
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_1200, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_1200 start";
    auto abilityManagerHelper = std::make_shared<AbilityManagerHelper>();
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockIAbilityManager();
    MockSaProxy(remoteObject);

    Want want;
    CommonEventData event;
    sptr<IRemoteObject> callerToken = nullptr;
    int32_t userId = 1;
    CommonEventData data;
    sptr<StaticSubscriberConnection> connection = new (std::nothrow) StaticSubscriberConnection(data, "");
    std::string connectionKey =
        want.GetBundle() + "_" + want.GetElement().GetAbilityName() + "_" + std::to_string(userId);
    abilityManagerHelper->subscriberConnection_[connectionKey] = connection;
    abilityManagerHelper->subscriberConnection_[connectionKey]->proxy_ = nullptr;

    int result1 = abilityManagerHelper->ConnectAbility(want, event, callerToken, userId);
    EXPECT_EQ(result1, ERR_OK);

    int result2 = abilityManagerHelper->ConnectAbility(want, event, callerToken, userId);
    EXPECT_EQ(result2, ERR_OK);

    int result3 = abilityManagerHelper->ConnectAbility(want, event, callerToken, userId);
    EXPECT_EQ(result3, ERR_OK);

    EXPECT_EQ(abilityManagerHelper->subscriberConnection_[connectionKey]->events_.size(), 4);

    GTEST_LOG_(INFO) << "AbilityManagerHelper_1200 end";
}

/**
* @tc.name  : test ConnectAbility multiple times
* @tc.number: AbilityManagerHelper_1300
* @tc.desc  : When calling the connection multiple times, the proxy_ is not empty
*/
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_1300, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_1300 start";
    auto abilityManagerHelper = std::make_shared<AbilityManagerHelper>();
    sptr<IRemoteObject> mockAbilityManager = new (std::nothrow) MockIAbilityManager();
    MockSaProxy(mockAbilityManager);

    Want want;
    CommonEventData event;
    sptr<IRemoteObject> callerToken = new MockStaticSubscriber();
    int32_t userId = 1;
    CommonEventData data;
    sptr<StaticSubscriberConnection> connection = new (std::nothrow) StaticSubscriberConnection(data, "");
    std::string connectionKey =
        want.GetBundle() + "_" + want.GetElement().GetAbilityName() + "_" + std::to_string(userId);
    abilityManagerHelper->subscriberConnection_[connectionKey] = connection;
    abilityManagerHelper->subscriberConnection_[connectionKey]->InitProxy(callerToken);

    int result1 = abilityManagerHelper->ConnectAbility(want, event, callerToken, userId);
    EXPECT_EQ(result1, ERR_OK);

    int result2 = abilityManagerHelper->ConnectAbility(want, event, callerToken, userId);
    EXPECT_EQ(result2, ERR_OK);

    int result3 = abilityManagerHelper->ConnectAbility(want, event, callerToken, userId);
    EXPECT_EQ(result3, ERR_OK);

    EXPECT_EQ(abilityManagerHelper->subscriberConnection_[connectionKey]->events_.size(), 1);

    GTEST_LOG_(INFO) << "AbilityManagerHelper_1300 end";
}

/**
* @tc.name  : test DisconnectAbility when connection is not empty and IsEmptyAction returns false
* @tc.number: AbilityManagerHelper_1400
* @tc.desc  : Test DisconnectAbility function when action_ has multiple elements.
*/
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_1400, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_1400 start";
    auto abilityManagerHelper = std::make_shared<AbilityManagerHelper>();
    CommonEventData data;
    sptr<StaticSubscriberConnection> connection = new (std::nothrow) StaticSubscriberConnection(data, "");

    std::string action = "test_action";
    connection->action_.push_back(action);
    connection->action_.push_back("other_action");
    abilityManagerHelper->subscriberConnection_.emplace("test_key", connection);

    abilityManagerHelper->DisconnectAbility(connection, action);

    EXPECT_EQ(connection->action_.size(), 1);
    EXPECT_EQ(connection->action_[0], "other_action");
    GTEST_LOG_(INFO) << "AbilityManagerHelper_1400 end";
}

/**
* @tc.name  : ConnectAbility_RealDelay_Disconnect_0001
* @tc.desc  : Verify that ConnectAbility auto-releases the connection after the delay task.
* @tc.type: FUNC
*/
HWTEST_F(AbilityManagerHelperTest, ConnectAbility_RealDelay_Disconnect_0001, Level1)
{
    auto abilityManagerHelper = std::make_shared<AbilityManagerHelper>();
    sptr<MockIAbilityManager> mockAbilityMgr = new MockIAbilityManager();
    MockSaProxy(mockAbilityMgr);

    Want want;
    want.SetBundle("test.bundle");
    ElementName element;
    element.SetAbilityName("TestAbility");
    want.SetElement(element);
    CommonEventData event;
    sptr<IRemoteObject> callerToken = nullptr;
    int32_t userId = 1;
    CommonEventData data;
    std::string connectionKey =
        want.GetBundle() + "_" + want.GetElement().GetAbilityName() + "_" + std::to_string(userId);
    EXPECT_CALL(*mockAbilityMgr, ConnectAbility(::testing::_, ::testing::_, ::testing::_, ::testing::_))
        .Times(1)
        .WillOnce(::testing::Return(ERR_OK));

    int result1 = abilityManagerHelper->ConnectAbility(want, event, callerToken, userId);

    auto it = abilityManagerHelper->subscriberConnection_.find(connectionKey);
    EXPECT_NE(it, abilityManagerHelper->subscriberConnection_.end());

    ffrt::this_task::sleep_for(std::chrono::seconds(16));

    it = abilityManagerHelper->subscriberConnection_.find(connectionKey);
    EXPECT_EQ(it, abilityManagerHelper->subscriberConnection_.end());
}

/**
* @tc.name: AbilityManagerHelper_RemoveConnection_0100
* @tc.desc: test RemoveConnection function when connection is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_RemoveConnection_0100, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_RemoveConnection_0100 start";
    auto abilityManagerHelper = std::make_shared<AbilityManagerHelper>();
    abilityManagerHelper->RemoveConnection(nullptr);
    // No crash is expected to be considered as passed
    GTEST_LOG_(INFO) << "AbilityManagerHelper_RemoveConnection_0100 end";
}

/**
* @tc.name: AbilityManagerHelper_RemoveConnection_0200
* @tc.desc: test RemoveConnection function when connection is not nullptr and not found in subscriberConnection_.
* @tc.type: FUNC
*/
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_RemoveConnection_0200, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_RemoveConnection_0200 start";
    auto abilityManagerHelper = std::make_shared<AbilityManagerHelper>();
    CommonEventData data;
    sptr<StaticSubscriberConnection> connection = new (std::nothrow) StaticSubscriberConnection(data, "");
    abilityManagerHelper->RemoveConnection(connection);
    // No crash and warning log is expected to be considered as passed
    GTEST_LOG_(INFO) << "AbilityManagerHelper_RemoveConnection_0200 end";
}

/**
* @tc.name: AbilityManagerHelper_RemoveConnection_0300
* @tc.desc: test RemoveConnection function when connection is found in subscriberConnection_ but abilityMgr is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_RemoveConnection_0300, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_RemoveConnection_0300 start";
    auto abilityManagerHelper = std::make_shared<AbilityManagerHelper>();
    CommonEventData data;
    sptr<StaticSubscriberConnection> connection = new (std::nothrow) StaticSubscriberConnection(data, "");
    abilityManagerHelper->subscriberConnection_.emplace("test_key", connection);
    sptr<MockIAbilityManager> mockAbilityMgr = nullptr;
    MockSaProxy(mockAbilityMgr);

    abilityManagerHelper->RemoveConnection(connection);
    
    // Connection should be removed from subscriberConnection_
    EXPECT_EQ(abilityManagerHelper->subscriberConnection_.size(), 0);
    GTEST_LOG_(INFO) << "AbilityManagerHelper_RemoveConnection_0300 end";
}

/**
* @tc.name: AbilityManagerHelper_RemoveConnection_0400
* @tc.desc: test RemoveConnection function when connection is found and abilityMgr is not nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_RemoveConnection_0400, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_RemoveConnection_0400 start";
    auto abilityManagerHelper = std::make_shared<AbilityManagerHelper>();
    sptr<MockIAbilityManager> mockAbilityMgr = new MockIAbilityManager();
    MockSaProxy(mockAbilityMgr);
    
    CommonEventData data;
    sptr<StaticSubscriberConnection> connection = new (std::nothrow) StaticSubscriberConnection(data, "");
    abilityManagerHelper->subscriberConnection_.emplace("test_key", connection);
    
    EXPECT_CALL(*mockAbilityMgr, DisconnectAbility(::testing::_))
        .Times(1)
        .WillOnce(::testing::Return(ERR_OK));
    
    abilityManagerHelper->RemoveConnection(connection);
    
    // Connection should be removed from subscriberConnection_
    EXPECT_EQ(abilityManagerHelper->subscriberConnection_.size(), 0);
    GTEST_LOG_(INFO) << "AbilityManagerHelper_RemoveConnection_0400 end";
}

/**
* @tc.name: AbilityManagerHelper_RemoveConnection_0500
* @tc.desc: test RemoveConnection function when DisconnectAbility returns error.
* @tc.type: FUNC
*/
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_RemoveConnection_0500, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_RemoveConnection_0500 start";
    auto abilityManagerHelper = std::make_shared<AbilityManagerHelper>();
    sptr<MockIAbilityManager> mockAbilityMgr = new MockIAbilityManager();
    MockSaProxy(mockAbilityMgr);
    
    CommonEventData data;
    sptr<StaticSubscriberConnection> connection = new (std::nothrow) StaticSubscriberConnection(data, "");
    abilityManagerHelper->subscriberConnection_.emplace("test_key", connection);
    
    EXPECT_CALL(*mockAbilityMgr, DisconnectAbility(::testing::_))
        .Times(1)
        .WillOnce(::testing::Return(ERR_INVALID_VALUE));
    
    abilityManagerHelper->RemoveConnection(connection);
    
    // Connection should still be removed from subscriberConnection_ even if DisconnectAbility fails
    EXPECT_EQ(abilityManagerHelper->subscriberConnection_.size(), 0);
    GTEST_LOG_(INFO) << "AbilityManagerHelper_RemoveConnection_0500 end";
}

/**
* @tc.name: AbilityManagerHelper_RemoveConnection_0600
* @tc.desc: test RemoveConnection function with multiple connections and removing one of them.
* @tc.type: FUNC
*/
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_RemoveConnection_0600, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_RemoveConnection_0600 start";
    auto abilityManagerHelper = std::make_shared<AbilityManagerHelper>();
    sptr<MockIAbilityManager> mockAbilityMgr = new MockIAbilityManager();
    MockSaProxy(mockAbilityMgr);
    CommonEventData data1;
    sptr<StaticSubscriberConnection> connection1 = new (std::nothrow) StaticSubscriberConnection(data1, "test_key1");
    abilityManagerHelper->subscriberConnection_.emplace("test_key1", connection1);
    
    CommonEventData data2;
    sptr<StaticSubscriberConnection> connection2 = new (std::nothrow) StaticSubscriberConnection(data2, "test_key2");
    abilityManagerHelper->subscriberConnection_.emplace("test_key2", connection2);
    
    CommonEventData data3;
    sptr<StaticSubscriberConnection> connection3 = new (std::nothrow) StaticSubscriberConnection(data3, "test_key3");
    abilityManagerHelper->subscriberConnection_.emplace("test_key3", connection3);

    EXPECT_CALL(*mockAbilityMgr, DisconnectAbility(::testing::_))
        .Times(1)
        .WillOnce(::testing::Return(ERR_OK));
    
    abilityManagerHelper->RemoveConnection(connection2);
    
    // Verify that connection2 is removed while others remain
    auto iterEnd = abilityManagerHelper->subscriberConnection_.end();
    EXPECT_EQ(abilityManagerHelper->subscriberConnection_.size(), 2);
    EXPECT_NE(abilityManagerHelper->subscriberConnection_.find("test_key1"), iterEnd);
    EXPECT_EQ(abilityManagerHelper->subscriberConnection_.find("test_key2"), iterEnd);
    EXPECT_NE(abilityManagerHelper->subscriberConnection_.find("test_key3"), iterEnd);
    GTEST_LOG_(INFO) << "AbilityManagerHelper_RemoveConnection_0600 end";
}