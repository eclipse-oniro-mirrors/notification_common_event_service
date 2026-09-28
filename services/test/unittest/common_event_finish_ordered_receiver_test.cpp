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
#include <chrono>
#include <thread>
#include "iremote_broker.h"

#define private public
#define protected public
#include "common_event_control_manager.h"
#include "common_event_manager_service.h"
#include "inner_common_event_manager.h"
#undef private
#undef protected

#include "subscriber_death_recipient.h"

using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace EventFwk {
namespace {
constexpr int32_t WAIT_QUEUE_TIME_MS = 50;
constexpr int32_t MAX_WAIT_QUEUE_RETRY = 40;  // 2s in total
}  // namespace

class CommonEventFinishOrderedReceiverTest : public testing::Test {
public:
    CommonEventFinishOrderedReceiverTest()
    {}

    ~CommonEventFinishOrderedReceiverTest()
    {}

    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void CommonEventFinishOrderedReceiverTest::SetUpTestCase(void)
{}

void CommonEventFinishOrderedReceiverTest::TearDownTestCase(void)
{}

void CommonEventFinishOrderedReceiverTest::SetUp(void)
{}

void CommonEventFinishOrderedReceiverTest::TearDown(void)
{}

class MockRemoteObject : public IRemoteObject {
public:
    MockRemoteObject() : IRemoteObject(u"mock_remote_object")
    {}

    ~MockRemoteObject()
    {}

    int32_t GetObjectRefCount() override
    {
        return 0;
    }

    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        return 0;
    }

    bool IsProxyObject() const override
    {
        return true;
    }

    bool CheckObjectLegality() const override
    {
        return true;
    }

    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return true;
    }

    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return true;
    }

    bool Marshalling(Parcel &parcel) const override
    {
        return true;
    }

    sptr<IRemoteBroker> AsInterface() override
    {
        return nullptr;
    }

    int Dump(int fd, const std::vector<std::u16string> &args) override
    {
        return 0;
    }
};

static std::shared_ptr<OrderedEventRecord> MakeOrderedRecord(const sptr<IRemoteObject> &curReceiver,
    int8_t state)
{
    std::shared_ptr<OrderedEventRecord> record = std::make_shared<OrderedEventRecord>();
    record->commonEventData = std::make_shared<CommonEventData>();
    record->curReceiver = curReceiver;
    record->state = state;
    return record;
}

/**
 * @tc.name: CommonEventFinishOrderedReceiver_0100
 * @tc.desc: test FinishMatchingOrderedReceiver function with empty ordered queue.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventFinishOrderedReceiverTest, CommonEventFinishOrderedReceiver_0100, Level2)
{
    GTEST_LOG_(INFO) << "CommonEventFinishOrderedReceiver_0100 start";
    CommonEventControlManager commonEventControlManager;
    sptr<MockRemoteObject> proxy = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(nullptr, proxy);
    EXPECT_EQ(nullptr, commonEventControlManager.GetMatchingOrderedReceiver(proxy));
    commonEventControlManager.FinishMatchingOrderedReceiver(proxy);
    EXPECT_TRUE(commonEventControlManager.orderedEventQueue_.empty());
    GTEST_LOG_(INFO) << "CommonEventFinishOrderedReceiver_0100 end";
}

/**
 * @tc.name: CommonEventFinishOrderedReceiver_0200
 * @tc.desc: test FinishMatchingOrderedReceiver function with nullptr front record.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventFinishOrderedReceiverTest, CommonEventFinishOrderedReceiver_0200, Level2)
{
    GTEST_LOG_(INFO) << "CommonEventFinishOrderedReceiver_0200 start";
    CommonEventControlManager commonEventControlManager;
    sptr<MockRemoteObject> proxy = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(nullptr, proxy);
    commonEventControlManager.orderedEventQueue_.emplace_back(nullptr);
    EXPECT_EQ(nullptr, commonEventControlManager.GetMatchingOrderedReceiver(proxy));
    commonEventControlManager.FinishMatchingOrderedReceiver(proxy);
    EXPECT_EQ(1, static_cast<int>(commonEventControlManager.orderedEventQueue_.size()));
    GTEST_LOG_(INFO) << "CommonEventFinishOrderedReceiver_0200 end";
}

/**
 * @tc.name: CommonEventFinishOrderedReceiver_0300
 * @tc.desc: test FinishMatchingOrderedReceiver function when front record does not match proxy.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventFinishOrderedReceiverTest, CommonEventFinishOrderedReceiver_0300, Level2)
{
    GTEST_LOG_(INFO) << "CommonEventFinishOrderedReceiver_0300 start";
    CommonEventControlManager commonEventControlManager;
    sptr<MockRemoteObject> proxy = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(nullptr, proxy);
    sptr<IRemoteObject> otherProxy = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(nullptr, otherProxy);
    // front record does not match, only the front record is checked
    std::shared_ptr<OrderedEventRecord> frontRecord = MakeOrderedRecord(otherProxy,
        OrderedEventRecord::RECEIVING);
    std::shared_ptr<OrderedEventRecord> secondRecord = MakeOrderedRecord(proxy,
        OrderedEventRecord::RECEIVING);
    commonEventControlManager.orderedEventQueue_.emplace_back(frontRecord);
    commonEventControlManager.orderedEventQueue_.emplace_back(secondRecord);
    EXPECT_EQ(nullptr, commonEventControlManager.GetMatchingOrderedReceiver(proxy));
    commonEventControlManager.FinishMatchingOrderedReceiver(proxy);
    EXPECT_EQ(otherProxy, frontRecord->curReceiver);
    EXPECT_EQ(OrderedEventRecord::RECEIVING, frontRecord->state.load());
    EXPECT_EQ(2, static_cast<int>(commonEventControlManager.orderedEventQueue_.size()));
    GTEST_LOG_(INFO) << "CommonEventFinishOrderedReceiver_0300 end";
}

/**
 * @tc.name: CommonEventFinishOrderedReceiver_0400
 * @tc.desc: test FinishMatchingOrderedReceiver function when receiver is matched and state is not RECEIVED.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventFinishOrderedReceiverTest, CommonEventFinishOrderedReceiver_0400, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventFinishOrderedReceiver_0400 start";
    CommonEventControlManager commonEventControlManager;
    sptr<MockRemoteObject> proxy = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(nullptr, proxy);
    std::shared_ptr<OrderedEventRecord> record = MakeOrderedRecord(proxy, OrderedEventRecord::RECEIVING);
    record->commonEventData->SetCode(100);
    record->commonEventData->SetData("finish receiver");
    commonEventControlManager.orderedEventQueue_.emplace_back(record);
    EXPECT_EQ(record, commonEventControlManager.GetMatchingOrderedReceiver(proxy));
    commonEventControlManager.FinishMatchingOrderedReceiver(proxy);
    // receiver is finished, but doNext is false, the record is still in the queue
    EXPECT_EQ(nullptr, record->curReceiver);
    EXPECT_EQ(OrderedEventRecord::IDLE, record->state.load());
    EXPECT_EQ(100, record->commonEventData->GetCode());
    EXPECT_EQ("finish receiver", record->commonEventData->GetData());
    EXPECT_EQ(1, static_cast<int>(commonEventControlManager.orderedEventQueue_.size()));
    GTEST_LOG_(INFO) << "CommonEventFinishOrderedReceiver_0400 end";
}

/**
 * @tc.name: CommonEventFinishOrderedReceiver_0500
 * @tc.desc: test FinishMatchingOrderedReceiver function when receiver is matched and state is RECEIVED.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventFinishOrderedReceiverTest, CommonEventFinishOrderedReceiver_0500, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventFinishOrderedReceiver_0500 start";
    std::shared_ptr<CommonEventControlManager> commonEventControlManager =
        std::make_shared<CommonEventControlManager>();
    ASSERT_NE(nullptr, commonEventControlManager);
    // init ordered queue for the async ProcessNextOrderedEvent task
    ASSERT_TRUE(commonEventControlManager->GetOrderedEventHandler());
    sptr<MockRemoteObject> proxy = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(nullptr, proxy);
    std::shared_ptr<OrderedEventRecord> record = MakeOrderedRecord(proxy, OrderedEventRecord::RECEIVED);
    commonEventControlManager->orderedEventQueue_.emplace_back(record);
    EXPECT_EQ(record, commonEventControlManager->GetMatchingOrderedReceiver(proxy));
    commonEventControlManager->FinishMatchingOrderedReceiver(proxy);
    EXPECT_EQ(nullptr, record->curReceiver);
    EXPECT_EQ(OrderedEventRecord::IDLE, record->state.load());
    // doNext is true, the record should be removed by async ProcessNextOrderedEvent
    bool queueEmpty = false;
    for (int i = 0; i < MAX_WAIT_QUEUE_RETRY; i++) {
        {
            std::lock_guard<ffrt::mutex> lock(commonEventControlManager->orderedMutex_);
            if (commonEventControlManager->orderedEventQueue_.empty()) {
                queueEmpty = true;
                break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_QUEUE_TIME_MS));
    }
    EXPECT_TRUE(queueEmpty);
    GTEST_LOG_(INFO) << "CommonEventFinishOrderedReceiver_0500 end";
}

/**
 * @tc.name: CommonEventFinishOrderedReceiver_0600
 * @tc.desc: test GetControlManager function when innerCommonEventManager is not initialized.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventFinishOrderedReceiverTest, CommonEventFinishOrderedReceiver_0600, Level2)
{
    GTEST_LOG_(INFO) << "CommonEventFinishOrderedReceiver_0600 start";
    CommonEventManagerService commonEventManagerService;
    EXPECT_EQ(nullptr, commonEventManagerService.GetControlManager());
    GTEST_LOG_(INFO) << "CommonEventFinishOrderedReceiver_0600 end";
}

/**
 * @tc.name: CommonEventFinishOrderedReceiver_0700
 * @tc.desc: test GetControlManager function after Init and InnerCommonEventManager GetControlManager.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventFinishOrderedReceiverTest, CommonEventFinishOrderedReceiver_0700, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventFinishOrderedReceiver_0700 start";
    CommonEventManagerService commonEventManagerService;
    EXPECT_EQ(ERR_OK, commonEventManagerService.Init());
    std::shared_ptr<CommonEventControlManager> controlManager =
        commonEventManagerService.GetControlManager();
    EXPECT_NE(nullptr, controlManager);
    EXPECT_NE(nullptr, commonEventManagerService.innerCommonEventManager_);
    EXPECT_EQ(controlManager, commonEventManagerService.innerCommonEventManager_->GetControlManager());
    InnerCommonEventManager innerCommonEventManager;
    EXPECT_NE(nullptr, innerCommonEventManager.GetControlManager());
    GTEST_LOG_(INFO) << "CommonEventFinishOrderedReceiver_0700 end";
}

/**
 * @tc.name: CommonEventFinishOrderedReceiver_0800
 * @tc.desc: test UnsubscribeCommonEvent function finishes the matched ordered receiver.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventFinishOrderedReceiverTest, CommonEventFinishOrderedReceiver_0800, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventFinishOrderedReceiver_0800 start";
    InnerCommonEventManager innerCommonEventManager;
    ASSERT_NE(nullptr, innerCommonEventManager.controlPtr_);
    sptr<MockRemoteObject> proxy = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(nullptr, proxy);
    std::shared_ptr<OrderedEventRecord> record = MakeOrderedRecord(proxy, OrderedEventRecord::RECEIVING);
    innerCommonEventManager.controlPtr_->orderedEventQueue_.emplace_back(record);
    EXPECT_TRUE(innerCommonEventManager.UnsubscribeCommonEvent(proxy));
    EXPECT_EQ(nullptr, record->curReceiver);
    EXPECT_EQ(OrderedEventRecord::IDLE, record->state.load());
    GTEST_LOG_(INFO) << "CommonEventFinishOrderedReceiver_0800 end";
}

/**
 * @tc.name: CommonEventFinishOrderedReceiver_0900
 * @tc.desc: test OnRemoteDied function when control manager is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventFinishOrderedReceiverTest, CommonEventFinishOrderedReceiver_0900, Level2)
{
    GTEST_LOG_(INFO) << "CommonEventFinishOrderedReceiver_0900 start";
    SubscriberDeathRecipient subscriberDeathRecipient;
    sptr<MockRemoteObject> proxy = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(nullptr, proxy);
    const wptr<MockRemoteObject> remote = proxy;
    // make sure the singleton is not initialized
    CommonEventManagerService::GetInstance()->innerCommonEventManager_ = nullptr;
    EXPECT_EQ(nullptr, CommonEventManagerService::GetInstance()->GetControlManager());
    subscriberDeathRecipient.OnRemoteDied(remote);
    GTEST_LOG_(INFO) << "CommonEventFinishOrderedReceiver_0900 end";
}

/**
 * @tc.name: CommonEventFinishOrderedReceiver_1000
 * @tc.desc: test OnRemoteDied function finishes the matched ordered receiver.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventFinishOrderedReceiverTest, CommonEventFinishOrderedReceiver_1000, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventFinishOrderedReceiver_1000 start";
    SubscriberDeathRecipient subscriberDeathRecipient;
    sptr<MockRemoteObject> proxy = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(nullptr, proxy);
    const wptr<MockRemoteObject> remote = proxy;
    ASSERT_EQ(ERR_OK, CommonEventManagerService::GetInstance()->Init());
    std::shared_ptr<CommonEventControlManager> controlManager =
        CommonEventManagerService::GetInstance()->GetControlManager();
    ASSERT_NE(nullptr, controlManager);
    std::shared_ptr<OrderedEventRecord> record = MakeOrderedRecord(proxy, OrderedEventRecord::RECEIVING);
    controlManager->orderedEventQueue_.emplace_back(record);
    subscriberDeathRecipient.OnRemoteDied(remote);
    EXPECT_EQ(nullptr, record->curReceiver);
    EXPECT_EQ(OrderedEventRecord::IDLE, record->state.load());
    GTEST_LOG_(INFO) << "CommonEventFinishOrderedReceiver_1000 end";
}

/**
 * @tc.name: CommonEventFinishOrderedReceiver_1100
 * @tc.desc: test OnRemoteDied function when promote remote object failed.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventFinishOrderedReceiverTest, CommonEventFinishOrderedReceiver_1100, Level2)
{
    GTEST_LOG_(INFO) << "CommonEventFinishOrderedReceiver_1100 start";
    SubscriberDeathRecipient subscriberDeathRecipient;
    sptr<MockRemoteObject> proxy = new (std::nothrow) MockRemoteObject();
    ASSERT_NE(nullptr, proxy);
    wptr<MockRemoteObject> remote = proxy;
    // drop the strong reference to make promote fail
    proxy = nullptr;
    subscriberDeathRecipient.OnRemoteDied(remote);
    GTEST_LOG_(INFO) << "CommonEventFinishOrderedReceiver_1100 end";
}
}  // namespace EventFwk
}  // namespace OHOS
