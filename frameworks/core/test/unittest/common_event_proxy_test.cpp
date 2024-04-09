/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "common_event.h"
#include "common_event_death_recipient.h"
#include "common_event_stub.h"
#include "common_event_proxy.h"
#include "common_event_data.h"
#include "common_event_subscriber.h"
#include "event_receive_proxy.h"
#include "common_event_publish_info.h"
#include "matching_skills.h"

#include "mock_message_parcel.h"

#include "event_log_wrapper.h"
#include "string_ex.h"
#include "ces_inner_error_code.h"
#include "iremote_broker.h"

#include <gtest/gtest.h>

using namespace testing::ext;
using namespace OHOS::EventFwk;

namespace {
    const std::string EVENT = "com.ces.test.event";
    const std::string PERMISSION = "com.ces.test.permission";
}

class CommonEventProxyTest : public CommonEventSubscriber, public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    virtual void OnReceiveEvent(const CommonEventData &data)
    {}
};

void CommonEventProxyTest::SetUpTestCase()
{}

void CommonEventProxyTest::TearDownTestCase()
{}

void CommonEventProxyTest::SetUp()
{}

void CommonEventProxyTest::TearDown()
{}

namespace OHOS {
class MockIRemoteObject : public IRemoteObject {
public:
    MockIRemoteObject() : IRemoteObject(u"mock_i_remote_object") {}

    ~MockIRemoteObject() {}

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

    std::u16string GetObjectDescriptor() const
    {
        std::u16string descriptor = std::u16string();
        return descriptor;
    }
};
}
/*
 * tc.number: PublishCommonEvent_001
 * tc.name: test OnRemoteRequest
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke CommonEventProxy interface verify whether it is normal
 */
HWTEST_F(CommonEventProxyTest, PublishCommonEvent_001, TestSize.Level1)
{
    OHOS::MessageParcel dataParcel;
    OHOS::MessageParcel reply;
    OHOS::sptr<OHOS::IRemoteObject> object = new OHOS::MockIRemoteObject();
    CommonEventProxy commonEventProxy(object);

    CommonEventData event;
    CommonEventData data;
    CommonEventPublishInfo publishInfo;
    dataParcel.WriteInterfaceToken(CommonEventProxy::GetDescriptor());
    dataParcel.WriteParcelable(&event);
    dataParcel.WriteParcelable(&publishInfo);

    const int32_t useId = 0;

    int result = commonEventProxy.PublishCommonEvent(data, publishInfo, nullptr, useId);
    EXPECT_EQ(OHOS::ERR_OK, result);
}

/*
 * tc.number: PublishCommonEvent_002
 * tc.name: test OnRemoteRequest
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke CommonEventProxy interface verify whether it is normal
 */
HWTEST_F(CommonEventProxyTest, PublishCommonEvent_002, TestSize.Level1)
{
    OHOS::MessageParcel dataParcel;
    OHOS::MessageParcel reply;
    OHOS::sptr<OHOS::IRemoteObject> object = new OHOS::MockIRemoteObject();
    CommonEventProxy commonEventProxy(object);
    OHOS::sptr<OHOS::IRemoteObject> commonEventListener = new OHOS::MockIRemoteObject();

    CommonEventData event;
    CommonEventData data;
    CommonEventPublishInfo publishInfo;

    MessageParcel::SetFlag(false);
    const int32_t useId = 1;
    int result = commonEventProxy.PublishCommonEvent(data, publishInfo, commonEventListener, useId);
    EXPECT_EQ(OHOS::ERR_OK, result);
}

/*
 * tc.number: PublishCommonEvent_003
 * tc.name: test OnRemoteRequest
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke CommonEventProxy interface verify whether it is normal
 */
HWTEST_F(CommonEventProxyTest, PublishCommonEvent_003, TestSize.Level1)
{
    OHOS::MessageParcel dataParcel;
    OHOS::MessageParcel reply;
    OHOS::sptr<OHOS::IRemoteObject> object = new OHOS::MockIRemoteObject();
    CommonEventProxy commonEventProxy(object);
    OHOS::sptr<OHOS::IRemoteObject> commonEventListener = new OHOS::MockIRemoteObject();

    CommonEventData event;
    CommonEventData data;
    CommonEventPublishInfo publishInfo;

    dataParcel.WriteInterfaceToken(CommonEventProxy::GetDescriptor());
    dataParcel.WriteParcelable(&event);

    MessageParcel::SetFlag(false);
    const int32_t useId = 1;
    bool result = commonEventProxy.PublishCommonEvent(data, publishInfo, commonEventListener, useId);
    EXPECT_EQ(false, result);
}

/*
 * tc.number: PublishCommonEvent_004
 * tc.name: test OnRemoteRequest
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke CommonEventProxy interface verify whether it is normal
 */
HWTEST_F(CommonEventProxyTest, PublishCommonEvent_004, TestSize.Level1)
{
    OHOS::MessageParcel dataParcel;
    OHOS::MessageParcel reply;
    OHOS::sptr<OHOS::IRemoteObject> object = new OHOS::MockIRemoteObject();
    CommonEventProxy commonEventProxy(object);
    OHOS::sptr<OHOS::IRemoteObject> commonEventListener = new OHOS::MockIRemoteObject();

    CommonEventData event;
    CommonEventData data;
    CommonEventPublishInfo publishInfo;

    dataParcel.WriteInterfaceToken(CommonEventProxy::GetDescriptor());
    dataParcel.WriteParcelable(&publishInfo);

    MessageParcel::SetFlag(false);
    const int32_t useId = 1;
    bool result = commonEventProxy.PublishCommonEvent(data, publishInfo, commonEventListener, useId);
    EXPECT_EQ(false, result);
}

/*
 * tc.number: PublishCommonEvent_005
 * tc.name: test OnRemoteRequest
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke CommonEventProxy interface verify whether it is normal
 */
HWTEST_F(CommonEventProxyTest, PublishCommonEvent_005, TestSize.Level1)
{
    OHOS::MessageParcel dataParcel;
    OHOS::MessageParcel reply;
    OHOS::sptr<OHOS::IRemoteObject> object = new OHOS::MockIRemoteObject();
    CommonEventProxy commonEventProxy(object);
    OHOS::sptr<OHOS::IRemoteObject> commonEventListener = new OHOS::MockIRemoteObject();

    CommonEventData event;
    CommonEventData data;
    CommonEventPublishInfo publishInfo;

    dataParcel.WriteParcelable(&event);
    dataParcel.WriteParcelable(&publishInfo);

    MessageParcel::SetFlag(false);
    const int32_t useId = 1;
    bool result = commonEventProxy.PublishCommonEvent(data, publishInfo, commonEventListener, useId);
    EXPECT_EQ(false, result);
}

/*
 * tc.number: PublishCommonEvent_006
 * tc.name: test OnRemoteRequest
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke CommonEventProxy interface verify whether it is normal
 */
HWTEST_F(CommonEventProxyTest, PublishCommonEvent_006, TestSize.Level1)
{
    OHOS::MessageParcel dataParcel;
    OHOS::MessageParcel reply;
    OHOS::sptr<OHOS::IRemoteObject> object = new OHOS::MockIRemoteObject();
    CommonEventProxy commonEventProxy(object);
    OHOS::sptr<OHOS::IRemoteObject> commonEventListener = new OHOS::MockIRemoteObject();

    uint8_t dumpType = 0;
    const std::string event = "this is an event";
    int32_t userId = 1;
    std::vector<std::string> state;

    CommonEventData data;
    CommonEventPublishInfo publishInfo;

    MessageParcel::SetFlag(false);
    bool result = commonEventProxy.DumpState(dumpType, event, userId, state);
    EXPECT_EQ(true, result);
}

/*
 * tc.number: PublishCommonEvent_007
 * tc.name: test OnRemoteRequest
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke CommonEventProxy interface verify whether it is normal
 */
HWTEST_F(CommonEventProxyTest, PublishCommonEvent_007, TestSize.Level1)
{
    OHOS::MessageParcel dataParcel;
    OHOS::MessageParcel reply;
    OHOS::sptr<OHOS::IRemoteObject> object = new OHOS::MockIRemoteObject();
    CommonEventProxy commonEventProxy(object);
    OHOS::sptr<OHOS::IRemoteObject> commonEventListener = new OHOS::MockIRemoteObject();

    uint8_t dumpType = 0;
    const std::string event = "this is an event";
    int32_t userId = 1;
    std::vector<std::string> state;

    CommonEventData data;
    CommonEventPublishInfo publishInfo;

    dataParcel.WriteInterfaceToken(CommonEventProxy::GetDescriptor());

    MessageParcel::SetFlag(false);
    bool result = commonEventProxy.DumpState(dumpType, event, userId, state);
    EXPECT_EQ(true, result);
}

/*
 * tc.number: PublishCommonEvent_008
 * tc.name: test OnRemoteRequest
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke CommonEventProxy interface verify whether it is normal
 */
HWTEST_F(CommonEventProxyTest, PublishCommonEvent_008, TestSize.Level1)
{
    OHOS::MessageParcel dataParcel;
    OHOS::MessageParcel reply;
    OHOS::sptr<OHOS::IRemoteObject> object = new OHOS::MockIRemoteObject();
    CommonEventProxy commonEventProxy(object);
    OHOS::sptr<OHOS::IRemoteObject> commonEventListener = new OHOS::MockIRemoteObject();

    uint8_t dumpType = 0;
    const std::string event = "this is an event";
    int32_t userId = 1;
    std::vector<std::string> state;

    CommonEventData data;
    CommonEventPublishInfo publishInfo;

    dataParcel.WriteParcelable(&publishInfo);

    MessageParcel::SetFlag(false);
    bool result = commonEventProxy.DumpState(dumpType, event, userId, state);
    EXPECT_EQ(true, result);
}

/*
 * tc.number: SetStaticSubscriberState_001
 * tc.name: test SetStaticSubscriberState
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke CommonEventProxy interface verify whether it is normal
 */
HWTEST_F(CommonEventProxyTest, SetStaticSubscriberState_001, TestSize.Level1)
{
    OHOS::MessageParcel dataParcel;
    OHOS::MessageParcel reply;
    OHOS::sptr<OHOS::IRemoteObject> object = new OHOS::MockIRemoteObject();
    CommonEventProxy commonEventProxy(object);
    int32_t result = commonEventProxy.SetStaticSubscriberState(true);
    EXPECT_EQ(OHOS::ERR_OK, result);
}

/*
 * tc.number: SetStaticSubscriberStateWithTwoParameters_0100
 * tc.name: test SetStaticSubscriberState
 * tc.type: FUNC
 * tc.desc: Successful verification by calling SetStaticSubscriberState API.
 */
HWTEST_F(CommonEventProxyTest, SetStaticSubscriberStateWithTwoParameters_0100, TestSize.Level1)
{
    auto object = new OHOS::MockIRemoteObject();
    CommonEventProxy commonEventProxy(object);
    std::vector<std::string> events;
    events.push_back("StaticCommonEventA");
    int32_t result = commonEventProxy.SetStaticSubscriberState(events, true);
    EXPECT_EQ(result, OHOS::ERR_OK);
}
