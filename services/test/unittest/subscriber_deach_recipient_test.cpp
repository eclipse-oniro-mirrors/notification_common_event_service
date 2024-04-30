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
#include "iremote_broker.h"
#include "subscriber_death_recipient.h"

namespace OHOS {
namespace EventFwk {
using namespace testing::ext;

class SubscriberDeathRecipientTest : public testing::Test {
public:
    SubscriberDeathRecipientTest()
    {}
    ~SubscriberDeathRecipientTest()
    {}

    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void SubscriberDeathRecipientTest::SetUpTestCase(void)
{}

void SubscriberDeathRecipientTest::TearDownTestCase(void)
{}

void SubscriberDeathRecipientTest::SetUp(void)
{}

void SubscriberDeathRecipientTest::TearDown(void)
{}

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

/**
 * @tc.name: SubscriberDeathRecipient_0100
 * @tc.desc: test OnRemoteDied function and remote is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(SubscriberDeathRecipientTest, SubscriberDeathRecipient_0100, Level1)
{
    GTEST_LOG_(INFO) << "SubscriberDeathRecipient_0100 start";
    std::shared_ptr<SubscriberDeathRecipient> subscriberDeathRecipient = std::make_shared<SubscriberDeathRecipient>();
    ASSERT_NE(nullptr, subscriberDeathRecipient);
    const wptr<MockIRemoteObject> remote = nullptr;
    subscriberDeathRecipient->OnRemoteDied(remote);
    GTEST_LOG_(INFO) << "SubscriberDeathRecipient_0100 end";
}

/**
 * @tc.name: SubscriberDeathRecipient_0200
 * @tc.desc: test OnRemoteDied function and remote is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(SubscriberDeathRecipientTest, SubscriberDeathRecipient_0200, Level1)
{
    GTEST_LOG_(INFO) << "SubscriberDeathRecipient_0200 start";
    SubscriberDeathRecipient subscriberDeathRecipient;
    sptr<MockIRemoteObject> sptrDeath = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, sptrDeath);
    const wptr<MockIRemoteObject> remote = sptrDeath;
    subscriberDeathRecipient.OnRemoteDied(remote);
    GTEST_LOG_(INFO) << "SubscriberDeathRecipient_0200 end";
}
}  // namespace EventFwk
}  // namespace OHOS