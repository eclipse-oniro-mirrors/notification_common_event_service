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

#include <memory>
#define private public
#include "common_event.h"
#include "common_event_data.h"
#include "common_event_listener.h"
#include "common_event_subscriber.h"
#include "common_event_subscribe_info.h"
#include "common_event_publish_info.h"
#include "matching_skills.h"
#undef private
#include "ces_inner_error_code.h"

#include <gtest/gtest.h>

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EventFwk;
using namespace OHOS::Notification;

namespace {
const std::string EVENT_NAME = "com.ces.test.api.misuse";
}

class MisuseSubscriber : public CommonEventSubscriber {
public:
    explicit MisuseSubscriber(const CommonEventSubscribeInfo &subscribeInfo) : CommonEventSubscriber(subscribeInfo)
    {}

    ~MisuseSubscriber()
    {}

    virtual void OnReceiveEvent(const CommonEventData &data)
    {}
};

class CommonEventApiMisuseTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CommonEventApiMisuseTest::SetUpTestCase()
{}

void CommonEventApiMisuseTest::TearDownTestCase()
{}

void CommonEventApiMisuseTest::SetUp()
{}

void CommonEventApiMisuseTest::TearDown()
{}

/*
 * @tc.name: SubscribeCommonEvent_0001
 * @tc.desc: test first subscribe success, which proves the mock proxy is reachable.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventApiMisuseTest, SubscribeCommonEvent_0001, TestSize.Level1)
{
    CommonEvent commonEvent;
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT_NAME);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<MisuseSubscriber> subscriber = std::make_shared<MisuseSubscriber>(subscribeInfo);

    int32_t ret = commonEvent.SubscribeCommonEvent(subscriber);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(1, static_cast<int32_t>(commonEvent.eventListeners_.size()));
}

/*
 * @tc.name: SubscribeCommonEvent_0002
 * @tc.desc: test duplicate subscribe is ignored and returns ERR_OK without new listener.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventApiMisuseTest, SubscribeCommonEvent_0002, TestSize.Level1)
{
    CommonEvent commonEvent;
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT_NAME);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<MisuseSubscriber> subscriber = std::make_shared<MisuseSubscriber>(subscribeInfo);

    int32_t ret = commonEvent.SubscribeCommonEvent(subscriber);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(1, static_cast<int32_t>(commonEvent.eventListeners_.size()));

    // Subscribe the same subscriber again: ALREADY_SUBSCRIBED, the duplicate subscribe is ignored.
    ret = commonEvent.SubscribeCommonEvent(subscriber);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(1, static_cast<int32_t>(commonEvent.eventListeners_.size()));
}

/*
 * @tc.name: Subscribe_0001
 * @tc.desc: test duplicate Subscribe takes the update path and returns ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventApiMisuseTest, Subscribe_0001, TestSize.Level1)
{
    CommonEvent commonEvent;
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT_NAME);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<MisuseSubscriber> subscriber = std::make_shared<MisuseSubscriber>(subscribeInfo);

    int32_t ret = commonEvent.Subscribe(subscriber);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(1, static_cast<int32_t>(commonEvent.eventListeners_.size()));

    // Subscribe the same subscriber again: ALREADY_SUBSCRIBED with isUpdate, subscribe is updated.
    ret = commonEvent.Subscribe(subscriber);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(1, static_cast<int32_t>(commonEvent.eventListeners_.size()));
}

/*
 * @tc.name: UnSubscribeCommonEvent_0001
 * @tc.desc: test unsubscribe a not subscribed subscriber is ignored and returns ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventApiMisuseTest, UnSubscribeCommonEvent_0001, TestSize.Level1)
{
    CommonEvent commonEvent;
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT_NAME);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<MisuseSubscriber> subscriber = std::make_shared<MisuseSubscriber>(subscribeInfo);

    // The subscriber was never subscribed: the unsubscribe is ignored and no error is returned.
    int32_t ret = commonEvent.UnSubscribeCommonEvent(subscriber);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_TRUE(commonEvent.eventListeners_.empty());
}

/*
 * @tc.name: UnSubscribeCommonEventSync_0001
 * @tc.desc: test sync unsubscribe a not subscribed subscriber is ignored and returns ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventApiMisuseTest, UnSubscribeCommonEventSync_0001, TestSize.Level1)
{
    CommonEvent commonEvent;
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT_NAME);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<MisuseSubscriber> subscriber = std::make_shared<MisuseSubscriber>(subscribeInfo);

    // The subscriber was never subscribed: the sync unsubscribe is ignored and no error is returned.
    int32_t ret = commonEvent.UnSubscribeCommonEventSync(subscriber);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_TRUE(commonEvent.eventListeners_.empty());
}

/*
 * @tc.name: CommonEventApiMisuse_0001
 * @tc.desc: test subscribe/unsubscribe with nullptr subscriber returns param invalid.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventApiMisuseTest, CommonEventApiMisuse_0001, TestSize.Level1)
{
    CommonEvent commonEvent;
    std::shared_ptr<CommonEventSubscriber> nullSubscriber = nullptr;

    EXPECT_EQ(ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, commonEvent.SubscribeCommonEvent(nullSubscriber));
    EXPECT_EQ(ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, commonEvent.Subscribe(nullSubscriber));
    EXPECT_EQ(ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, commonEvent.UnSubscribeCommonEvent(nullSubscriber));
    EXPECT_EQ(ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, commonEvent.UnSubscribeCommonEventSync(nullSubscriber));
    EXPECT_TRUE(commonEvent.eventListeners_.empty());
}
