/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#define private public
#define protected public
#include "bundle_manager_helper.h"
#undef private
#undef protected

#include "common_event.h"
#include "common_event_support.h"
#include "inner_common_event_manager.h"
#include "mock_bundle_manager.h"

#include <gtest/gtest.h>

using namespace testing::ext;
using namespace OHOS::EventFwk;

namespace {
const int PID = 0;
const int UID = 1000;  // system app
const int PUBLISH_SLEEP = 5;
}  // namespace

static OHOS::sptr<OHOS::IRemoteObject> bundleObject = nullptr;

class CommonEventPublishSystemEventTest : public testing::Test {
public:
    CommonEventPublishSystemEventTest()
    {}
    ~CommonEventPublishSystemEventTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

public:
    InnerCommonEventManager innerCommonEventManager;
};

void CommonEventPublishSystemEventTest::SetUpTestCase(void)
{
    bundleObject = new OHOS::AppExecFwk::MockBundleMgrService();
    OHOS::DelayedSingleton<BundleManagerHelper>::GetInstance()->sptrBundleMgr_ =
        OHOS::iface_cast<OHOS::AppExecFwk::IBundleMgr>(bundleObject);
}

void CommonEventPublishSystemEventTest::TearDownTestCase(void)
{}

void CommonEventPublishSystemEventTest::SetUp(void)
{}

void CommonEventPublishSystemEventTest::TearDown(void)
{}

class SubscriberTest : public CommonEventSubscriber {
public:
    explicit SubscriberTest(const CommonEventSubscribeInfo &sp) : CommonEventSubscriber(sp)
    {}

    ~SubscriberTest()
    {}

    virtual void OnReceiveEvent(const CommonEventData &data)
    {
        GTEST_LOG_(INFO) << "CESPublishOrderedEventSystmTest::Subscriber OnReceiveEvent ";
        std::string action = data.GetWant().GetAction();
        std::string event = GetSubscribeInfo().GetMatchingSkills().GetEvent(0);
        EXPECT_EQ(action, event);
    }
};

/*
 * @tc.number: CommonEventPublishSystemEventTest_0100
 * @tc.name: test PublishCommonEvent
 * @tc.desc: Verify Publish System CommonEvent success
 */
HWTEST_F(CommonEventPublishSystemEventTest, CommonEventPublishSystemEventTest_0100, Function | MediumTest | Level1)
{
    /* Publish */

    // make a want
    Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_LOCKED_BOOT_COMPLETED);

    // make common event data
    CommonEventData data;
    data.SetWant(want);

    // make publish info
    CommonEventPublishInfo publishInfo;
    publishInfo.SetOrdered(false);

    struct tm curTime;
    // publish system event
    bool publishResult = innerCommonEventManager.PublishCommonEvent(
        data, publishInfo, nullptr, curTime, PID, UID, UNDEFINED_USER, "bundlename");
    EXPECT_EQ(true, publishResult);
    sleep(PUBLISH_SLEEP);
}

/*
 * @tc.number: CommonEventPublishSystemEventTest_0200
 * @tc.name: test PublishCommonEvent
 * @tc.desc: Verify Publish System CommonEvent fail because is not systemapp
 */
HWTEST_F(CommonEventPublishSystemEventTest, CommonEventPublishSystemEventTest_0200, Function | MediumTest | Level1)
{
    /* Publish */

    // make a want
    Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_LOCKED_BOOT_COMPLETED);

    // make common event data
    CommonEventData data;
    data.SetWant(want);

    // make publish info
    CommonEventPublishInfo publishInfo;
    publishInfo.SetOrdered(false);

    struct tm curTime;
    // publish system event
    bool publishResult = innerCommonEventManager.PublishCommonEvent(
        data, publishInfo, nullptr, curTime, PID, 0, UNDEFINED_USER, "bundlename");
    EXPECT_EQ(false, publishResult);
    sleep(PUBLISH_SLEEP);
}

/*
 * @tc.number: CommonEventPublishSystemEventTest_0300
 * @tc.name: test PublishCommonEvent
 * @tc.desc: Verify Publish mapped System CommonEvent
 */
HWTEST_F(CommonEventPublishSystemEventTest, CommonEventPublishSystemEventTest_0300, Function | MediumTest | Level1)
{
    /* Subscribe */

    // make subcriber info
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_TEST_ACTION1);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    // make subscriber
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);

    // make common event listner
    OHOS::sptr<CommonEventListener> commonEventListener = new CommonEventListener(subscriber);
    OHOS::sptr<OHOS::IRemoteObject> commonEventListenerPtr(commonEventListener);

    // SubscribeCommonEvent
    struct tm curTime{0};
    InnerCommonEventManager innerCommonEventManager;
    bool subscribeResult = innerCommonEventManager.SubscribeCommonEvent(
        subscribeInfo, commonEventListenerPtr, curTime, PID, 0, "bundlename");
    EXPECT_EQ(true, subscribeResult);

    /* Publish */

    // make a want
    Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_TEST_ACTION2);

    // make common event data
    CommonEventData data;
    data.SetWant(want);

    // make publish info
    CommonEventPublishInfo publishInfo;
    publishInfo.SetOrdered(false);

    // publish system event
    bool publishResult = innerCommonEventManager.PublishCommonEvent(
        data, publishInfo, nullptr, curTime, PID, 0, UNDEFINED_USER, "bundlename");
    sleep(1);
    EXPECT_EQ(true, publishResult);

    innerCommonEventManager.UnsubscribeCommonEvent(commonEventListenerPtr);
}

/*
 * @tc.number: CommonEventPublishSystemEventTest_0400
 * @tc.name: test PublishCommonEvent
 * @tc.desc: Verify Publish mapped System CommonEvent
 */
HWTEST_F(CommonEventPublishSystemEventTest, CommonEventPublishSystemEventTest_0400, Function | MediumTest | Level1)
{
    /* Subscribe */

    // make subcriber info
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_TEST_ACTION2);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    // make subscriber
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);

    // make common event listner
    OHOS::sptr<CommonEventListener> commonEventListener = new CommonEventListener(subscriber);
    OHOS::sptr<OHOS::IRemoteObject> commonEventListenerPtr(commonEventListener);

    // SubscribeCommonEvent
    struct tm curTime{0};
    InnerCommonEventManager innerCommonEventManager;
    bool subscribeResult = innerCommonEventManager.SubscribeCommonEvent(
        subscribeInfo, commonEventListenerPtr, curTime, PID, 0, "bundlename");
    EXPECT_EQ(true, subscribeResult);

    /* Publish */

    // make a want
    Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_TEST_ACTION1);

    // make common event data
    CommonEventData data;
    data.SetWant(want);

    // make publish info
    CommonEventPublishInfo publishInfo;
    publishInfo.SetOrdered(false);

    // publish system event
    bool publishResult = innerCommonEventManager.PublishCommonEvent(
        data, publishInfo, nullptr, curTime, PID, 0, UNDEFINED_USER, "bundlename");
    sleep(1);
    EXPECT_EQ(true, publishResult);

    innerCommonEventManager.UnsubscribeCommonEvent(commonEventListenerPtr);
}
