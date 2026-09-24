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
#include "want.h"
#define private public  // NOLINT
#include "static_subscriber_manager.h"
#undef private

#include "user_app_test_mock_apis.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EventFwk;

class StaticSubscriberManagerUserAppUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: ATC_CheckMatched_UserAppTypeInstalledInUserSpace
 * @tc.desc: test USER_APP subscriber type matched when static subscriber installed in normal user space.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberManagerUserAppUnitTest, ATC_CheckMatched_UserAppTypeInstalledInUserSpace,
    Level0)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    StaticSubscriberManager::StaticSubscriberInfo subscriber;
    subscriber.bundleName = "testBundle";
    subscriber.userId = 100;
    CommonEventPublishInfo publishInfo;
    publishInfo.SetSubscriberType(static_cast<int32_t>(SubscriberType::USER_APP_SUBSCRIBER_TYPE));
    publishInfo.SetValidationRule(ValidationRule::AND);
    SetSystemMock(true);

    EXPECT_TRUE(manager->CheckSubscriberWhetherMatched(subscriber, publishInfo));
}

/**
 * @tc.name: ATC_CheckNotMatched_UserAppTypeInstalledInSystemUserSpace
 * @tc.desc: test USER_APP subscriber type not matched when static subscriber installed in system user space.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberManagerUserAppUnitTest,
    ATC_CheckNotMatched_UserAppTypeInstalledInSystemUserSpace, Level0)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    CommonEventPublishInfo publishInfo;
    publishInfo.SetSubscriberType(static_cast<int32_t>(SubscriberType::USER_APP_SUBSCRIBER_TYPE));
    publishInfo.SetValidationRule(ValidationRule::AND);
    SetSystemMock(true);

    StaticSubscriberManager::StaticSubscriberInfo user0Subscriber;
    user0Subscriber.bundleName = "testBundleUser0";
    user0Subscriber.userId = 0;
    EXPECT_FALSE(manager->CheckSubscriberWhetherMatched(user0Subscriber, publishInfo));

    StaticSubscriberManager::StaticSubscriberInfo user99Subscriber;
    user99Subscriber.bundleName = "testBundleUser99";
    user99Subscriber.userId = 99;
    EXPECT_FALSE(manager->CheckSubscriberWhetherMatched(user99Subscriber, publishInfo));
}

/**
 * @tc.name: ATC_PublishInner_UserAppTypeSkipSystemUserSpaceSubscriber
 * @tc.desc: test static subscriber installed in system user space is not started for USER_APP type event.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberManagerUserAppUnitTest, ATC_PublishInner_UserAppTypeSkipSystemUserSpaceSubscriber, Level0)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    const std::string event = "test.event.static.userapp.user0";
    StaticSubscriberManager::StaticSubscriberInfo subscriber;
    subscriber.bundleName = "staticBundleUser0";
    subscriber.name = "StaticSubscriber";
    subscriber.userId = 0;
    manager->validSubscribers_[event].push_back(subscriber);

    CommonEventData data;
    AAFwk::Want want;
    want.SetAction(event);
    data.SetWant(want);
    CommonEventPublishInfo publishInfo;
    publishInfo.SetSubscriberType(static_cast<int32_t>(SubscriberType::USER_APP_SUBSCRIBER_TYPE));

    ResetAbilityManagerHelperState();
    manager->PublishCommonEventInner(data, publishInfo, 1, 100, nullptr, "publisherBundle");
    EXPECT_FALSE(IsConnectAbilityCalled());
}

/**
 * @tc.name: ATC_PublishInner_UserAppTypeDeliverTargetUserSubscriber
 * @tc.desc: test static subscriber installed in target user is started for USER_APP type event.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberManagerUserAppUnitTest, ATC_PublishInner_UserAppTypeDeliverTargetUserSubscriber, Level0)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    const std::string event = "test.event.static.userapp.user100";
    StaticSubscriberManager::StaticSubscriberInfo subscriber;
    subscriber.bundleName = "staticBundleUser100";
    subscriber.name = "StaticSubscriber";
    subscriber.userId = 100;
    manager->validSubscribers_[event].push_back(subscriber);

    CommonEventData data;
    AAFwk::Want want;
    want.SetAction(event);
    data.SetWant(want);
    CommonEventPublishInfo publishInfo;
    publishInfo.SetSubscriberType(static_cast<int32_t>(SubscriberType::USER_APP_SUBSCRIBER_TYPE));
    SetSystemMock(true);

    ResetAbilityManagerHelperState();
    manager->PublishCommonEventInner(data, publishInfo, 1, 100, nullptr, "publisherBundle");
    EXPECT_TRUE(IsConnectAbilityCalled());
}

/**
 * @tc.name: ATC_PublishInner_UserAppTypeSkipOtherUserSubscriber
 * @tc.desc: test static subscriber installed in other user is not started for USER_APP type event.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberManagerUserAppUnitTest, ATC_PublishInner_UserAppTypeSkipOtherUserSubscriber, Level0)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    const std::string event = "test.event.static.userapp.user101";
    StaticSubscriberManager::StaticSubscriberInfo subscriber;
    subscriber.bundleName = "staticBundleUser101";
    subscriber.name = "StaticSubscriber";
    subscriber.userId = 101;
    manager->validSubscribers_[event].push_back(subscriber);

    CommonEventData data;
    AAFwk::Want want;
    want.SetAction(event);
    data.SetWant(want);
    CommonEventPublishInfo publishInfo;
    publishInfo.SetSubscriberType(static_cast<int32_t>(SubscriberType::USER_APP_SUBSCRIBER_TYPE));

    ResetAbilityManagerHelperState();
    manager->PublishCommonEventInner(data, publishInfo, 1, 100, nullptr, "publisherBundle");
    EXPECT_FALSE(IsConnectAbilityCalled());
}

/**
 * @tc.name: ATC_PublishInner_UserAppTypeNegativeUserId
 * @tc.desc: test negative install userId behavior is consistent with the shared range predicate.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberManagerUserAppUnitTest, ATC_PublishInner_UserAppTypeNegativeUserId, Level0)
{
    auto manager = std::make_shared<StaticSubscriberManager>();
    const std::string event = "test.event.static.userapp.negative";
    StaticSubscriberManager::StaticSubscriberInfo subscriber;
    subscriber.bundleName = "staticBundleNegative";
    subscriber.name = "StaticSubscriber";
    subscriber.userId = -1;
    manager->validSubscribers_[event].push_back(subscriber);

    CommonEventData data;
    AAFwk::Want want;
    want.SetAction(event);
    data.SetWant(want);
    CommonEventPublishInfo publishInfo;
    publishInfo.SetSubscriberType(static_cast<int32_t>(SubscriberType::USER_APP_SUBSCRIBER_TYPE));

    EXPECT_TRUE(manager->CheckSubscriberWhetherMatched(subscriber, publishInfo));
    ResetAbilityManagerHelperState();
    manager->PublishCommonEventInner(data, publishInfo, 1, 100, nullptr, "publisherBundle");
    EXPECT_FALSE(IsConnectAbilityCalled());
}
