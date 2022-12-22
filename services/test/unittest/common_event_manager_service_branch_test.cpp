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
#include <numeric>
#define private public
#include "common_event_manager_service.h"
#undef private
#include "ces_inner_error_code.h"

extern void mockVerifyNativeToken(bool mockRet);

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EventFwk;
using namespace OHOS::Notification;
using namespace OHOS::AppExecFwk;

class CommonEventManagerServiceTest : public testing::Test {
public:
    CommonEventManagerServiceTest()
    {}
    ~CommonEventManagerServiceTest()
    {}

    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void CommonEventManagerServiceTest::SetUpTestCase(void)
{}

void CommonEventManagerServiceTest::TearDownTestCase(void)
{}

void CommonEventManagerServiceTest::SetUp(void)
{}

void CommonEventManagerServiceTest::TearDown(void)
{}

/**
 * @tc.name: CommonEventManagerServiceBranch_0100
 * @tc.desc: test PublishCommonEvent function and VerifyNativeToken is false.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventManagerServiceTest, CommonEventManagerServiceBranch_0100, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventManagerServiceBranch_0100 start";
    std::shared_ptr<CommonEventManagerService> comm = std::make_shared<CommonEventManagerService>();
    ASSERT_NE(nullptr, comm);
    // set IsReady is true
    comm->innerCommonEventManager_ = std::make_shared<InnerCommonEventManager>();
    comm->runner_ = EventRunner::Create("CesSrvMain");
    comm->handler_ = std::make_shared<EventHandler>(comm->runner_);
    // set VerifyNativeToken is false
    mockVerifyNativeToken(false);
    // test PublishCommonEvent
    CommonEventData event;
    CommonEventPublishInfo publishinfo;
    sptr<IRemoteObject> commonEventListener = nullptr;
    uid_t uid = 1;
    int32_t userId = 2;
    EXPECT_EQ(false, comm->PublishCommonEvent(event, publishinfo, commonEventListener, uid, userId));
    GTEST_LOG_(INFO) << "CommonEventManagerServiceBranch_0100 end";
}

/**
 * @tc.name: CommonEventManagerServiceBranch_0200
 * @tc.desc: test SubscribeCommonEvent function and IsReady is false.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventManagerServiceTest, CommonEventManagerServiceBranch_0200, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventManagerServiceBranch_0200 start";
    std::shared_ptr<CommonEventManagerService> comm = std::make_shared<CommonEventManagerService>();
    ASSERT_NE(nullptr, comm);
    // set IsReady is false
    comm->innerCommonEventManager_ = nullptr;
    // test SubscribeCommonEvent
    CommonEventSubscribeInfo subscribeInfo;
    sptr<IRemoteObject> commonEventListener = nullptr;
    EXPECT_EQ(
        ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, comm->SubscribeCommonEvent(subscribeInfo, commonEventListener));
    GTEST_LOG_(INFO) << "CommonEventManagerServiceBranch_0200 end";
}

/**
 * @tc.name: CommonEventManagerServiceBranch_0300
 * @tc.desc: test UnsubscribeCommonEvent function and IsReady is false.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventManagerServiceTest, CommonEventManagerServiceBranch_0300, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventManagerServiceBranch_0300 start";
    std::shared_ptr<CommonEventManagerService> comm = std::make_shared<CommonEventManagerService>();
    ASSERT_NE(nullptr, comm);
    // set IsReady is false
    comm->innerCommonEventManager_ = nullptr;
    // test SubscribeCommonEvent
    sptr<IRemoteObject> commonEventListener = nullptr;
    EXPECT_EQ(
        ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, comm->UnsubscribeCommonEvent(commonEventListener));
    GTEST_LOG_(INFO) << "CommonEventManagerServiceBranch_0300 end";
}

/**
 * @tc.name: CommonEventManagerServiceBranch_0400
 * @tc.desc: test GetStickyCommonEvent function and IsReady is false.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventManagerServiceTest, CommonEventManagerServiceBranch_0400, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventManagerServiceBranch_0400 start";
    std::shared_ptr<CommonEventManagerService> comm = std::make_shared<CommonEventManagerService>();
    ASSERT_NE(nullptr, comm);
    // set IsReady is false
    comm->innerCommonEventManager_ = nullptr;
    // test SubscribeCommonEvent
    std::string event = "aa";
    CommonEventData eventData;
    EXPECT_EQ(false, comm->GetStickyCommonEvent(event, eventData));
    GTEST_LOG_(INFO) << "CommonEventManagerServiceBranch_0400 end";
}