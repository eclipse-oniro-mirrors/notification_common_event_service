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
#define private public
#define protected public
#include "common_event_manager_service.h"

#include "ces_inner_error_code.h"
#include "common_event.h"
#include "common_event_death_recipient.h"
#include "common_event_stub.h"
#include "common_event_proxy.h"
#include "common_event_data.h"
#include "common_event_subscriber.h"
#include "event_receive_proxy.h"
#include "common_event_publish_info.h"
#include "matching_skills.h"

#include "event_receive_stub.h"
#include "event_log_wrapper.h"
#include "datetime_ex.h"

#undef private
#undef protected

#include <gtest/gtest.h>

using namespace testing::ext;
using namespace OHOS::EventFwk;
using namespace OHOS;

class CommonEventManagerServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    virtual void OnReceiveEvent(const CommonEventData &data)
    {}
};

void CommonEventManagerServiceTest::SetUpTestCase()
{}

void CommonEventManagerServiceTest::TearDownTestCase()
{}

void CommonEventManagerServiceTest::SetUp()
{}

void CommonEventManagerServiceTest::TearDown()
{}

/**
 * @tc.name: Init_001
 * @tc.desc: Test CommonEventManagerService_
 * @tc.type: FUNC
 * @tc.require: I582Y4
 */
HWTEST_F(CommonEventManagerServiceTest, Init_001, Level1)
{   
    CommonEventManagerService commonEventManagerService;
    int result = commonEventManagerService.Init();
    EXPECT_EQ(ERR_OK, result);
}

/**
 * @tc.name: Init_002
 * @tc.desc: Test CommonEventManagerService_
 * @tc.type: FUNC
 * @tc.require: I582Y4
 */
HWTEST_F(CommonEventManagerServiceTest, Init_002, Level1)
{   
    CommonEventManagerService commonEventManagerService;
    int result = commonEventManagerService.Init();
    EXPECT_NE(ERR_INVALID_OPERATION, result);
}

/**
 * @tc.name: PublishCommonEvent_001
 * @tc.desc: Test CommonEventManagerService_
 * @tc.type: FUNC
 * @tc.require: I582Y4
 */
HWTEST_F(CommonEventManagerServiceTest, PublishCommonEvent_001, Level1)
{   
    CommonEventManagerService commonEventManagerService;
    CommonEventData event;
    CommonEventPublishInfo publishInfo;

    int32_t userId = 1;
    const int32_t ERR_NOTIFICATION_CESM_ERROR = 1500008;
    int32_t result = commonEventManagerService.PublishCommonEvent(event, publishInfo, nullptr, userId);
    EXPECT_EQ(ERR_NOTIFICATION_CESM_ERROR, result);
}

/**
 * @tc.name: PublishCommonEvent_002
 * @tc.desc: Test CommonEventManagerService_
 * @tc.type: FUNC
 * @tc.require: I582Y4
 */
HWTEST_F(CommonEventManagerServiceTest, PublishCommonEvent_002, Level1)
{
    CommonEventManagerService commonEventManagerService;
    CommonEventData event;
    CommonEventPublishInfo publishInfo;

    int32_t userId = 1;
    bool result = commonEventManagerService.PublishCommonEvent(event, publishInfo, nullptr, userId);
    EXPECT_EQ(true, result);
}

/**
 * @tc.name: SubscribeCommonEvent_001
 * @tc.desc: Test CommonEventManagerService_
 * @tc.type: FUNC
 * @tc.require: I582Y4
 */
HWTEST_F(CommonEventManagerServiceTest, SubscribeCommonEvent_001, Level1)
{   
    CommonEventManagerService commonEventManagerService;
    CommonEventData event;
    CommonEventSubscribeInfo subscribeInfo;

    int32_t result = commonEventManagerService.SubscribeCommonEvent(subscribeInfo, nullptr);
    const int32_t ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID = 401;
    EXPECT_EQ(ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, result);
}

/**
 * @tc.name: SubscribeCommonEvent_002
 * @tc.desc: Test CommonEventManagerService_
 * @tc.type: FUNC
 * @tc.require: I582Y4
 */
HWTEST_F(CommonEventManagerServiceTest, SubscribeCommonEvent_002, Level1)
{   
    CommonEventManagerService commonEventManagerService;
    CommonEventData event;
    CommonEventSubscribeInfo subscribeInfo;

    struct tm recordTime = {0};
    GetSystemCurrentTime(&recordTime);

    int32_t result = commonEventManagerService.SubscribeCommonEvent(subscribeInfo, nullptr);
    const int32_t ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID = 401;
    EXPECT_EQ(ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, result);
}

/**
 * @tc.name: SubscribeCommonEvent_003
 * @tc.desc: Test CommonEventManagerService_
 * @tc.type: FUNC
 * @tc.require: I582Y4
 */
HWTEST_F(CommonEventManagerServiceTest, SubscribeCommonEvent_003, Level1)
{   
    CommonEventManagerService commonEventManagerService;
    CommonEventData event;
    CommonEventSubscribeInfo subscribeInfo;

    struct tm recordTime = {0};
    GetSystemCurrentTime(&recordTime);

    int32_t result = commonEventManagerService.SubscribeCommonEvent(subscribeInfo, nullptr);
    const int32_t ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID = 401;
    EXPECT_EQ(ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, result);
}

/**
 * @tc.name: SubscribeCommonEvent_004
 * @tc.desc: Test CommonEventManagerService_
 * @tc.type: FUNC
 * @tc.require: I582Y4
 */
HWTEST_F(CommonEventManagerServiceTest, SubscribeCommonEvent_004, Level1)
{   
    CommonEventManagerService commonEventManagerService;
    CommonEventData event;
    CommonEventSubscribeInfo subscribeInfo;

    struct tm recordTime = {0};
    
    auto callingUid = 0;
    auto callingPid = 0;
    auto callerToken = 0;
    std::string bundleName = "bundleName";
    std::shared_ptr<InnerCommonEventManager> innerCommonEventManager = std::make_shared<InnerCommonEventManager>();
    bool ret = innerCommonEventManager->SubscribeCommonEvent(subscribeInfo,
            nullptr,
            recordTime,
            callingPid,
            callingUid,
            callerToken,
            bundleName);
   
    int32_t result = commonEventManagerService.SubscribeCommonEvent(subscribeInfo, nullptr);
    const int32_t ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID = 401;
    EXPECT_EQ(false, ret);
    EXPECT_EQ(ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, result);
}

/**
 * @tc.name: GetStickyCommonEvent_001
 * @tc.desc: Test CommonEventManagerService_
 * @tc.type: FUNC
 * @tc.require: I582Y4
 */
HWTEST_F(CommonEventManagerServiceTest, GetStickyCommonEvent_001, Level1)
{ 
    const std::string event = "this is an event";
    std::shared_ptr<InnerCommonEventManager> innerCommonEventManager_ = std::make_shared<InnerCommonEventManager>();

    CommonEventData eventData;
    bool ret = innerCommonEventManager_->GetStickyCommonEvent(event, eventData);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.name: FinishReceiver_001
 * @tc.desc: Test CommonEventManagerService_
 * @tc.type: FUNC
 * @tc.require: I582Y4
 */
HWTEST_F(CommonEventManagerServiceTest, FinishReceiver_001, Level1)
{   
    GTEST_LOG_(INFO) << "FinishReceiver_001 start";

    const std::string event = "this is an event";
    std::shared_ptr<InnerCommonEventManager> innerCommonEventManager_ = std::make_shared<InnerCommonEventManager>();
    ASSERT_NE(nullptr, innerCommonEventManager_);
    const sptr<IRemoteObject> proxy = nullptr;
    const int32_t code = 0;
    const std::string receiverData = "this is an receiverData";
    const bool abortEvent = true;

    innerCommonEventManager_->FinishReceiver(proxy, code, receiverData, abortEvent);
    GTEST_LOG_(INFO) << "FinishReceiver_001 end";
}

/**
 * @tc.name: Unfreeze_001
 * @tc.desc: Test CommonEventManagerService_
 * @tc.type: FUNC
 * @tc.require: I582Y4
 */
HWTEST_F(CommonEventManagerServiceTest, Unfreeze_001, Level1)
{   
    GTEST_LOG_(INFO) << "Unfreeze_001 start";

    std::shared_ptr<InnerCommonEventManager> innerCommonEventManager = std::make_shared<InnerCommonEventManager>();
    ASSERT_NE(nullptr, innerCommonEventManager);
    const uid_t uid = 0;

    innerCommonEventManager->Unfreeze(uid);
    GTEST_LOG_(INFO) << "Unfreeze_001 end";
}

/**
 * @tc.name: UnfreezeAll_001
 * @tc.desc: Test CommonEventManagerService_
 * @tc.type: FUNC
 * @tc.require: I582Y4
 */
HWTEST_F(CommonEventManagerServiceTest, UnfreezeAll_001, Level1)
{   
    GTEST_LOG_(INFO) << "UnfreezeAll_001 start";

    std::shared_ptr<InnerCommonEventManager> innerCommonEventManager = std::make_shared<InnerCommonEventManager>();
    ASSERT_NE(nullptr, innerCommonEventManager);

    innerCommonEventManager->UnfreezeAll();
    GTEST_LOG_(INFO) << "UnfreezeAll_001 end";
}

/**
 * @tc.name: SetStaticSubscriberStateWithTwoParameters_0100
 * @tc.desc: Test the SetStaticSubscriberState function, test whether it is a system application.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventManagerServiceTest, SetStaticSubscriberStateWithTwoParameters_0100, Level1)
{
    CommonEventManagerService commonEventManagerService;
    std::vector<std::string> events;
    events.push_back("StaticCommonEventA");
    int32_t result = commonEventManagerService.SetStaticSubscriberState(events, true);
    EXPECT_EQ(result, OHOS::Notification::ERR_NOTIFICATION_CES_COMMON_NOT_SYSTEM_APP);
}
