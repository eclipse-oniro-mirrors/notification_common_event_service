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

#include <gtest/gtest.h>
#include <numeric>
#define private public
#include "common_event_manager_service.h"
#undef privat
#include "ffrt.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security::AccessToken;
namespace OHOS {
namespace EventFwk {
extern void MockIsVerfyPermisson(bool isVerify);
extern void MockGetTokenTypeFlag(ATokenTypeEnum mockRet);

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
 * @tc.name: CommonEventManagerService_0100
 * @tc.desc: test IsReady function and handler_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventManagerServiceTest, CommonEventManagerService_0100, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventManagerService_0100 start";
    std::shared_ptr<CommonEventManagerService> comm = std::make_shared<CommonEventManagerService>();
    ASSERT_NE(nullptr, comm);
    comm->innerCommonEventManager_ = std::make_shared<InnerCommonEventManager>();
    EXPECT_EQ(false, comm->IsReady());
    GTEST_LOG_(INFO) << "CommonEventManagerService_0100 end";
}

/**
 * @tc.name: CommonEventManagerService_0200
 * @tc.desc: test IsReady function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventManagerServiceTest, CommonEventManagerService_0200, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventManagerService_0200 start";
    sptr<CommonEventManagerService> comm = new (std::nothrow) CommonEventManagerService();
    ASSERT_NE(nullptr, comm);
    // set IsReady is true
    comm->innerCommonEventManager_ = std::make_shared<InnerCommonEventManager>();
    comm->commonEventSrvQueue_ = std::make_shared<ffrt::queue>("CesSrvMain");
    // set VerifyNativeToken is true
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    // test PublishCommonEvent
    CommonEventData event;
    CommonEventPublishInfo publishinfo;
    uid_t uid = 1;
    int32_t userId = 2;
    int32_t callerToken = 0;
    EXPECT_EQ(true, comm->PublishCommonEvent(event, publishinfo, nullptr, uid, callerToken, userId));
    GTEST_LOG_(INFO) << "CommonEventManagerService_0200 end";
}

/**
 * @tc.name: CommonEventManagerService_0500
 * @tc.desc: test GetStickyCommonEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventManagerServiceTest, CommonEventManagerService_0500, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventManagerService_0500 start";
    std::shared_ptr<CommonEventManagerService> comm = std::make_shared<CommonEventManagerService>();
    ASSERT_NE(nullptr, comm);
    // set IsReady is true
    comm->innerCommonEventManager_ = std::make_shared<InnerCommonEventManager>();
    comm->commonEventSrvQueue_ = std::make_shared<ffrt::queue>("CesSrvMain");
    // set event is empty
    std::string event = "";
    CommonEventData eventData;
    EXPECT_EQ(false, comm->GetStickyCommonEvent(event, eventData));
    GTEST_LOG_(INFO) << "CommonEventManagerService_0500 end";
}

/**
 * @tc.name: CommonEventManagerService_0600
 * @tc.desc: test GetStickyCommonEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventManagerServiceTest, CommonEventManagerService_0600, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventManagerService_0600 start";
    std::shared_ptr<CommonEventManagerService> comm = std::make_shared<CommonEventManagerService>();
    ASSERT_NE(nullptr, comm);
    // set IsReady is true
    comm->innerCommonEventManager_ = std::make_shared<InnerCommonEventManager>();
    comm->commonEventSrvQueue_ = std::make_shared<ffrt::queue>("CesSrvMain");
    // set VerifyAccessToken is false
    MockIsVerfyPermisson(false);
    // test GetStickyCommonEvent function
    std::string event = "sticky common event";
    CommonEventData eventData;
    EXPECT_EQ(false, comm->GetStickyCommonEvent(event, eventData));
    GTEST_LOG_(INFO) << "CommonEventManagerService_0600 end";
}

/**
 * @tc.name: CommonEventManagerService_0700
 * @tc.desc: test DumpState function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventManagerServiceTest, CommonEventManagerService_0700, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventManagerService_0700 start";
    std::shared_ptr<CommonEventManagerService> comm = std::make_shared<CommonEventManagerService>();
    ASSERT_NE(nullptr, comm);
    // set VerifyNativeToken is true
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    // set IsReady is false
    comm->innerCommonEventManager_ = std::make_shared<InnerCommonEventManager>();
    // test DumpState function
    uint8_t dumpType = 1;
    std::string event = "dump state";
    int32_t userId = 2;
    std::vector<std::string> state;
    EXPECT_EQ(false, comm->DumpState(dumpType, event, userId, state));
    GTEST_LOG_(INFO) << "CommonEventManagerService_0700 end";
}

/**
 * @tc.name: CommonEventManagerService_0800
 * @tc.desc: test DumpState function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventManagerServiceTest, CommonEventManagerService_0800, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventManagerService_0800 start";
    std::shared_ptr<CommonEventManagerService> comm = std::make_shared<CommonEventManagerService>();
    ASSERT_NE(nullptr, comm);
    // set VerifyNativeToken is true
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    // set IsReady is true
    comm->innerCommonEventManager_ = std::make_shared<InnerCommonEventManager>();
    comm->commonEventSrvQueue_ = std::make_shared<ffrt::queue>("CesSrvMain");
    // test DumpState function
    uint8_t dumpType = 1;
    std::string event = "dump state";
    int32_t userId = 2;
    std::vector<std::string> state;
    EXPECT_EQ(true, comm->DumpState(dumpType, event, userId, state));
    GTEST_LOG_(INFO) << "CommonEventManagerService_0800 end";
}

/**
 * @tc.name: CommonEventManagerService_0900
 * @tc.desc: test FinishReceiver function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventManagerServiceTest, CommonEventManagerService_0900, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventManagerService_0900 start";
    std::shared_ptr<CommonEventManagerService> comm = std::make_shared<CommonEventManagerService>();
    ASSERT_NE(nullptr, comm);
    // set IsReady is true
    comm->innerCommonEventManager_ = std::make_shared<InnerCommonEventManager>();
    comm->commonEventSrvQueue_ = std::make_shared<ffrt::queue>("CesSrvMain");
    // test FinishReceiver function
    int32_t code = 1;
    std::string receiverData = "finish receiver";
    bool abortEvent = true;
    EXPECT_EQ(true, comm->FinishReceiver(nullptr, code, receiverData, abortEvent));
    GTEST_LOG_(INFO) << "CommonEventManagerService_0900 end";
}

/**
 * @tc.name: CommonEventManagerService_1000
 * @tc.desc: test Freeze function and IsReady is false.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventManagerServiceTest, CommonEventManagerService_1000, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventManagerService_1000 start";
    std::shared_ptr<CommonEventManagerService> comm = std::make_shared<CommonEventManagerService>();
    ASSERT_NE(nullptr, comm);
    // set VerifyNativeToken is true
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    uid_t uid = 1;
    EXPECT_EQ(false, comm->Freeze(uid));
    GTEST_LOG_(INFO) << "CommonEventManagerService_1000 end";
}

/**
 * @tc.name: CommonEventManagerService_1100
 * @tc.desc: test Freeze function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventManagerServiceTest, CommonEventManagerService_1100, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventManagerService_1100 start";
    std::shared_ptr<CommonEventManagerService> comm = std::make_shared<CommonEventManagerService>();
    ASSERT_NE(nullptr, comm);
    // set VerifyNativeToken is true
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    // set IsReady is true
    comm->innerCommonEventManager_ = std::make_shared<InnerCommonEventManager>();
    comm->commonEventSrvQueue_ = std::make_shared<ffrt::queue>("CesSrvMain");
    // test Freeze function
    uid_t uid = 1;
    EXPECT_EQ(true, comm->Freeze(uid));
    GTEST_LOG_(INFO) << "CommonEventManagerService_1100 end";
}

/**
 * @tc.name: CommonEventManagerService_1200
 * @tc.desc: test Unfreeze function and IsReady is false.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventManagerServiceTest, CommonEventManagerService_1200, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventManagerService_1200 start";
    std::shared_ptr<CommonEventManagerService> comm = std::make_shared<CommonEventManagerService>();
    ASSERT_NE(nullptr, comm);
    // set VerifyNativeToken is true
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    uid_t uid = 1;
    EXPECT_EQ(false, comm->Unfreeze(uid));
    GTEST_LOG_(INFO) << "CommonEventManagerService_1200 end";
}

/**
 * @tc.name: CommonEventManagerService_1300
 * @tc.desc: test Unfreeze function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventManagerServiceTest, CommonEventManagerService_1300, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventManagerService_1300 start";
    std::shared_ptr<CommonEventManagerService> comm = std::make_shared<CommonEventManagerService>();
    ASSERT_NE(nullptr, comm);
    // set VerifyNativeToken is true
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    // set IsReady is true
    comm->innerCommonEventManager_ = std::make_shared<InnerCommonEventManager>();
    comm->commonEventSrvQueue_ = std::make_shared<ffrt::queue>("CesSrvMain");
    // test Unfreeze function
    uid_t uid = 1;
    EXPECT_EQ(true, comm->Unfreeze(uid));
    GTEST_LOG_(INFO) << "CommonEventManagerService_1300 end";
}

/**
 * @tc.name: CommonEventManagerService_1400
 * @tc.desc: test UnfreezeAll function and IsReady is false.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventManagerServiceTest, CommonEventManagerService_1400, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventManagerService_1400 start";
    std::shared_ptr<CommonEventManagerService> comm = std::make_shared<CommonEventManagerService>();
    ASSERT_NE(nullptr, comm);
    // set VerifyNativeToken is true
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    EXPECT_EQ(false, comm->UnfreezeAll());
    GTEST_LOG_(INFO) << "CommonEventManagerService_1400 end";
}

/**
 * @tc.name: CommonEventManagerService_1500
 * @tc.desc: test UnfreezeAll function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventManagerServiceTest, CommonEventManagerService_1500, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventManagerService_1500 start";
    std::shared_ptr<CommonEventManagerService> comm = std::make_shared<CommonEventManagerService>();
    ASSERT_NE(nullptr, comm);
    // set VerifyNativeToken is true
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    // set IsReady is true
    comm->innerCommonEventManager_ = std::make_shared<InnerCommonEventManager>();
    comm->commonEventSrvQueue_ = std::make_shared<ffrt::queue>("CesSrvMain");
    // test UnfreezeAll function
    EXPECT_EQ(true, comm->UnfreezeAll());
    GTEST_LOG_(INFO) << "CommonEventManagerService_1500 end";
}

/**
 * @tc.name: CommonEventManagerService_1600
 * @tc.desc: test Dump function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventManagerServiceTest, CommonEventManagerService_1600, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventManagerService_1600 start";
    std::shared_ptr<CommonEventManagerService> comm = std::make_shared<CommonEventManagerService>();
    ASSERT_NE(nullptr, comm);
    // set VerifyNativeToken is true
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    int fd = 1;
    std::vector<std::u16string> args;
    EXPECT_EQ(OHOS::ERR_INVALID_VALUE, comm->Dump(fd, args));
    GTEST_LOG_(INFO) << "CommonEventManagerService_1600 end";
}

/**
 * @tc.name: CommonEventManagerService_1700
 * @tc.desc: test Dump function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventManagerServiceTest, CommonEventManagerService_1700, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventManagerService_1700 start";
    std::shared_ptr<CommonEventManagerService> comm = std::make_shared<CommonEventManagerService>();
    ASSERT_NE(nullptr, comm);
    // set VerifyNativeToken is true
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    // set IsReady is true
    comm->innerCommonEventManager_ = std::make_shared<InnerCommonEventManager>();
    comm->commonEventSrvQueue_ = std::make_shared<ffrt::queue>("CesSrvMain");
    // test Dump function.
    int fd = 1;
    std::vector<std::u16string> args;
    EXPECT_EQ(OHOS::ERR_OK, comm->Dump(fd, args));
    GTEST_LOG_(INFO) << "CommonEventManagerService_1700 end";
}

/**
 * @tc.name: CommonEventManagerService_1800
 * @tc.desc: test SetStaticSubscriberState function.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventManagerServiceTest, CommonEventManagerService_1800, Level1)
{
    GTEST_LOG_(INFO) << "CommonEventManagerService_1800 start";
    std::shared_ptr<CommonEventManagerService> comm = std::make_shared<CommonEventManagerService>();
    ASSERT_NE(nullptr, comm);
    // mock ATokenTypeEnum type
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    // set IsReady is true
    comm->innerCommonEventManager_ = std::make_shared<InnerCommonEventManager>();
    comm->commonEventSrvQueue_ = std::make_shared<ffrt::queue>("CesSrvMain");
    EXPECT_EQ(OHOS::ERR_INVALID_OPERATION, comm->SetStaticSubscriberState(true));
    GTEST_LOG_(INFO) << "CommonEventManagerService_1800 end";
}
}
}
