/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "async_common_event_result.h"
#include "matching_skills.h"
#include "common_event_subscribe_info.h"
#undef private
#undef protected

#include <gtest/gtest.h>

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EventFwk;
using OHOS::Parcel;

namespace {
const std::string EVENT = "com.ces.test.event";
}

class CommomEventSubscribeInfoTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void CommomEventSubscribeInfoTest::SetUpTestCase(void)
{}

void CommomEventSubscribeInfoTest::TearDownTestCase(void)
{}

void CommomEventSubscribeInfoTest::SetUp(void)
{}

void CommomEventSubscribeInfoTest::TearDown(void)
{}

/*
 * Feature: CommomEventSubscribeInfoTest
 * Function: SetPriority/GetPriority
 * SubFunction: NA
 * FunctionPoints: AddEntity/GetEntity
 * EnvConditions: NA
 * CaseDescription: Verify the function when after set priority can get priority
 */
HWTEST_F(CommomEventSubscribeInfoTest, CommomEventSubscribeInfoTest_001, TestSize.Level1)
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetPriority(1);
    EXPECT_EQ(1, subscribeInfo.GetPriority());
}

/*
 * Feature: CommomEventSubscribeInfoTest
 * Function: SetUserId/GetUserId
 * SubFunction: NA
 * FunctionPoints: SetUserId/GetUserId
 * EnvConditions: NA
 * CaseDescription: Verify the function when after set userId can get userId
 */
HWTEST_F(CommomEventSubscribeInfoTest, CommomEventSubscribeInfoTest_002, TestSize.Level1)
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetUserId(1);
    EXPECT_EQ(1, subscribeInfo.GetUserId());
}

/*
 * Feature: CommomEventSubscribeInfoTest
 * Function: SetPermission/GetPermission
 * SubFunction: NA
 * FunctionPoints: SetPermission/GetPermission
 * EnvConditions: NA
 * CaseDescription: Verify the function when after set premission can get premission
 */
HWTEST_F(CommomEventSubscribeInfoTest, CommomEventSubscribeInfoTest_003, TestSize.Level1)
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetPermission("abc");
    EXPECT_EQ("abc", subscribeInfo.GetPermission());
}

/*
 * Feature: CommomEventSubscribeInfoTest
 * Function: SetDeviceId/GetDeviceId
 * SubFunction: NA
 * FunctionPoints: SetDeviceId/GetDeviceId
 * EnvConditions: NA
 * CaseDescription: Verify the function when after set deviceId can get deviceId
 */
HWTEST_F(CommomEventSubscribeInfoTest, CommomEventSubscribeInfoTest_005, TestSize.Level1)
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetDeviceId("abc");
    EXPECT_EQ("abc", subscribeInfo.GetDeviceId());
}

/*
 * Feature: CommomEventSubscribeInfoTest
 * Function: SetPublisherBundleName/GetPublisherBundleName
 * SubFunction: NA
 * FunctionPoints: SetPublisherBundleName/GetPublisherBundleName
 * EnvConditions: NA
 * CaseDescription: Verify the function when after set publisherBundleName can get publisherBundleName
 */
HWTEST_F(CommomEventSubscribeInfoTest, CommomEventSubscribeInfoTest_007, TestSize.Level1)
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetPublisherBundleName("abc");
    EXPECT_EQ("abc", subscribeInfo.GetPublisherBundleName());
}

/*
 * Feature: CommomEventSubscribeInfoTest
 * Function: SetPublisherUid/GetPublisherUid
 * SubFunction: NA
 * FunctionPoints: SetPublisherUid/GetPublisherUid
 * EnvConditions: NA
 * CaseDescription: Verify the function when after set SetPublisherUid can get GetPublisherUid
 */
HWTEST_F(CommomEventSubscribeInfoTest, CommomEventSubscribeInfoTest_008, TestSize.Level1)
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetPublisherUid(1);
    EXPECT_EQ(1, subscribeInfo.GetPublisherUid());
}