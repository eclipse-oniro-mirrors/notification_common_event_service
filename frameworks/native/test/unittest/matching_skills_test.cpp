/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#include "async_common_event_result.h"
#include "matching_skills.h"
#undef private
#undef protected

#include <gtest/gtest.h>

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EventFwk;
using OHOS::Parcel;

static const size_t SET_COUNT = 1;
static const size_t MAX_COUNT = 100;

class MatchingSkillsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void MatchingSkillsTest::SetUpTestCase(void)
{}

void MatchingSkillsTest::TearDownTestCase(void)
{}

void MatchingSkillsTest::SetUp(void)
{}

void MatchingSkillsTest::TearDown(void)
{}

/*
 * Feature: MatchingSkills
 * Function: AddEntity/GetEntity/CountEntities/HasEntity/RemoveEntity
 * SubFunction: NA
 * FunctionPoints: AddEntity/GetEntity
 * EnvConditions: NA
 * CaseDescription: Verify the function when after add entity can get entity
 * and count entity is right,has entity and can success remove entity
 */
HWTEST_F(MatchingSkillsTest, MatchingSkills_Entity_001, TestSize.Level1)
{
    MatchingSkills matchSkills;
    std::string empty;
    std::string entity = "event.unit.test";
    matchSkills.AddEntity(entity);
    matchSkills.AddEntity(entity);
    EXPECT_EQ(SET_COUNT, matchSkills.CountEntities());

    EXPECT_EQ(true, matchSkills.HasEntity(entity));

    EXPECT_EQ(entity, matchSkills.GetEntity(0));

    EXPECT_EQ(false, entity == matchSkills.GetEntity(MAX_COUNT));

    matchSkills.RemoveEntity(entity);

    matchSkills.RemoveEntity(entity);

    EXPECT_EQ(0, matchSkills.CountEntities());
}

/*
 * Feature: MatchingSkills
 * Function: event
 * SubFunction: NA
 * FunctionPoints: AddEvent/GetEvent/CountEvent/HasEvent/RemoveEvent
 * EnvConditions: NA
 * CaseDescription: Verify the function when after add event can get event
 * and count event is right,has event and can success remove event
 */
HWTEST_F(MatchingSkillsTest, MatchingSkills_Event_001, TestSize.Level1)
{
    MatchingSkills matchSkills;
    std::string empty;
    std::string event = "event.unit.test";
    matchSkills.AddEvent(event);
    matchSkills.AddEvent(event);

    EXPECT_EQ(true, matchSkills.HasEvent(event));

    EXPECT_EQ(event, matchSkills.GetEvent(0));

    EXPECT_EQ(false, event == matchSkills.GetEvent(SET_COUNT));
    matchSkills.RemoveEvent(event);

    matchSkills.RemoveEvent(event);

    EXPECT_EQ(0, matchSkills.CountEvent());
}

/*
 * Feature: MatchingSkills
 * Function: scheme
 * SubFunction: NA
 * FunctionPoints: AddScheme/GetScheme/CountScheme/HasScheme/RemoveScheme
 * EnvConditions: NA
 * CaseDescription: Verify the function when after add scheme can get scheme
 * and count scheme is right,has scheme and can success remove scheme
 */
HWTEST_F(MatchingSkillsTest, MatchingSkills_Scheme_001, TestSize.Level1)
{
    MatchingSkills matchSkills;
    std::string empty;
    std::string shceme = "event.unit.test";
    matchSkills.AddScheme(shceme);
    matchSkills.AddScheme(shceme);

    EXPECT_EQ(true, matchSkills.HasScheme(shceme));

    EXPECT_EQ(shceme, matchSkills.GetScheme(0));

    EXPECT_EQ(false, shceme == matchSkills.GetScheme(SET_COUNT));

    matchSkills.RemoveScheme(shceme);

    matchSkills.RemoveScheme(shceme);

    EXPECT_EQ(0, matchSkills.CountSchemes());
}

/*
 * Feature: MatchingSkills
 * Function: Match Event
 * SubFunction: NA
 * FunctionPoints: Match Event
 * EnvConditions: NA
 * CaseDescription: Verify match event
 */
HWTEST_F(MatchingSkillsTest, MatchingSkills_MatchEvent_001, TestSize.Level1)
{
    MatchingSkills matchSkills;
    EXPECT_EQ(false, matchSkills.MatchEvent(""));

    std::string event = "event.unit.test";
    matchSkills.AddEvent(event);
    EXPECT_EQ(true, matchSkills.MatchEvent(event));
}

/*
 * Feature: MatchingSkills
 * Function: Match entity
 * SubFunction: NA
 * FunctionPoints: Match entity
 * EnvConditions: NA
 * CaseDescription: Verify match entity
 */

HWTEST_F(MatchingSkillsTest, MatchingSkills_MatchEntity_001, TestSize.Level1)
{
    MatchingSkills matchSkills;
    std::vector<std::string> entities;
    EXPECT_EQ(true, matchSkills.MatchEntity(entities));

    std::string entity = "event.unit.test";
    matchSkills.AddEntity(entity);
    entities.emplace_back(entity);
    EXPECT_EQ(true, matchSkills.MatchEntity(entities));
    entities.emplace_back("entitydiffer");
    EXPECT_EQ(false, matchSkills.MatchEntity(entities));
}

/*
 * Feature: MatchingSkills
 * Function: Match scheme
 * SubFunction: NA
 * FunctionPoints: Match scheme
 * EnvConditions: NA
 * CaseDescription: Verify match scheme
 */

HWTEST_F(MatchingSkillsTest, MatchingSkills_MatchScheme_001, TestSize.Level1)
{
    MatchingSkills matchSkills;
    EXPECT_EQ(true, matchSkills.MatchScheme(""));
    std::string scheme = "action.system.event";
    matchSkills.AddScheme(scheme);
    EXPECT_EQ(true, matchSkills.MatchScheme(scheme));
    EXPECT_EQ(false, matchSkills.MatchScheme("schemediffer"));
}

/*
 * Feature: Match
 * Function: Match
 * SubFunction: NA
 * FunctionPoints: Match
 * EnvConditions: NA
 * CaseDescription: Verify match
 */

HWTEST_F(MatchingSkillsTest, MatchingSkills_Match_001, TestSize.Level1)
{
    MatchingSkills matchSkills;
    std::string event = "event.unit.test";
    matchSkills.AddEvent(event);
    std::string entity;
    matchSkills.AddEntity(entity);
    Want want;
    want.AddEntity(entity);
    want.SetAction(event);
    EXPECT_EQ(true, matchSkills.Match(want));
}

/*
 * Feature: GetEntity
 * Function: GetEntity
 * SubFunction: NA
 * FunctionPoints: GetEntity
 * EnvConditions: NA
 * CaseDescription: test GetEntity function
 */

HWTEST_F(MatchingSkillsTest, MatchingSkills_001, TestSize.Level1)
{
    MatchingSkills matchSkills;
    std::string event = "event.unit.test";
    matchSkills.entities_.emplace_back(event);
    size_t index = 1;
    EXPECT_EQ("", matchSkills.GetEntity(index));
}

/*
 * Feature: GetEntity
 * Function: GetEntity
 * SubFunction: NA
 * FunctionPoints: GetEntity
 * EnvConditions: NA
 * CaseDescription: test GetEntity function
 */

HWTEST_F(MatchingSkillsTest, MatchingSkills_002, TestSize.Level1)
{
    MatchingSkills matchSkills;
    std::string event = "event.unit.test";
    matchSkills.entities_.emplace_back(event);
    size_t index = -1;
    EXPECT_EQ("", matchSkills.GetEntity(index));
}

/*
 * Feature: GetEntity
 * Function: GetEntity
 * SubFunction: NA
 * FunctionPoints: GetEntity
 * EnvConditions: NA
 * CaseDescription: test GetEntity function
 */

HWTEST_F(MatchingSkillsTest, MatchingSkills_003, TestSize.Level1)
{
    MatchingSkills matchSkills;
    std::string event = "event.unit.test";
    matchSkills.entities_.emplace_back(event);
    size_t index = 0;
    EXPECT_EQ("event.unit.test", matchSkills.GetEntity(index));
}

/*
 * Feature: GetEvent
 * Function: GetEvent
 * SubFunction: NA
 * FunctionPoints: GetEvent
 * EnvConditions: NA
 * CaseDescription: test GetEvent function
 */

HWTEST_F(MatchingSkillsTest, MatchingSkills_004, TestSize.Level1)
{
    MatchingSkills matchSkills;
    std::string event = "event.unit.test";
    matchSkills.events_.emplace_back(event);
    size_t index = 1;
    EXPECT_EQ("", matchSkills.GetEvent(index));
}

/*
 * Feature: GetEvent
 * Function: GetEvent
 * SubFunction: NA
 * FunctionPoints: GetEvent
 * EnvConditions: NA
 * CaseDescription: test GetEvent function
 */

HWTEST_F(MatchingSkillsTest, MatchingSkills_005, TestSize.Level1)
{
    MatchingSkills matchSkills;
    std::string event = "event.unit.test";
    matchSkills.events_.emplace_back(event);
    size_t index = -1;
    EXPECT_EQ("", matchSkills.GetEvent(index));
}

/*
 * Feature: GetEvent
 * Function: GetEvent
 * SubFunction: NA
 * FunctionPoints: GetEvent
 * EnvConditions: NA
 * CaseDescription: test GetEvent function
 */

HWTEST_F(MatchingSkillsTest, MatchingSkills_006, TestSize.Level1)
{
    MatchingSkills matchSkills;
    std::string event = "event.unit.test";
    matchSkills.events_.emplace_back(event);
    size_t index = 0;
    EXPECT_EQ("event.unit.test", matchSkills.GetEvent(index));
}

/*
 * Feature: GetScheme
 * Function: GetScheme
 * SubFunction: NA
 * FunctionPoints: GetScheme
 * EnvConditions: NA
 * CaseDescription: test GetScheme function
 */

HWTEST_F(MatchingSkillsTest, MatchingSkills_007, TestSize.Level1)
{
    MatchingSkills matchSkills;
    std::string event = "event.unit.test";
    matchSkills.schemes_.emplace_back(event);
    size_t index = 1;
    EXPECT_EQ("", matchSkills.GetScheme(index));
}

/*
 * Feature: GetScheme
 * Function: GetScheme
 * SubFunction: NA
 * FunctionPoints: GetScheme
 * EnvConditions: NA
 * CaseDescription: test GetScheme function
 */

HWTEST_F(MatchingSkillsTest, MatchingSkills_008, TestSize.Level1)
{
    MatchingSkills matchSkills;
    std::string event = "event.unit.test";
    matchSkills.schemes_.emplace_back(event);
    size_t index = -1;
    EXPECT_EQ("", matchSkills.GetScheme(index));
}

/*
 * Feature: GetScheme
 * Function: GetScheme
 * SubFunction: NA
 * FunctionPoints: GetScheme
 * EnvConditions: NA
 * CaseDescription: test GetScheme function
 */

HWTEST_F(MatchingSkillsTest, MatchingSkills_009, TestSize.Level1)
{
    MatchingSkills matchSkills;
    std::string event = "event.unit.test";
    matchSkills.schemes_.emplace_back(event);
    size_t index = 0;
    EXPECT_EQ("event.unit.test", matchSkills.GetScheme(index));
}

/*
 * Feature: FinishCommonEvent
 * Function: FinishCommonEvent
 * SubFunction: NA
 * FunctionPoints: FinishCommonEvent
 * EnvConditions: NA
 * CaseDescription: test FinishCommonEvent function
 */

HWTEST_F(MatchingSkillsTest, AsyncCommonEventResult_001, TestSize.Level1)
{
    int32_t resultCode = 1;
    std::string resultData = "aa";
    bool ordered = true;
    bool sticky = true;
    sptr<IRemoteObject> token = nullptr;
    AsyncCommonEventResult asyncCommonEventResult(resultCode, resultData, ordered, sticky, token);
    asyncCommonEventResult.finished_ = true;
    EXPECT_EQ(false, asyncCommonEventResult.FinishCommonEvent());
}

/*
 * @tc.number: AsyncCommonEventResult_002
 * @tc.name: AsyncCommonEventResult CheckSynchronous
 * @tc.desc: test SetCode function
 */

HWTEST_F(MatchingSkillsTest, AsyncCommonEventResult_002, TestSize.Level1)
{
    int32_t resultCode = 1;
    std::string resultData = "aa";
    bool ordered = false;
    bool sticky = true;
    sptr<IRemoteObject> token = nullptr;
    AsyncCommonEventResult asyncCommonEventResult(resultCode, resultData, ordered, sticky, token);
    EXPECT_EQ(asyncCommonEventResult.CheckSynchronous(), false);
    int32_t code = 1;
    bool result = asyncCommonEventResult.SetCode(code);
    EXPECT_EQ(result, false);
}

/*
 * @tc.number: AsyncCommonEventResult_003
 * @tc.name: AsyncCommonEventResult SetData
 * @tc.desc: test SetData function
 */

HWTEST_F(MatchingSkillsTest, AsyncCommonEventResult_003, TestSize.Level1)
{
    int32_t resultCode = 1;
    std::string resultData = "aa";
    bool ordered = false;
    bool sticky = true;
    sptr<IRemoteObject> token = nullptr;
    AsyncCommonEventResult asyncCommonEventResult(resultCode, resultData, ordered, sticky, token);
    EXPECT_EQ(asyncCommonEventResult.CheckSynchronous(), false);
    std::string data = "this is data";
    bool result = asyncCommonEventResult.SetData(data);
    EXPECT_EQ(result, false);
}

/*
 * @tc.number: AsyncCommonEventResult_004
 * @tc.name: AsyncCommonEventResult SetCodeAndData
 * @tc.desc: test SetCodeAndData function
 */

HWTEST_F(MatchingSkillsTest, AsyncCommonEventResult_004, TestSize.Level1)
{
    int32_t resultCode = 1;
    std::string resultData = "aa";
    bool ordered = false;
    bool sticky = true;
    sptr<IRemoteObject> token = nullptr;
    AsyncCommonEventResult asyncCommonEventResult(resultCode, resultData, ordered, sticky, token);
    EXPECT_EQ(asyncCommonEventResult.CheckSynchronous(), false);
    int32_t code = 1;
    std::string data = "this is data";
    bool result = asyncCommonEventResult.SetCodeAndData(code, data);
    EXPECT_EQ(result, false);
}

/*
 * @tc.number: AsyncCommonEventResult_005
 * @tc.name: AsyncCommonEventResult AbortCommonEvent
 * @tc.desc: test AbortCommonEvent function
 */

HWTEST_F(MatchingSkillsTest, AsyncCommonEventResult_005, TestSize.Level1)
{
    int32_t resultCode = 1;
    std::string resultData = "aa";
    bool ordered = false;
    bool sticky = true;
    sptr<IRemoteObject> token = nullptr;
    AsyncCommonEventResult asyncCommonEventResult(resultCode, resultData, ordered, sticky, token);
    EXPECT_EQ(asyncCommonEventResult.CheckSynchronous(), false);
    bool result = asyncCommonEventResult.AbortCommonEvent();
    EXPECT_EQ(result, false);
}

/*
 * @tc.number: AsyncCommonEventResult_006
 * @tc.name: AsyncCommonEventResult ClearAbortCommonEvent
 * @tc.desc: test ClearAbortCommonEvent function
 */

HWTEST_F(MatchingSkillsTest, AsyncCommonEventResult_006, TestSize.Level1)
{
    int32_t resultCode = 1;
    std::string resultData = "aa";
    bool ordered = false;
    bool sticky = true;
    sptr<IRemoteObject> token = nullptr;
    AsyncCommonEventResult asyncCommonEventResult(resultCode, resultData, ordered, sticky, token);
    EXPECT_EQ(asyncCommonEventResult.CheckSynchronous(), false);
    bool result = asyncCommonEventResult.ClearAbortCommonEvent();
    EXPECT_EQ(result, false);
}

/*
 * @tc.number: AsyncCommonEventResult_007
 * @tc.name: AsyncCommonEventResult FinishCommonEvent
 * @tc.desc: test FinishCommonEvent function
 */

HWTEST_F(MatchingSkillsTest, AsyncCommonEventResult_007, TestSize.Level1)
{
    int32_t resultCode = 1;
    std::string resultData = "aa";
    bool ordered = false;
    bool sticky = true;
    sptr<IRemoteObject> token = nullptr;
    AsyncCommonEventResult asyncCommonEventResult(resultCode, resultData, ordered, sticky, token);
    EXPECT_EQ(asyncCommonEventResult.CheckSynchronous(), false);
    bool result = asyncCommonEventResult.FinishCommonEvent();
    EXPECT_EQ(result, false);
}

/**
* @tc.name  : toString_ShouldReturnCorrectString_WhenEventsIsNotEmpty
* @tc.number: MatchingSkillsTest_001
* @tc.desc  : Test when events_ is not empty, ToString should return correct string
*/
HWTEST_F(MatchingSkillsTest, toString_ShouldReturnCorrectString_WhenEventsIsNotEmpty, TestSize.Level1)
{
    MatchingSkills matchingSkills;
    matchingSkills.events_ = {"event1", "event2"};
    std::string expected = " Events: event1,event2";
    EXPECT_EQ(matchingSkills.ToString(), expected);
}

/**
* @tc.name  : toString_ShouldReturnCorrectString_WhenSchemesIsNotEmpty
* @tc.number: MatchingSkillsTest_002
* @tc.desc  : Test when schemes_ is not empty, ToString should return correct string
*/
HWTEST_F(MatchingSkillsTest, toString_ShouldReturnCorrectString_WhenSchemesIsNotEmpty, TestSize.Level1)
{
    MatchingSkills matchingSkills;
    matchingSkills.schemes_ = {"scheme1", "scheme2"};
    std::string expected = " Schemes: scheme1,scheme2";
    EXPECT_EQ(matchingSkills.ToString(), expected);
}

/**
* @tc.name  : toString_ShouldReturnCorrectString_WhenEntitiesIsNotEmpty
* @tc.number: MatchingSkillsTest_003
* @tc.desc  : Test when entities_ is not empty, ToString should return correct string
*/
HWTEST_F(MatchingSkillsTest, toString_ShouldReturnCorrectString_WhenEntitiesIsNotEmpty, TestSize.Level1)
{
    MatchingSkills matchingSkills;
    matchingSkills.entities_ = {"entity1", "entity2"};
    std::string expected = " Entrities: entity1,entity2";
    EXPECT_EQ(matchingSkills.ToString(), expected);
}

/**
* @tc.name  : toString_ShouldReturnCorrectString_WhenAllFieldsAreNotEmpty
* @tc.number: MatchingSkillsTest_004
* @tc.desc  : Test when all fields are not empty, ToString should return correct string
*/
HWTEST_F(MatchingSkillsTest, toString_ShouldReturnCorrectString_WhenAllFieldsAreNotEmpty, TestSize.Level1)
{
    MatchingSkills matchingSkills;
    matchingSkills.events_ = {"event1", "event2"};
    matchingSkills.schemes_ = {"scheme1", "scheme2"};
    matchingSkills.entities_ = {"entity1", "entity2"};
    std::string expected = " Events: event1,event2 Schemes: scheme1,scheme2 Entrities: entity1,entity2";
    EXPECT_EQ(matchingSkills.ToString(), expected);
}

/**
* @tc.name  : toString_ShouldReturnCorrectString_WhenAllFieldsAreEmpty
* @tc.number: MatchingSkillsTest_005
* @tc.desc  : Test when all fields are empty, ToString should return correct string
*/
HWTEST_F(MatchingSkillsTest, toString_ShouldReturnCorrectString_WhenAllFieldsAreEmpty, TestSize.Level1)
{
    MatchingSkills matchingSkills;
    std::string expected = "";
    EXPECT_EQ(matchingSkills.ToString(), expected);
}