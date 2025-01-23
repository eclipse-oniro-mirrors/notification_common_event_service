/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <chrono>
#include <gtest/gtest.h>
#include <thread>

#define private public
#define protected public
#include "oh_commonevent.h"
#include "oh_commonevent_parameters_parse.h"
#include "oh_commonevent_wrapper.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EventFwk;

namespace {
const char* EVENT = "com.ces.test.event";
const char* EVENT2 = "com.ces.test.event2";
const char* PUBLISHER_PERMISSION = "ohos.permission.test";
const char* PUBLISHER_PERMISSION2 = "ohos.permission.test2";
const char* TEST_BUNDLENAME = "com.example.test";
const char* TEST_DATA = "initial data";
const char* TEST_DATA2 = "test data";
const char* INT_KEY = "intKey";
const char* INT_ARRAY_KEY = "intArrayKey";
const char* LONG_KEY = "longKey";
const char* LONG_ARRAY_KEY = "longArrayKey";
const char* DOUBLE_KEY = "doubleKey";
const char* DOUBLE_ARRAY_KEY = "doubleArrayKey";
const char* BOOL_KEY = "boolKey";
const char* BOOL_ARRAY_KEY = "boolArrayKey";
const char* CHAR_KEY = "charKey";
const char* CHAR_ARRAY_KEY = "charArrayKey";
const char* INVALID_KEY = "invalidKey";
constexpr int INT_VALUE = 10;
constexpr int INT_ARRAY_VALUE[] = { 1, 2, 3 };
constexpr long LONG_VALUE = 100;
constexpr long LONG_ARRAY_VALUE[] = { 10, 20, 30 };
constexpr double DOUBLE_VALUE = 10.1;
constexpr double DOUBLE_ARRAY_VALUE[] = { 1.1, 2.2, 3.3 };
constexpr bool BOOL_VALUE = true;
constexpr bool BOOL_ARRAY_VALUE[] = { true, false, true };
constexpr char CHAR_VALUE = 'a';
const char* CHAR_ARRAY_VALUE = "abc";
constexpr int32_t TEST_CODE = 1;
constexpr int32_t TEST_CODE2 = 2;
constexpr int32_t TEST_NUM = 2;
constexpr int32_t TEST_VALUE_NUM = 3;
constexpr int32_t SLEEP_TIME = 3;
} // namespace

class CapiCommonEventTest : public testing::Test {
public:
    CapiCommonEventTest() {}
    virtual ~CapiCommonEventTest() {}

    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CapiCommonEventTest::SetUpTestCase() {}

void CapiCommonEventTest::TearDownTestCase() {}

void CapiCommonEventTest::SetUp() {}

void CapiCommonEventTest::TearDown() {}

static void OnReceive(const CommonEvent_RcvData* data)
{
    const char* event = OH_CommonEvent_GetEventFromRcvData(data);
    ASSERT_STREQ(event, EVENT);
    int code = OH_CommonEvent_GetCodeFromRcvData(data);
    ASSERT_EQ(code, TEST_CODE);
    const char* retData = OH_CommonEvent_GetDataStrFromRcvData(data);
    ASSERT_STREQ(retData, TEST_DATA);
    const CommonEvent_Parameters* parameters = OH_CommonEvent_GetParametersFromRcvData(data);
    ASSERT_NE(parameters, nullptr);
}

static void OnReceiveWithoutData(const CommonEvent_RcvData* data)
{
    const char* event = OH_CommonEvent_GetEventFromRcvData(data);
    ASSERT_STREQ(event, EVENT);
    int code = OH_CommonEvent_GetCodeFromRcvData(data);
    ASSERT_EQ(code, 0);
    const char* retData = OH_CommonEvent_GetDataStrFromRcvData(data);
    ASSERT_STREQ(retData, "");
}

/*
 * @tc.name: CapiCommonEventTest_0100
 * @tc.desc: Test create and set empty subscribeInfo.
 * @tc.type: FUNC
 */
HWTEST_F(CapiCommonEventTest, CapiCommonEventTest_0100, Function | MediumTest | Level1)
{
    const char* events[] = {};
    auto subscribeInfo = OH_CommonEvent_CreateSubscribeInfo(events, 0);
    ASSERT_EQ(subscribeInfo, nullptr);

    int32_t ret = OH_CommonEvent_SetPublisherPermission(subscribeInfo, "");
    ASSERT_EQ(ret, COMMONEVENT_ERR_INVALID_PARAMETER);

    ret = OH_CommonEvent_SetPublisherBundleName(subscribeInfo, "");
    ASSERT_EQ(ret, COMMONEVENT_ERR_INVALID_PARAMETER);

    OH_CommonEvent_DestroySubscribeInfo(subscribeInfo);
}

/*
 * @tc.name: CapiCommonEventTest_0200
 * @tc.desc: Test create and set subscribeInfo.
 * @tc.type: FUNC
 */
HWTEST_F(CapiCommonEventTest, CapiCommonEventTest_0200, Function | MediumTest | Level1)
{
    const char* events[] = { EVENT, EVENT2 };
    auto subscribeInfo = OH_CommonEvent_CreateSubscribeInfo(events, TEST_NUM);
    ASSERT_NE(subscribeInfo, nullptr);

    int32_t ret = OH_CommonEvent_SetPublisherPermission(subscribeInfo, nullptr);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);
    ASSERT_EQ(subscribeInfo->permission, std::string());

    ret = OH_CommonEvent_SetPublisherPermission(subscribeInfo, PUBLISHER_PERMISSION);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);
    ASSERT_STREQ(subscribeInfo->permission.c_str(), PUBLISHER_PERMISSION);

    ret = OH_CommonEvent_SetPublisherBundleName(subscribeInfo, nullptr);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);
    ASSERT_EQ(subscribeInfo->bundleName, std::string());

    ret = OH_CommonEvent_SetPublisherBundleName(subscribeInfo, TEST_BUNDLENAME);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);
    ASSERT_STREQ(subscribeInfo->bundleName.c_str(), TEST_BUNDLENAME);

    OH_CommonEvent_DestroySubscribeInfo(subscribeInfo);
}

/*
 * @tc.name: CapiCommonEventTest_0300
 * @tc.desc: Test create subscriber.
 * @tc.type: FUNC
 */
HWTEST_F(CapiCommonEventTest, CapiCommonEventTest_0300, Function | MediumTest | Level1)
{
    auto subscriber = OH_CommonEvent_CreateSubscriber(nullptr, OnReceive);
    ASSERT_EQ(subscriber, nullptr);

    const char* events[] = { EVENT, EVENT2 };
    auto subscribeInfo = OH_CommonEvent_CreateSubscribeInfo(events, TEST_NUM);
    ASSERT_NE(subscribeInfo, nullptr);

    auto subscriber2 = OH_CommonEvent_CreateSubscriber(subscribeInfo, OnReceive);
    ASSERT_NE(subscriber2, nullptr);

    OH_CommonEvent_DestroySubscriber(subscriber2);
}

/*
 * @tc.name: CapiCommonEventTest_0400
 * @tc.desc: Test subscribe and unsubscribe event.
 * @tc.type: FUNC
 */
HWTEST_F(CapiCommonEventTest, CapiCommonEventTest_0400, Function | MediumTest | Level1)
{
    int32_t ret = OH_CommonEvent_Subscribe(nullptr);
    ASSERT_EQ(ret, COMMONEVENT_ERR_INVALID_PARAMETER);

    const char* events[] = { EVENT, EVENT2 };
    auto subscribeInfo = OH_CommonEvent_CreateSubscribeInfo(events, TEST_NUM);
    ASSERT_NE(subscribeInfo, nullptr);

    auto subscriber = OH_CommonEvent_CreateSubscriber(subscribeInfo, OnReceive);
    ASSERT_NE(subscriber, nullptr);

    ret = OH_CommonEvent_Subscribe(subscriber);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);
    ret = OH_CommonEvent_UnSubscribe(subscriber);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);

    OH_CommonEvent_DestroySubscriber(subscriber);
}

/*
 * @tc.name: CapiCommonEventTest_0500
 * @tc.desc: Test create and set publishInfo.
 * @tc.type: FUNC
 */
HWTEST_F(CapiCommonEventTest, CapiCommonEventTest_0500, Function | MediumTest | Level1)
{
    auto publishInfo = OH_CommonEvent_CreatePublishInfo(true);
    ASSERT_NE(publishInfo, nullptr);

    int32_t ret = OH_CommonEvent_SetPublishInfoBundleName(publishInfo, nullptr);
    ASSERT_EQ(publishInfo->bundleName, std::string());
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);

    ret = OH_CommonEvent_SetPublishInfoBundleName(publishInfo, TEST_BUNDLENAME);
    ASSERT_STREQ(publishInfo->bundleName.c_str(), TEST_BUNDLENAME);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);

    const char* permissions[] = { PUBLISHER_PERMISSION, PUBLISHER_PERMISSION2 };
    ret = OH_CommonEvent_SetPublishInfoPermissions(publishInfo, permissions, TEST_NUM);
    ASSERT_FALSE(publishInfo->subscriberPermissions.empty());
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);

    const char* permissions2[] = {};
    ret = OH_CommonEvent_SetPublishInfoPermissions(publishInfo, permissions2, 0);
    ASSERT_TRUE(publishInfo->subscriberPermissions.empty());
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);

    ret = OH_CommonEvent_SetPublishInfoCode(publishInfo, TEST_CODE);
    ASSERT_EQ(publishInfo->code, TEST_CODE);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);

    ret = OH_CommonEvent_SetPublishInfoData(publishInfo, nullptr, 0);
    ASSERT_EQ(publishInfo->data, std::string());
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);

    ret = OH_CommonEvent_SetPublishInfoData(publishInfo, TEST_DATA, strlen(TEST_DATA));
    ASSERT_STREQ(publishInfo->data.c_str(), TEST_DATA);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);

    OH_CommonEvent_DestroyPublishInfo(publishInfo);
}

/*
 * @tc.name: CapiCommonEventTest_0600
 * @tc.desc: Test create empty publishInfo.
 * @tc.type: FUNC
 */
HWTEST_F(CapiCommonEventTest, CapiCommonEventTest_0600, Function | MediumTest | Level1)
{
    CommonEvent_PublishInfo* publishInfo = nullptr;
    CommonEvent_Parameters* param = nullptr;

    int32_t ret = OH_CommonEvent_SetPublishInfoBundleName(publishInfo, nullptr);
    ASSERT_EQ(ret, COMMONEVENT_ERR_INVALID_PARAMETER);

    const char* permissions[] = {};
    ret = OH_CommonEvent_SetPublishInfoPermissions(publishInfo, permissions, 0);
    ASSERT_EQ(ret, COMMONEVENT_ERR_INVALID_PARAMETER);

    ret = OH_CommonEvent_SetPublishInfoCode(publishInfo, 0);
    ASSERT_EQ(ret, COMMONEVENT_ERR_INVALID_PARAMETER);

    ret = OH_CommonEvent_SetPublishInfoData(publishInfo, nullptr, 0);
    ASSERT_EQ(ret, COMMONEVENT_ERR_INVALID_PARAMETER);

    ret = OH_CommonEvent_SetPublishInfoParameters(publishInfo, param);
    ASSERT_EQ(ret, COMMONEVENT_ERR_INVALID_PARAMETER);
}

/*
 * @tc.name: CapiCommonEventTest_0700
 * @tc.desc: Test create and set int parameters.
 * @tc.type: FUNC
 */
HWTEST_F(CapiCommonEventTest, CapiCommonEventTest_0700, Function | MediumTest | Level1)
{
    auto param = OH_CommonEvent_CreateParameters();

    int32_t ret = OH_CommonEvent_SetIntToParameters(nullptr, nullptr, 0);
    ASSERT_EQ(ret, COMMONEVENT_ERR_INVALID_PARAMETER);
    bool exist = OH_CommonEvent_HasKeyInParameters(nullptr, nullptr);
    ASSERT_FALSE(exist);
    ret = OH_CommonEvent_GetIntFromParameters(nullptr, nullptr, 0);
    ASSERT_EQ(ret, 0);

    ret = OH_CommonEvent_SetIntToParameters(param, nullptr, 0);
    ASSERT_EQ(ret, COMMONEVENT_ERR_INVALID_PARAMETER);
    exist = OH_CommonEvent_HasKeyInParameters(param, nullptr);
    ASSERT_FALSE(exist);
    ret = OH_CommonEvent_GetIntFromParameters(param, nullptr, 0);
    ASSERT_EQ(ret, 0);

    ret = OH_CommonEvent_SetIntToParameters(param, INT_KEY, INT_VALUE);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);
    exist = OH_CommonEvent_HasKeyInParameters(param, INT_KEY);
    ASSERT_TRUE(exist);
    ret = OH_CommonEvent_GetIntFromParameters(param, INVALID_KEY, 0);
    ASSERT_EQ(ret, 0);
    ret = OH_CommonEvent_GetIntFromParameters(param, INT_KEY, 0);
    ASSERT_EQ(ret, INT_VALUE);

    OH_CommonEvent_DestroyParameters(param);
}

/*
 * @tc.name: CapiCommonEventTest_0800
 * @tc.desc: Test create and set int array parameters.
 * @tc.type: FUNC
 */
HWTEST_F(CapiCommonEventTest, CapiCommonEventTest_0800, Function | MediumTest | Level1)
{
    auto param = OH_CommonEvent_CreateParameters();

    int32_t ret = OH_CommonEvent_SetIntArrayToParameters(nullptr, nullptr, nullptr, 0);
    ASSERT_EQ(ret, COMMONEVENT_ERR_INVALID_PARAMETER);
    ret = OH_CommonEvent_GetIntArrayFromParameters(nullptr, nullptr, nullptr);
    ASSERT_EQ(ret, 0);

    ret = OH_CommonEvent_SetIntArrayToParameters(param, nullptr, nullptr, 0);
    ASSERT_EQ(ret, COMMONEVENT_ERR_INVALID_PARAMETER);
    ret = OH_CommonEvent_GetIntArrayFromParameters(param, nullptr, nullptr);
    ASSERT_EQ(ret, 0);

    ret = OH_CommonEvent_SetIntArrayToParameters(param, INT_ARRAY_KEY, INT_ARRAY_VALUE, TEST_VALUE_NUM);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);
    bool exist = OH_CommonEvent_HasKeyInParameters(param, INT_ARRAY_KEY);
    ASSERT_TRUE(exist);
    int** arr = new int*;
    ret = OH_CommonEvent_GetIntArrayFromParameters(param, INVALID_KEY, arr);
    ASSERT_EQ(ret, 0);
    ret = OH_CommonEvent_GetIntArrayFromParameters(param, INT_ARRAY_KEY, arr);
    ASSERT_EQ(ret, TEST_VALUE_NUM);

    OH_CommonEvent_DestroyParameters(param);
}

/*
 * @tc.name: CapiCommonEventTest_0900
 * @tc.desc: Test create and set long parameters.
 * @tc.type: FUNC
 */
HWTEST_F(CapiCommonEventTest, CapiCommonEventTest_0900, Function | MediumTest | Level1)
{
    auto param = OH_CommonEvent_CreateParameters();

    int32_t ret = OH_CommonEvent_SetLongToParameters(nullptr, nullptr, 0);
    ASSERT_EQ(ret, COMMONEVENT_ERR_INVALID_PARAMETER);
    bool exist = OH_CommonEvent_HasKeyInParameters(nullptr, nullptr);
    ASSERT_FALSE(exist);
    long retLong = OH_CommonEvent_GetLongFromParameters(nullptr, nullptr, 0);
    ASSERT_EQ(retLong, 0);

    ret = OH_CommonEvent_SetLongToParameters(param, nullptr, 0);
    ASSERT_EQ(ret, COMMONEVENT_ERR_INVALID_PARAMETER);
    exist = OH_CommonEvent_HasKeyInParameters(param, nullptr);
    ASSERT_FALSE(exist);
    retLong = OH_CommonEvent_GetLongFromParameters(param, nullptr, 0);
    ASSERT_EQ(retLong, 0);

    ret = OH_CommonEvent_SetLongToParameters(param, LONG_KEY, LONG_VALUE);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);
    exist = OH_CommonEvent_HasKeyInParameters(param, LONG_KEY);
    ASSERT_TRUE(exist);
    retLong = OH_CommonEvent_GetLongFromParameters(param, INVALID_KEY, 0);
    ASSERT_EQ(retLong, 0);
    retLong = OH_CommonEvent_GetLongFromParameters(param, LONG_KEY, 0);
    ASSERT_EQ(retLong, LONG_VALUE);

    OH_CommonEvent_DestroyParameters(param);
}

/*
 * @tc.name: CapiCommonEventTest_1000
 * @tc.desc: Test create and set long array parameters.
 * @tc.type: FUNC
 */
HWTEST_F(CapiCommonEventTest, CapiCommonEventTest_1000, Function | MediumTest | Level1)
{
    auto param = OH_CommonEvent_CreateParameters();

    int32_t ret = OH_CommonEvent_SetLongArrayToParameters(nullptr, nullptr, nullptr, 0);
    ASSERT_EQ(ret, COMMONEVENT_ERR_INVALID_PARAMETER);
    ret = OH_CommonEvent_GetLongArrayFromParameters(nullptr, nullptr, nullptr);
    ASSERT_EQ(ret, 0);

    ret = OH_CommonEvent_SetLongArrayToParameters(param, nullptr, nullptr, 0);
    ASSERT_EQ(ret, COMMONEVENT_ERR_INVALID_PARAMETER);
    ret = OH_CommonEvent_GetLongArrayFromParameters(param, nullptr, nullptr);
    ASSERT_EQ(ret, 0);

    ret = OH_CommonEvent_SetLongArrayToParameters(param, LONG_ARRAY_KEY, LONG_ARRAY_VALUE, TEST_VALUE_NUM);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);
    bool exist = OH_CommonEvent_HasKeyInParameters(param, LONG_ARRAY_KEY);
    ASSERT_TRUE(exist);
    long** arr = new long*;
    ret = OH_CommonEvent_GetLongArrayFromParameters(param, INVALID_KEY, arr);
    ASSERT_EQ(ret, 0);
    ret = OH_CommonEvent_GetLongArrayFromParameters(param, LONG_ARRAY_KEY, arr);
    ASSERT_EQ(ret, TEST_VALUE_NUM);

    OH_CommonEvent_DestroyParameters(param);
}

/*
 * @tc.name: CapiCommonEventTest_1100
 * @tc.desc: Test create and set double parameters.
 * @tc.type: FUNC
 */
HWTEST_F(CapiCommonEventTest, CapiCommonEventTest_1100, Function | MediumTest | Level1)
{
    auto param = OH_CommonEvent_CreateParameters();

    int32_t ret = OH_CommonEvent_SetDoubleToParameters(nullptr, nullptr, 0.0);
    ASSERT_EQ(ret, COMMONEVENT_ERR_INVALID_PARAMETER);
    bool exist = OH_CommonEvent_HasKeyInParameters(nullptr, nullptr);
    ASSERT_FALSE(exist);
    double retDouble = OH_CommonEvent_GetDoubleFromParameters(nullptr, nullptr, 0.0);
    ASSERT_EQ(retDouble, 0.0);

    ret = OH_CommonEvent_SetDoubleToParameters(param, nullptr, 0.0);
    ASSERT_EQ(ret, COMMONEVENT_ERR_INVALID_PARAMETER);
    exist = OH_CommonEvent_HasKeyInParameters(param, nullptr);
    ASSERT_FALSE(exist);
    retDouble = OH_CommonEvent_GetDoubleFromParameters(param, nullptr, 0.0);
    ASSERT_EQ(retDouble, 0.0);

    ret = OH_CommonEvent_SetDoubleToParameters(param, DOUBLE_KEY, DOUBLE_VALUE);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);
    exist = OH_CommonEvent_HasKeyInParameters(param, DOUBLE_KEY);
    ASSERT_TRUE(exist);
    retDouble = OH_CommonEvent_GetDoubleFromParameters(param, INVALID_KEY, 0.0);
    ASSERT_EQ(retDouble, 0.0);
    retDouble = OH_CommonEvent_GetDoubleFromParameters(param, DOUBLE_KEY, 0.0);
    ASSERT_EQ(retDouble, DOUBLE_VALUE);

    OH_CommonEvent_DestroyParameters(param);
}

/*
 * @tc.name: CapiCommonEventTest_1200
 * @tc.desc: Test create and set double array parameters.
 * @tc.type: FUNC
 */
HWTEST_F(CapiCommonEventTest, CapiCommonEventTest_1200, Function | MediumTest | Level1)
{
    auto param = OH_CommonEvent_CreateParameters();

    int32_t ret = OH_CommonEvent_SetDoubleArrayToParameters(nullptr, nullptr, nullptr, 0);
    ASSERT_EQ(ret, COMMONEVENT_ERR_INVALID_PARAMETER);
    ret = OH_CommonEvent_GetDoubleArrayFromParameters(nullptr, nullptr, nullptr);
    ASSERT_EQ(ret, 0);

    ret = OH_CommonEvent_SetDoubleArrayToParameters(param, nullptr, nullptr, 0);
    ASSERT_EQ(ret, COMMONEVENT_ERR_INVALID_PARAMETER);
    ret = OH_CommonEvent_GetDoubleArrayFromParameters(param, nullptr, nullptr);
    ASSERT_EQ(ret, 0);

    ret = OH_CommonEvent_SetDoubleArrayToParameters(param, DOUBLE_ARRAY_KEY, DOUBLE_ARRAY_VALUE, TEST_VALUE_NUM);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);
    bool exist = OH_CommonEvent_HasKeyInParameters(param, DOUBLE_ARRAY_KEY);
    ASSERT_TRUE(exist);
    double** arr = new double*;
    ret = OH_CommonEvent_GetDoubleArrayFromParameters(param, INVALID_KEY, arr);
    ASSERT_EQ(ret, 0);
    ret = OH_CommonEvent_GetDoubleArrayFromParameters(param, DOUBLE_ARRAY_KEY, arr);
    ASSERT_EQ(ret, TEST_VALUE_NUM);

    OH_CommonEvent_DestroyParameters(param);
}

/*
 * @tc.name: CapiCommonEventTest_1300
 * @tc.desc: Test create and set bool parameters.
 * @tc.type: FUNC
 */
HWTEST_F(CapiCommonEventTest, CapiCommonEventTest_1300, Function | MediumTest | Level1)
{
    auto param = OH_CommonEvent_CreateParameters();

    int32_t ret = OH_CommonEvent_SetBoolToParameters(nullptr, nullptr, false);
    ASSERT_EQ(ret, COMMONEVENT_ERR_INVALID_PARAMETER);
    bool exist = OH_CommonEvent_HasKeyInParameters(nullptr, nullptr);
    ASSERT_FALSE(exist);
    bool retBool = OH_CommonEvent_GetBoolFromParameters(nullptr, nullptr, false);
    ASSERT_EQ(retBool, false);

    ret = OH_CommonEvent_SetBoolToParameters(param, nullptr, false);
    ASSERT_EQ(ret, COMMONEVENT_ERR_INVALID_PARAMETER);
    exist = OH_CommonEvent_HasKeyInParameters(param, nullptr);
    ASSERT_FALSE(exist);
    retBool = OH_CommonEvent_GetBoolFromParameters(param, nullptr, false);
    ASSERT_EQ(retBool, false);

    ret = OH_CommonEvent_SetBoolToParameters(param, BOOL_KEY, BOOL_VALUE);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);
    exist = OH_CommonEvent_HasKeyInParameters(param, BOOL_KEY);
    ASSERT_TRUE(exist);
    retBool = OH_CommonEvent_GetBoolFromParameters(param, INVALID_KEY, false);
    ASSERT_EQ(retBool, false);
    retBool = OH_CommonEvent_GetBoolFromParameters(param, BOOL_KEY, false);
    ASSERT_EQ(retBool, BOOL_VALUE);

    OH_CommonEvent_DestroyParameters(param);
}

/*
 * @tc.name: CapiCommonEventTest_1400
 * @tc.desc: Test create and set bool array parameters.
 * @tc.type: FUNC
 */
HWTEST_F(CapiCommonEventTest, CapiCommonEventTest_1400, Function | MediumTest | Level1)
{
    auto param = OH_CommonEvent_CreateParameters();

    int32_t ret = OH_CommonEvent_SetBoolArrayToParameters(nullptr, nullptr, nullptr, 0);
    ASSERT_EQ(ret, COMMONEVENT_ERR_INVALID_PARAMETER);
    ret = OH_CommonEvent_GetBoolArrayFromParameters(nullptr, nullptr, nullptr);
    ASSERT_EQ(ret, 0);

    ret = OH_CommonEvent_SetBoolArrayToParameters(param, nullptr, nullptr, 0);
    ASSERT_EQ(ret, COMMONEVENT_ERR_INVALID_PARAMETER);
    ret = OH_CommonEvent_GetBoolArrayFromParameters(param, nullptr, nullptr);
    ASSERT_EQ(ret, 0);

    ret = OH_CommonEvent_SetBoolArrayToParameters(param, BOOL_ARRAY_KEY, BOOL_ARRAY_VALUE, TEST_VALUE_NUM);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);
    bool exist = OH_CommonEvent_HasKeyInParameters(param, BOOL_ARRAY_KEY);
    ASSERT_TRUE(exist);
    bool** arr = new bool*;
    ret = OH_CommonEvent_GetBoolArrayFromParameters(param, INVALID_KEY, arr);
    ASSERT_EQ(ret, 0);
    ret = OH_CommonEvent_GetBoolArrayFromParameters(param, BOOL_ARRAY_KEY, arr);
    ASSERT_EQ(ret, TEST_VALUE_NUM);

    OH_CommonEvent_DestroyParameters(param);
}

/*
 * @tc.name: CapiCommonEventTest_1500
 * @tc.desc: Test create and set char parameters.
 * @tc.type: FUNC
 */
HWTEST_F(CapiCommonEventTest, CapiCommonEventTest_1500, Function | MediumTest | Level1)
{
    auto param = OH_CommonEvent_CreateParameters();

    int32_t ret = OH_CommonEvent_SetCharToParameters(nullptr, nullptr, ' ');
    ASSERT_EQ(ret, COMMONEVENT_ERR_INVALID_PARAMETER);
    bool exist = OH_CommonEvent_HasKeyInParameters(nullptr, nullptr);
    ASSERT_FALSE(exist);
    char retChar = OH_CommonEvent_GetCharFromParameters(nullptr, nullptr, ' ');
    ASSERT_EQ(retChar, ' ');

    ret = OH_CommonEvent_SetCharToParameters(param, nullptr, ' ');
    ASSERT_EQ(ret, COMMONEVENT_ERR_INVALID_PARAMETER);
    exist = OH_CommonEvent_HasKeyInParameters(param, nullptr);
    ASSERT_FALSE(exist);
    retChar = OH_CommonEvent_GetCharFromParameters(param, nullptr, ' ');
    ASSERT_EQ(retChar, ' ');

    ret = OH_CommonEvent_SetCharToParameters(param, CHAR_KEY, CHAR_VALUE);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);
    exist = OH_CommonEvent_HasKeyInParameters(param, CHAR_KEY);
    ASSERT_TRUE(exist);
    retChar = OH_CommonEvent_GetCharFromParameters(param, INVALID_KEY, ' ');
    ASSERT_EQ(retChar, ' ');
    retChar = OH_CommonEvent_GetCharFromParameters(param, CHAR_KEY, ' ');
    ASSERT_EQ(retChar, CHAR_VALUE);

    OH_CommonEvent_DestroyParameters(param);
}

/*
 * @tc.name: CapiCommonEventTest_1600
 * @tc.desc: Test create and set char array parameters.
 * @tc.type: FUNC
 */
HWTEST_F(CapiCommonEventTest, CapiCommonEventTest_1600, Function | MediumTest | Level1)
{
    auto param = OH_CommonEvent_CreateParameters();

    int32_t ret = OH_CommonEvent_SetCharArrayToParameters(nullptr, nullptr, nullptr, 0);
    ASSERT_EQ(ret, COMMONEVENT_ERR_INVALID_PARAMETER);
    ret = OH_CommonEvent_GetCharArrayFromParameters(nullptr, nullptr, nullptr);
    ASSERT_EQ(ret, 0);

    ret = OH_CommonEvent_SetCharArrayToParameters(param, nullptr, nullptr, 0);
    ASSERT_EQ(ret, COMMONEVENT_ERR_INVALID_PARAMETER);
    ret = OH_CommonEvent_GetCharArrayFromParameters(param, nullptr, nullptr);
    ASSERT_EQ(ret, 0);

    ret = OH_CommonEvent_SetCharArrayToParameters(param, CHAR_ARRAY_KEY, CHAR_ARRAY_VALUE, TEST_VALUE_NUM);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);
    bool exist = OH_CommonEvent_HasKeyInParameters(param, CHAR_ARRAY_KEY);
    ASSERT_TRUE(exist);
    char** arr = new char*;
    ret = OH_CommonEvent_GetCharArrayFromParameters(param, INVALID_KEY, arr);
    ASSERT_EQ(ret, 0);
    ret = OH_CommonEvent_GetCharArrayFromParameters(param, CHAR_ARRAY_KEY, arr);
    ASSERT_EQ(ret, TEST_VALUE_NUM + 1);

    OH_CommonEvent_DestroyParameters(param);
}

/*
 * @tc.name: CapiCommonEventTest_1700
 * @tc.desc: Test publish commonEvent.
 * @tc.type: FUNC
 */
HWTEST_F(CapiCommonEventTest, CapiCommonEventTest_1700, Function | MediumTest | Level1)
{
    int32_t ret = OH_CommonEvent_Publish(nullptr);
    ASSERT_EQ(ret, COMMONEVENT_ERR_INVALID_PARAMETER);

    ret = OH_CommonEvent_Publish(EVENT);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);
}

/*
 * @tc.name: CapiCommonEventTest_1800
 * @tc.desc: Test publish commonEvent with publishInfo.
 * @tc.type: FUNC
 */
HWTEST_F(CapiCommonEventTest, CapiCommonEventTest_1800, Function | MediumTest | Level1)
{
    auto publishInfo = OH_CommonEvent_CreatePublishInfo(true);
    ASSERT_NE(publishInfo, nullptr);

    int32_t ret = OH_CommonEvent_SetPublishInfoBundleName(publishInfo, TEST_BUNDLENAME);
    ASSERT_STREQ(publishInfo->bundleName.c_str(), TEST_BUNDLENAME);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);

    ret = OH_CommonEvent_SetPublishInfoCode(publishInfo, TEST_CODE);
    ASSERT_EQ(publishInfo->code, TEST_CODE);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);

    ret = OH_CommonEvent_SetPublishInfoData(publishInfo, TEST_DATA, strlen(TEST_DATA));
    ASSERT_STREQ(publishInfo->data.c_str(), TEST_DATA);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);

    auto param = OH_CommonEvent_CreateParameters();
    ret = OH_CommonEvent_SetIntToParameters(param, INT_KEY, INT_VALUE);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);
    ret = OH_CommonEvent_SetPublishInfoParameters(publishInfo, param);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);

    const char* events[] = { EVENT, EVENT2 };
    auto subscribeInfo = OH_CommonEvent_CreateSubscribeInfo(events, TEST_NUM);
    ASSERT_NE(subscribeInfo, nullptr);

    auto subscriber = OH_CommonEvent_CreateSubscriber(subscribeInfo, OnReceive);
    ASSERT_NE(subscriber, nullptr);

    ret = OH_CommonEvent_Subscribe(subscriber);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);

    ret = OH_CommonEvent_PublishWithInfo(nullptr, nullptr);
    ASSERT_EQ(ret, COMMONEVENT_ERR_INVALID_PARAMETER);
    ret = OH_CommonEvent_PublishWithInfo(EVENT, nullptr);
    ASSERT_EQ(ret, COMMONEVENT_ERR_INVALID_PARAMETER);
    ret = OH_CommonEvent_PublishWithInfo(EVENT, publishInfo);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);

    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_TIME));

    ret = OH_CommonEvent_UnSubscribe(subscriber);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);

    OH_CommonEvent_DestroySubscriber(subscriber);
    OH_CommonEvent_DestroyParameters(param);
    OH_CommonEvent_DestroyPublishInfo(publishInfo);
}

/*
 * @tc.name: CapiCommonEventTest_1900
 * @tc.desc: Test handle ordered common event.
 * @tc.type: FUNC
 */
HWTEST_F(CapiCommonEventTest, CapiCommonEventTest_1900, Function | MediumTest | Level1)
{
    auto publishInfo = OH_CommonEvent_CreatePublishInfo(true);
    ASSERT_NE(publishInfo, nullptr);

    const char* events[] = { EVENT, EVENT2 };
    auto subscribeInfo = OH_CommonEvent_CreateSubscribeInfo(events, TEST_NUM);
    ASSERT_NE(subscribeInfo, nullptr);

    auto subscriber = OH_CommonEvent_CreateSubscriber(subscribeInfo, OnReceiveWithoutData);
    ASSERT_NE(subscriber, nullptr);

    int32_t ret = OH_CommonEvent_Subscribe(subscriber);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);

    ret = OH_CommonEvent_PublishWithInfo(EVENT, publishInfo);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);

    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_TIME));

    bool retBool = OH_CommonEvent_IsOrderedCommonEvent(subscriber);
    ASSERT_TRUE(retBool);
    retBool = OH_CommonEvent_AbortCommonEvent(subscriber);
    ASSERT_TRUE(retBool);
    retBool = OH_CommonEvent_GetAbortCommonEvent(subscriber);
    ASSERT_TRUE(retBool);
    retBool = OH_CommonEvent_ClearAbortCommonEvent(subscriber);
    ASSERT_TRUE(retBool);
    retBool = OH_CommonEvent_GetAbortCommonEvent(subscriber);
    ASSERT_FALSE(retBool);
    retBool = OH_CommonEvent_FinishCommonEvent(subscriber);
    ASSERT_TRUE(retBool);

    ret = OH_CommonEvent_UnSubscribe(subscriber);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);

    OH_CommonEvent_DestroySubscriber(subscriber);
    OH_CommonEvent_DestroyPublishInfo(publishInfo);
}

/*
 * @tc.name: CapiCommonEventTest_2000
 * @tc.desc: Test handle ordered common event.
 * @tc.type: FUNC
 */
HWTEST_F(CapiCommonEventTest, CapiCommonEventTest_2000, Function | MediumTest | Level1)
{
    auto publishInfo = OH_CommonEvent_CreatePublishInfo(true);
    ASSERT_NE(publishInfo, nullptr);

    const char* events[] = { EVENT, EVENT2 };
    auto subscribeInfo = OH_CommonEvent_CreateSubscribeInfo(events, TEST_NUM);
    ASSERT_NE(subscribeInfo, nullptr);

    int32_t ret = OH_CommonEvent_SetPublishInfoCode(publishInfo, TEST_CODE);
    ASSERT_EQ(publishInfo->code, TEST_CODE);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);

    ret = OH_CommonEvent_SetPublishInfoData(publishInfo, TEST_DATA, strlen(TEST_DATA));
    ASSERT_STREQ(publishInfo->data.c_str(), TEST_DATA);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);

    auto param = OH_CommonEvent_CreateParameters();
    ret = OH_CommonEvent_SetPublishInfoParameters(publishInfo, param);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);

    auto subscriber = OH_CommonEvent_CreateSubscriber(subscribeInfo, OnReceive);
    ASSERT_NE(subscriber, nullptr);

    ret = OH_CommonEvent_Subscribe(subscriber);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);

    ret = OH_CommonEvent_PublishWithInfo(EVENT, publishInfo);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);

    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_TIME));

    bool retBool = OH_CommonEvent_SetCodeToSubscriber(subscriber, TEST_CODE2);
    ASSERT_TRUE(retBool);
    retBool = OH_CommonEvent_SetDataToSubscriber(subscriber, TEST_DATA2, strlen(TEST_DATA2));
    ASSERT_TRUE(retBool);
    int32_t code = OH_CommonEvent_GetCodeFromSubscriber(subscriber);
    ASSERT_EQ(code, TEST_CODE2);
    const char* data = OH_CommonEvent_GetDataFromSubscriber(subscriber);
    ASSERT_STREQ(data, TEST_DATA2);

    ret = OH_CommonEvent_UnSubscribe(subscriber);
    ASSERT_EQ(ret, COMMONEVENT_ERR_OK);

    OH_CommonEvent_DestroySubscriber(subscriber);
    OH_CommonEvent_DestroyParameters(param);
    OH_CommonEvent_DestroyPublishInfo(publishInfo);
}

/*
 * @tc.name: CapiCommonEventTest_2100
 * @tc.desc: Test handle ordered common event with empty subscriber.
 * @tc.type: FUNC
 */
HWTEST_F(CapiCommonEventTest, CapiCommonEventTest_2100, Function | MediumTest | Level1)
{
    bool ret = OH_CommonEvent_IsOrderedCommonEvent(nullptr);
    ASSERT_FALSE(ret);
    ret = OH_CommonEvent_AbortCommonEvent(nullptr);
    ASSERT_FALSE(ret);
    ret = OH_CommonEvent_GetAbortCommonEvent(nullptr);
    ASSERT_FALSE(ret);
    ret = OH_CommonEvent_ClearAbortCommonEvent(nullptr);
    ASSERT_FALSE(ret);
    ret = OH_CommonEvent_FinishCommonEvent(nullptr);
    ASSERT_FALSE(ret);
    ret = OH_CommonEvent_SetCodeToSubscriber(nullptr, 0);
    ASSERT_FALSE(ret);
    ret = OH_CommonEvent_SetDataToSubscriber(nullptr, nullptr, 0);
    ASSERT_FALSE(ret);
    int32_t code = OH_CommonEvent_GetCodeFromSubscriber(nullptr);
    ASSERT_EQ(code, 0);
    const char* data = OH_CommonEvent_GetDataFromSubscriber(nullptr);
    ASSERT_EQ(data, nullptr);
}