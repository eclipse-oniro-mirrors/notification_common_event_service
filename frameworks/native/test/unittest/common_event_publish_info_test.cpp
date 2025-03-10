/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"
#include "common_event_publish_info.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EventFwk;
namespace {
    const int32_t SUBSCRIBER_UIDS_MAX_NUM = 3;
}

class CommonEventPublishInfoTest : public ::testing::Test {
protected:
void SetUp() override {}
void TearDown() override {}
};


/**
 * @tc.name  : SetSubscriberUid_ShouldSetCorrectly_WhenUidsLessThanMax
 * @tc.number: CommonEventPublishInfoTest_001
 * @tc.desc  : Test SetSubscriberUid method when the size of subscriberUids is less than the maximum limit
 */
HWTEST_F(CommonEventPublishInfoTest, SetSubscriberUid_ShouldSetCorrectly_WhenUidsLessThanMax, TestSize.Level1)
{
    CommonEventPublishInfo commonEventPublishInfo;
    std::vector<int32_t> subscriberUids = {1, 2, 3};
    commonEventPublishInfo.SetSubscriberUid(subscriberUids);
    EXPECT_EQ(commonEventPublishInfo.GetSubscriberUid(), subscriberUids);
}

/**
 * @tc.name  : SetSubscriberUid_ShouldSetCorrectly_WhenUidsMoreThanMax
 * @tc.number: CommonEventPublishInfoTest_002
 * @tc.desc  : Test SetSubscriberUid method when the size of subscriberUids is more than the maximum limit
 */
HWTEST_F(CommonEventPublishInfoTest, SetSubscriberUid_ShouldSetCorrectly_WhenUidsMoreThanMax, TestSize.Level1)
{
    CommonEventPublishInfo commonEventPublishInfo;
    std::vector<int32_t> subscriberUids(SUBSCRIBER_UIDS_MAX_NUM + 1, 1);
    commonEventPublishInfo.SetSubscriberUid(subscriberUids);
    std::vector<int32_t> expectedUids(subscriberUids.begin(), subscriberUids.begin() + SUBSCRIBER_UIDS_MAX_NUM);
    EXPECT_EQ(commonEventPublishInfo.GetSubscriberUid(), expectedUids);
}

/**
 * @tc.name  : SetSubscriberUid_ShouldSetEmpty_WhenUidsIsEmpty
 * @tc.number: CommonEventPublishInfoTest_003
 * @tc.desc  : Test SetSubscriberUid method when the subscriberUids is empty
 */
HWTEST_F(CommonEventPublishInfoTest, SetSubscriberUid_ShouldSetEmpty_WhenUidsIsEmpty, TestSize.Level1)
{
    CommonEventPublishInfo commonEventPublishInfo;
    std::vector<int32_t> subscriberUids;
    commonEventPublishInfo.SetSubscriberUid(subscriberUids);
    EXPECT_TRUE(commonEventPublishInfo.GetSubscriberUid().empty());
}