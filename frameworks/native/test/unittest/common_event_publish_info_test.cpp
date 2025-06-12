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
HWTEST_F(CommonEventPublishInfoTest, SetSubscriberUid_ShouldSetCorrectly_WhenUidsLessThanMax, TestSize.Level0)
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
HWTEST_F(CommonEventPublishInfoTest, SetSubscriberUid_ShouldSetCorrectly_WhenUidsMoreThanMax, TestSize.Level0)
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
HWTEST_F(CommonEventPublishInfoTest, SetSubscriberUid_ShouldSetEmpty_WhenUidsIsEmpty, TestSize.Level0)
{
    CommonEventPublishInfo commonEventPublishInfo;
    std::vector<int32_t> subscriberUids;
    commonEventPublishInfo.SetSubscriberUid(subscriberUids);
    EXPECT_TRUE(commonEventPublishInfo.GetSubscriberUid().empty());
}

/*
 * tc.number: CommonEventPublishInfo_001
 * tc.name: test ReadFromParcel
 * tc.type: FUNC
 * tc.require: issueI5RULW
 * tc.desc: Invoke ReadFromParcel interface verify whether it is normal
 */
HWTEST_F(CommonEventPublishInfoTest, CommonEventPublishInfo_001, TestSize.Level0)
{
    Parcel parcel;
    CommonEventPublishInfo commonEventPublishInfo;
    commonEventPublishInfo.SetBundleName("testBundle");
    commonEventPublishInfo.SetOrdered(true);
    commonEventPublishInfo.SetSticky(true);
    std::vector<std::string> permissions;
    permissions.push_back("testPermission");
    commonEventPublishInfo.SetSubscriberPermissions(permissions);
    commonEventPublishInfo.SetSubscriberType(OHOS::EventFwk::SYSTEM_SUBSCRIBER_TYPE);
    commonEventPublishInfo.SetValidationRule(OHOS::EventFwk::ValidationRule::OR);
    std::vector<int32_t> uids;
    commonEventPublishInfo.SetSubscriberUid(uids);

    EXPECT_EQ(commonEventPublishInfo.Marshalling(parcel), true);

    sptr<CommonEventPublishInfo> publishInfo = CommonEventPublishInfo::Unmarshalling(parcel);
    EXPECT_EQ(publishInfo->GetBundleName(), "testBundle");
    EXPECT_TRUE(publishInfo->IsOrdered());
    EXPECT_TRUE(publishInfo->IsSticky());
    EXPECT_EQ(publishInfo->GetSubscriberType(), OHOS::EventFwk::SYSTEM_SUBSCRIBER_TYPE);
    EXPECT_EQ(publishInfo->GetValidationRule(), OHOS::EventFwk::ValidationRule::OR);
    EXPECT_EQ(publishInfo->GetSubscriberPermissions().size(), 1);
    EXPECT_EQ(publishInfo->GetSubscriberUid().size(), 0);
}

HWTEST_F(CommonEventPublishInfoTest, GetFilterSettings_002, TestSize.Level0)
{
    CommonEventPublishInfo commonEventPublishInfo;
    EXPECT_EQ(commonEventPublishInfo.GetFilterSettings(), 4);
}