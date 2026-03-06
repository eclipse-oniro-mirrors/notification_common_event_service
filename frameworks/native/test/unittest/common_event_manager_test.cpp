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

#include <thread>
#include <chrono>

#include <sys/time.h>

// redefine private and protected since testcase need to invoke and test private function
#define private public
#define protected public
#include "common_event_manager.h"
#undef private
#undef protected

#include <gtest/gtest.h>

using namespace testing::ext;
using namespace OHOS::EventFwk;
using OHOS::Parcel;

class CommonEventManagerTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

/*
 * Feature: CommonEventManagerTest
 * Function:CommonEventManager PublishCommonEvent
 * SubFunction: publish comonEvent
 * FunctionPoints: test publish comon event
 * EnvConditions: system run normally
 * CaseDescription:  1. subscribe common event
 *                   2. fail publish common event with wrong parameters
 */
HWTEST_F(CommonEventManagerTest, PublishCommonEvent_ShouldReturnFalse_WhenInvalidParameters, TestSize.Level0)
{
    CommonEventData data;
    CommonEventPublishInfo publishInfo;
    std::shared_ptr<CommonEventSubscriber> subscriber = nullptr;
    uid_t uid = 0;
    int32_t callerToken = 0;
    bool result = CommonEventManager::PublishCommonEvent(data, publishInfo, subscriber, uid, callerToken);
    EXPECT_FALSE(result);
}