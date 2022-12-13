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
#include "common_event_control_manager.h"
#include "ordered_event_handler.h"

using namespace testing::ext;
using namespace OHOS::EventFwk;
using namespace OHOS::AppExecFwk;

class OrderedEventHandlerTest : public testing::Test {
public:
    OrderedEventHandlerTest()
    {}
    ~OrderedEventHandlerTest()
    {}

    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void OrderedEventHandlerTest::SetUpTestCase(void)
{}

void OrderedEventHandlerTest::TearDownTestCase(void)
{}

void OrderedEventHandlerTest::SetUp(void)
{}

void OrderedEventHandlerTest::TearDown(void)
{}

/**
 * @tc.name: OrderedEventHandler_0100
 * @tc.desc: test ProcessEvent function and controlManager_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(OrderedEventHandlerTest, OrderedEventHandler_0100, Level1)
{
    GTEST_LOG_(INFO) << "OrderedEventHandler_0100 start";
    std::shared_ptr<EventRunner> runner = nullptr;
    std::shared_ptr<CommonEventControlManager> controlManager = nullptr;
    OrderedEventHandler orderedEventHandler(runner, controlManager);
    InnerEvent::Pointer event(nullptr, nullptr);
    orderedEventHandler.ProcessEvent(event);
    GTEST_LOG_(INFO) << "OrderedEventHandler_0100 end";
}

/**
 * @tc.name: OrderedEventHandler_0200
 * @tc.desc: test ProcessEvent function and event->GetInnerEventId is ORDERED_EVENT_TIMEOUT.
 * @tc.type: FUNC
 */
HWTEST_F(OrderedEventHandlerTest, OrderedEventHandler_0200, Level1)
{
    GTEST_LOG_(INFO) << "OrderedEventHandler_0200 start";
    std::shared_ptr<EventRunner> runner = nullptr;
    std::shared_ptr<CommonEventControlManager> controlManager = std::make_shared<CommonEventControlManager>();
    OrderedEventHandler orderedEventHandler(runner, controlManager);
    uint32_t eventId = 2;
    InnerEvent::Pointer event = InnerEvent::Get(eventId);
    orderedEventHandler.ProcessEvent(event);
    GTEST_LOG_(INFO) << "OrderedEventHandler_0200 end";
}

/**
 * @tc.name: OrderedEventHandler_0300
 * @tc.desc: test ProcessEvent function and event->GetInnerEventId is not ORDERED_EVENT_TIMEOUT.
 * @tc.type: FUNC
 */
HWTEST_F(OrderedEventHandlerTest, OrderedEventHandler_0300, Level1)
{
    GTEST_LOG_(INFO) << "OrderedEventHandler_0300 start";
    std::shared_ptr<EventRunner> runner = nullptr;
    std::shared_ptr<CommonEventControlManager> controlManager = std::make_shared<CommonEventControlManager>();
    OrderedEventHandler orderedEventHandler(runner, controlManager);
    uint32_t eventId = 0;
    InnerEvent::Pointer event = InnerEvent::Get(eventId);
    orderedEventHandler.ProcessEvent(event);
    GTEST_LOG_(INFO) << "OrderedEventHandler_0300 end";
}

/**
 * @tc.name: OrderedEventHandler_0400
 * @tc.desc: test ProcessEvent function and event->GetInnerEventId is ORDERED_EVENT_START.
 * @tc.type: FUNC
 */
HWTEST_F(OrderedEventHandlerTest, OrderedEventHandler_0400, Level1)
{
    GTEST_LOG_(INFO) << "OrderedEventHandler_0400 start";
    std::shared_ptr<EventRunner> runner = nullptr;
    std::shared_ptr<CommonEventControlManager> controlManager = std::make_shared<CommonEventControlManager>();
    OrderedEventHandler orderedEventHandler(runner, controlManager);
    uint32_t eventId = 1;
    InnerEvent::Pointer event = InnerEvent::Get(eventId);
    orderedEventHandler.ProcessEvent(event);
    GTEST_LOG_(INFO) << "OrderedEventHandler_0400 end";
}