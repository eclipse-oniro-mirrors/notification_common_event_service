/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_CES_STANDARD_CESFWK_TOOLS_TEST_MOCK_MOCK_COMMON_EVENT_STUB_H
#define BASE_NOTIFICATION_CES_STANDARD_CESFWK_TOOLS_TEST_MOCK_MOCK_COMMON_EVENT_STUB_H

#include "gmock/gmock.h"
#include <mutex>

#include "common_event_stub.h"
#include "event_log_wrapper.h"
#include "refbase.h"

namespace OHOS {
namespace EventFwk {
class MockCommonEventStub : public CommonEventStub {
public:
    static sptr<MockCommonEventStub> GetInstance();
    MOCK_METHOD4(FinishReceiver, bool(const sptr<IRemoteObject> &proxy, const int32_t &code,
                                     const std::string &receiverData, const bool &abortEvent));
    MOCK_METHOD4(SubscribeCommonEvent, int32_t(const CommonEventSubscribeInfo& subscribeInfo,
        const sptr<IRemoteObject>& commonEventListener, int32_t instanceKey, int32_t& funcResult));
    ErrCode PublishCommonEvent(
        const CommonEventData& event,
        const CommonEventPublishInfo& publishInfo,
        int32_t userId,
        int32_t& funcResult) override;

    ErrCode PublishCommonEvent(
        const CommonEventData& event,
        const CommonEventPublishInfo& publishInfo,
        const sptr<IRemoteObject>& commonEventListener,
        int32_t userId,
        int32_t& funcResult) override;

    ErrCode PublishCommonEvent(
        const CommonEventData& event,
        const CommonEventPublishInfo& publishInfo,
        uint32_t uid,
        int32_t callerToken,
        int32_t userId,
        bool& funcResult) override;

    ErrCode PublishCommonEvent(
        const CommonEventData& event,
        const CommonEventPublishInfo& publishInfo,
        const sptr<IRemoteObject>& commonEventListener,
        uint32_t uid,
        int32_t callerToken,
        int32_t userId,
        bool& funcResult) override;

    ErrCode UnsubscribeCommonEvent(
        const sptr<IRemoteObject>& commonEventListener,
        int32_t& funcResult) override;

    ErrCode UnsubscribeCommonEventSync(
        const sptr<IRemoteObject>& commonEventListener,
        int32_t& funcResult) override;

    ErrCode GetStickyCommonEvent(
        const std::string& event,
        CommonEventData& eventData,
        bool& funcResult) override;

    ErrCode DumpState(
        uint8_t dumpType,
        const std::string& event,
        int32_t userId,
        std::vector<std::string>& state,
        bool& funcResult) override;

    ErrCode FinishReceiver(
        const sptr<IRemoteObject>& proxy,
        int32_t code,
        const std::string& receiverData,
        bool abortEvent,
        bool& funcResult) override;

    ErrCode Freeze(
        uint32_t uid,
        bool& funcResult) override;

    ErrCode Unfreeze(
        uint32_t uid,
        bool& funcResult) override;

    ErrCode UnfreezeAll(
        bool& funcResult) override;

    ErrCode RemoveStickyCommonEvent(
        const std::string& event,
        int32_t& funcResult) override;

    ErrCode SetStaticSubscriberState(
        bool enable,
        int32_t& funcResult) override;

    ErrCode SetStaticSubscriberStateByEvents(
        const std::vector<std::string>& events,
        bool enable,
        int32_t& funcResult) override;

    ErrCode SetFreezeStatus(
        const std::set<int32_t>& pidList,
        bool isFreeze,
        bool& funcResult) override;

private:
    static std::mutex instanceMutex_;
    static sptr<MockCommonEventStub> instance_;
    std::shared_ptr<CommonEventSubscribeInfo> subscribeInfoPtr;
};
}  // namespace EventFwk
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_CES_STANDARD_CESFWK_TOOLS_TEST_MOCK_MOCK_COMMON_EVENT_STUB_H
