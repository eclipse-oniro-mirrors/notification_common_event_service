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

#include "mock_common_event_stub.h"
#include "refbase.h"
namespace OHOS {
namespace EventFwk {

sptr<MockCommonEventStub> MockCommonEventStub::instance_;
std::mutex MockCommonEventStub::instanceMutex_;

OHOS::sptr<MockCommonEventStub> MockCommonEventStub::GetInstance()
{
    std::lock_guard<std::mutex> lock(instanceMutex_);

    if (instance_ == nullptr) {
        instance_ = new (std::nothrow) MockCommonEventStub();
        if (instance_ == nullptr) {
            return nullptr;
        }
    }

    return instance_;
}

ErrCode MockCommonEventStub::PublishCommonEvent(
    const CommonEventData& event,
    const CommonEventPublishInfo& publishInfo,
    int32_t userId,
    int32_t& funcResult)
{
    EVENT_LOGD(LOG_TAG_CES, "enter");
    funcResult = ERR_OK;
    return ERR_OK;
}

ErrCode MockCommonEventStub::PublishCommonEvent(
    const CommonEventData& event,
    const CommonEventPublishInfo& publishInfo,
    const sptr<IRemoteObject>& commonEventListener,
    int32_t userId,
    int32_t& funcResult)
{
    EVENT_LOGD(LOG_TAG_CES, "enter");
    funcResult = ERR_OK;
    return ERR_OK;
}

ErrCode MockCommonEventStub::PublishCommonEvent(
    const CommonEventData& event,
    const CommonEventPublishInfo& publishInfo,
    uint32_t uid,
    int32_t callerToken,
    int32_t userId,
    bool& funcResult)
{
    EVENT_LOGD(LOG_TAG_CES, "enter");
    funcResult = ERR_OK;
    return ERR_OK;
}

ErrCode MockCommonEventStub::PublishCommonEvent(
    const CommonEventData& event,
    const CommonEventPublishInfo& publishInfo,
    const sptr<IRemoteObject>& commonEventListener,
    uint32_t uid,
    int32_t callerToken,
    int32_t userId,
    bool& funcResult)
{
    EVENT_LOGD(LOG_TAG_CES, "enter");
    funcResult = true;
    return ERR_OK;
}

int32_t MockCommonEventStub::SubscribeCommonEvent(
    const CommonEventSubscribeInfo& subscribeInfo,
    const sptr<IRemoteObject>& commonEventListener,
    int32_t instanceKey,
    int32_t& funcResult)
{
    EVENT_LOGD(LOG_TAG_CES, "enter");

    subscribeInfoPtr = std::make_shared<CommonEventSubscribeInfo>(subscribeInfo);

    funcResult = ERR_OK;
    return ERR_OK;
}

ErrCode MockCommonEventStub::UnsubscribeCommonEvent(
    const sptr<IRemoteObject>& commonEventListener,
    int32_t& funcResult)
{
    EVENT_LOGD(LOG_TAG_CES, "enter");
    funcResult = true;
    return ERR_OK;
}

ErrCode MockCommonEventStub::UnsubscribeCommonEventSync(
    const sptr<IRemoteObject>& commonEventListener,
    int32_t& funcResult)
{
    EVENT_LOGD(LOG_TAG_CES, "enter");
    funcResult = true;
    return ERR_OK;
}

ErrCode MockCommonEventStub::GetStickyCommonEvent(
    const std::string& event,
    CommonEventData& eventData,
    bool& funcResult)
{
    EVENT_LOGD(LOG_TAG_CES, "enter");
    funcResult = true;
    return ERR_OK;
}

ErrCode MockCommonEventStub::DumpState(
    uint8_t dumpType,
    const std::string& event,
    int32_t userId,
    std::vector<std::string>& state,
    bool& funcResult)
{
    EVENT_LOGD(LOG_TAG_CES, "enter");

    if (subscribeInfoPtr) {
        // get matchingSkills
        auto matchingSkills = subscribeInfoPtr->GetMatchingSkills();
        // get events
        auto events = matchingSkills.GetEvents();
        EVENT_LOGD(LOG_TAG_CES, "event size %{public}zu", events.size());

        for (auto it : events) {
            state.emplace_back(it);
        }
    } else {
        // do nothing
    }

    subscribeInfoPtr = nullptr;
    funcResult = true;
    return ERR_OK;
}

ErrCode MockCommonEventStub::FinishReceiver(
    const sptr<IRemoteObject>& proxy,
    int32_t code,
    const std::string& receiverData,
    bool abortEvent,
    bool& funcResult)
{
    EVENT_LOGD(LOG_TAG_CES, "enter");
    funcResult = true;
    return ERR_OK;
}

ErrCode MockCommonEventStub::Freeze(
    uint32_t uid,
    bool& funcResult)
{
    EVENT_LOGD(LOG_TAG_CES, "enter");
    funcResult = true;
    return ERR_OK;
}

ErrCode MockCommonEventStub::Unfreeze(
    uint32_t uid,
    bool& funcResult)
{
    EVENT_LOGD(LOG_TAG_CES, "enter");
    funcResult = true;
    return ERR_OK;
}

ErrCode MockCommonEventStub::UnfreezeAll(
    bool& funcResult)
{
    EVENT_LOGD(LOG_TAG_CES, "enter");
    funcResult = true;
    return ERR_OK;
}

ErrCode MockCommonEventStub::RemoveStickyCommonEvent(
    const std::string& event,
    int32_t& funcResult)
{
    EVENT_LOGD(LOG_TAG_CES, "enter");
    funcResult = ERR_OK;
    return ERR_OK;
}

ErrCode MockCommonEventStub::SetStaticSubscriberState(
    bool enable,
    int32_t& funcResult)
{
    EVENT_LOGD(LOG_TAG_CES, "enter");
    funcResult = ERR_OK;
    return ERR_OK;
}

ErrCode MockCommonEventStub::SetStaticSubscriberStateByEvents(
    const std::vector<std::string>& events,
    bool enable,
    int32_t& funcResult)
{
    EVENT_LOGD(LOG_TAG_CES, "enter");
    funcResult = ERR_OK;
    return ERR_OK;
}

ErrCode MockCommonEventStub::SetFreezeStatus(
    const std::set<int32_t>& pidList,
    bool isFreeze,
    bool& funcResult)
{
    EVENT_LOGD(LOG_TAG_CES, "enter");
    funcResult = ERR_OK;
    return ERR_OK;
}
} // namespace EventFwk
} // namespace OHOS
