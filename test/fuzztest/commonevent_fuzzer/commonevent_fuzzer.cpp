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

#include "commonevent_fuzzer.h"
#include "common_event.h"
#include "common_event_constant.h"
#include "common_event_listener.h"
#include "common_event_subscriber.h"
#include "event_log_wrapper.h"
#include "fuzz_common_base.h"
#include "refbase.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <set>

namespace OHOS {
namespace EventFwk {
class TestSubscriber : public CommonEventSubscriber {
public:
    explicit TestSubscriber(const CommonEventSubscribeInfo &sp) : CommonEventSubscriber(sp)
    {}

    ~TestSubscriber()
    {}

    void OnReceiveEvent(const CommonEventData &data) override
    {
        EVENT_LOGI(LOG_TAG_CES, "OnReceiveEvent data code: %{public}d", data.GetCode());
    }
};
}  // namespace EventFwk

struct FuzzCommonEventContext {
    EventFwk::CommonEvent commonEvent;
    EventFwk::CommonEventData commonEventData;
    EventFwk::CommonEventPublishInfo commonEventPublishInfo;
    std::shared_ptr<EventFwk::TestSubscriber> subscriber;
    std::string stringData;
    int32_t code;
    std::vector<std::string> state;
};

void TestPublishCommonEvent(FuzzCommonEventContext &ctx)
{
    ctx.commonEvent.PublishCommonEvent(ctx.commonEventData, ctx.commonEventPublishInfo, ctx.subscriber);
    // test PublishCommonEvent and four paramter
    ctx.commonEvent.PublishCommonEvent(
        ctx.commonEventData, ctx.commonEventPublishInfo, ctx.subscriber, ctx.code, ctx.code);
    ctx.commonEvent.PublishCommonEventAsUser(ctx.commonEventData, ctx.commonEventPublishInfo, nullptr, ctx.code);
    ctx.commonEvent.PublishCommonEventAsUser(
        ctx.commonEventData, ctx.commonEventPublishInfo, nullptr, ctx.code, ctx.code, ctx.code);
}

void TestSubscribeCommonEvent(FuzzCommonEventContext &ctx)
{
    ctx.commonEvent.SubscribeCommonEvent(ctx.subscriber);
    ctx.commonEvent.Subscribe(ctx.subscriber);
    EventFwk::CommonEventData stickyCommonEventData;
    ctx.commonEvent.GetStickyCommonEvent(ctx.stringData, stickyCommonEventData);
    ctx.commonEvent.RemoveStickyCommonEvent(ctx.stringData);
    ctx.commonEvent.UnSubscribeCommonEvent(ctx.subscriber);
    ctx.commonEvent.UnSubscribeCommonEventSync(ctx.subscriber);
    ctx.commonEvent.Reconnect();
    ctx.commonEvent.Resubscribe();
}

void TestFreezeAndReceiverCommonEvent(FuzzedDataProvider *fdp, FuzzCommonEventContext &ctx)
{
    ctx.commonEvent.Freeze(fdp->ConsumeIntegral<uint32_t>());
    ctx.commonEvent.Unfreeze(fdp->ConsumeIntegral<uint32_t>());
    ctx.commonEvent.UnfreezeAll();
    ctx.commonEvent.SetStaticSubscriberState(fdp->ConsumeBool());
    ctx.commonEvent.SetStaticSubscriberState(ctx.state, fdp->ConsumeBool());
    std::set<int> pidList;
    pidList.insert(fdp->ConsumeIntegral<int>());
    ctx.commonEvent.SetFreezeStatus(pidList, fdp->ConsumeBool());
    sptr<IRemoteObject> receiverProxy = new (std::nothrow) EventFwk::CommonEventListener(ctx.subscriber);
    ctx.commonEvent.FinishReceiver(receiverProxy, ctx.code, ctx.stringData, fdp->ConsumeBool());
#ifdef CEM_SUPPORT_DUMP
    uint8_t dumpType = fdp->ConsumeIntegral<uint8_t>();
    ctx.commonEvent.DumpState(dumpType, ctx.stringData, ctx.code, ctx.state);
#endif
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    FuzzCommonEventContext ctx;
    ctx.code = fdp->ConsumeIntegral<int32_t>();
    ctx.stringData = fdp->ConsumeRandomLengthString();
    ctx.state.emplace_back(ctx.stringData);
    // test GetInstance function
    EventFwk::CommonEvent::GetInstance();
    // make commonEventData
    AAFwk::Want want;
    ctx.commonEventData = EventFwk::CommonEventData(want);
    ctx.commonEventData.SetCode(ctx.code);
    ctx.commonEventData.SetData(ctx.stringData);
    // make commonEventPublishInfo info
    std::vector<std::string> permissions;
    permissions.emplace_back(ctx.stringData);
    ctx.commonEventPublishInfo.SetSubscriberPermissions(permissions);
    ctx.commonEventPublishInfo.IsSticky();
    ctx.commonEventPublishInfo.GetSubscriberPermissions();
    ctx.commonEventPublishInfo.SetOrdered(fdp->ConsumeBool());
    ctx.commonEventPublishInfo.SetBundleName(ctx.stringData);
    ctx.commonEventPublishInfo.GetBundleName();
    // make CommonEventSubscriber info
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(ctx.stringData);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetDeviceId(ctx.stringData);
    ctx.subscriber = std::make_shared<EventFwk::TestSubscriber>(subscribeInfo);
    ctx.subscriber->SetCode(ctx.code);
    ctx.subscriber->GetCode();
    ctx.subscriber->SetData(ctx.stringData);
    ctx.subscriber->GetData();
    ctx.subscriber->SetCodeAndData(ctx.code, ctx.stringData);
    ctx.subscriber->AbortCommonEvent();
    ctx.subscriber->ClearAbortCommonEvent();
    ctx.subscriber->GetAbortCommonEvent();
    ctx.subscriber->GoAsyncCommonEvent();
    ctx.subscriber->GetSubscribeInfo();
    ctx.subscriber->IsOrderedCommonEvent();
    ctx.subscriber->IsStickyCommonEvent();
    TestPublishCommonEvent(ctx);
    TestSubscribeCommonEvent(ctx);
    TestFreezeAndReceiverCommonEvent(fdp, ctx);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    std::vector<std::string> permissions;
    NativeTokenGet(permissions);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
