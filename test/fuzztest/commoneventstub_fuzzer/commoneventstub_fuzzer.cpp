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

#include "common_event_stub.h"
#include "common_event_data.h"
#include "commoneventstub_fuzzer.h"
#include "fuzz_common_base.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    std::string stringData = fdp->ConsumeRandomLengthString();
    int32_t code = fdp->ConsumeIntegral<int32_t>();
    bool enabled = fdp->ConsumeBool();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    EventFwk::CommonEventStub commonEventStub;
    // test PublishCommonEvent function
    AAFwk::Want want;
    EventFwk::CommonEventData commonEventData;
    EventFwk::CommonEventData eventData(want, code, stringData);
    commonEventData.SetWant(want);
    commonEventData.SetCode(code);
    commonEventData.SetData(stringData);
    commonEventData.GetWant();
    commonEventData.GetCode();
    commonEventData.GetData();
    Parcel p;
    commonEventData.Marshalling(p);
    commonEventData.Unmarshalling(p);
    // make commonEventPublishInfo info
    EventFwk::CommonEventPublishInfo commonEventPublishInfo;
    std::vector<std::string> permissions;
    permissions.emplace_back(stringData);
    commonEventPublishInfo.SetSubscriberPermissions(permissions);
    sptr<IRemoteObject> commonEventListener = nullptr;
    commonEventStub.PublishCommonEvent(commonEventData, commonEventPublishInfo, commonEventListener, code, code, code);
    // test SubscribeCommonEvent function
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(stringData);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetPriority(code);
    commonEventStub.SubscribeCommonEvent(subscribeInfo, commonEventListener);
    // test UnsubscribeCommonEvent function
    commonEventStub.UnsubscribeCommonEvent(commonEventListener);
    // test UnsubscribeCommonEventSync function
    commonEventStub.UnsubscribeCommonEventSync(commonEventListener);
    // test GetStickyCommonEvent function
    commonEventStub.GetStickyCommonEvent(stringData, commonEventData);
    // test DumpState function
    uint8_t dumpType = fdp->ConsumeIntegral<uint8_t>();
    std::vector<std::string> state;
    state.emplace_back(stringData);
    commonEventStub.DumpState(dumpType, stringData, code, state);
    // test FinishReceiver function
    commonEventStub.FinishReceiver(commonEventListener, code, stringData, enabled);
    // test Freeze function
    commonEventStub.Freeze(code);
    // test Unfreeze function
    commonEventStub.Unfreeze(code);
    commonEventStub.OnRemoteRequest(code, dataParcel, reply, option);
    // test UnfreezeAll function
    return commonEventStub.UnfreezeAll();
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
