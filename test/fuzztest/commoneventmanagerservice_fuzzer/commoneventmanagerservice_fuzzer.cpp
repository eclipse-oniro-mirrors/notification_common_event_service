/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "common_event_manager_service.h"
#include "common_event_data.h"
#include "commoneventmanagerservice_fuzzer.h"
#include "refbase.h"
#include "fuzz_common_base.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>

namespace OHOS {
bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    std::string stringData = fdp->ConsumeRandomLengthString();
    int32_t code = fdp->ConsumeIntegral<int32_t>();
    bool enabled = fdp->ConsumeBool();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    EventFwk::CommonEventManagerService::GetInstance();
    sptr<EventFwk::CommonEventManagerService> service =
        sptr<EventFwk::CommonEventManagerService>(new EventFwk::CommonEventManagerService());
    service->Init();
    AAFwk::Want want;
    EventFwk::CommonEventData commonEventData;
    commonEventData.SetWant(want);
    commonEventData.SetCode(code);
    commonEventData.SetData(stringData);

    Parcel p;
    commonEventData.Marshalling(p);
    commonEventData.Unmarshalling(p);
    EventFwk::CommonEventPublishInfo commonEventPublishInfo;
    std::vector<std::string> permissions;
    permissions.emplace_back(stringData);
    commonEventPublishInfo.SetSubscriberPermissions(permissions);
    sptr<IRemoteObject> commonEventListener = nullptr;
    service->PublishCommonEvent(commonEventData, commonEventPublishInfo, commonEventListener, code);
    service->PublishCommonEvent(
        commonEventData, commonEventPublishInfo, commonEventListener, code, code, code);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(stringData);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetPriority(code);
    service->SubscribeCommonEvent(subscribeInfo, commonEventListener);
    service->UnsubscribeCommonEvent(commonEventListener);
    service->GetStickyCommonEvent(stringData, commonEventData);
    uint8_t dumpType = fdp->ConsumeIntegral<uint8_t>();
    std::vector<std::string> state;
    state.emplace_back(stringData);
    service->DumpState(dumpType, stringData, code, state);
    service->FinishReceiver(commonEventListener, code, stringData, enabled);
    service->Freeze(code);
    service->Unfreeze(code);
    service->UnfreezeAll();
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
