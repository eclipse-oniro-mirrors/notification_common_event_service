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
#include "out/rk3568/obj/third_party/musl/intermidiates/linux/musl_src_ported/include/unistd.h"
#include "refbase.h"
#include "fuzz_common_base.h"
#include <string>
#include <vector>

namespace OHOS {
namespace {
    constexpr size_t U32_AT_SIZE = 3;
}
bool DoSomethingInterestingWithMyAPI(FuzzData fuzzData)
{
    std::string stringData = fuzzData.GenerateRandomString();
    int32_t code = fuzzData.GetData<int32_t>();
    bool enabled = fuzzData.GenerateRandomBool();
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
    uint8_t dumpType = fuzzData.GetData<uint8_t>();
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
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }
    std::vector<std::string> permissions;
    NativeTokenGet(permissions);
    OHOS::FuzzData fuzzData(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(fuzzData);
    return 0;
}
