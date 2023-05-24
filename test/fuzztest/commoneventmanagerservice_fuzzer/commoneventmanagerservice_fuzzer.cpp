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
#include "securec.h"

namespace OHOS {
namespace {
    constexpr size_t U32_AT_SIZE = 4;
    constexpr uint8_t ENABLE = 2;
}
bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    std::string stringData(data);
    int32_t code = U32_AT(reinterpret_cast<const uint8_t*>(data));
    bool enabled = *data % ENABLE;
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    EventFwk::CommonEventManagerService commonEventManagerService;
    AAFwk::Want want;
    EventFwk::CommonEventData commonEventData;
    commonEventData.SetWant(want);
    commonEventData.SetCode(code);
    commonEventData.SetData(stringData);
    commonEventData.GetWant();
    commonEventData.GetCode();
    commonEventData.GetData();
    Parcel p;
    commonEventData.Marshalling(p);
    commonEventData.Unmarshalling(p);
    EventFwk::CommonEventPublishInfo commonEventPublishInfo;
    std::vector<std::string> permissions;
    permissions.emplace_back(stringData);
    commonEventPublishInfo.SetSubscriberPermissions(permissions);
    sptr<IRemoteObject> commonEventListener = nullptr;
    commonEventManagerService.PublishCommonEvent(commonEventData, commonEventPublishInfo, commonEventListener, code);
    commonEventManagerService.PublishCommonEvent(
        commonEventData, commonEventPublishInfo, commonEventListener, code, code, code);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(stringData);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetPriority(code);
    commonEventManagerService.SubscribeCommonEvent(subscribeInfo, commonEventListener);
    commonEventManagerService.UnsubscribeCommonEvent(commonEventListener);
    commonEventManagerService.GetStickyCommonEvent(stringData, commonEventData);
    uint8_t dumpType = *data;
    std::vector<std::string> state;
    state.emplace_back(stringData);
    commonEventManagerService.DumpState(dumpType, stringData, code, state);
    commonEventManagerService.FinishReceiver(commonEventListener, code, stringData, enabled);
    commonEventManagerService.Freeze(code);
    commonEventManagerService.Unfreeze(code);
    return commonEventManagerService.UnfreezeAll();
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

    char* ch = (char *)malloc(size + 1);
    if (ch == nullptr) {
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size, data, size) != EOK) {
        free(ch);
        ch = nullptr;
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}
