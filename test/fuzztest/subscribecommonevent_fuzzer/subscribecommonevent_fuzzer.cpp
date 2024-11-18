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

#define private public
#define protected public
#include "common_event_subscribe_info.h"
#undef private
#undef protected

#include "subscribecommonevent_fuzzer.h"
#include "common_event_manager.h"
#include "fuzz_common_base.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace EventFwk {
class TestSubscriber : public CommonEventSubscriber {
public:
    explicit TestSubscriber(const CommonEventSubscribeInfo &sp) : CommonEventSubscriber(sp)
    {}

    ~TestSubscriber()
    {}

    void OnReceiveEvent(const CommonEventData &data) override
    {}
};
}  // namespace EventFwk

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    std::string stringData = fdp->ConsumeRandomLengthString();

    EventFwk::MatchingSkills matchingSkills;
    Parcel parcel;
    matchingSkills.AddEvent(stringData);
    matchingSkills.AddEntity(stringData);
    matchingSkills.AddScheme(stringData);
    // set CommonEventSubscribeInfo and test CommonEventSubscribeInfo class function
    uint8_t mode = fdp->ConsumeIntegral<uint8_t>();
    EventFwk::CommonEventSubscribeInfo::ThreadMode threadMode =
        EventFwk::CommonEventSubscribeInfo::ThreadMode(mode);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    int32_t priority = fdp->ConsumeIntegral<int32_t>();
    subscribeInfo.ReadFromParcel(parcel);
    subscribeInfo.Unmarshalling(parcel);
    subscribeInfo.SetPriority(priority);
    subscribeInfo.SetPermission(stringData);
    subscribeInfo.SetDeviceId(stringData);
    subscribeInfo.SetThreadMode(threadMode);
    subscribeInfo.SetPublisherBundleName(fdp->ConsumeRandomLengthString());
    subscribeInfo.GetPriority();
    subscribeInfo.SetUserId(priority);
    subscribeInfo.GetUserId();
    subscribeInfo.GetPermission();
    subscribeInfo.GetDeviceId();
    subscribeInfo.GetMatchingSkills();
    subscribeInfo.Marshalling(parcel);

    std::shared_ptr<EventFwk::TestSubscriber> subscriber =
        std::make_shared<EventFwk::TestSubscriber>(subscribeInfo);
    if (subscriber != nullptr) {
        subscriber->IsOrderedCommonEvent();
        subscriber->IsStickyCommonEvent();
    }
    return EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber);
}
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
