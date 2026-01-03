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

#include "commoneventpublishinfo_fuzzer.h"
#include "fuzz_common_base.h"
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "common_event_publish_info.h"
#undef private
#undef protected

namespace OHOS {
bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    Parcel parcel;
    constexpr uint32_t TYPE_NUM = 3;
    constexpr uint32_t RULE_NUM = 2;
    constexpr uint32_t NUM_MAX = 10;
    bool enabled = fdp->ConsumeBool();
    int32_t id1 = fdp->ConsumeIntegral<int32_t>();
    int32_t id2 = fdp->ConsumeIntegral<int32_t>();
    int32_t id3 = fdp->ConsumeIntegral<int32_t>();
    uint32_t num = fdp->ConsumeIntegral<uint32_t>() % NUM_MAX;
    std::vector<int32_t> subscriberUids1{id1, id2, id3};
    std::vector<int32_t> subscriberUids2(num, id1);
    uint32_t type = fdp->ConsumeIntegral<uint32_t>() % TYPE_NUM;
    uint32_t rule = fdp->ConsumeIntegral<uint32_t>() % RULE_NUM + 1;
    EventFwk::CommonEventPublishInfo PublishInfo;
    EventFwk::CommonEventPublishInfo commonEventPublishInfo(PublishInfo);
    commonEventPublishInfo.SetSticky(enabled);
    commonEventPublishInfo.SetOrdered(enabled);
    commonEventPublishInfo.IsOrdered();
    commonEventPublishInfo.SetSubscriberUid(subscriberUids1);
    commonEventPublishInfo.SetSubscriberUid(subscriberUids2);
    commonEventPublishInfo.GetSubscriberUid();
    commonEventPublishInfo.SetSubscriberType(type);
    commonEventPublishInfo.GetSubscriberType();
    commonEventPublishInfo.SetValidationRule(static_cast<EventFwk::ValidationRule>(rule));
    commonEventPublishInfo.GetValidationRule();
    commonEventPublishInfo.GetFilterSettings();
    commonEventPublishInfo.Marshalling(parcel);
    commonEventPublishInfo.Unmarshalling(parcel);
    return true;
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
