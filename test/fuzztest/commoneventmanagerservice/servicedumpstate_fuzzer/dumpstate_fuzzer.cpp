/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "dumpstate_fuzzer.h"

#include "common_event_manager_service.h"
#include "common_event_data.h"
#include "fuzz_common_base.h"
#include "refbase.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>

using namespace OHOS::EventFwk;

namespace OHOS {
bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    sptr<CommonEventManagerService> service = CommonEventManagerService::GetInstance();
    service->Init();

    AAFwk::Want want;
    want.SetAction(fdp->ConsumeRandomLengthString());
    CommonEventData commonEventData;
    commonEventData.SetWant(want);
    commonEventData.SetCode(fdp->ConsumeIntegral<int32_t>());
    commonEventData.SetData(fdp->ConsumeRandomLengthString());
    CommonEventPublishInfo commonEventPublishInfo;
    if (fdp->ConsumeBool()) {
        std::vector<std::string> permissions;
        permissions.emplace_back(fdp->ConsumeRandomLengthString());
        commonEventPublishInfo.SetSubscriberPermissions(permissions);
    }
    commonEventPublishInfo.SetOrdered(fdp->ConsumeBool());

    int32_t funcResult = -1;
    service->PublishCommonEvent(commonEventData, commonEventPublishInfo,
        fdp->ConsumeIntegralInRange<int32_t>(-3, 1000), funcResult);
    
    uint8_t dumpType = fdp->ConsumeIntegral<uint8_t>();
    std::vector<std::string> state;
    bool funcResult1 = false;
    
    service->DumpState(dumpType, fdp->ConsumeRandomLengthString(), fdp->ConsumeIntegralInRange<int32_t>(-3, 1000),
        state, funcResult1);
    usleep(10000);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    std::vector<std::string> permissions;
    MockRandomToken(&fdp, permissions);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
