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
#include "setstaticsubscriberstate_fuzzer.h"

#define private public
#include "common_event_manager_service.h"
#include "common_utils.h"
#include "fuzz_common_base.h"
#include "refbase.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>

using namespace OHOS::EventFwk;

namespace OHOS {
bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    sptr<CommonEventManagerService> service = new (std::nothrow) CommonEventManagerService();
    service->Init();

    std::vector<std::string> events;
    for (int32_t i = 0; i < fdp->ConsumeIntegralInRange<int32_t>(0, 50); i++) {
        events.push_back(fdp->ConsumeRandomLengthString());
    }
    int32_t funcResult1 = -1;
    service->SetStaticSubscriberStateByEvents(events, fdp->ConsumeBool(), funcResult1);
    usleep(10000);
    CleanFfrt(service);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    std::vector<std::string> permissions;
    SystemHapTokenGet(permissions);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
