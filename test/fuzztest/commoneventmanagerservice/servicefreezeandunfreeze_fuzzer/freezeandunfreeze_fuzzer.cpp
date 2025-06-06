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
#include "freezeandunfreeze_fuzzer.h"

#include "common_event_manager_service.h"
#include "common_event_data.h"
#include "fuzz_common_base.h"
#include "refbase.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <set>

using namespace OHOS::EventFwk;

namespace OHOS {
bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    sptr<CommonEventManagerService> service = CommonEventManagerService::GetInstance();
    service->Init();

    bool funcResult1 = false;
    service->Freeze(fdp->ConsumeIntegral<uint32_t>(), funcResult1);
    service->Unfreeze(fdp->ConsumeIntegral<uint32_t>(), funcResult1);
    service->UnfreezeAll(funcResult1);
    std::set<int32_t> pidList;
    for (int32_t i = 0; i < fdp->ConsumeIntegralInRange<int32_t>(0, 50); i++) {
        pidList.insert(fdp->ConsumeIntegral<int32_t>());
    }
    service->SetFreezeStatus(pidList, fdp->ConsumeBool(), funcResult1);
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
