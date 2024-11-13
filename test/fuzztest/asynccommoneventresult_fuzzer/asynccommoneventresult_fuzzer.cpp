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

#include "async_common_event_result.h"
#include "asynccommoneventresult_fuzzer.h"
#include "fuzz_common_base.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    std::string stringData = fdp->ConsumeRandomLengthString();
    int32_t code = fdp->ConsumeIntegral<int32_t>();
    bool enabled = fdp->ConsumeBool();
    std::shared_ptr<EventFwk::AsyncCommonEventResult> result = std::make_shared<EventFwk::AsyncCommonEventResult>(
        code, stringData, enabled, enabled, nullptr);
    if (result != nullptr) {
        // test SetCode function
        result->SetCode(code);
        // test GetCode function
        result->GetCode();
        // test SetData function
        result->SetData(stringData);
        // test GetData function
        result->GetData();
        // test SetCodeAndData function
        result->SetCodeAndData(code, stringData);
        // test AbortCommonEvent function
        result->AbortCommonEvent();
        // test ClearAbortCommonEvent function
        result->ClearAbortCommonEvent();
        // test GetAbortCommonEvent function
        result->GetAbortCommonEvent();
        // test IsOrderedCommonEvent function
        result->IsOrderedCommonEvent();
        // test CheckSynchronous function
        result->CheckSynchronous();
        // test IsStickyCommonEvent function
        return result->IsStickyCommonEvent();
    }
    return false;
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
