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

#include "common_event_proxy.h"
#include "common_event_listener.h"
#include "commoneventproxy_fuzzer.h"
#include "fuzz_common_base.h"

namespace OHOS {
namespace {
    constexpr size_t U32_AT_SIZE = 4;
}
bool DoSomethingInterestingWithMyAPI(FuzzData fuzzData)
{
    sptr<IRemoteObject> object = nullptr;
    EventFwk::CommonEventProxy commonEventProxy(object);
    commonEventProxy.UnsubscribeCommonEvent(object);
    std::shared_ptr<EventFwk::CommonEventSubscriber> commonEventSubscriber = nullptr;
    EventFwk::CommonEventListener commonEventListener(commonEventSubscriber);
    commonEventListener.Stop();
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
    OHOS::FuzzData fuzzData(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(fuzzData);
    return 0;
}
