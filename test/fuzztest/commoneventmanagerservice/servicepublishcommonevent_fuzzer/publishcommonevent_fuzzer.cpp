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
#include "publishcommonevent_fuzzer.h"

#include "common_event_data.h"
#define private public
#include "common_event_manager_service.h"
#include "common_utils.h"
#include "refbase.h"
#include "fuzz_common_base.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>

using namespace OHOS::EventFwk;

namespace OHOS {
bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{

    sptr<CommonEventManagerService> service = new (std::nothrow) CommonEventManagerService();
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
    sptr<IRemoteObject> commonEventListener = nullptr;

    int32_t funcResult = -1;
    service->PublishCommonEvent(commonEventData, commonEventPublishInfo, commonEventListener,
        fdp->ConsumeIntegralInRange<int32_t>(-3, 1000), funcResult);
    service->PublishCommonEvent(commonEventData, commonEventPublishInfo,
        fdp->ConsumeIntegralInRange<int32_t>(-3, 1000), funcResult);

    bool funcResult1 = false;
    service->PublishCommonEvent(commonEventData, commonEventPublishInfo, commonEventListener,
        fdp->ConsumeIntegral<uint32_t>(), fdp->ConsumeIntegral<int32_t>(),
        fdp->ConsumeIntegralInRange<int32_t>(-3, 1000), funcResult1);
    service->PublishCommonEvent(commonEventData, commonEventPublishInfo,
        fdp->ConsumeIntegral<uint32_t>(), fdp->ConsumeIntegral<int32_t>(),
        fdp->ConsumeIntegralInRange<int32_t>(-3, 1000), funcResult1);
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
    if (fdp.ConsumeBool()) {
        permissions.push_back("ohos.permission.COMMONEVEVT_STICKY");
    }
    MockRandomToken(&fdp, permissions);

    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
