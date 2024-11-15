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

#include "publishcommonevent_fuzzer.h"
#include "securec.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "fuzz_common_base.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>

namespace OHOS {

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_TEST_ACTION1);
    EventFwk::CommonEventData commonEventData;
    commonEventData.SetWant(want);
    int32_t code = fdp->ConsumeIntegral<int32_t>();
    commonEventData.SetCode(code);
    std::string stringData = fdp->ConsumeRandomLengthString();
    commonEventData.SetData(stringData);

    EventFwk::CommonEventPublishInfo commonEventPublishInfo;
    std::vector<std::string> permissions;
    permissions.emplace_back(stringData);
    commonEventPublishInfo.SetSubscriberPermissions(permissions);

    std::shared_ptr<EventFwk::CommonEventSubscriber> subscriber = nullptr;

    // test pubilshCommonEvent function and two paramter
    EventFwk::CommonEventManager::PublishCommonEvent(commonEventData, commonEventPublishInfo);
    EventFwk::CommonEventManager::NewPublishCommonEvent(commonEventData, commonEventPublishInfo);

    EventFwk::CommonEventManager::PublishCommonEvent(commonEventData, commonEventPublishInfo, subscriber);
    int32_t uid = fdp->ConsumeIntegral<int32_t>();
    EventFwk::CommonEventManager::PublishCommonEvent(
        commonEventData, commonEventPublishInfo, subscriber, uid, code);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    std::vector<std::string> permissions;
    NativeTokenGet(permissions);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
