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
#include "subscribecommonevent_fuzzer.h"

#include "common_event_data.h"
#include "common_event_listener.h"
#include "common_event_manager_service.h"
#include "common_event_subscriber.h"
#include "refbase.h"
#include "fuzz_common_base.h"

#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>

using namespace OHOS::EventFwk;
namespace OHOS {
class SubscriberTest : public CommonEventSubscriber {
public:
    explicit SubscriberTest(const CommonEventSubscribeInfo &sp) : CommonEventSubscriber(sp)
    {}

    ~SubscriberTest()
    {}

    virtual void OnReceiveEvent(const CommonEventData &data)
    {}
};

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    bool enabled = fdp->ConsumeBool();
    sptr<CommonEventManagerService> service = CommonEventManagerService::GetInstance();
    service->Init();
   
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(fdp->ConsumeRandomLengthString());
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    int32_t userId = fdp->ConsumeIntegralInRange<int32_t>(-3, 1000);
    if (fdp->ConsumeBool()) {
        subscribeInfo.SetUserId(userId);
    }
    subscribeInfo.SetPriority(fdp->ConsumeIntegral<int32_t>());
    std::shared_ptr<CommonEventSubscriber> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);
    int32_t funcResult = -1;
    sptr<IRemoteObject> commonEventListener = new (std::nothrow) CommonEventListener(subscriber);
    service->SubscribeCommonEvent(subscribeInfo, commonEventListener, fdp->ConsumeIntegral<int32_t>(), funcResult);
    
    service->UnsubscribeCommonEventSync(commonEventListener, funcResult);
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
