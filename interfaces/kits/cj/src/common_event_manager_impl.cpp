/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "common_event_manager_impl.h"
#include "native_log.h"
#include "common_event.h"
#include "parameter_parse.h"
#include "common_event_manager.h"
#include "securec.h"

#include "common_event_publish_info.h"

namespace OHOS::CommonEventManager {
    using Want = OHOS::AAFwk::Want;
    using CommonEventPublishInfo = OHOS::EventFwk::CommonEventPublishInfo;

    int32_t CommonEventManagerImpl::PublishEvent(char *event, int32_t userId)
    {
        Want want;
        want.SetAction(std::string(event));
        auto data = CommonEventData(want);
        return OHOS::EventFwk::CommonEventManager::PublishCommonEventAsUser(data, userId) ? NO_ERROR : ERR_CES_FAILED;
    }

    int32_t CommonEventManagerImpl::PublishEventWithData(char *event, int32_t userId,
        CommonEventPublishDataBycj options)
    {
        Want want;
        want.SetAction(std::string(event));
        // parameters
        if (options.parameters.size != 0) {
            WantParams wantP;
            SetDataParameters(options.parameters, wantP);
            want.SetParams(wantP);
        }
        auto data = CommonEventData(want, options.code, std::string(options.data));
        CommonEventPublishInfo publishInfo = CommonEventPublishInfo();
        // subPermissions
        if (options.permissions.size != 0) {
            std::vector<std::string> subscriberPermissions;
            charPtrToVector(options.permissions.head, options.permissions.size, subscriberPermissions);
            publishInfo.SetSubscriberPermissions(subscriberPermissions);
        }
        publishInfo.SetOrdered(options.isOrdered);
        publishInfo.SetSticky(options.isSticky);
        publishInfo.SetBundleName(std::string(options.bundleName));
        return OHOS::EventFwk::CommonEventManager::NewPublishCommonEventAsUser(data, publishInfo, userId);
    }

    int32_t CommonEventManagerImpl::SetStaticSubscriberState(bool enable)
    {
        return OHOS::EventFwk::CommonEventManager::SetStaticSubscriberState(enable);
    }

    int32_t CommonEventManagerImpl::RemoveStickyCommonEvent(char *event)
    {
        return OHOS::EventFwk::CommonEventManager::RemoveStickyCommonEvent(std::string(event));
    }

    std::shared_ptr<CommonEventSubscribeInfo> CommonEventManagerImpl::CreateCommonEventSubscribeInfo(
        char **event, int64_t size)
    {
        LOGI("CJ_CreateSubscribeInfo start");
        OHOS::EventFwk::MatchingSkills matchingSkills;
        for (int64_t i = 0; i < size; i++) {
            matchingSkills.AddEvent(std::string(event[i]));
        }
        CommonEventSubscribeInfo subscriberInfo(matchingSkills);
        return std::make_shared<CommonEventSubscribeInfo>(subscriberInfo);
    }

    int32_t CommonEventManagerImpl::Subscribe(std::shared_ptr<SubscriberImpl> subscriber,
        const std::function<void(CCommonEventData)> &callback)
    {
        LOGI("Start Subscribe!")
        auto errorCode = OHOS::EventFwk::CommonEventManager::NewSubscribeCommonEvent(subscriber);
        if (errorCode == NO_ERROR) {
            SetSubscribeInfo(subscriber, callback);
        }
        return errorCode;
    }

    int32_t CommonEventManagerImpl::Unsubscribe(std::shared_ptr<SubscriberImpl> subscriber)
    {
        auto errorCode = OHOS::EventFwk::CommonEventManager::NewUnSubscribeCommonEvent(subscriber);
        DeleteSubscribe(subscriber);
        return errorCode;
    }

}