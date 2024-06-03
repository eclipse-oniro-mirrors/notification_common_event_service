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

#include "subscribe_info.h"
#include "subscriber.h"
#include "common_event_defination.h"

namespace OHOS::CommonEventManager {
    // CommonEventSubscribeInfoImpl
    void CommonEventSubscribeInfoImpl::SetPriority(int32_t &priority)
    {
        return info_->SetPriority(priority);
    }

    int32_t CommonEventSubscribeInfoImpl::GetPriority()
    {
        return info_->GetPriority();
    }

    void CommonEventSubscribeInfoImpl::SetUserId(int32_t &userId)
    {
        return info_->SetUserId(userId);
    }

    int32_t CommonEventSubscribeInfoImpl::GetUserId()
    {
        return info_->GetUserId();
    }

    void CommonEventSubscribeInfoImpl::SetPermission(const std::string &permission)
    {
        return info_->SetPermission(permission);
    }

    std::string CommonEventSubscribeInfoImpl::GetPermission()
    {
        return info_->GetPermission();
    }

    void CommonEventSubscribeInfoImpl::SetDeviceId(const std::string &deviceId)
    {
        return info_->SetDeviceId(deviceId);
    }

    std::string CommonEventSubscribeInfoImpl::GetDeviceId()
    {
        return info_->GetDeviceId();
    }

    void CommonEventSubscribeInfoImpl::SetPublisherBundleName(const std::string &publisherBundleName)
    {
        return info_->SetPublisherBundleName(publisherBundleName);
    }

    std::string CommonEventSubscribeInfoImpl::GetPublisherBundleName()
    {
        return info_->GetPublisherBundleName();
    }

    std::vector<std::string> CommonEventSubscribeInfoImpl::GetEvents()
    {
        return info_->GetMatchingSkills().GetEvents();
    }

    std::shared_ptr<CommonEventSubscribeInfo> CommonEventSubscribeInfoImpl::GetInfoPtr()
    {
        return info_;
    }
}