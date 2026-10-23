/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "static_subscriber_stub_impl.h"

#include "event_log_wrapper.h"

namespace OHOS {
namespace EventFwk {
ErrCode StaticSubscriberStubImpl::OnReceiveEvent(const CommonEventData& data)
{
    EVENT_LOGD(LOG_TAG_CES, "OnReceiveEvent begin.");
    auto extension = extension_.lock();
    if (extension == nullptr) {
        EVENT_LOGE(LOG_TAG_CES, "OnReceiveEvent end failed.");
        return ERR_INVALID_DATA;
    }
    std::shared_ptr<CommonEventData> commonEventData = std::make_shared<CommonEventData>(data);
    extension->OnReceiveEvent(commonEventData);
    return ERR_OK;
}
} // namespace EventFwk
} // namespace OHOS
