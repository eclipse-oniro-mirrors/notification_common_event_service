/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

 #include "ces_xcollie.h"
 #include "xcollie/xcollie.h"
 #include "event_log_wrapper.h"

namespace OHOS {
namespace EventFwk {
CesXCollie::CesXCollie(const std::string& tag, uint32_t timeoutSeconds,
    std::function<void(void *)> func, void* arg, uint32_t flag)
{
    tag_ = tag;
    id_ = HiviewDFX::XCollie::GetInstance().SetTimer(tag_, timeoutSeconds, func, arg, flag);
    isCanceled_ = false;
    EVENT_LOGD("start CesXCollie, tag:%{public}s, timeoutSeconds:%{public}u,flag:%{public}u, id:%{public}d",
        tag_.c_str(), timeoutSeconds, flag, id_);
}

CesXCollie::~CesXCollie()
{
    CancelCesXCollie();
}

void CesXCollie::CancelCesXCollie()
{
    if (!isCanceled_) {
        HiviewDFX::XCollie::GetInstance().CancelTimer(id_);
        isCanceled_ = true;
        EVENT_LOGD("CancelCesXCollie tag:%{public}s, id:%{public}d", tag_.c_str(), id_);
    }
}
}
}