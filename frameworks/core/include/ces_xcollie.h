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

#ifndef FOUNDATION_EVENT_CESFWK_INNERKITS_INCLUDE_COMMON_EVENT_CONSTANT_H
#define FOUNDATION_EVENT_CESFWK_INNERKITS_INCLUDE_COMMON_EVENT_CONSTANT_H

#include <stdint.h>

#include "xcollie/xcollie.h"

namespace OHOS {
namespace EventFwk {

static const uint32_t TIME_OUT_SECONDS = 30;

class CesXCollie {
public:
    CesXCollie(const std::string& tag, uint32_t timeoutSeconds = TIME_OUT_SECONDS,
        std::function<void(void *)> func = nullptr, void* arg = nullptr, uint32_t flag = 1);
    ~CesXCollie();

    void CancelCesXCollie();

private:
    int32_t id_;
    std::string tag_;
    bool isCanceled_;
};
}
}
#endif  // FOUNDATION_EVENT_CESFWK_INNERKITS_INCLUDE_COMMON_EVENT_DEATH_RECIPIENT_H