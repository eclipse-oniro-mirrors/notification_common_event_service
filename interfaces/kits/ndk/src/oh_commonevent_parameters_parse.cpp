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

#include "oh_commonevent_parameters_parse.h"

namespace OHOS {
namespace EventFwk {
int32_t GetStringFromParams(const CArrParameters& parameters, const std::string& key, char** str)
{
    AAFwk::IString* ao = AAFwk::IString::Query(parameters.wantParams.GetParam(key));
    if (ao == nullptr) {
        EVENT_LOGE(LOG_TAG_CES_CAPI, "No value");
        return 0;
    }

    std::string nativeValue = OHOS::AAFwk::String::Unbox(ao);
    size_t size = nativeValue.length() + 1;
    *str = static_cast<char*>(malloc(size));
    if (*str == nullptr) {
        EVENT_LOGE(LOG_TAG_CES_CAPI, "malloc fail");
        return 0;
    }
    parameters.allocatedPointers.push_back(*str);
    std::char_traits<char>::copy(*str, nativeValue.c_str(), size);
    return static_cast<int32_t>(size);
}
}  // namespace EventFwk
}  // namespace OHOS