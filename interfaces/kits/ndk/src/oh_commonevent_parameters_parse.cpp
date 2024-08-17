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

#include "event_log_wrapper.h"
#include "oh_commonevent_parameters_parse.h"
#include "want.h"
#include <memory>
#include <new>

char *MallocCString(const std::string &origin)
{
    if (origin.empty()) {
        return nullptr;
    }
    auto len = origin.length() + 1;
    char *res = static_cast<char *>(malloc(sizeof(char) * len));
    if (res == nullptr) {
        return nullptr;
    }
    return std::char_traits<char>::copy(res, origin.c_str(), len);
}

char *MallocCString(const std::string &origin, int32_t &code)
{
    if (origin.empty() || code != COMMONEVENT_ERR_OK) {
        return nullptr;
    }
    auto len = origin.length() + 1;
    char *res = static_cast<char *>(malloc(sizeof(char) * len));
    if (res == nullptr) {
        code = COMMONEVENT_ERR_SYSTEM;
        return nullptr;
    }
    return std::char_traits<char>::copy(res, origin.c_str(), len);
}

void FreeCCommonEventDataCharPtr(CommonEventRcvData *cData)
{
    free(cData->data);
    free(cData->event);
    free(cData->bundleName);
    cData->data = nullptr;
    cData->event = nullptr;
    cData->bundleName = nullptr;
    auto wantPtr = reinterpret_cast<std::shared_ptr<OHOS::AAFwk::Want>*>(cData);
    delete wantPtr;
    cData->want = nullptr;
}

int32_t GetCommonEventData(const OHOS::EventFwk::CommonEventData &data, CommonEventRcvData *cData)
{
    auto want = data.GetWant();
    cData->code = data.GetCode();
    int32_t code = COMMONEVENT_ERR_OK;
    cData->data = MallocCString(data.GetData(), code);
    cData->event = MallocCString(want.GetAction(), code);
    cData->bundleName = MallocCString(want.GetBundle(), code);
    auto wantPtr = std::make_shared<OHOS::AAFwk::Want>(want);
    cData->want = new (std::nothrow) std::shared_ptr<OHOS::AAFwk::Want>(wantPtr);
    return code;
}

void FreeCCommonEventData(CommonEventRcvData *cData)
{
    FreeCCommonEventDataCharPtr(cData);
    free(cData);
    cData = nullptr;
}