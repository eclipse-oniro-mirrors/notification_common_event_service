/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifndef OH_COMMONEVENT_PARAMETERS_PARSE_H
#define OH_COMMONEVENT_PARAMETERS_PARSE_H

#include "oh_commonevent_wrapper.h"
#include "securec.h"
#include "stdlib.h"
#include <string>

char *MallocCString(const std::string &origin);
int32_t GetCommonEventData(const OHOS::EventFwk::CommonEventData &data, CommonEventRcvData* cData);
void FreeCCommonEventDataCharPtr(CommonEventRcvData* cData);
void FreeCCommonEventData(CommonEventRcvData* cData);

#endif