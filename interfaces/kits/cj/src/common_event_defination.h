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

#ifndef COMMON_EVENT_DEFINATION_H
#define COMMON_EVENT_DEFINATION_H

#include "cj_common_ffi.h"

struct CParameters {
    int8_t valueType;
    char *key;
    void *value;
    int64_t size;
};

struct CArrParameters {
    CParameters *head;
    int64_t size;
};

struct CommonEventPublishDataBycj {
    char *bundleName;
    char *data;
    int32_t code;
    CArrString permissions;
    bool isOrdered;
    bool isSticky;
    CArrParameters parameters;
};

struct CCommonEventData {
    char *event;
    char *bundleName;
    int32_t code;
    char *data;
    CArrParameters parameters;
};

namespace OHOS::CommonEventManager {
    constexpr int8_t NO_ERROR = 0;
    constexpr int8_t ERR_CES_FAILED = 1;

    char *MallocCString(const std::string &origin);
}
#endif // COMMON_EVENT_CONSTANT_H