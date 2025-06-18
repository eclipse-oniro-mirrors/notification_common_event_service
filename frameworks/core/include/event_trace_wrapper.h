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

#ifndef FOUNDATION_EVENT_COMMON_LOG_INCLUDE_EVENT_TRACE_WRAPPER_H
#define FOUNDATION_EVENT_COMMON_LOG_INCLUDE_EVENT_TRACE_WRAPPER_H

#include "hitrace_meter.h"

#define NOTIFICATION_HITRACE(tag) \
    HITRACE_METER_NAME_EX(HiTraceOutputLevel::HITRACE_LEVEL_INFO, tag, __PRETTY_FUNCTION__, "")

#endif  // FOUNDATION_EVENT_COMMON_LOG_INCLUDE_EVENT_TRACE_WRAPPER_H
