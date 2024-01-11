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

#ifndef FOUNDATION_EVENT_COMMON_LOG_INCLUDE_EVENT_LOG_WRAPPER_H
#define FOUNDATION_EVENT_COMMON_LOG_INCLUDE_EVENT_LOG_WRAPPER_H

#include "hilog/log.h"

#ifndef EVENT_LOG_DOMAIN
#define EVENT_LOG_DOMAIN 0xD001200
#endif
#ifndef EVENT_LOG_TAG
#define EVENT_LOG_TAG "Ces"
#endif

#define CUR_FILE_NAME (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)

#define EVENT_LOGF(fmt, ...)            \
    ((void)HILOG_IMPL(LOG_CORE, LOG_FATAL, EVENT_LOG_DOMAIN, EVENT_LOG_TAG, \
    "[%{public}s(%{public}s:%{public}d)]" fmt, CUR_FILE_NAME, __FUNCTION__, __LINE__, ##__VA_ARGS__))
#define EVENT_LOGE(fmt, ...)            \
    ((void)HILOG_IMPL(LOG_CORE, LOG_ERROR, EVENT_LOG_DOMAIN, EVENT_LOG_TAG, \
    "[%{public}s(%{public}s:%{public}d)]" fmt, CUR_FILE_NAME, __FUNCTION__, __LINE__, ##__VA_ARGS__))
#define EVENT_LOGW(fmt, ...)            \
    ((void)HILOG_IMPL(LOG_CORE, LOG_WARN, EVENT_LOG_DOMAIN, EVENT_LOG_TAG, \
    "[%{public}s(%{public}s:%{public}d)]" fmt, CUR_FILE_NAME, __FUNCTION__, __LINE__, ##__VA_ARGS__))
#define EVENT_LOGI(fmt, ...)            \
    ((void)HILOG_IMPL(LOG_CORE, LOG_INFO, EVENT_LOG_DOMAIN, EVENT_LOG_TAG, \
    "[%{public}s(%{public}s:%{public}d)]" fmt, CUR_FILE_NAME, __FUNCTION__, __LINE__, ##__VA_ARGS__))
#define EVENT_LOGD(fmt, ...)            \
    ((void)HILOG_IMPL(LOG_CORE, LOG_DEBUG, EVENT_LOG_DOMAIN, EVENT_LOG_TAG, \
    "[%{public}s(%{public}s:%{public}d)]" fmt, CUR_FILE_NAME, __FUNCTION__, __LINE__, ##__VA_ARGS__))

#endif  // FOUNDATION_EVENT_COMMON_LOG_INCLUDE_EVENT_LOG_WRAPPER_H
