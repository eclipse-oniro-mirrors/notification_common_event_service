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

#include <inttypes.h>
#include <string>
#include "hilog/log.h"

namespace OHOS {
namespace EventFwk {
#ifndef EVENT_LOG_DOMAIN
#define EVENT_LOG_DOMAIN 0xD001200
#endif
#ifndef EVENT_LOG_TAG
#define EVENT_LOG_TAG "Ces"
#endif

enum class EventLogLevel {
    DEBUG = 0,
    INFO,
    WARN,
    ERROR,
    FATAL
};

static constexpr OHOS::HiviewDFX::HiLogLabel Event_LABEL = { LOG_CORE, EVENT_LOG_DOMAIN, EVENT_LOG_TAG };

class EventLogWrapper {
public:
    /**
     * Judges the level of the log.
     *
     * @param level Indicates the level of the log.
     * @return Returns true if success; false otherwise.
     */
    static bool JudgeLevel(const EventLogLevel& level);

    /**
     * Sets the level of the log.
     *
     * @param level Indicates the level of the log.
     */
    static void SetLogLevel(const EventLogLevel& level)
    {
        level_ = level;
    }

    /**
     * Gets the level of the log.
     *
     * @return Returns the level of the log.
     */
    static const EventLogLevel& GetLogLevel()
    {
        return level_;
    }

    /**
     * Gets the brief name of the file.
     *
     * @param str Indicates the full name of the file.
     * @return Returns the full name of the file.
     */
    static std::string GetBriefFileName(const char* str);

private:
    static EventLogLevel level_;
};

#define PRINT_LOG(LEVEL, level, fmt, ...)                    \
    if (EventLogWrapper::JudgeLevel(EventLogLevel::LEVEL))   \
    HILOG_IMPL(LOG_CORE, level, EVENT_LOG_DOMAIN, EVENT_LOG_TAG  \
        "[%{public}s:(%{public}s):%{public}d] " fmt,         \
        EventLogWrapper::GetBriefFileName(__FILE__).c_str(), \
        __FUNCTION__,                                        \
        __LINE__,                                            \
        ##__VA_ARGS__)

#define EVENT_LOGD(fmt, ...) PRINT_LOG(DEBUG, LOG_DEBUG, fmt, ##__VA_ARGS__)
#define EVENT_LOGI(fmt, ...) PRINT_LOG(INFO, LOG_INFO, fmt, ##__VA_ARGS__)
#define EVENT_LOGW(fmt, ...) PRINT_LOG(WARN, LOG_WARN, fmt, ##__VA_ARGS__)
#define EVENT_LOGE(fmt, ...) PRINT_LOG(ERROR, LOG_ERROR, fmt, ##__VA_ARGS__)
#define EVENT_LOGF(fmt, ...) PRINT_LOG(FATAL, LOG_FATAL, fmt, ##__VA_ARGS__)
}  // namespace EventFwk
}  // namespace OHOS
#endif  // FOUNDATION_EVENT_COMMON_LOG_INCLUDE_EVENT_LOG_WRAPPER_H
