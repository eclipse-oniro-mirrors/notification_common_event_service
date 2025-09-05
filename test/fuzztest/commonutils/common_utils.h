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
#ifndef TEST_FUZZTEST_COMMON_UTILS_H
#define TEST_FUZZTEST_COMMON_UTILS_H

#include "common_event_manager_service.h"

inline void CleanFfrt(OHOS::sptr<OHOS::EventFwk::CommonEventManagerService> &service)
{
    service->commonEventSrvQueue_.reset();
    service->innerCommonEventManager_->controlPtr_->orderedQueue_.reset();
    service->innerCommonEventManager_->controlPtr_->unorderedQueue_.reset();
    service->innerCommonEventManager_->controlPtr_->unorderedImmediateQueue_.reset();
}

#endif