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
#ifndef BASE_NOTIFICATION_COMMON_EVENT_MANAGER_INCLUDE_ANI_STATIC_SUBSCRIBER_EXTENSION_CONTEXT_H
#define BASE_NOTIFICATION_COMMON_EVENT_MANAGER_INCLUDE_ANI_STATIC_SUBSCRIBER_EXTENSION_CONTEXT_H

#include <array>
#include <ani.h>
#include <iostream>
#include <unistd.h>

#include "context.h"
#include "ohos_application.h"
#include "static_subscriber_extension_context.h"

namespace OHOS {
namespace EventManagerFwkAni {
using namespace OHOS::EventFwk;
using namespace OHOS::AbilityRuntime;

ani_object CreateStaticSubscriberExtensionContext(ani_env *env,
    std::shared_ptr<EventFwk::StaticSubscriberExtensionContext> context,
    const std::shared_ptr<AppExecFwk::OHOSApplication> &application);
}  // namespace EventManagerFwkAni
}  // namespace OHOS
#endif // BASE_NOTIFICATION_COMMON_EVENT_MANAGER_INCLUDE_ANI_STATIC_SUBSCRIBER_EXTENSION_CONTEXT_H