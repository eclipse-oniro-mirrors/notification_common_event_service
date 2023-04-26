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

#include "static_subscriber_extension_module_loader.h"

#include "event_log_wrapper.h"
#include "static_subscriber_extension.h"

namespace OHOS {
namespace EventFwk {
StaticSubscriberExtensionModuleLoader::StaticSubscriberExtensionModuleLoader() = default;
StaticSubscriberExtensionModuleLoader::~StaticSubscriberExtensionModuleLoader() = default;

AbilityRuntime::Extension* StaticSubscriberExtensionModuleLoader::Create(
    const std::unique_ptr<AbilityRuntime::Runtime>& runtime) const
{
    EVENT_LOGD("Create module loader.");
    return StaticSubscriberExtension::Create(runtime);
}

std::map<std::string, std::string> StaticSubscriberExtensionModuleLoader::GetParams()
{
    EVENT_LOGD("Get params.");
    std::map<std::string, std::string> params;
    // type means extension type in ExtensionAbilityType of extension_ability_info.h, 7 means static_subscriber.
    params.insert(std::pair<std::string, std::string>("type", "7"));
    // extension name
    params.insert(std::pair<std::string, std::string>("name", "StaticSubscriberExtension"));
    return params;
}

extern "C" __attribute__((visibility("default"))) void* OHOS_EXTENSION_GetExtensionModule()
{
    return &StaticSubscriberExtensionModuleLoader::GetInstance();
}
} // namespace EventFwk
} // namespace OHOS
