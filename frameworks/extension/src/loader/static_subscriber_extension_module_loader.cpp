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
#include "js_static_subscriber_extension.h"

#include <dlfcn.h>

constexpr char STS_STATIC_SUBSCRIBER_EXT_LIB_NAME[] = "libstatic_subscriber_extension_ani.z.so";
static constexpr char STS_STATIC_SUBSCRIBER_EXT_CREATE_FUNC[] = "OHOS_STS_StaticSubscriberExtension_Creation";

namespace OHOS {
namespace EventFwk {

typedef StaticSubscriberExtension* (*CREATE_FUNC)(const std::unique_ptr<AbilityRuntime::Runtime>& runtime);

__attribute__((no_sanitize("cfi"))) StaticSubscriberExtension* CreateStsExtension(
    const std::unique_ptr<AbilityRuntime::Runtime>& runtime)
{
    void *handle = dlopen(STS_STATIC_SUBSCRIBER_EXT_LIB_NAME, RTLD_LAZY);
    if (handle == nullptr) {
        EVENT_LOGE("open sts_static_subscriber_extension library %{public}s failed, reason: %{public}sn",
            STS_STATIC_SUBSCRIBER_EXT_LIB_NAME, dlerror());
        return new (std::nothrow) StaticSubscriberExtension();
    }

    auto func = reinterpret_cast<CREATE_FUNC>(dlsym(handle, STS_STATIC_SUBSCRIBER_EXT_CREATE_FUNC));
    if (func == nullptr) {
        dlclose(handle);
        EVENT_LOGE("get sts_static_subscriber_extension symbol %{public}s in %{public}s failed",
            STS_STATIC_SUBSCRIBER_EXT_CREATE_FUNC, STS_STATIC_SUBSCRIBER_EXT_LIB_NAME);
        return new (std::nothrow) StaticSubscriberExtension();
    }

    auto instance = func(runtime);
    if (instance == nullptr) {
        dlclose(handle);
        EVENT_LOGE("get sts_static_subscriber_extension instance in %{public}s failed",
            STS_STATIC_SUBSCRIBER_EXT_CREATE_FUNC);
        return new (std::nothrow) StaticSubscriberExtension();
    }
    return instance;
}

StaticSubscriberExtensionModuleLoader::StaticSubscriberExtensionModuleLoader() = default;
StaticSubscriberExtensionModuleLoader::~StaticSubscriberExtensionModuleLoader() = default;

AbilityRuntime::Extension* StaticSubscriberExtensionModuleLoader::Create(
    const std::unique_ptr<AbilityRuntime::Runtime>& runtime) const
{
    EVENT_LOGD("Create module loader.");
    if (!runtime) {
        return StaticSubscriberExtension::Create(runtime);
    }

    EVENT_LOGI("Create runtime");
    switch (runtime->GetLanguage()) {
        case AbilityRuntime::Runtime::Language::JS:
            return JsStaticSubscriberExtension::Create(runtime);
        case AbilityRuntime::Runtime::Language::ETS:
            return CreateStsExtension(runtime);
        default:
            return StaticSubscriberExtension::Create(runtime);
    }
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
