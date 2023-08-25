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

#include "static_subscriber_extension.h"

#include "event_log_wrapper.h"
#include "js_static_subscriber_extension.h"
#include "runtime.h"
#include "static_subscriber_extension_context.h"

namespace OHOS {
namespace EventFwk {
using namespace OHOS::AppExecFwk;
StaticSubscriberExtension* StaticSubscriberExtension::Create(const std::unique_ptr<AbilityRuntime::Runtime>& runtime)
{
    if (!runtime) {
        return new (std::nothrow) StaticSubscriberExtension();
    }

    EVENT_LOGI("Create runtime");
    switch (runtime->GetLanguage()) {
        case AbilityRuntime::Runtime::Language::JS:
            return JsStaticSubscriberExtension::Create(runtime);
        default:
            return new (std::nothrow) StaticSubscriberExtension();
    }
}

void StaticSubscriberExtension::Init(const std::shared_ptr<AbilityLocalRecord>& record,
    const std::shared_ptr<OHOSApplication>& application,
    std::shared_ptr<AbilityHandler>& handler,
    const sptr<IRemoteObject>& token)
{
    EVENT_LOGI("Init");
    ExtensionBase<StaticSubscriberExtensionContext>::Init(record, application, handler, token);
}

std::shared_ptr<StaticSubscriberExtensionContext> StaticSubscriberExtension::CreateAndInitContext(
    const std::shared_ptr<AbilityLocalRecord>& record,
    const std::shared_ptr<OHOSApplication>& application,
    std::shared_ptr<AbilityHandler>& handler,
    const sptr<IRemoteObject>& token)
{
    std::shared_ptr<StaticSubscriberExtensionContext> context =
        ExtensionBase<StaticSubscriberExtensionContext>::CreateAndInitContext(record, application, handler, token);
    if (record == nullptr) {
        EVENT_LOGE("record is nullptr");
        return context;
    }
    return context;
}

void StaticSubscriberExtension::OnReceiveEvent(std::shared_ptr<CommonEventData> data)
{
    EVENT_LOGD("OnReceiveEvent called.");
}
} // namespace EventFwk
} // namespace OHOS
