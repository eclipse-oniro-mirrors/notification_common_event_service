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

#ifndef OHOS_COMMON_EVENT_SERVICE_JS_STATIC_SUBSCRIBER_EXTENSION_H
#define OHOS_COMMON_EVENT_SERVICE_JS_STATIC_SUBSCRIBER_EXTENSION_H

#include "common_event_data.h"
#include "js_runtime.h"
#include "native_engine/native_reference.h"
#include "native_engine/native_value.h"
#include "runtime.h"
#include "static_subscriber_extension.h"

namespace OHOS {
namespace EventFwk {
class JsStaticSubscriberExtension : public StaticSubscriberExtension {
public:
    explicit JsStaticSubscriberExtension(AbilityRuntime::JsRuntime& jsRuntime);
    virtual ~JsStaticSubscriberExtension() override;

    /**
     * @brief Create JsStaticSubscriberExtension.
     *
     * @param runtime The runtime.
     * @return The JsStaticSubscriberExtension instance.
     */
    static JsStaticSubscriberExtension* Create(const std::unique_ptr<AbilityRuntime::Runtime>& runtime);

    void Init(const std::shared_ptr<AppExecFwk::AbilityLocalRecord>& record,
              const std::shared_ptr<AppExecFwk::OHOSApplication>& application,
              std::shared_ptr<AppExecFwk::AbilityHandler>& handler,
              const sptr<IRemoteObject>& token) override;

    void OnStart(const AAFwk::Want& want) override;

    sptr<IRemoteObject> OnConnect(const AAFwk::Want& want) override;

    void OnDisconnect(const AAFwk::Want& want) override;

    void OnStop() override;

    void OnReceiveEvent(std::shared_ptr<CommonEventData> data) override;

private:
    AbilityRuntime::JsRuntime& jsRuntime_;
    std::unique_ptr<NativeReference> jsObj_;
};
} // namespace EventFwk
} // namespace OHOS
#endif // OHOS_COMMON_EVENT_SERVICE_JS_STATIC_SUBSCRIBER_EXTENSION_H
