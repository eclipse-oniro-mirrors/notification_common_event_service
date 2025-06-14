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

#ifndef BASE_NOTIFICATION_COMMON_EVENT_MANAGER_INCLUDE_ANI_STATIC_SUBSCRIBER_EXTENSION_H
#define BASE_NOTIFICATION_COMMON_EVENT_MANAGER_INCLUDE_ANI_STATIC_SUBSCRIBER_EXTENSION_H

#include <ani.h>
#include <memory>
#include <unordered_set>

#include "ani_static_subscriber_extension_context.h"
#include "ability_handler.h"
#include "common_event_data.h"
#include "common_event_manager.h"
#include "extension_base.h"
#include "native_engine/native_engine.h"
#include "ohos_application.h"
#include "static_subscriber_extension.h"
#include "static_subscriber_extension_context.h"
#include "sts_runtime.h"

class STSNativeReference;

namespace OHOS {
namespace EventManagerFwkAni {
using namespace OHOS::AppExecFwk;
using namespace OHOS::EventFwk;
using namespace OHOS::AbilityRuntime;
using CommonEventData = OHOS::EventFwk::CommonEventData;

class StsStaticSubscriberExtension : public StaticSubscriberExtension {
public:
    explicit StsStaticSubscriberExtension(AbilityRuntime::STSRuntime &stsRuntime);
    virtual ~StsStaticSubscriberExtension() override;

    static StsStaticSubscriberExtension* Create(const std::unique_ptr<AbilityRuntime::Runtime>& stsRuntime);

    void Init(const std::shared_ptr<AppExecFwk::AbilityLocalRecord>& record,
              const std::shared_ptr<AppExecFwk::OHOSApplication>& application,
              std::shared_ptr<AppExecFwk::AbilityHandler>& handler,
              const sptr<IRemoteObject>& token) override;

    void OnStart(const AAFwk::Want& want) override;

    sptr<IRemoteObject> OnConnect(const AAFwk::Want& want) override;

    void OnDisconnect(const AAFwk::Want& want) override;

    void OnStop() override;

    void OnReceiveEvent(const std::shared_ptr<CommonEventData> data) override;

    void ResetEnv(ani_env* env);

    std::weak_ptr<StsStaticSubscriberExtension> GetWeakPtr();
    
    void CallObjectMethod(bool withResult, const char* name, const char* signature, ...);

private:
    void BindContext(ani_env *env, const std::shared_ptr<OHOSApplication> &application);
    ani_object CreateSTSContext(ani_env *env, std::shared_ptr<StaticSubscriberExtensionContext> context,
        const std::shared_ptr<OHOSApplication> &application);
    std::map<uint64_t, std::shared_ptr<STSNativeReferenceWrapper>> contentSessions_;
    AbilityRuntime::STSRuntime& stsRuntime_;
    std::unique_ptr<STSNativeReference> stsObj_;
};
}  // namespace EventManagerFwkAni
}  // namespace OHOS
#endif // BASE_NOTIFICATION_COMMON_EVENT_MANAGER_INCLUDE_ANI_STATIC_SUBSCRIBER_EXTENSION_H