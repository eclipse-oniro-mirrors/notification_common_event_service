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

#ifndef OHOS_COMMON_EVENT_SERVICE_STATIC_SUBSCRIBER_EXTENSION_CONTEXT_H
#define OHOS_COMMON_EVENT_SERVICE_STATIC_SUBSCRIBER_EXTENSION_CONTEXT_H

#include "extension_context.h"
#include "want.h"

namespace OHOS {
namespace EventFwk {
class StaticSubscriberExtensionContext : public AbilityRuntime::ExtensionContext {
public:
    StaticSubscriberExtensionContext();

    virtual ~StaticSubscriberExtensionContext();

    using SelfType = StaticSubscriberExtensionContext;
    static const size_t CONTEXT_TYPE_ID;
    ErrCode StartAbility(const AAFwk::Want& want);

protected:
    bool IsContext(size_t contextTypeId) override
    {
        return contextTypeId == CONTEXT_TYPE_ID || ExtensionContext::IsContext(contextTypeId);
    }

    bool CheckCallerIsSystemApp();
    bool VerifyCallingPermission(const std::string& permissionName) const;
};
} // namespace EventFwk
} // namespace OHOS
#endif // OHOS_COMMON_EVENT_SERVICE_STATIC_SUBSCRIBER_EXTENSION_CONTEXT_H
