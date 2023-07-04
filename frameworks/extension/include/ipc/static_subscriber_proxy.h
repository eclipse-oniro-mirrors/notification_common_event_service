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

#ifndef OHOS_COMMON_EVENT_SERVICE_STATIC_SUBSCRIBER_PROXY_H
#define OHOS_COMMON_EVENT_SERVICE_STATIC_SUBSCRIBER_PROXY_H

#include <iremote_proxy.h>
#include "common_event_service_ipc_interface_code.h"
#include "istatic_subscriber.h"

namespace OHOS {
namespace EventFwk {
class StaticSubscriberProxy : public IRemoteProxy<IStaticSubscriber> {
public:
    explicit StaticSubscriberProxy(const sptr<IRemoteObject>& remote) : IRemoteProxy<IStaticSubscriber>(remote) {}

    virtual ~StaticSubscriberProxy() = default;

    ErrCode OnReceiveEvent(CommonEventData* inData) override;

private:
    static inline BrokerDelegator<StaticSubscriberProxy> delegator_;
};
} // namespace EventFwk
} // namespace OHOS
#endif // OHOS_COMMON_EVENT_SERVICE_STATIC_SUBSCRIBER_PROXY_H

