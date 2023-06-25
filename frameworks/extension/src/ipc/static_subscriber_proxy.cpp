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

#include "static_subscriber_proxy.h"

namespace OHOS {
namespace EventFwk {
ErrCode StaticSubscriberProxy::OnReceiveEvent(CommonEventData* inData)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return ERR_INVALID_VALUE;
    }

    data.WriteParcelable(inData);

    int32_t st = Remote()->SendRequest(static_cast<uint32_t>(CommonEventInterfaceCode::COMMAND_ON_RECEIVE_EVENT), data, reply, option);
    if (st != ERR_NONE) {
        return st;
    }

    ErrCode ec = reply.ReadInt32();
    if (FAILED(ec)) {
        return ec;
    }

    return ERR_OK;
}
} // namespace EventFwk
} // namespace OHOS
