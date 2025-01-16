/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "common_event_proxy.h"
#include "common_event_constant.h"
#include "event_log_wrapper.h"
#include "string_ex.h"
#include "ces_inner_error_code.h"

namespace OHOS {
namespace EventFwk {
using namespace OHOS::AppExecFwk;
using namespace OHOS::Notification;
namespace {
constexpr int32_t VECTOR_MAX_SIZE = 1000;
}
CommonEventProxy::CommonEventProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<ICommonEvent>(object)
{
    EVENT_LOGD("CommonEventProxy instance created");
}

CommonEventProxy::~CommonEventProxy()
{
    EVENT_LOGD("CommonEventProxy instance destroyed");
}

int32_t CommonEventProxy::PublishCommonEvent(const CommonEventData &event, const CommonEventPublishInfo &publishInfo,
    const sptr<IRemoteObject> &commonEventListener, const int32_t &userId)
{
    EVENT_LOGD("start");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EVENT_LOGE("Failed to write InterfaceToken");
        return ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID;
    }

    if (!data.WriteParcelable(&event)) {
        EVENT_LOGE("Failed to write parcelable event");
        return ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID;
    }

    if (!data.WriteParcelable(&publishInfo)) {
        EVENT_LOGE("Failed to write parcelable publishInfo");
        return ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID;
    }

    if (commonEventListener) {
        if (!data.WriteBool(true)) {
            EVENT_LOGE("Failed to write parcelable hasLastSubscrbier");
            return ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID;
        }
        if (!data.WriteRemoteObject(commonEventListener)) {
            EVENT_LOGE("Failed to write parcelable commonEventListener");
            return ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID;
        }
    } else {
        if (!data.WriteBool(false)) {
            EVENT_LOGE("Failed to write parcelable hasLastSubscrbier");
            return ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID;
        }
    }

    if (!data.WriteInt32(userId)) {
        EVENT_LOGE("Failed to write parcelable userId");
        return ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID;
    }

    bool ret = SendRequest(CommonEventInterfaceCode::CES_PUBLISH_COMMON_EVENT, data, reply);
    if (!ret) {
        EVENT_LOGE("Failed to send request");
        return ERR_NOTIFICATION_SEND_ERROR;
    }

    EVENT_LOGD("end");
    return reply.ReadInt32();
}

bool CommonEventProxy::PublishCommonEvent(const CommonEventData &event, const CommonEventPublishInfo &publishInfo,
    const sptr<IRemoteObject> &commonEventListener, const uid_t &uid, const int32_t &callerToken,
    const int32_t &userId)
{
    EVENT_LOGD("start");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EVENT_LOGE("Failed to write InterfaceToken");
        return false;
    }

    if (!data.WriteParcelable(&event)) {
        EVENT_LOGE("Failed to write parcelable event");
        return false;
    }

    if (!data.WriteParcelable(&publishInfo)) {
        EVENT_LOGE("Failed to write parcelable publishInfo");
        return false;
    }

    if (commonEventListener) {
        if (!data.WriteBool(true)) {
            EVENT_LOGE("Failed to write parcelable hasLastSubscriber");
            return false;
        }
        if (!data.WriteRemoteObject(commonEventListener)) {
            EVENT_LOGE("Failed to write parcelable commonEventListener");
            return false;
        }
    } else {
        if (!data.WriteBool(false)) {
            EVENT_LOGE("Failed to write parcelable hasLastSubscriber");
            return false;
        }
    }

    if (!data.WriteInt32(uid)) {
        EVENT_LOGE("Failed to write int uid");
        return false;
    }

    if (!data.WriteInt32(callerToken)) {
        EVENT_LOGE("Failed to write parcelable callerToken");
        return false;
    }

    if (!data.WriteInt32(userId)) {
        EVENT_LOGE("Failed to write parcelable userId");
        return false;
    }

    bool ret = SendRequest(CommonEventInterfaceCode::CES_PUBLISH_COMMON_EVENT2, data, reply);
    if (ret) {
        ret = reply.ReadBool();
    }

    EVENT_LOGD("end");
    return ret;
}

int32_t CommonEventProxy::SubscribeCommonEvent(const CommonEventSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &commonEventListener, const int32_t instanceKey)
{
    EVENT_LOGD("start");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EVENT_LOGE("Failed to write InterfaceToken");
        return ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID;
    }

    if (!data.WriteParcelable(&subscribeInfo)) {
        EVENT_LOGE("error to write parcelable subscribeInfo");
        return ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID;
    }

    if (commonEventListener != nullptr) {
        if (!data.WriteBool(true)) {
            EVENT_LOGE("error to write parcelable hasSubscriber");
            return ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID;
        }
        if (!data.WriteRemoteObject(commonEventListener)) {
            EVENT_LOGE("error to write parcelable commonEventListener");
            return ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID;
        }
    } else {
        EVENT_LOGW("invalid commonEventListener");
        if (!data.WriteBool(false)) {
            EVENT_LOGE("error to write parcelable hasSubscriber");
            return ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID;
        }
    }

    if (!data.WriteInt32(instanceKey)) {
        EVENT_LOGE("Failed to write parcelable instanceKey");
        return false;
    }

    bool ret = SendRequest(CommonEventInterfaceCode::CES_SUBSCRIBE_COMMON_EVENT, data, reply);
    if (!ret) {
        EVENT_LOGE("Failed to send request");
        return ERR_NOTIFICATION_SEND_ERROR;
    }

    EVENT_LOGD("end");
    return reply.ReadInt32();
}

int32_t CommonEventProxy::UnsubscribeCommonEvent(const sptr<IRemoteObject> &commonEventListener)
{
    EVENT_LOGD("start");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EVENT_LOGE("Failed to write InterfaceToken");
        return ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID;
    }

    if (commonEventListener != nullptr) {
        if (!data.WriteBool(true)) {
            EVENT_LOGE("Failed to write parcelable hasSubscriber");
            return ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID;
        }
        if (!data.WriteRemoteObject(commonEventListener)) {
            EVENT_LOGE("Failed to write parcelable commonEventListener");
            return ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID;
        }
    } else {
        EVENT_LOGW("invalid commonEventListener");
        if (!data.WriteBool(false)) {
            EVENT_LOGE("Failed to write parcelable hasSubscriber");
            return ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID;
        }
    }

    bool ret = SendRequest(CommonEventInterfaceCode::CES_UNSUBSCRIBE_COMMON_EVENT, data, reply);
    if (!ret) {
        EVENT_LOGE("Failed to send request");
        return ERR_NOTIFICATION_SEND_ERROR;
    }

    EVENT_LOGD("end");
    return reply.ReadInt32();
}

int32_t CommonEventProxy::UnsubscribeCommonEventSync(const sptr<IRemoteObject> &commonEventListener)
{
    EVENT_LOGD("start");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EVENT_LOGE("Failed to write InterfaceToken");
        return ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID;
    }

    if (commonEventListener != nullptr) {
        if (!data.WriteBool(true)) {
            EVENT_LOGE("Failed to write parcelable hasSubscriber");
            return ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID;
        }
        if (!data.WriteRemoteObject(commonEventListener)) {
            EVENT_LOGE("Failed to write parcelable commonEventListener");
            return ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID;
        }
    } else {
        EVENT_LOGW("invalid commonEventListener");
        if (!data.WriteBool(false)) {
            EVENT_LOGE("Failed to write parcelable hasSubscriber");
            return ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID;
        }
    }

    bool ret = SendRequest(CommonEventInterfaceCode::CES_UNSUBSCRIBE_COMMON_EVENT_SYNC, data, reply);
    if (!ret) {
        EVENT_LOGE("Failed to send request");
        return ERR_NOTIFICATION_SEND_ERROR;
    }

    EVENT_LOGD("end");
    return reply.ReadInt32();
}

bool CommonEventProxy::GetStickyCommonEvent(const std::string &event, CommonEventData &eventData)
{
    EVENT_LOGD("start");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EVENT_LOGE("Failed to write InterfaceToken");
        return false;
    }

    if (!data.WriteString16(Str8ToStr16(event))) {
        EVENT_LOGE("Failed to write string event");
        return false;
    }

    bool ret = SendRequest(CommonEventInterfaceCode::CES_GET_STICKY_COMMON_EVENT, data, reply);
    if (ret) {
        ret = reply.ReadBool();
        if (ret) {
            std::unique_ptr<CommonEventData> eventDataPtr(reply.ReadParcelable<CommonEventData>());
            eventData = *eventDataPtr;
        }
    }

    EVENT_LOGD("end");
    return ret;
}

bool CommonEventProxy::DumpState(const uint8_t &dumpType, const std::string &event, const int32_t &userId,
    std::vector<std::string> &state)
{
    EVENT_LOGD("start");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EVENT_LOGE("Failed to write InterfaceToken");
        return false;
    }

    if (!data.WriteUint8(dumpType)) {
        EVENT_LOGE("Failed to write parcelable dumpType");
        return false;
    }

    if (!data.WriteString16(Str8ToStr16(event))) {
        EVENT_LOGE("Failed to write string event");
        return false;
    }

    if (!data.WriteInt32(userId)) {
        EVENT_LOGE("Failed to write parcelable userId");
        return false;
    }

    bool ret = SendRequest(CommonEventInterfaceCode::CES_DUMP_STATE, data, reply);
    if (ret) {
        int32_t stackNum = reply.ReadInt32();
        stackNum = stackNum > MAX_HISTORY_SIZE ? MAX_HISTORY_SIZE : stackNum;
        for (int32_t i = 0; i < stackNum; i++) {
            std::string stack = Str16ToStr8(reply.ReadString16());
            state.emplace_back(stack);
        }
    }

    EVENT_LOGD("end");
    return ret;
}

bool CommonEventProxy::FinishReceiver(
    const sptr<IRemoteObject> &proxy, const int32_t &code, const std::string &receiverData, const bool &abortEvent)
{
    EVENT_LOGD("start");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EVENT_LOGE("Failed to write InterfaceToken");
        return false;
    }

    if (proxy != nullptr) {
        if (!data.WriteBool(true)) {
            EVENT_LOGE("Failed to write parcelable hasproxy");
            return false;
        }
        if (!data.WriteRemoteObject(proxy)) {
            EVENT_LOGE("Failed to write parcelable proxy");
            return false;
        }
    } else {
        EVENT_LOGW("invalid proxy");
        if (!data.WriteBool(false)) {
            EVENT_LOGE("Failed to write parcelable hasproxy");
            return false;
        }
    }

    if (!data.WriteInt32(code)) {
        EVENT_LOGE("Failed to write int code");
        return false;
    }
    if (!data.WriteString16(Str8ToStr16(receiverData))) {
        EVENT_LOGE("Failed to write string receiverData");
        return false;
    }
    if (!data.WriteBool(abortEvent)) {
        EVENT_LOGE("Failed to write bool abortEvent");
        return false;
    }

    bool ret = SendRequest(CommonEventInterfaceCode::CES_FINISH_RECEIVER, data, reply);
    if (ret) {
        ret = reply.ReadBool();
    }

    EVENT_LOGD("end");
    return ret;
}

bool CommonEventProxy::Freeze(const uid_t &uid)
{
    EVENT_LOGD("Freeze start");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EVENT_LOGE("Error to write InterfaceToken");
        return false;
    }

    if (!data.WriteInt32(uid)) {
        EVENT_LOGE("Error to write int uid");
        return false;
    }

    bool ret = SendRequest(CommonEventInterfaceCode::CES_FREEZE, data, reply);
    if (ret) {
        ret = reply.ReadBool();
    }

    EVENT_LOGD("end");
    return ret;
}

bool CommonEventProxy::Unfreeze(const uid_t &uid)
{
    EVENT_LOGD("start");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EVENT_LOGE("Failed to write InterfaceToken");
        return false;
    }

    if (!data.WriteInt32(uid)) {
        EVENT_LOGE("Failed to write int uid");
        return false;
    }

    bool ret = SendRequest(CommonEventInterfaceCode::CES_UNFREEZE, data, reply);
    if (ret) {
        ret = reply.ReadBool();
    }

    EVENT_LOGD("end");
    return ret;
}

bool CommonEventProxy::UnfreezeAll()
{
    EVENT_LOGD("start");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EVENT_LOGE("Failed to write InterfaceToken");
        return false;
    }

    bool ret = SendRequest(CommonEventInterfaceCode::CES_UNFREEZE_ALL, data, reply);
    if (ret) {
        ret = reply.ReadBool();
    }

    EVENT_LOGD("end");
    return ret;
}

int32_t CommonEventProxy::RemoveStickyCommonEvent(const std::string &event)
{
    EVENT_LOGD("start");

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EVENT_LOGE("Failed to write InterfaceToken");
        return ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID;
    }

    if (!data.WriteString16(Str8ToStr16(event))) {
        EVENT_LOGE("Failed to write string event");
        return ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID;
    }

    MessageParcel reply;
    bool ret = SendRequest(CommonEventInterfaceCode::CES_REMOVE_STICKY_COMMON_EVENT, data, reply);
    if (!ret) {
        return ERR_NOTIFICATION_SEND_ERROR;
    }

    EVENT_LOGD("end");
    return reply.ReadInt32();
}

int32_t CommonEventProxy::SetStaticSubscriberState(bool enable)
{
    EVENT_LOGD("start");

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EVENT_LOGE("Failed to write InterfaceToken");
        return ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID;
    }

    if (!data.WriteBool(enable)) {
        EVENT_LOGE("Failed to write bool enable");
        return ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID;
    }

    MessageParcel reply;
    bool ret = SendRequest(CommonEventInterfaceCode::CES_SET_STATIC_SUBSCRIBER_STATE, data, reply);
    if (!ret) {
        return ERR_NOTIFICATION_SEND_ERROR;
    }

    EVENT_LOGD("end");
    return reply.ReadInt32();
}

int32_t CommonEventProxy::SetStaticSubscriberState(const std::vector<std::string> &events, bool enable)
{
    EVENT_LOGD("Called.");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EVENT_LOGE("Failed to write interface token.");
        return ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID;
    }

    if (events.size() > VECTOR_MAX_SIZE) {
        EVENT_LOGE("Events size exceeds the max size.");
        return ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID;
    }

    if (!data.WriteStringVector(events)) {
        EVENT_LOGE("Failed to write event.");
        return ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID;
    }

    if (!data.WriteBool(enable)) {
        EVENT_LOGE("Failed to write enable.");
        return ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID;
    }

    MessageParcel reply;
    bool ret = SendRequest(CommonEventInterfaceCode::CES_SET_STATIC_SUBSCRIBER_EVENTS_STATE, data, reply);
    if (!ret) {
        return ERR_NOTIFICATION_SEND_ERROR;
    }

    return reply.ReadInt32();
}

bool CommonEventProxy::SetFreezeStatus(std::set<int> pidList, bool isFreeze)
{
    EVENT_LOGD("start");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EVENT_LOGE("Failed to write InterfaceToken");
        return false;
    }

    if (pidList.size() > VECTOR_MAX_SIZE) {
        EVENT_LOGE("PidList size exceeds the max size.");
        return false;
    }

    if (!data.WriteInt32(pidList.size())) {
        EVENT_LOGE("Failed to write int pidList size");
        return false;
    }

    for (auto it = pidList.begin(); it != pidList.end(); it++) {
        if (!data.WriteInt32(*it)) {
            EVENT_LOGE("Failed to write int pidList");
            return false;
        }
    }

    if (!data.WriteBool(isFreeze)) {
        EVENT_LOGE("Failed to write isFreeze");
        return false;
    }

    bool ret = SendRequest(CommonEventInterfaceCode::CES_SET_FREEZE_STATUS, data, reply);
    if (ret) {
        ret = reply.ReadBool();
    }

    EVENT_LOGD("end");
    return ret;
}

bool CommonEventProxy::SendRequest(CommonEventInterfaceCode code, MessageParcel &data, MessageParcel &reply)
{
    EVENT_LOGD("start");

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        EVENT_LOGE("Remote is NULL, %{public}d", code);
        return false;
    }

    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != OHOS::NO_ERROR) {
        EVENT_LOGE("Failed to SendRequest %{public}d, error code: %{public}d", code, result);
        return false;
    }

    EVENT_LOGD("end");
    return true;
}
}  // namespace EventFwk
}  // namespace OHOS