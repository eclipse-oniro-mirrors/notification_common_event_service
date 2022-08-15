/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "common_event_manager_service.h"

#include "access_token_helper.h"
#include "accesstoken_kit.h"
#include "bundle_manager_helper.h"
#include "common_event_constant.h"
#include "datetime_ex.h"
#include "event_log_wrapper.h"
#include "hitrace_meter.h"
#include "ipc_skeleton.h"
#include "publish_manager.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace EventFwk {
CommonEventManagerService::CommonEventManagerService()
    : serviceRunningState_(ServiceRunningState::STATE_NOT_START),
      runner_(nullptr),
      handler_(nullptr)
{
    EVENT_LOGI("instance created");
}

CommonEventManagerService::~CommonEventManagerService()
{
    EVENT_LOGI("instance destroyed");
}

ErrCode CommonEventManagerService::Init()
{
    EVENT_LOGI("ready to init");
    innerCommonEventManager_ = std::make_shared<InnerCommonEventManager>();
    if (!innerCommonEventManager_) {
        EVENT_LOGE("Failed to init without inner service");
        return ERR_INVALID_OPERATION;
    }

    runner_ = EventRunner::Create("CesSrvMain");
    if (!runner_) {
        EVENT_LOGE("Failed to init due to create runner error");
        return ERR_INVALID_OPERATION;
    }
    handler_ = std::make_shared<EventHandler>(runner_);
    if (!handler_) {
        EVENT_LOGE("Failed to init due to create handler error");
        return ERR_INVALID_OPERATION;
    }

    serviceRunningState_ = ServiceRunningState::STATE_RUNNING;

    return ERR_OK;
}

bool CommonEventManagerService::IsReady() const
{
    if (!innerCommonEventManager_) {
        EVENT_LOGE("innerCommonEventManager is null");
        return false;
    }

    if (!handler_) {
        EVENT_LOGE("handler is null");
        return false;
    }

    return true;
}

bool CommonEventManagerService::PublishCommonEvent(const CommonEventData &event,
    const CommonEventPublishInfo &publishinfo, const sptr<IRemoteObject> &commonEventListener, const int32_t &userId)
{
    EVENT_LOGI("enter");

    if (!IsReady()) {
        return false;
    }

    return PublishCommonEventDetailed(event,
        publishinfo,
        commonEventListener,
        IPCSkeleton::GetCallingPid(),
        IPCSkeleton::GetCallingUid(),
        userId);
}

bool CommonEventManagerService::PublishCommonEvent(const CommonEventData &event,
    const CommonEventPublishInfo &publishinfo, const sptr<IRemoteObject> &commonEventListener, const uid_t &uid,
    const int32_t &userId)
{
    EVENT_LOGI("enter");

    if (!IsReady()) {
        return false;
    }

    return PublishCommonEventDetailed(event, publishinfo, commonEventListener, UNDEFINED_PID, uid, userId);
}

bool CommonEventManagerService::PublishCommonEventDetailed(const CommonEventData &event,
    const CommonEventPublishInfo &publishinfo, const sptr<IRemoteObject> &commonEventListener, const pid_t &pid,
    const uid_t &uid, const int32_t &userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    EVENT_LOGI("enter");

    Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    EVENT_LOGI("callerToken = %{public}d", callerToken);
    if (AccessTokenHelper::IsDlpHap(callerToken)) {
        EVENT_LOGE("DLP hap not allowed to send common event");
        return false;
    }
    struct tm recordTime = {0};
    if (!GetSystemCurrentTime(&recordTime)) {
        EVENT_LOGE("Failed to GetSystemCurrentTime");
        return false;
    }

    std::string bundleName = DelayedSingleton<BundleManagerHelper>::GetInstance()->GetBundleName(uid);

    if (DelayedSingleton<PublishManager>::GetInstance()->CheckIsFloodAttack(uid)) {
        EVENT_LOGE("Too many common events have been sent in a short period from %{public}s (pid = %{public}d, uid = "
                   "%{public}d, userId = %{public}d)",
            bundleName.c_str(),
            pid,
            uid,
            userId);
        return false;
    }

    std::function<void()> PublishCommonEventFunc = std::bind(&InnerCommonEventManager::PublishCommonEvent,
        innerCommonEventManager_,
        event,
        publishinfo,
        commonEventListener,
        recordTime,
        pid,
        uid,
        callerToken,
        userId,
        bundleName,
        this);
    return handler_->PostTask(PublishCommonEventFunc);
}

bool CommonEventManagerService::SubscribeCommonEvent(
    const CommonEventSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &commonEventListener)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    EVENT_LOGI("enter");

    if (!IsReady()) {
        return false;
    }

    struct tm recordTime = {0};
    if (!GetSystemCurrentTime(&recordTime)) {
        EVENT_LOGE("Failed to GetSystemCurrentTime");
        return false;
    }
    auto callingUid = IPCSkeleton::GetCallingUid();
    std::string bundleName = DelayedSingleton<BundleManagerHelper>::GetInstance()->GetBundleName(callingUid);

    Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();

    std::function<void()> SubscribeCommonEventFunc = std::bind(&InnerCommonEventManager::SubscribeCommonEvent,
        innerCommonEventManager_,
        subscribeInfo,
        commonEventListener,
        recordTime,
        IPCSkeleton::GetCallingPid(),
        callingUid,
        callerToken,
        bundleName);
    return handler_->PostTask(SubscribeCommonEventFunc);
}

bool CommonEventManagerService::UnsubscribeCommonEvent(const sptr<IRemoteObject> &commonEventListener)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    EVENT_LOGI("enter");

    if (!IsReady()) {
        return false;
    }

    std::function<void()> UnsubscribeCommonEventFunc =
        std::bind(&InnerCommonEventManager::UnsubscribeCommonEvent, innerCommonEventManager_, commonEventListener);
    return handler_->PostTask(UnsubscribeCommonEventFunc);
}

bool CommonEventManagerService::GetStickyCommonEvent(const std::string &event, CommonEventData &eventData)
{
    EVENT_LOGI("enter");

    if (!IsReady()) {
        return false;
    }

    if (event.empty()) {
        EVENT_LOGE("event is empty");
        return false;
    }

    auto callingUid = IPCSkeleton::GetCallingUid();
    std::string bundleName = DelayedSingleton<BundleManagerHelper>::GetInstance()->GetBundleName(callingUid);
    const std::string permission = "ohos.permission.COMMONEVENT_STICKY";
    bool ret = AccessTokenHelper::VerifyAccessToken(IPCSkeleton::GetCallingTokenID(), permission);
    if (!ret) {
        EVENT_LOGE("No permission to get a sticky common event from %{public}s (uid = %{public}d)",
            bundleName.c_str(),
            callingUid);
        return false;
    }

    return innerCommonEventManager_->GetStickyCommonEvent(event, eventData);
}

bool CommonEventManagerService::DumpState(const uint8_t &dumpType, const std::string &event, const int32_t &userId,
    std::vector<std::string> &state)
{
    EVENT_LOGI("enter");

    if (!IsReady()) {
        return false;
    }

    innerCommonEventManager_->DumpState(dumpType, event, userId, state);

    return true;
}

bool CommonEventManagerService::FinishReceiver(
    const sptr<IRemoteObject> &proxy, const int32_t &code, const std::string &receiverData, const bool &abortEvent)
{
    EVENT_LOGI("enter");

    if (!IsReady()) {
        return false;
    }

    std::function<void()> FinishReceiverFunc = std::bind(
        &InnerCommonEventManager::FinishReceiver, innerCommonEventManager_, proxy, code, receiverData, abortEvent);
    return handler_->PostTask(FinishReceiverFunc);
}

bool CommonEventManagerService::Freeze(const uid_t &uid)
{
    EVENT_LOGI("enter");

    if (!IsReady()) {
        return false;
    }

    std::function<void()> FreezeFunc = std::bind(&InnerCommonEventManager::Freeze, innerCommonEventManager_, uid);
    return handler_->PostImmediateTask(FreezeFunc);
}

bool CommonEventManagerService::Unfreeze(const uid_t &uid)
{
    EVENT_LOGI("enter");

    if (!IsReady()) {
        return false;
    }

    std::function<void()> UnfreezeFunc = std::bind(&InnerCommonEventManager::Unfreeze, innerCommonEventManager_, uid);
    return handler_->PostImmediateTask(UnfreezeFunc);
}

bool CommonEventManagerService::UnfreezeAll()
{
    EVENT_LOGI("enter");

    if (!IsReady()) {
        return false;
    }

    std::function<void()> UnfreezeAllFunc = std::bind(&InnerCommonEventManager::UnfreezeAll, innerCommonEventManager_);
    return handler_->PostImmediateTask(UnfreezeAllFunc);
}

int CommonEventManagerService::Dump(int fd, const std::vector<std::u16string> &args)
{
    EVENT_LOGI("enter");
    if (!IsReady()) {
        return ERR_INVALID_VALUE;
    }
    std::string result;
    innerCommonEventManager_->HiDump(args, result);
    int ret = dprintf(fd, "%s\n", result.c_str());
    if (ret < 0) {
        EVENT_LOGE("dprintf error");
        return ERR_INVALID_VALUE;
    }
    return ERR_OK;
}
}  // namespace EventFwk
}  // namespace OHOS
