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

#include "inner_common_event_manager.h"

#include "ces_inner_error_code.h"
#include "common_event_constant.h"
#include "common_event_record.h"
#include "common_event_sticky_manager.h"
#include "common_event_subscriber_manager.h"
#include "common_event_support.h"
#include "common_event_support_mapper.h"
#include "event_log_wrapper.h"
#include "event_trace_wrapper.h"
#include "event_report.h"
#include "hitrace_meter_adapter.h"
#include "ipc_skeleton.h"
#include "nlohmann/json.hpp"
#include "os_account_manager_helper.h"
#include "parameters.h"
#include "system_time.h"
#include "want.h"
#include <fstream>
#include "securec.h"
#ifdef CONFIG_POLICY_ENABLE
#include "config_policy_utils.h"
#endif


namespace OHOS {
namespace EventFwk {
namespace {
const std::string NOTIFICATION_CES_CHECK_SA_PERMISSION = "notification.ces.check.sa.permission";
}  // namespace

static const int32_t PUBLISH_SYS_EVENT_INTERVAL = 10;  // 10s
#ifdef CONFIG_POLICY_ENABLE
    constexpr static const char* CONFIG_FILE = "etc/notification/common_event_config.json";
#else
    constexpr static const char* CONFIG_FILE = "system/etc/notification/common_event_config.json";
#endif

InnerCommonEventManager::InnerCommonEventManager() : controlPtr_(std::make_shared<CommonEventControlManager>()),
    staticSubscriberManager_(std::make_shared<StaticSubscriberManager>())
{
    supportCheckSaPermission_ = OHOS::system::GetParameter(NOTIFICATION_CES_CHECK_SA_PERMISSION, "false");
    if (!GetJsonByFilePath(CONFIG_FILE, eventConfigJson_)) {
        EVENT_LOGE("Failed to get config file.");
    }

    getCcmPublishControl();
}

constexpr char HIDUMPER_HELP_MSG[] =
    "Usage:dump <command> [options]\n"
    "Description:\n"
    "  -h, --help                   list available commands\n"
    "  -a, --all                    dump the info of all events\n"
    "  -e, --event <name>           dump the info of a specified event\n";

const std::unordered_map<std::string, char> HIDUMPER_CMD_MAP = {
    { "--help", 'h'},
    { "--all", 'a'},
    { "--event", 'e'},
    { "-h", 'h' },
    { "-a", 'a' },
    { "-e", 'e' },
};

const std::map<std::string, std::string> EVENT_COUNT_DISALLOW = {
    { CommonEventSupport::COMMON_EVENT_TIME_TICK, "usual.event.TIME_TICK" },
};

constexpr size_t HIDUMP_OPTION_MAX_SIZE = 2;

bool InnerCommonEventManager::GetJsonFromFile(const char *path, nlohmann::json &root)
{
    std::ifstream file(path);
    if (!file.good()) {
        EVENT_LOGE("Failed to open file %{public}s.", path);
        return false;
    }
    root = nlohmann::json::parse(file, nullptr, false);
    file.close();
    if (root.is_discarded() || !root.is_structured()) {
        EVENT_LOGE("Failed to parse json from file %{public}s.", path);
        return false;
    }
    if (root.is_null() || root.empty() || !root.is_object()) {
        EVENT_LOGE("GetJsonFromFile fail as invalid root.");
        return false;
    }
    return true;
}

bool InnerCommonEventManager::GetJsonByFilePath(const char *filePath, std::vector<nlohmann::json> &roots)
{
    EVENT_LOGD("Get json value by file path.");
    if (filePath == nullptr) {
        EVENT_LOGE("GetJsonByFilePath fail as filePath is null.");
        return false;
    }
    bool ret = false;
    nlohmann::json localRoot;
#ifdef CONFIG_POLICY_ENABLE
    CfgFiles *cfgFiles = GetCfgFiles(filePath);
    if (cfgFiles == nullptr) {
        EVENT_LOGE("Not found file");
        return false;
    }

    for (int32_t i = 0; i <= MAX_CFG_POLICY_DIRS_CNT - 1; i++) {
        if (cfgFiles->paths[i] && *(cfgFiles->paths[i]) != '\0' && GetJsonFromFile(cfgFiles->paths[i], localRoot)) {
            roots.push_back(localRoot);
            ret = true;
        }
    }
    FreeCfgFiles(cfgFiles);
#else
    EVENT_LOGD("Use default config file");
    ret = GetJsonFromFile(filePath, localRoot);
    if (ret) {
        roots.push_back(localRoot);
    }
#endif
    return ret;
}

bool InnerCommonEventManager::GetConfigJson(const std::string &keyCheck, nlohmann::json &configJson) const
{
    if (eventConfigJson_.size() <= 0) {
        EVENT_LOGE("Failed to get config json cause empty configJsons.");
        return false;
    }
    bool ret = false;
    std::for_each(eventConfigJson_.rbegin(), eventConfigJson_.rend(),
        [&keyCheck, &configJson, &ret](const nlohmann::json &json) {
        if (keyCheck.find("/") == std::string::npos && json.contains(keyCheck)) {
            configJson = json;
            ret = true;
        }

        if (keyCheck.find("/") != std::string::npos) {
            nlohmann::json::json_pointer keyCheckPoint(keyCheck);
            if (json.contains(keyCheckPoint)) {
                configJson = json;
                ret = true;
            }
        }
    });
    if (!ret) {
        EVENT_LOGE("Cannot find keyCheck: %{public}s in configJsons.", keyCheck.c_str());
    }
    return ret;
}

void InnerCommonEventManager::getCcmPublishControl()
{
    nlohmann::json root;
    std::string JsonPoint = "/";
    JsonPoint.append("publishControl");
    if (!GetConfigJson(JsonPoint, root)) {
        EVENT_LOGE("Failed to get JsonPoint CCM config file.");
        return;
    }
    if (!root.contains("publishControl")) {
        EVENT_LOGE("not found jsonKey publishControl");
        return;
    }
    // 访问数据
    const nlohmann::json& publish_control = root["publishControl"];
    if (publish_control.is_null() || publish_control.empty()) {
        EVENT_LOGE("GetCcm publishControl failed as invalid publishControl json.");
        return;
    }
    for (const auto& item : publish_control) {
        std::string event_name = item["eventName"];
        const nlohmann::json& uid_list = item["uidList"];
        std::vector<int> uids;
        for (const auto& uid : uid_list) {
            uids.push_back(uid);
        }
        publishControlMap_[event_name] = uids;
    }
}

bool InnerCommonEventManager::IsPublishAllowed(const std::string &event, int32_t uid)
{
    if (publishControlMap_.empty()) {
        EVENT_LOGD("PublishControlMap event no need control");
        return true;
    }
    auto it = publishControlMap_.find(event);
    if (it != publishControlMap_.end()) {
        EVENT_LOGD("PublishControlMap event = %{public}s,uid = %{public}d", event.c_str(), it->second[0]);
        return std::find(it->second.begin(), it->second.end(), uid) != it->second.end();
    }
    return true;
}

bool InnerCommonEventManager::PublishCommonEvent(const CommonEventData &data, const CommonEventPublishInfo &publishInfo,
    const sptr<IRemoteObject> &commonEventListener, const struct tm &recordTime, const pid_t &pid, const uid_t &uid,
    const Security::AccessToken::AccessTokenID &callerToken, const int32_t &userId, const std::string &bundleName,
    const sptr<IRemoteObject> &service)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (data.GetWant().GetAction().empty()) {
        EVENT_LOGE("the commonEventdata action is null");
        return false;
    }

    if ((!publishInfo.IsOrdered()) && (commonEventListener != nullptr)) {
        EVENT_LOGE("When publishing unordered events, the subscriber object is not required.");
        return false;
    }

    std::string action = data.GetWant().GetAction();
    bool isAllowed = IsPublishAllowed(action, uid);
    if (!isAllowed) {
        EVENT_LOGE("Publish event = %{public}s not allowed uid = %{public}d.", action.c_str(), uid);
        return false;
    }
    bool isSystemEvent = DelayedSingleton<CommonEventSupport>::GetInstance()->IsSystemEvent(action);
    int32_t user = userId;
    EventComeFrom comeFrom;
    if (!CheckUserId(pid, uid, callerToken, comeFrom, user)) {
        SendPublishHiSysEvent(user, bundleName, pid, uid, data.GetWant().GetAction(), false);
        return false;
    }

    if (isSystemEvent) {
        EVENT_LOGD("System common event");
        if (!comeFrom.isSystemApp && !comeFrom.isSubsystem) {
            EVENT_LOGE(
                "No permission to send a system common event from %{public}s(pid = %{public}d, uid = %{public}d)"
                ", userId = %{public}d", bundleName.c_str(), pid, uid, userId);
            SendPublishHiSysEvent(user, bundleName, pid, uid, data.GetWant().GetAction(), false);
            return false;
        }
    }
    
    EVENT_LOGD("pid=%{public}d publish %{public}s to %{public}d", pid, data.GetWant().GetAction().c_str(), user);

    if (staticSubscriberManager_ != nullptr) {
        staticSubscriberManager_->PublishCommonEvent(data, publishInfo, callerToken, user, service, bundleName);
    }

    CommonEventRecord eventRecord;
    eventRecord.commonEventData = std::make_shared<CommonEventData>(data);
    eventRecord.publishInfo = std::make_shared<CommonEventPublishInfo>(publishInfo);
    eventRecord.recordTime = recordTime;
    eventRecord.eventRecordInfo.pid = pid;
    eventRecord.eventRecordInfo.uid = uid;
    eventRecord.eventRecordInfo.callerToken = callerToken;
    eventRecord.userId = user;
    eventRecord.eventRecordInfo.bundleName = bundleName;
    eventRecord.eventRecordInfo.isSubsystem = comeFrom.isSubsystem;
    eventRecord.eventRecordInfo.isSystemApp = (comeFrom.isSystemApp || comeFrom.isCemShell);
    eventRecord.eventRecordInfo.isProxy = comeFrom.isProxy;
    eventRecord.isSystemEvent = isSystemEvent;

    if (publishInfo.IsSticky()) {
        if (!ProcessStickyEvent(eventRecord)) {
            SendPublishHiSysEvent(user, bundleName, pid, uid, data.GetWant().GetAction(), false);
            return false;
        }
    }

    if (!controlPtr_) {
        EVENT_LOGE("CommonEventControlManager ptr is nullptr");
        SendPublishHiSysEvent(user, bundleName, pid, uid, data.GetWant().GetAction(), false);
        return false;
    }
    controlPtr_->PublishCommonEvent(eventRecord, commonEventListener);

    std::string mappedSupport = "";
    if (DelayedSingleton<CommonEventSupportMapper>::GetInstance()->GetMappedSupport(
        eventRecord.commonEventData->GetWant().GetAction(), mappedSupport)) {
        Want want = eventRecord.commonEventData->GetWant();
        want.SetAction(mappedSupport);
        CommonEventRecord mappedEventRecord = eventRecord;
        mappedEventRecord.commonEventData->SetWant(want);
        controlPtr_->PublishCommonEvent(mappedEventRecord, commonEventListener);
    }
    return true;
}

bool InnerCommonEventManager::SubscribeCommonEvent(const CommonEventSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &commonEventListener, const struct tm &recordTime,
    const pid_t &pid, const uid_t &uid, const Security::AccessToken::AccessTokenID &callerToken,
    const std::string &bundleName, const int32_t instanceKey, const int64_t startTime)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    int64_t taskStartTime = SystemTime::GetNowSysTime();
    EVENT_LOGD("enter %{public}s(pid = %{public}d, uid = %{public}d, userId = %{public}d)",
        bundleName.c_str(), pid, uid, subscribeInfo.GetUserId());

    if (subscribeInfo.GetMatchingSkills().CountEvent() == 0) {
        EVENT_LOGE("the subscriber has no event");
        return false;
    }
    if (commonEventListener == nullptr) {
        EVENT_LOGE("commonEventListener is nullptr");
        return false;
    }

    CommonEventSubscribeInfo subscribeInfo_(subscribeInfo);
    int32_t userId = subscribeInfo_.GetUserId();
    EventComeFrom comeFrom;
    if (!CheckUserId(pid, uid, callerToken, comeFrom, userId)) {
        return false;
    }
    subscribeInfo_.SetUserId(userId);

    std::shared_ptr<CommonEventSubscribeInfo> sp = std::make_shared<CommonEventSubscribeInfo>(subscribeInfo_);

    // create EventRecordInfo here
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.pid = pid;
    eventRecordInfo.uid = uid;
    eventRecordInfo.callerToken = callerToken;
    eventRecordInfo.bundleName = bundleName;
    eventRecordInfo.isSubsystem = comeFrom.isSubsystem;
    eventRecordInfo.isSystemApp = comeFrom.isSystemApp;
    eventRecordInfo.isProxy = comeFrom.isProxy;

    // generate subscriber id : pid_uid_instanceKey_subCount_time
    int64_t now = SystemTime::GetNowSysTime();
    std::string subId = std::to_string(pid) + "_" + std::to_string(uid) + "_" +
        std::to_string(instanceKey) + "_" + std::to_string(subCount.load()) + "_" + std::to_string(now);
    subCount.fetch_add(1);
    eventRecordInfo.subId = subId;
    auto record = DelayedSingleton<CommonEventSubscriberManager>::GetInstance()->InsertSubscriber(
        sp, commonEventListener, recordTime, eventRecordInfo);

    now = SystemTime::GetNowSysTime();
    EVENT_LOGI("Subscribe %{public}s(userId = %{public}d, subId = %{public}s, "
        "ffrtCost %{public}s ms, taskCost %{public}s ms)", bundleName.c_str(), userId, subId.c_str(),
        std::to_string(taskStartTime - startTime).c_str(), std::to_string(now - taskStartTime).c_str());
    PublishStickyEvent(sp, record);
    return true;
};

bool InnerCommonEventManager::UnsubscribeCommonEvent(const sptr<IRemoteObject> &commonEventListener)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    EVENT_LOGD("enter");

    if (commonEventListener == nullptr) {
        EVENT_LOGE("commonEventListener is nullptr");
        return false;
    }

    if (!controlPtr_) {
        EVENT_LOGE("CommonEventControlManager ptr is nullptr");
        return false;
    }

    std::shared_ptr<OrderedEventRecord> sp = controlPtr_->GetMatchingOrderedReceiver(commonEventListener);
    if (sp) {
        EVENT_LOGD("Unsubscribe the subscriber who is waiting to receive finish feedback");
        int32_t code = sp->commonEventData->GetCode();
        std::string data = sp->commonEventData->GetData();
        controlPtr_->FinishReceiverAction(sp, code, data, sp->resultAbort);
    }
    DelayedSingleton<CommonEventSubscriberManager>::GetInstance()->RemoveSubscriber(commonEventListener);
    return true;
}

bool InnerCommonEventManager::GetStickyCommonEvent(const std::string &event, CommonEventData &eventData)
{
    EVENT_LOGD("enter");

    return DelayedSingleton<CommonEventStickyManager>::GetInstance()->GetStickyCommonEvent(event, eventData);
}

void InnerCommonEventManager::DumpState(const uint8_t &dumpType, const std::string &event, const int32_t &userId,
    std::vector<std::string> &state)
{
    EVENT_LOGD("enter");

    switch (dumpType) {
        case DumpEventType::SUBSCRIBER: {
            DelayedSingleton<CommonEventSubscriberManager>::GetInstance()->DumpState(event, userId, state);
            break;
        }
        case DumpEventType::STICKY: {
            DelayedSingleton<CommonEventStickyManager>::GetInstance()->DumpState(event, userId, state);
            break;
        }
        case DumpEventType::PENDING: {
            if (controlPtr_) {
                controlPtr_->DumpState(event, userId, state);
            }
            break;
        }
        case DumpEventType::HISTORY: {
            break;
        }
        default: {
            DelayedSingleton<CommonEventSubscriberManager>::GetInstance()->DumpState(event, userId, state);
            DelayedSingleton<CommonEventStickyManager>::GetInstance()->DumpState(event, userId, state);
            if (controlPtr_) {
                controlPtr_->DumpState(event, userId, state);
            }
            break;
        }
    }

    if (!controlPtr_) {
        EVENT_LOGE("CommonEventControlManager ptr is nullptr");
    }
}

void InnerCommonEventManager::FinishReceiver(
    const sptr<IRemoteObject> &proxy, const int32_t &code, const std::string &receiverData, const bool &abortEvent)
{
    EVENT_LOGD("enter");

    if (!controlPtr_) {
        EVENT_LOGE("CommonEventControlManager ptr is nullptr");
        return;
    }

    std::shared_ptr<OrderedEventRecord> sp = controlPtr_->GetMatchingOrderedReceiver(proxy);
    if (sp) {
        controlPtr_->FinishReceiverAction(sp, code, receiverData, abortEvent);
    }

    return;
}

void InnerCommonEventManager::Freeze(const uid_t &uid)
{
    EVENT_LOGD("enter");
    DelayedSingleton<CommonEventSubscriberManager>::GetInstance()->UpdateFreezeInfo(
        uid, true, SystemTime::GetNowSysTime());
}

void InnerCommonEventManager::Unfreeze(const uid_t &uid)
{
    EVENT_LOGD("enter");
    DelayedSingleton<CommonEventSubscriberManager>::GetInstance()->UpdateFreezeInfo(uid, false);
    if (!controlPtr_) {
        EVENT_LOGE("CommonEventControlManager ptr is nullptr");
        return;
    }
    controlPtr_->PublishFreezeCommonEvent(uid);
}

bool InnerCommonEventManager::SetFreezeStatus(std::set<int> pidList, bool isFreeze)
{
    EVENT_LOGD("enter");
    DelayedSingleton<CommonEventSubscriberManager>::GetInstance()->UpdateFreezeInfo(
        pidList, isFreeze, SystemTime::GetNowSysTime());
    if (!isFreeze) {
        if (!controlPtr_) {
            EVENT_LOGE("CommonEventControlManager ptr is nullptr");
            return false;
        }
        return controlPtr_->PublishFreezeCommonEvent(pidList);
    }
    return true;
}

void InnerCommonEventManager::UnfreezeAll()
{
    EVENT_LOGD("enter");
    DelayedSingleton<CommonEventSubscriberManager>::GetInstance()->UpdateAllFreezeInfos(false);
    if (!controlPtr_) {
        EVENT_LOGE("CommonEventControlManager ptr is nullptr");
        return;
    }
    controlPtr_->PublishAllFreezeCommonEvents();
}

bool InnerCommonEventManager::ProcessStickyEvent(const CommonEventRecord &record)
{
    EVENT_LOGD("enter");
    const std::string permission = "ohos.permission.COMMONEVENT_STICKY";
    bool result = AccessTokenHelper::VerifyAccessToken(record.eventRecordInfo.callerToken, permission);
    // Only subsystems and system apps with permissions can publish sticky common events
    if ((result && record.eventRecordInfo.isSystemApp) ||
        (!record.eventRecordInfo.isProxy && record.eventRecordInfo.isSubsystem)) {
        DelayedSingleton<CommonEventStickyManager>::GetInstance()->UpdateStickyEvent(record);
        return true;
    } else {
        EVENT_LOGE("No permission to send a sticky common event from %{public}s (pid = %{public}d, uid = %{public}d)",
            record.eventRecordInfo.bundleName.c_str(), record.eventRecordInfo.pid, record.eventRecordInfo.uid);
        return false;
    }
}

void InnerCommonEventManager::SetSystemUserId(const uid_t &uid, EventComeFrom &comeFrom, int32_t &userId)
{
    if (userId == CURRENT_USER) {
        DelayedSingleton<OsAccountManagerHelper>::GetInstance()->GetOsAccountLocalIdFromUid(uid, userId);
    } else if (userId == UNDEFINED_USER) {
        if (comeFrom.isSubsystem) {
            userId = ALL_USER;
        } else {
            DelayedSingleton<OsAccountManagerHelper>::GetInstance()->GetOsAccountLocalIdFromUid(uid, userId);
            if (userId >= SUBSCRIBE_USER_SYSTEM_BEGIN && userId <= SUBSCRIBE_USER_SYSTEM_END) {
                userId = ALL_USER;
            }
        }
    }
}

bool InnerCommonEventManager::CheckUserId(const pid_t &pid, const uid_t &uid,
    const Security::AccessToken::AccessTokenID &callerToken, EventComeFrom &comeFrom, int32_t &userId)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    EVENT_LOGD("enter");

    if (userId < UNDEFINED_USER) {
        EVENT_LOGE("Invalid User ID %{public}d", userId);
        return false;
    }

    comeFrom.isSubsystem = AccessTokenHelper::VerifyNativeToken(callerToken);

    if (!comeFrom.isSubsystem || supportCheckSaPermission_.compare("true") == 0) {
        if (AccessTokenHelper::VerifyShellToken(callerToken)) {
            comeFrom.isCemShell = true;
        } else {
            comeFrom.isSystemApp = DelayedSingleton<BundleManagerHelper>::GetInstance()->CheckIsSystemAppByUid(uid);
        }
    }
    comeFrom.isProxy = pid == UNDEFINED_PID;
    if ((comeFrom.isSystemApp || comeFrom.isSubsystem || comeFrom.isCemShell) && !comeFrom.isProxy) {
        SetSystemUserId(uid, comeFrom, userId);
    } else {
        if (userId == UNDEFINED_USER) {
            DelayedSingleton<OsAccountManagerHelper>::GetInstance()->GetOsAccountLocalIdFromUid(uid, userId);
        } else {
            EVENT_LOGE("No permission to subscribe or send a common event to another user from uid = %{public}d", uid);
            return false;
        }
    }

    return true;
}

bool InnerCommonEventManager::PublishStickyEvent(
    const std::shared_ptr<CommonEventSubscribeInfo> &sp, const std::shared_ptr<EventSubscriberRecord> &subscriberRecord)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    EVENT_LOGD("enter");

    if (!sp) {
        EVENT_LOGE("sp is null");
        return false;
    }

    if (!subscriberRecord) {
        EVENT_LOGE("subscriberRecord is null");
        return false;
    }

    std::vector<std::shared_ptr<CommonEventRecord>> commonEventRecords;
    if (DelayedSingleton<CommonEventStickyManager>::GetInstance()->FindStickyEvents(sp, commonEventRecords)) {
        return false;
    }

    for (auto commonEventRecord : commonEventRecords) {
        if (!commonEventRecord) {
            EVENT_LOGW("commonEventRecord is nullptr and get next");
            continue;
        }
        if (!commonEventRecord->publishInfo->GetBundleName().empty() &&
            commonEventRecord->publishInfo->GetBundleName() != subscriberRecord->eventRecordInfo.bundleName) {
            EVENT_LOGD("Event only assigned to [%{public}s]",
                commonEventRecord->publishInfo->GetBundleName().c_str());
            continue;
        }

        commonEventRecord->publishInfo->SetOrdered(false);
        if (!controlPtr_) {
            EVENT_LOGE("CommonEventControlManager ptr is nullptr");
            return false;
        }
        EVENT_LOGI("publish %{public}s",
            commonEventRecord->commonEventData->GetWant().GetAction().c_str());
        controlPtr_->PublishStickyCommonEvent(*commonEventRecord, subscriberRecord);
    }

    return true;
}

void InnerCommonEventManager::HiDump(const std::vector<std::u16string> &args, std::string &result)
{
    if (args.size() == 0 || args.size() > HIDUMP_OPTION_MAX_SIZE) {
        result = "error: unknown option.";
        return;
    }
    std::string cmd = Str16ToStr8(args[0]);
    if (HIDUMPER_CMD_MAP.find(cmd) == HIDUMPER_CMD_MAP.end()) {
        result = "error: unknown option.";
        return;
    }
    std::string event;
    if (args.size() == HIDUMP_OPTION_MAX_SIZE) {
        event = Str16ToStr8(args[1]);
    }
    char cmdValue = HIDUMPER_CMD_MAP.find(cmd)->second;
    switch (cmdValue) {
        case 'h' :
            result = HIDUMPER_HELP_MSG;
            return;
        case 'a' :
            event = "";
            break;
        case 'e' :
            if (event.empty()) {
                result = "error: request a event value.";
                return;
            }
            break;
        default:
            break;
    }
    std::vector<std::string> records;
    DumpState(DumpEventType::ALL, event, ALL_USER, records);
    for (const auto &record : records) {
        result.append(record).append("\n");
    }
}

void InnerCommonEventManager::SendPublishHiSysEvent(int32_t userId, const std::string &publisherName, int32_t pid,
    int32_t uid, const std::string &event, bool succeed)
{
    EventInfo eventInfo;
    eventInfo.userId = userId;
    eventInfo.publisherName = publisherName;
    eventInfo.pid = pid;
    eventInfo.uid = uid;
    eventInfo.eventName = event;

    if (!succeed) {
        EventReport::SendHiSysEvent(PUBLISH_ERROR, eventInfo);
    }
}

int32_t InnerCommonEventManager::RemoveStickyCommonEvent(const std::string &event, uint32_t callerUid)
{
    return DelayedSingleton<CommonEventStickyManager>::GetInstance()->RemoveStickyCommonEvent(event, callerUid);
}

int32_t InnerCommonEventManager::SetStaticSubscriberState(bool enable)
{
    if (staticSubscriberManager_ != nullptr) {
        return staticSubscriberManager_->SetStaticSubscriberState(enable);
    }
    return Notification::ERR_NOTIFICATION_CESM_ERROR;
}

int32_t InnerCommonEventManager::SetStaticSubscriberState(const std::vector<std::string> &events, bool enable)
{
    if (staticSubscriberManager_ != nullptr) {
        return staticSubscriberManager_->SetStaticSubscriberState(events, enable);
    }
    return Notification::ERR_NOTIFICATION_CESM_ERROR;
}
}  // namespace EventFwk
}  // namespace OHOS
