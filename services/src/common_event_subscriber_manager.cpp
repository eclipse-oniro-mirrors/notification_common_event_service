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
#include "common_event_subscriber_manager.h"

#include <csignal>
#include <utility>
#include <vector>
#include <set>

#include "ability_manager_client.h"
#include "access_token_helper.h"
#include "common_event_permission_manager.h"
#include "common_event_support.h"
#include "event_log_wrapper.h"
#include "event_trace_wrapper.h"
#include "event_report.h"
#include "hisysevent.h"
#include "hitrace_meter_adapter.h"
#include "subscriber_death_recipient.h"
#ifdef WATCH_CUSTOMIZED_SCREEN_EVENT_TO_OTHER_APP
#include <dlfcn.h>
#endif

namespace OHOS {
namespace EventFwk {
constexpr int32_t LENGTH = 80;
constexpr int32_t SIGNAL_KILL = 9;
static constexpr int32_t SUBSCRIBE_EVENT_MAX_NUM = 512;
static constexpr char CES_REGISTER_EXCEED_LIMIT[] = "Kill Reason: CES Register exceed limit";
const std::string CONNECTOR = " or ";

#ifdef WATCH_CUSTOMIZED_SCREEN_EVENT_TO_OTHER_APP
static const char *POWER_MANAGER_EXT_PATH = "libpower_manager_ext.z.so";
static const char *WATCH_SUBSCRIBE_SCREEN_EVENT_TO_OTHER_APP = "WatchSubscribeScreenEventToOtherApp";
void *handler = dlopen(POWER_MANAGER_EXT_PATH, RTLD_LAZY | RTLD_NODELETE);
typedef bool (*FuncSubscriber)(std::vector<std::string>, std::vector<int32_t>, std::string, int);
FuncSubscriber SubscribeScreenEventToBlackListAppFlag =
    reinterpret_cast<FuncSubscriber>(dlsym(handler, WATCH_SUBSCRIBE_SCREEN_EVENT_TO_OTHER_APP));
#endif

CommonEventSubscriberManager::CommonEventSubscriberManager()
    : death_(sptr<IRemoteObject::DeathRecipient>(new (std::nothrow) SubscriberDeathRecipient()))
{}

CommonEventSubscriberManager::~CommonEventSubscriberManager() {}

std::shared_ptr<EventSubscriberRecord> CommonEventSubscriberManager::InsertSubscriber(
    const SubscribeInfoPtr &eventSubscribeInfo, const sptr<IRemoteObject> &commonEventListener,
    const struct tm &recordTime, const EventRecordInfo &eventRecordInfo)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    EVENT_LOGD(LOG_TAG_SUBSCRIBER, "enter");

    if (eventSubscribeInfo == nullptr) {
        EVENT_LOGE(LOG_TAG_SUBSCRIBER, "eventSubscribeInfo is null");
        return nullptr;
    }

    if (commonEventListener == nullptr) {
        EVENT_LOGE(LOG_TAG_SUBSCRIBER, "commonEventListener is null");
        return nullptr;
    }

    std::vector<std::string> events = eventSubscribeInfo->GetMatchingSkills().GetEvents();
    if (events.size() == 0 || events.size() > SUBSCRIBE_EVENT_MAX_NUM) {
        EVENT_LOGE(LOG_TAG_SUBSCRIBER, "subscribed events size is error");
        return nullptr;
    }

    auto record = std::make_shared<EventSubscriberRecord>();
    if (record == nullptr) {
        EVENT_LOGE(LOG_TAG_SUBSCRIBER, "Failed to create EventSubscriberRecord");
        return nullptr;
    }

    record->eventSubscribeInfo = eventSubscribeInfo;
    record->commonEventListener = commonEventListener;
    record->recordTime = recordTime;
    record->eventRecordInfo = eventRecordInfo;

    if (death_ != nullptr) {
        commonEventListener->AddDeathRecipient(death_);
    }

    if (!InsertSubscriberRecordLocked(events, record)) {
        return nullptr;
    }

    if (eventRecordInfo.uid != SAMGR_UID) {
        std::string unsafeEventsLogger = "";
        for (auto event : events) {
            bool isSystemEvent = DelayedSingleton<CommonEventSupport>::GetInstance()->IsSystemEvent(event);
            if (!isSystemEvent && eventSubscribeInfo->GetPermission().empty() &&
                eventSubscribeInfo->GetPublisherBundleName().empty() && eventSubscribeInfo->GetPublisherUid() == 0) {
                unsafeEventsLogger.append(event).append(",");
            }
        }
        if (!unsafeEventsLogger.empty()) {
            EVENT_LOGW(LOG_TAG_SUBSCRIBER, "Subscribe %{public}s without any restrict subid = %{public}s",
                unsafeEventsLogger.c_str(), eventRecordInfo.subId.c_str());
        }
    }

    return record;
}

int CommonEventSubscriberManager::RemoveSubscriber(const sptr<IRemoteObject> &commonEventListener)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    EVENT_LOGD(LOG_TAG_SUBSCRIBER, "enter");

    if (commonEventListener == nullptr) {
        EVENT_LOGE(LOG_TAG_SUBSCRIBER, "commonEventListener is null");
        return ERR_INVALID_VALUE;
    }

    int res = RemoveSubscriberRecordLocked(commonEventListener);
    return res;
}

std::vector<std::shared_ptr<EventSubscriberRecord>> CommonEventSubscriberManager::GetSubscriberRecords(
    const CommonEventRecord &eventRecord)
{
    EVENT_LOGD(LOG_TAG_SUBSCRIBER, "enter");

    auto records = std::vector<SubscriberRecordPtr>();

    GetSubscriberRecordsByWantLocked(eventRecord, records);

    return records;
}

std::shared_ptr<EventSubscriberRecord> CommonEventSubscriberManager::GetSubscriberRecord(
    const sptr<IRemoteObject> &commonEventListener)
{
    std::lock_guard<ffrt::mutex> lock(mutex_);

    for (auto it = subscribers_.begin(); it != subscribers_.end(); ++it) {
        if (commonEventListener == (*it)->commonEventListener) {
            return *it;
        }
    }

    return nullptr;
}

void CommonEventSubscriberManager::DumpDetailed(
    const std::string &title, const SubscriberRecordPtr &record, const std::string format, std::string &dumpInfo)
{
    if (record == nullptr || record->eventSubscribeInfo == nullptr) {
        EVENT_LOGE(LOG_TAG_SUBSCRIBER, "record or eventSubscribeInfo is null");
        return;
    }
    char systime[LENGTH];
    strftime(systime, sizeof(char) * LENGTH, "%Y%m%d %I:%M %p", &record->recordTime);

    std::string recordTime = format + "Time: " + std::string(systime) + "\n";
    std::string pid = format + "PID: " + std::to_string(record->eventRecordInfo.pid) + "\n";
    std::string uid = format + "UID: " + std::to_string(record->eventRecordInfo.uid) + "\n";
    std::string bundleName = format + "BundleName: " + record->eventRecordInfo.bundleName + "\n";
    std::string priority = format + "Priority: " + std::to_string(record->eventSubscribeInfo->GetPriority()) + "\n";
    std::string userId;
    switch (record->eventSubscribeInfo->GetUserId()) {
        case UNDEFINED_USER:
            userId = "UNDEFINED_USER";
            break;
        case ALL_USER:
            userId = "ALL_USER";
            break;
        default:
            userId = std::to_string(record->eventSubscribeInfo->GetUserId());
            break;
    }
    userId = format + "USERID: " + userId + "\n";
    std::string permission = format + "Permission: " + record->eventSubscribeInfo->GetPermission() + "\n";

    std::string events = format + "\tEvent: ";
    std::string separator;
    size_t countSize = record->eventSubscribeInfo->GetMatchingSkills().CountEvent();
    for (size_t eventNum = 0; eventNum < countSize; ++eventNum) {
        if (eventNum == 0) {
            separator = "";
        } else {
            separator = ", ";
        }
        events = events + separator + record->eventSubscribeInfo->GetMatchingSkills().GetEvent(eventNum);
    }
    events = events + "\n";

    std::string entities = format + "\tEntity: ";
    size_t entitySize = record->eventSubscribeInfo->GetMatchingSkills().CountEntities();
    for (size_t entityNum = 0; entityNum < entitySize; ++entityNum) {
        if (entityNum == 0) {
            separator = "";
        } else {
            separator = ", ";
        }
        entities = entities + separator + record->eventSubscribeInfo->GetMatchingSkills().GetEntity(entityNum);
    }
    entities = entities + "\n";

    std::string scheme = format + "\tScheme: ";
    size_t schemeSize = record->eventSubscribeInfo->GetMatchingSkills().CountSchemes();
    for (size_t schemeNum = 0; schemeNum < schemeSize; ++schemeNum) {
        if (schemeNum == 0) {
            separator = "";
        } else {
            separator = ", ";
        }
        scheme = scheme + separator + record->eventSubscribeInfo->GetMatchingSkills().GetScheme(schemeNum);
    }
    scheme = scheme + "\n";

    std::string matchingSkills = format + "MatchingSkills:\n" + events + entities + scheme;

    std::string isFreeze = record->isFreeze ? "true" : "false";
    isFreeze = format + "IsFreeze: " + isFreeze + "\n";

    std::string freezeTime;
    if (record->freezeTime == 0) {
        freezeTime = format + "FreezeTime:  -\n";
    } else {
        freezeTime = format + "FreezeTime: " + std::to_string(record->freezeTime) + "\n";
    }

    dumpInfo = title + recordTime + pid + uid + bundleName + priority + userId + permission +
               matchingSkills + isFreeze + freezeTime;
}

void CommonEventSubscriberManager::DumpState(const std::string &event, const int32_t &userId,
    std::vector<std::string> &state)
{
    EVENT_LOGD(LOG_TAG_SUBSCRIBER, "enter");

    std::vector<SubscriberRecordPtr> records;

    std::lock_guard<ffrt::mutex> lock(mutex_);
    GetSubscriberRecordsByEvent(event, userId, records);

    if (records.size() == 0) {
        state.emplace_back("Subscribers:\tNo information");
        return;
    }

    size_t num = 0;
    for (auto record : records) {
        num++;
        std::string title = std::to_string(num);
        if (num == 1) {
            title = "Subscribers:\tTotal " + std::to_string(records.size()) + " subscribers\nNO " + title + "\n";
        } else {
            title = "NO " + title + "\n";
        }
        std::string dumpInfo;
        DumpDetailed(title, record, "\t", dumpInfo);
        state.emplace_back(dumpInfo);
    }
}

__attribute__((no_sanitize("cfi"))) bool CommonEventSubscriberManager::InsertSubscriberRecordLocked(
    const std::vector<std::string> &events, const SubscriberRecordPtr &record)
{
    EVENT_LOGD(LOG_TAG_SUBSCRIBER, "enter");

    if (events.size() == 0) {
        EVENT_LOGE(LOG_TAG_SUBSCRIBER, "No subscribed events");
        return false;
    }

    if (record == nullptr) {
        EVENT_LOGE(LOG_TAG_SUBSCRIBER, "record is null");
        return false;
    }

    std::lock_guard<ffrt::mutex> lock(mutex_);

    pid_t pid = record->eventRecordInfo.pid;

    if (CheckSubscriberCountReachedMaxinum()) {
        std::vector<std::pair<pid_t, uint32_t>> vtSubscriberCounts = GetTopSubscriberCounts(1);
        pid_t killedPid = (*vtSubscriberCounts.begin()).first;
        if (pid == killedPid) {
            return false;
        }

        AAFwk::ExitReason reason = { AAFwk::REASON_RESOURCE_CONTROL, "Kill Reason: CES Register exceed limit"};
        AAFwk::AbilityManagerClient::GetInstance()->RecordProcessExitReason(killedPid, reason);
        int killResult = kill(killedPid, SIGNAL_KILL);
        EVENT_LOGW(LOG_TAG_SUBSCRIBER, "kill pid=%{public}d which has the most subscribers %{public}s", killedPid,
            killResult < 0 ? "failed" : "successfully");
        int result = HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::FRAMEWORK, "PROCESS_KILL",
            HiviewDFX::HiSysEvent::EventType::FAULT, "PID", killedPid, "PROCESS_NAME",
            record->eventRecordInfo.bundleName, "MSG", CES_REGISTER_EXCEED_LIMIT, "REASON", CES_REGISTER_EXCEED_LIMIT);
        EVENT_LOGW(LOG_TAG_SUBSCRIBER, "hisysevent write result=%{public}d,send[FRAMEWORK,PROCESS_KILL],pid=%{public}d"
            ",processName=%{public}s,msg=%{public}s", result, killedPid, record->eventRecordInfo.bundleName.c_str(),
            CES_REGISTER_EXCEED_LIMIT);
    }

    for (auto event : events) {
        auto infoItem = eventSubscribers_.find(event);
        if (infoItem != eventSubscribers_.end()) {
            infoItem->second.insert(record);

            if (infoItem->second.size() > MAX_SUBSCRIBER_NUM_PER_EVENT && record->eventSubscribeInfo != nullptr) {
                EVENT_LOGW(LOG_TAG_SUBSCRIBER, "%{public}s event has %{public}zu subscriber, please check",
                    event.c_str(), infoItem->second.size());
                SendSubscriberExceedMaximumHiSysEvent(record->eventSubscribeInfo->GetUserId(), event,
                    infoItem->second.size());
            }
        } else {
            std::set<SubscriberRecordPtr> EventSubscribersPtr;
            EventSubscribersPtr.insert(record);
            eventSubscribers_[event] = EventSubscribersPtr;
        }
    }

    subscribers_.emplace_back(record);
    subscriberCounts_[pid]++;

    return true;
}

int CommonEventSubscriberManager::RemoveSubscriberRecordLocked(const sptr<IRemoteObject> &commonEventListener)
{
    if (commonEventListener == nullptr) {
        EVENT_LOGE(LOG_TAG_SUBSCRIBER, "commonEventListener is null");
        return ERR_INVALID_VALUE;
    }
    
    if (death_ != nullptr) {
        commonEventListener->RemoveDeathRecipient(death_);
    }

    std::lock_guard<ffrt::mutex> lock(mutex_);
    std::vector<std::string> events;

    for (auto it = subscribers_.begin(); it != subscribers_.end(); ++it) {
        if (commonEventListener == (*it)->commonEventListener) {
            RemoveFrozenEventsBySubscriber((*it));
            RemoveFrozenEventsMapBySubscriber((*it));
            events = (*it)->eventSubscribeInfo->GetMatchingSkills().GetEvents();
            EVENT_LOGI(LOG_TAG_SUBSCRIBER, "Unsubscribe %{public}s", (*it)->eventRecordInfo.subId.c_str());
            pid_t pid = (*it)->eventRecordInfo.pid;
            subscriberCounts_[pid] > 1 ? subscriberCounts_[pid]-- : subscriberCounts_.erase(pid);
            subscribers_.erase(it);
            break;
        }
    }

    for (auto event : events) {
        for (auto it = eventSubscribers_[event].begin(); it != eventSubscribers_[event].end(); ++it) {
            if ((commonEventListener == (*it)->commonEventListener) || ((*it)->commonEventListener == nullptr)) {
                eventSubscribers_[event].erase(it);
                break;
            }
        }
        if (eventSubscribers_[event].size() == 0) {
            eventSubscribers_.erase(event);
        }
    }

    return ERR_OK;
}

bool CommonEventSubscriberManager::CheckSubscriberByUserId(
    const int32_t &subscriberUserId, const bool &isSystemApp, const int32_t &userId)
{
    if (subscriberUserId == ALL_USER || subscriberUserId == userId) {
        return true;
    }
 
    if (isSystemApp && (userId == UNDEFINED_USER || userId == ALL_USER ||
        (subscriberUserId >= SUBSCRIBE_USER_SYSTEM_BEGIN && subscriberUserId <= SUBSCRIBE_USER_SYSTEM_END))) {
        return true;
    }
    EVENT_LOGD(LOG_TAG_SUBSCRIBER, "Subscriber userId [%{public}d] isn't equal to publish required userId %{public}d",
        subscriberUserId, userId);
    return false;
}

bool CommonEventSubscriberManager::CheckSubscriberBySpecifiedUids(
    const int32_t &subscriberUid, const std::vector<int32_t> &specifiedSubscriberUids)
{
    for (auto it = specifiedSubscriberUids.begin(); it != specifiedSubscriberUids.end(); ++it) {
        if (*it == subscriberUid) {
            return true;
        }
    }
    return false;
}
 
bool CommonEventSubscriberManager::CheckSubscriberBySpecifiedType(
    const int32_t &specifiedSubscriberType, const bool &isSystemApp)
{
    return specifiedSubscriberType == static_cast<int32_t>(SubscriberType::ALL_SUBSCRIBER_TYPE) ||
        (specifiedSubscriberType == static_cast<int32_t>(SubscriberType::SYSTEM_SUBSCRIBER_TYPE) && isSystemApp);
}

void CommonEventSubscriberManager::GetSubscriberRecordsByWantLocked(const CommonEventRecord &eventRecord,
    std::vector<SubscriberRecordPtr> &records)
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    if (eventSubscribers_.size() <= 0) {
        return;
    }
    auto recordsItem = eventSubscribers_.find(eventRecord.commonEventData->GetWant().GetAction());
    if (recordsItem == eventSubscribers_.end()) {
        return;
    }
    bool isSystemApp = (eventRecord.eventRecordInfo.isSystemApp || eventRecord.eventRecordInfo.isSubsystem) &&
        !eventRecord.eventRecordInfo.isProxy;
    auto bundleName = eventRecord.eventRecordInfo.bundleName;
    auto uid = eventRecord.eventRecordInfo.uid;

    for (auto it = (recordsItem->second).begin(); it != (recordsItem->second).end(); it++) {
        SubscriberRecordPtr subscriberRecord = *it;
        auto subscriberUid = subscriberRecord->eventRecordInfo.uid;
        auto subscriberUserId = subscriberRecord->eventSubscribeInfo->GetUserId();
        if (subscriberRecord->eventSubscribeInfo == nullptr) {
            continue;
        }
        if (!subscriberRecord->eventSubscribeInfo->GetMatchingSkills().Match(eventRecord.commonEventData->GetWant())) {
            continue;
        }
        if (!CheckSubscriberByUserId(subscriberUserId, isSystemApp, eventRecord.userId)) {
            continue;
        }
        if (!CheckSubscriberPermission(subscriberRecord, eventRecord)) {
            continue;
        }
        if (!CheckPublisherWhetherMatched(subscriberRecord, eventRecord)) {
            continue;
        }
        if (!CheckSubscriberWhetherMatched(subscriberRecord, eventRecord)) {
            continue;
        }
        SubscribeScreenEventToBlackListApp(eventRecord, bundleName, subscriberUid, records, subscriberRecord);
    }
}

bool CommonEventSubscriberManager::CheckPublisherWhetherMatched(
    const SubscriberRecordPtr &subscriberRecord, const CommonEventRecord &eventRecord)
{
    auto bundleName = eventRecord.eventRecordInfo.bundleName;
    auto uid = eventRecord.eventRecordInfo.uid;
    auto subscriberRequiredBundle = subscriberRecord->eventSubscribeInfo->GetPublisherBundleName();
    if (!subscriberRequiredBundle.empty() && subscriberRequiredBundle != bundleName) {
        EVENT_LOGD(LOG_TAG_SUBSCRIBER, "Publisher[%{public}s] isn't equal to subscriber required bundleName"
            "[%{public}s] is not matched", bundleName.c_str(), subscriberRequiredBundle.c_str());
        return false;
    }
    auto subscriberRequiredUid = subscriberRecord->eventSubscribeInfo->GetPublisherUid();
    if (subscriberRequiredUid > 0 && uid > 0 && static_cast<uid_t>(subscriberRequiredUid) != uid) {
        EVENT_LOGD(LOG_TAG_SUBSCRIBER, "Publisher[%{public}d] isn't equal to subscriber required uid[%{public}d]",
            uid, subscriberRequiredUid);
        return false;
    }
    
    if (!CheckSubscriberRequiredPermission(subscriberRecord, eventRecord)) {
        return false;
    }
    return true;
}

bool CommonEventSubscriberManager::CheckSubscriberWhetherMatched(
    const SubscriberRecordPtr &subscriberRecord, const CommonEventRecord &eventRecord)
{
    auto specifiedSubscriberUids = eventRecord.publishInfo->GetSubscriberUid();
    auto specifiedSubscriberType = eventRecord.publishInfo->GetSubscriberType();
    uint16_t filterSettings = eventRecord.publishInfo->GetFilterSettings();
    if (filterSettings == 0) {
        return true;
    }
    uint16_t checkResult = 0;
    if (!eventRecord.publishInfo->GetBundleName().empty() &&
        eventRecord.publishInfo->GetBundleName() == subscriberRecord->eventRecordInfo.bundleName) {
        checkResult |= SUBSCRIBER_FILTER_BUNDLE_INDEX;
    }
    auto isSubscriberSystemApp = subscriberRecord->eventRecordInfo.isSystemApp ||
        subscriberRecord->eventRecordInfo.isSubsystem;
    if (specifiedSubscriberType != UNINITIALIZATED_SUBSCRIBER_TYPE &&
        CheckSubscriberBySpecifiedType(specifiedSubscriberType, isSubscriberSystemApp)) {
        checkResult |= SUBSCRIBER_FILTER_SUBSCRIBER_TYPE_INDEX;
    }

    auto subscriberUid = subscriberRecord->eventRecordInfo.uid;
    if (!specifiedSubscriberUids.empty() &&
        CheckSubscriberBySpecifiedUids(static_cast<int32_t>(subscriberUid), specifiedSubscriberUids)) {
        checkResult |= SUBSCRIBER_FILTER_SUBSCRIBER_UID_INDEX;
    }
    std::vector<std::string> publisherRequiredPermissions = eventRecord.publishInfo->GetSubscriberPermissions();
    if (!publisherRequiredPermissions.empty() &&
        CheckPublisherRequiredPermissions(subscriberRecord, eventRecord)) {
        checkResult |= SUBSCRIBER_FILTER_PERMISSION_INDEX;
    }
    bool result = false;
    if (eventRecord.publishInfo->GetValidationRule() == ValidationRule::AND) {
        result = (checkResult == filterSettings);
    } else {
        result = ((checkResult & filterSettings) != 0);
    }
    if (!result) {
        EVENT_LOGD(LOG_TAG_SUBSCRIBER, "Not match,%{public}d_%{public}u_%{public}u",
            static_cast<int32_t>(eventRecord.publishInfo->GetValidationRule()),
            static_cast<uint32_t>(checkResult), static_cast<uint32_t>(filterSettings));
    }
    return result;
}

bool CommonEventSubscriberManager::CheckSubscriberPermission(
    const SubscriberRecordPtr &subscriberRecord, const CommonEventRecord &eventRecord)
{
    EVENT_LOGD(LOG_TAG_SUBSCRIBER, "enter");
    bool ret = false;
    std::string lackPermission {};
    std::string event = eventRecord.commonEventData->GetWant().GetAction();
    bool isSystemAPIEvent = DelayedSingleton<CommonEventPermissionManager>::GetInstance()->IsSystemAPIEvent(event);
    if (isSystemAPIEvent && !(subscriberRecord->eventRecordInfo.isSubsystem
        || subscriberRecord->eventRecordInfo.isSystemApp)) {
        EVENT_LOGW(LOG_TAG_SUBSCRIBER, "Invalid permission for system api event.");
        return false;
    }
    if (subscriberRecord->eventRecordInfo.uid == eventRecord.eventRecordInfo.uid) {
        return true;
    }
    Permission permission = DelayedSingleton<CommonEventPermissionManager>::GetInstance()->GetEventPermission(event);
    if (permission.names.empty()) {
        return true;
    }

    if (permission.names.size() == 1) {
        ret = AccessTokenHelper::VerifyAccessToken(subscriberRecord->eventRecordInfo.callerToken, permission.names[0]);
        lackPermission = permission.names[0];
    } else if (permission.state == PermissionState::AND) {
        for (const auto& vec : permission.names) {
            ret = AccessTokenHelper::VerifyAccessToken(subscriberRecord->eventRecordInfo.callerToken, vec);
            if (!ret) {
                lackPermission = vec;
                break;
            }
        }
    } else if (permission.state == PermissionState::OR) {
        for (const auto& vec : permission.names) {
            ret = AccessTokenHelper::VerifyAccessToken(subscriberRecord->eventRecordInfo.callerToken, vec);
            lackPermission += vec + CONNECTOR;
            if (ret) {
                break;
            }
        }
        lackPermission = lackPermission.substr(0, lackPermission.length() - CONNECTOR.length());
    }
    if (!ret) {
        EVENT_LOGD(LOG_TAG_SUBSCRIBER, "No permission to receive %{public}s, due to %{public}s lacks the "
            "%{public}s permission", event.c_str(), subscriberRecord->eventRecordInfo.subId.c_str(),
            lackPermission.c_str());
    }
    return ret;
}

bool CommonEventSubscriberManager::CheckSubscriberRequiredPermission(const SubscriberRecordPtr &subscriberRecord,
    const CommonEventRecord &eventRecord)
{
    if (subscriberRecord->eventRecordInfo.uid == eventRecord.eventRecordInfo.uid) {
        return true;
    }
    std::string subscriberRequiredPermission = subscriberRecord->eventSubscribeInfo->GetPermission();
    if (subscriberRequiredPermission.empty()) {
        return true;
    }

    bool ret = AccessTokenHelper::VerifyAccessToken(eventRecord.eventRecordInfo.callerToken,
        subscriberRequiredPermission);
    if (!ret) {
        EVENT_LOGD(LOG_TAG_SUBSCRIBER, "No permission to send %{public}s "
                    "to %{public}s due to subscriber requires the %{public}s permission.",
            eventRecord.commonEventData->GetWant().GetAction().c_str(),
            subscriberRecord->eventRecordInfo.subId.c_str(),
            subscriberRequiredPermission.c_str());
        return false;
    }

    return true;
}

bool CommonEventSubscriberManager::CheckPublisherRequiredPermissions(const SubscriberRecordPtr &subscriberRecord,
    const CommonEventRecord &eventRecord)
{
    if (subscriberRecord->eventRecordInfo.uid == eventRecord.eventRecordInfo.uid) {
        return true;
    }
    std::vector<std::string> publisherRequiredPermissions = eventRecord.publishInfo->GetSubscriberPermissions();
    for (const auto& publisherRequiredPermission : publisherRequiredPermissions) {
        bool ret = AccessTokenHelper::VerifyAccessToken(
            subscriberRecord->eventRecordInfo.callerToken, publisherRequiredPermission);
        if (!ret) {
            EVENT_LOGD(LOG_TAG_SUBSCRIBER, "No permission to receive %{public}s to %{public}s"
                        "due to publisher requires the %{public}s permission.",
                eventRecord.commonEventData->GetWant().GetAction().c_str(),
                subscriberRecord->eventRecordInfo.subId.c_str(),
                publisherRequiredPermission.c_str());
            return false;
        }
    }
    return true;
}

void CommonEventSubscriberManager::SubscribeScreenEventToBlackListApp(const CommonEventRecord &eventRecord,
    std::string subscribeBundleName, int subscribeUid, std::vector<SubscriberRecordPtr> &records,
    SubscriberRecordPtr it)
{
#ifdef WATCH_CUSTOMIZED_SCREEN_EVENT_TO_OTHER_APP
    std::string action = eventRecord.commonEventData->GetWant().GetAction();
    if (!action.empty() && (action != CommonEventSupport::COMMON_EVENT_SCREEN_ON &&
                               action != CommonEventSupport::COMMON_EVENT_SCREEN_OFF)) {
        records.emplace_back(it);
        return;
    }
    std::vector<std::string> excludeSubscriberBundleNames =
        eventRecord.commonEventData->GetWant().GetStringArrayParam("exceptBundleNames");
    std::vector<int32_t> excludeSubscriberUids = eventRecord.commonEventData->GetWant().GetIntArrayParam("exceptUids");
    if (handler != nullptr && SubscribeScreenEventToBlackListAppFlag != nullptr) {
        bool result = SubscribeScreenEventToBlackListAppFlag(
            excludeSubscriberBundleNames, excludeSubscriberUids, subscribeBundleName, subscribeUid);
        if (result) {
            records.emplace_back(it);
        }
    }
#else
    records.emplace_back(it);
#endif
}

void CommonEventSubscriberManager::GetSubscriberRecordsByEvent(
    const std::string &event, const int32_t &userId, std::vector<SubscriberRecordPtr> &records)
{
    if (event.empty() && userId == ALL_USER) {
        records = subscribers_;
    } else if (event.empty()) {
        for (auto recordPtr : subscribers_) {
            if (recordPtr->eventSubscribeInfo->GetUserId() == userId) {
                records.emplace_back(recordPtr);
            }
        }
    } else if (userId == ALL_USER) {
        auto infoItem = eventSubscribers_.find(event);
        if (infoItem != eventSubscribers_.end()) {
            for (auto recordPtr : infoItem->second) {
                records.emplace_back(recordPtr);
            }
        }
    } else {
        auto infoItem = eventSubscribers_.find(event);
        if (infoItem != eventSubscribers_.end()) {
            for (auto recordPtr : infoItem->second) {
                if (CheckSubscriberByUserId(recordPtr->eventSubscribeInfo->GetUserId(), true, userId)) {
                    records.emplace_back(recordPtr);
                }
            }
        }
    }
}

void CommonEventSubscriberManager::UpdateFreezeInfo(
    const uid_t &uid, const bool &freezeState, const int64_t &freezeTime)
{
    EVENT_LOGD(LOG_TAG_FREEZED, "enter");

    std::lock_guard<ffrt::mutex> lock(mutex_);
    for (auto recordPtr : subscribers_) {
        if (recordPtr->eventRecordInfo.uid == uid) {
            if (freezeState) {
                recordPtr->freezeTime = freezeTime;
            } else {
                recordPtr->freezeTime = 0;
            }
            recordPtr->isFreeze = freezeState;
            EVENT_LOGD(LOG_TAG_FREEZED, "recordPtr->uid: %{public}d, recordPtr->isFreeze: %{public}d",
                recordPtr->eventRecordInfo.uid, recordPtr->isFreeze);
        }
    }
}

void CommonEventSubscriberManager::UpdateFreezeInfo(
    std::set<int> pidList, const bool &freezeState, const int64_t &freezeTime)
{
    EVENT_LOGD(LOG_TAG_FREEZED, "enter");

    std::lock_guard<ffrt::mutex> lock(mutex_);
    for (auto recordPtr : subscribers_) {
        for (auto it = pidList.begin(); it != pidList.end(); it++) {
            if (recordPtr->eventRecordInfo.pid == *it) {
                if (freezeState) {
                    recordPtr->freezeTime = freezeTime;
                } else {
                    recordPtr->freezeTime = 0;
                }
                recordPtr->isFreeze = freezeState;
                EVENT_LOGD(LOG_TAG_FREEZED, "recordPtr->pid: %{public}d, recordPtr->isFreeze: %{public}d",
                    recordPtr->eventRecordInfo.pid, recordPtr->isFreeze);
            }
        }
    }
}

void CommonEventSubscriberManager::UpdateAllFreezeInfos(const bool &freezeState, const int64_t &freezeTime)
{
    EVENT_LOGD(LOG_TAG_FREEZED, "enter");

    std::lock_guard<ffrt::mutex> lock(mutex_);
    for (auto recordPtr : subscribers_) {
        if (freezeState) {
            recordPtr->freezeTime = freezeTime;
        } else {
            recordPtr->freezeTime = 0;
        }
        recordPtr->isFreeze = freezeState;
    }
    EVENT_LOGD(LOG_TAG_FREEZED, "all subscribers update freeze state to %{public}d", freezeState);
}

void CommonEventSubscriberManager::InsertFrozenEvents(
    const SubscriberRecordPtr &subscriberRecord, const CommonEventRecord &eventRecord)
{
    EVENT_LOGD(LOG_TAG_FREEZED, "enter");

    if (subscriberRecord == nullptr) {
        EVENT_LOGE(LOG_TAG_FREEZED, "subscriberRecord is null");
        return;
    }

    auto record = std::make_shared<CommonEventRecord>(eventRecord);
    std::lock_guard<ffrt::mutex> lock(mutex_);
    auto frozenRecordsItem = frozenEvents_.find(subscriberRecord->eventRecordInfo.uid);
    if (frozenRecordsItem != frozenEvents_.end()) {
        auto eventRecordsItem = frozenRecordsItem->second.find(*subscriberRecord);
        if (eventRecordsItem != frozenRecordsItem->second.end()) {
            eventRecordsItem->second.emplace_back(record);
            time_t backRecordTime = mktime(&eventRecordsItem->second.back()->recordTime);
            time_t frontRecordTime = mktime(&eventRecordsItem->second.front()->recordTime);
            time_t timeDiff = backRecordTime - frontRecordTime;
            if (timeDiff > FREEZE_EVENT_TIMEOUT) {
                eventRecordsItem->second.erase(eventRecordsItem->second.begin());
            }
        } else {
            std::vector<EventRecordPtr> EventRecords;
            EventRecords.emplace_back(record);
            frozenRecordsItem->second[*subscriberRecord] = EventRecords;
        }
    } else {
        std::map<EventSubscriberRecord, std::vector<EventRecordPtr>> frozenRecords;
        std::vector<EventRecordPtr> EventRecords;
        EventRecords.emplace_back(record);
        frozenRecords[*subscriberRecord] = EventRecords;
        frozenEvents_[subscriberRecord->eventRecordInfo.uid] = frozenRecords;
    }
}

std::map<EventSubscriberRecord, std::vector<EventRecordPtr>> CommonEventSubscriberManager::GetFrozenEvents(
    const uid_t &uid)
{
    EVENT_LOGD(LOG_TAG_FREEZED, "enter");

    std::map<EventSubscriberRecord, std::vector<EventRecordPtr>> frozenEvents;
    std::lock_guard<ffrt::mutex> lock(mutex_);
    auto infoItem = frozenEvents_.find(uid);
    if (infoItem != frozenEvents_.end()) {
        frozenEvents = infoItem->second;
    }

    RemoveFrozenEvents(uid);

    return frozenEvents;
}

std::map<uid_t, FrozenRecords> CommonEventSubscriberManager::GetAllFrozenEvents()
{
    EVENT_LOGD(LOG_TAG_FREEZED, "enter");
    std::lock_guard<ffrt::mutex> lock(mutex_);
    return std::move(frozenEvents_);
}

void CommonEventSubscriberManager::RemoveFrozenEvents(const uid_t &uid)
{
    EVENT_LOGD(LOG_TAG_FREEZED, "enter");
    auto infoItem = frozenEvents_.find(uid);
    if (infoItem != frozenEvents_.end()) {
        frozenEvents_.erase(uid);
    }
}

void CommonEventSubscriberManager::RemoveFrozenEventsBySubscriber(const SubscriberRecordPtr &subscriberRecord)
{
    EVENT_LOGD(LOG_TAG_FREEZED, "enter");

    auto frozenRecordsItem = frozenEvents_.find(subscriberRecord->eventRecordInfo.uid);
    if (frozenRecordsItem != frozenEvents_.end()) {
        auto eventRecordsItems = frozenRecordsItem->second.find(*subscriberRecord);
        if (eventRecordsItems != frozenRecordsItem->second.end()) {
            frozenRecordsItem->second.erase(*subscriberRecord);
        }
    }
}

void CommonEventSubscriberManager::InsertFrozenEventsMap(
    const SubscriberRecordPtr &subscriberRecord, const CommonEventRecord &eventRecord)
{
    EVENT_LOGD(LOG_TAG_FREEZED, "enter");

    if (subscriberRecord == nullptr) {
        EVENT_LOGE(LOG_TAG_FREEZED, "subscriberRecord is null");
        return;
    }

    auto record = std::make_shared<CommonEventRecord>(eventRecord);
    std::lock_guard<ffrt::mutex> lock(mutex_);
    auto frozenRecordsItem = frozenEventsMap_.find(subscriberRecord->eventRecordInfo.pid);
    if (frozenRecordsItem != frozenEventsMap_.end()) {
        auto eventRecordsItem = frozenRecordsItem->second.find(*subscriberRecord);
        if (eventRecordsItem != frozenRecordsItem->second.end()) {
            eventRecordsItem->second.emplace_back(record);
            time_t backRecordTime = mktime(&eventRecordsItem->second.back()->recordTime);
            time_t frontRecordTime = mktime(&eventRecordsItem->second.front()->recordTime);
            time_t timeDiff = backRecordTime - frontRecordTime;
            if (timeDiff > FREEZE_EVENT_TIMEOUT) {
                eventRecordsItem->second.erase(eventRecordsItem->second.begin());
            }
        } else {
            std::vector<EventRecordPtr> EventRecords;
            EventRecords.emplace_back(record);
            frozenRecordsItem->second[*subscriberRecord] = EventRecords;
        }
    } else {
        std::map<EventSubscriberRecord, std::vector<EventRecordPtr>> frozenRecords;
        std::vector<EventRecordPtr> EventRecords;
        EventRecords.emplace_back(record);
        frozenRecords[*subscriberRecord] = EventRecords;
        frozenEventsMap_[subscriberRecord->eventRecordInfo.pid] = frozenRecords;
    }
}

std::map<EventSubscriberRecord, std::vector<EventRecordPtr>> CommonEventSubscriberManager::GetFrozenEventsMapByPid(
    const pid_t &pid)
{
    EVENT_LOGD(LOG_TAG_FREEZED, "enter");

    std::map<EventSubscriberRecord, std::vector<EventRecordPtr>> frozenEvents;
    std::lock_guard<ffrt::mutex> lock(mutex_);
    auto infoItem = frozenEventsMap_.find(pid);
    if (infoItem != frozenEventsMap_.end()) {
        frozenEvents = infoItem->second;
    }

    RemoveFrozenEventsMapByPid(pid);

    return frozenEvents;
}

std::map<pid_t, FrozenRecords> CommonEventSubscriberManager::GetAllFrozenEventsMap()
{
    EVENT_LOGD(LOG_TAG_FREEZED, "enter");
    std::lock_guard<ffrt::mutex> lock(mutex_);
    return std::move(frozenEventsMap_);
}

void CommonEventSubscriberManager::RemoveFrozenEventsMapByPid(const pid_t &pid)
{
    EVENT_LOGD(LOG_TAG_FREEZED, "enter");
    auto infoItem = frozenEventsMap_.find(pid);
    if (infoItem != frozenEventsMap_.end()) {
        frozenEventsMap_.erase(pid);
    }
}

void CommonEventSubscriberManager::RemoveFrozenEventsMapBySubscriber(const SubscriberRecordPtr &subscriberRecord)
{
    EVENT_LOGD(LOG_TAG_FREEZED, "enter");

    auto frozenRecordsItem = frozenEventsMap_.find(subscriberRecord->eventRecordInfo.pid);
    if (frozenRecordsItem != frozenEventsMap_.end()) {
        auto eventRecordsItems = frozenRecordsItem->second.find(*subscriberRecord);
        if (eventRecordsItems != frozenRecordsItem->second.end()) {
            frozenRecordsItem->second.erase(*subscriberRecord);
        }
    }
}

void CommonEventSubscriberManager::SendSubscriberExceedMaximumHiSysEvent(int32_t userId, const std::string &eventName,
    uint32_t subscriberNum)
{
    EventInfo eventInfo;
    eventInfo.userId = userId;
    eventInfo.eventName = eventName;
    eventInfo.subscriberNum = subscriberNum;
    EventReport::SendHiSysEvent(SUBSCRIBER_EXCEED_MAXIMUM, eventInfo);
}

bool CommonEventSubscriberManager::CheckSubscriberCountReachedMaxinum()
{
    uint32_t subscriberCount = subscribers_.size();
    uint32_t maxSubscriberNum = GetUintParameter("hiviewdfx.ces.subscriber_limit",
        DEFAULT_MAX_SUBSCRIBER_NUM_ALL_APP);
    if (subscriberCount == (uint32_t)(maxSubscriberNum * WARNING_REPORT_PERCENTAGE)) {
        EVENT_LOGW(LOG_TAG_SUBSCRIBER, "subscribers reaches the alarm threshold");
        PrintSubscriberCounts(GetTopSubscriberCounts());
        return false;
    }
    if (subscriberCount == maxSubscriberNum) {
        EVENT_LOGE(LOG_TAG_SUBSCRIBER, "subscribers reaches the maxinum");
        PrintSubscriberCounts(GetTopSubscriberCounts());
        return true;
    }
    return false;
}

std::vector<std::pair<pid_t, uint32_t>> CommonEventSubscriberManager::GetTopSubscriberCounts(size_t topNum)
{
    topNum = subscriberCounts_.size() < topNum ? subscriberCounts_.size() : topNum;

    std::vector<std::pair<pid_t, uint32_t>> vtSubscriberCounts;
    std::set<pid_t> pidSet;
    for (size_t i = 0; i < topNum; i++) {
        std::pair<pid_t, uint32_t> curPair;
        for (auto it = subscriberCounts_.begin(); it != subscriberCounts_.end(); it++) {
            pid_t pid = it->first;
            uint32_t count = it->second;
            if (pidSet.find(pid) != pidSet.end()) {
                continue;
            }
            if (curPair.second < count) {
                curPair = std::make_pair(pid, count);
            }
        }
        pidSet.insert(curPair.first);
        vtSubscriberCounts.push_back(curPair);
    }

    return vtSubscriberCounts;
}

void CommonEventSubscriberManager::PrintSubscriberCounts(std::vector<std::pair<pid_t, uint32_t>> vtSubscriberCounts)
{
    EVENT_LOGI(LOG_TAG_SUBSCRIBER, "Print top App by subscribers in descending order");
    int index = 1;
    for (auto vtIt = vtSubscriberCounts.begin(); vtIt != vtSubscriberCounts.end(); vtIt++) {
        EVENT_LOGI(LOG_TAG_SUBSCRIBER, "top%{public}d pid=%{public}d subscribers=%{public}d",
            index, vtIt->first, vtIt->second);
        index++;
    }
}
}  // namespace EventFwk
}  // namespace OHOS