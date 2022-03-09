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

#include "event_log_wrapper.h"
#include "subscriber_death_recipient.h"

namespace OHOS {
namespace EventFwk {
const int LENGTH = 80;

CommonEventSubscriberManager::CommonEventSubscriberManager()
    : death_(sptr<IRemoteObject::DeathRecipient>(new SubscriberDeathRecipient()))
{
}

CommonEventSubscriberManager::~CommonEventSubscriberManager()
{
}

bool CommonEventSubscriberManager::InsertSubscriber(const SubscribeInfoPtr &eventSubscribeInfo,
    const sptr<IRemoteObject> &commonEventListener, const struct tm &recordTime,
    const EventRecordInfo &eventRecordInfo)
{
    EVENT_LOGI("enter");

    if (eventSubscribeInfo == nullptr) {
        EVENT_LOGE("eventSubscribeInfo is null");
        return false;
    }

    if (commonEventListener == nullptr) {
        EVENT_LOGE("commonEventListener is null");
        return false;
    }

    std::vector<std::string> events = eventSubscribeInfo->GetMatchingSkills().GetEvents();
    if (events.size() <= 0) {
        EVENT_LOGE("No subscribed events");
        return false;
    }

    auto record = std::make_shared<EventSubscriberRecord>();
    if (record == nullptr) {
        EVENT_LOGE("Failed to create EventSubscriberRecord");
        return false;
    }

    record->eventSubscribeInfo = eventSubscribeInfo;
    record->commonEventListener = commonEventListener;
    record->recordTime = recordTime;
    record->eventRecordInfo = eventRecordInfo;

    if (death_ != nullptr) {
        commonEventListener->AddDeathRecipient(death_);
    }

    return InsertSubscriberRecordLocked(events, record);
}

int CommonEventSubscriberManager::RemoveSubscriber(const sptr<IRemoteObject> &commonEventListener)
{
    EVENT_LOGI("enter");

    if (commonEventListener == nullptr) {
        EVENT_LOGE("commonEventListener is null");
        return ERR_INVALID_VALUE;
    }

    if (death_ != nullptr) {
        commonEventListener->RemoveDeathRecipient(death_);
    }

    return RemoveSubscriberRecordLocked(commonEventListener);
}

std::vector<std::shared_ptr<EventSubscriberRecord>> CommonEventSubscriberManager::GetSubscriberRecords(
    const Want &want, const bool &isSystemApp, const int32_t &userId)
{
    EVENT_LOGI("enter");

    auto records = std::vector<SubscriberRecordPtr>();

    GetSubscriberRecordsByWantLocked(want, isSystemApp, userId, records);

    return records;
}

void CommonEventSubscriberManager::DumpDetailed(
    const std::string &title, const SubscriberRecordPtr &record, const std::string format, std::string &dumpInfo)
{
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
    std::string deviceId = format + "DevicedID: " + record->eventSubscribeInfo->GetDeviceId() + "\n";

    std::string events = format + "\tEvent: ";
    std::string separator;
    for (int eventNum = 0; eventNum < record->eventSubscribeInfo->GetMatchingSkills().CountEvent(); ++eventNum) {
        if (eventNum == 0) {
            separator = "";
        } else {
            separator = ", ";
        }
        events = events + separator + record->eventSubscribeInfo->GetMatchingSkills().GetEvent(eventNum);
    }
    events = events + "\n";

    std::string entities = format + "\tEntity: ";
    for (int entityNum = 0; entityNum < record->eventSubscribeInfo->GetMatchingSkills().CountEntities(); ++entityNum) {
        if (entityNum == 0) {
            separator = "";
        } else {
            separator = ", ";
        }
        entities = entities + separator + record->eventSubscribeInfo->GetMatchingSkills().GetEntity(entityNum);
    }
    entities = entities + "\n";

    std::string scheme = format + "\tScheme: ";
    for (int schemeNum = 0; schemeNum < record->eventSubscribeInfo->GetMatchingSkills().CountSchemes(); ++schemeNum) {
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

    dumpInfo = title + recordTime + pid + uid + bundleName + priority + userId + permission + deviceId +
               matchingSkills + isFreeze + freezeTime;
}

void CommonEventSubscriberManager::DumpState(const std::string &event, const int32_t &userId,
    std::vector<std::string> &state)
{
    EVENT_LOGI("enter");

    std::vector<SubscriberRecordPtr> records;

    std::lock_guard<std::mutex> lock(mutex_);
    GetSubscriberRecordsByEvent(event, userId, records);

    if (records.size() == 0) {
        state.emplace_back("Subscribers:\tNo information");
        return;
    }

    int num = 0;
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

bool CommonEventSubscriberManager::InsertSubscriberRecordLocked(
    const std::vector<std::string> &events, const SubscriberRecordPtr &record)
{
    if (events.size() == 0) {
        EVENT_LOGE("No subscribed events");
        return false;
    }

    if (record == nullptr) {
        EVENT_LOGE("record is null");
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    for (auto event : events) {
        auto infoItem = eventSubscribers_.find(event);
        if (infoItem != eventSubscribers_.end()) {
            infoItem->second.insert(record);
        } else {
            std::multiset<SubscriberRecordPtr> EventSubscribersPtr;
            EventSubscribersPtr.insert(record);
            eventSubscribers_[event] = EventSubscribersPtr;
        }
    }

    subscribers_.emplace_back(record);

    return true;
}

int CommonEventSubscriberManager::RemoveSubscriberRecordLocked(const sptr<IRemoteObject> &commonEventListener)
{
    if (commonEventListener == nullptr) {
        EVENT_LOGE("commonEventListener is null");
        return ERR_INVALID_VALUE;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> events;

    for (auto it = subscribers_.begin(); it != subscribers_.end(); ++it) {
        if (commonEventListener == (*it)->commonEventListener) {
            RemoveFrozenEventsBySubscriber((*it));
            (*it)->commonEventListener = nullptr;
            events = (*it)->eventSubscribeInfo->GetMatchingSkills().GetEvents();
            subscribers_.erase(it);
            break;
        }
    }

    for (auto event : events) {
        for (auto it = eventSubscribers_[event].begin(); it != eventSubscribers_[event].end(); ++it) {
            if ((commonEventListener == (*it)->commonEventListener) || ((*it)->commonEventListener == nullptr)) {
                (*it)->commonEventListener = nullptr;
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

bool CommonEventSubscriberManager::CheckSubscriberByUserId(const int32_t &subscriberUserId, const bool &isSystemApp,
    const int32_t &userId)
{
    if (subscriberUserId == ALL_USER) {
        return true;
    }

    if (isSystemApp && (userId == UNDEFINED_USER || userId == ALL_USER)) {
        return true;
    }

    if (!isSystemApp && subscriberUserId == userId) {
        return true;
    }

    if (isSystemApp && (subscriberUserId == userId
        || (subscriberUserId >= SUBSCRIBE_USER_SYSTEM_BEGIN && subscriberUserId <= SUBSCRIBE_USER_SYSTEM_END))) {
        return true;
    }

    return false;
}

void CommonEventSubscriberManager::GetSubscriberRecordsByWantLocked(const Want &want, const bool &isSystemApp,
    const int32_t &userId, std::vector<SubscriberRecordPtr> &records)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (eventSubscribers_.size() <= 0) {
        return;
    }

    auto recordsItem = eventSubscribers_.find(want.GetAction());
    if (recordsItem == eventSubscribers_.end()) {
        return;
    }

    std::multiset<SubscriberRecordPtr> subscriberRecords = recordsItem->second;
    for (auto it = subscriberRecords.begin(); it != subscriberRecords.end(); it++) {
        if ((*it)->eventSubscribeInfo->GetMatchingSkills().Match(want)) {
            if (CheckSubscriberByUserId((*it)->eventSubscribeInfo->GetUserId(), isSystemApp, userId)) {
                records.emplace_back(*it);
            }
        }
    }
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
    EVENT_LOGI("enter");

    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> events;
    for (auto recordPtr : subscribers_) {
        if (recordPtr->eventRecordInfo.uid == uid) {
            if (freezeState) {
                recordPtr->freezeTime = freezeTime;
            } else {
                recordPtr->freezeTime = 0;
            }
            recordPtr->isFreeze = freezeState;
            EVENT_LOGI("recordPtr->uid: %{public}d", recordPtr->eventRecordInfo.uid);
            EVENT_LOGI("recordPtr->isFreeze: %{public}d", recordPtr->isFreeze);
        }
    }
}

void CommonEventSubscriberManager::InsertFrozenEvents(
    const SubscriberRecordPtr &subscriberRecord, const CommonEventRecord &eventRecord)
{
    EVENT_LOGI("enter");

    if (subscriberRecord == nullptr) {
        EVENT_LOGE("subscriberRecord is null");
        return;
    }

    auto record = std::make_shared<CommonEventRecord>(eventRecord);
    std::lock_guard<std::mutex> lock(mutex_);
    auto frozenRecordsItem = frozenEvents_.find(subscriberRecord->eventRecordInfo.uid);
    if (frozenRecordsItem != frozenEvents_.end()) {
        auto eventRecordsItem = frozenRecordsItem->second.find(subscriberRecord);
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
            frozenRecordsItem->second[subscriberRecord] = EventRecords;
        }
    } else {
        std::map<SubscriberRecordPtr, std::vector<EventRecordPtr>> frozenRecords;
        std::vector<EventRecordPtr> EventRecords;
        EventRecords.emplace_back(record);
        frozenRecords[subscriberRecord] = EventRecords;
        frozenEvents_[subscriberRecord->eventRecordInfo.uid] = frozenRecords;
    }
}

std::map<SubscriberRecordPtr, std::vector<EventRecordPtr>> CommonEventSubscriberManager::GetFrozenEvents(
    const uid_t &uid)
{
    EVENT_LOGI("enter");

    std::map<SubscriberRecordPtr, std::vector<EventRecordPtr>> frozenEvents;
    std::lock_guard<std::mutex> lock(mutex_);
    auto infoItem = frozenEvents_.find(uid);
    if (infoItem != frozenEvents_.end()) {
        frozenEvents = infoItem->second;
    }

    RemoveFrozenEvents(uid);

    return frozenEvents;
}

void CommonEventSubscriberManager::RemoveFrozenEvents(const uid_t &uid)
{
    EVENT_LOGI("enter");
    auto infoItem = frozenEvents_.find(uid);
    if (infoItem != frozenEvents_.end()) {
        frozenEvents_.erase(uid);
    }
}

void CommonEventSubscriberManager::RemoveFrozenEventsBySubscriber(const SubscriberRecordPtr &subscriberRecord)
{
    EVENT_LOGI("enter");

    auto frozenRecordsItem = frozenEvents_.find(subscriberRecord->eventRecordInfo.uid);
    if (frozenRecordsItem != frozenEvents_.end()) {
        auto eventRecordsItems = frozenRecordsItem->second.find(subscriberRecord);
        if (eventRecordsItems != frozenRecordsItem->second.end()) {
            frozenRecordsItem->second.erase(subscriberRecord);
        }
    }
}
}  // namespace EventFwk
}  // namespace OHOS