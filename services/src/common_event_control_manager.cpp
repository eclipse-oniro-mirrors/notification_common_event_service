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

#include "common_event_control_manager.h"

#include <cinttypes>

#include "access_token_helper.h"
#include "bundle_manager_helper.h"
#include "common_event_constant.h"
#include "event_log_wrapper.h"
#include "event_trace_wrapper.h"
#include "event_report.h"
#include "hitrace_meter_adapter.h"
#include "ievent_receive.h"
#include "system_time.h"
#include "xcollie/watchdog.h"
namespace OHOS {
namespace EventFwk {
constexpr int32_t LENGTH = 80;
constexpr int32_t DOUBLE = 2;
static const int32_t TIME_UNIT_SIZE = 1000;

CommonEventControlManager::CommonEventControlManager()
    : handler_(nullptr), handlerOrdered_(nullptr), pendingTimeoutMessage_(false), scheduled_(false)
{
    EVENT_LOGD(LOG_TAG_CES, "enter");
}

CommonEventControlManager::~CommonEventControlManager()
{
    EVENT_LOGD(LOG_TAG_CES, "enter");
}

bool CommonEventControlManager::PublishCommonEvent(
    const CommonEventRecord &eventRecord, const sptr<IRemoteObject> &commonEventListener)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    EVENT_LOGD(LOG_TAG_CES, "enter");

    bool ret = false;

    if (!eventRecord.publishInfo->IsOrdered()) {
        ret = ProcessUnorderedEvent(eventRecord);
    } else {
        ret = ProcessOrderedEvent(eventRecord, commonEventListener);
    }

    return ret;
}

bool CommonEventControlManager::PublishStickyCommonEvent(
    const CommonEventRecord &eventRecord, const std::shared_ptr<EventSubscriberRecord> &subscriberRecord)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    EVENT_LOGD(LOG_TAG_STICKY, "enter");

    if (!subscriberRecord) {
        EVENT_LOGE(LOG_TAG_STICKY, "subscriberRecord is null");
        return false;
    }
    return ProcessUnorderedEvent(eventRecord, subscriberRecord);
}

bool CommonEventControlManager::PublishFreezeCommonEvent(const uid_t &uid)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    EVENT_LOGD(LOG_TAG_FREEZED, "enter");

    if (!GetUnorderedEventHandler()) {
        EVENT_LOGE(LOG_TAG_FREEZED, "failed to get eventhandler");
        return false;
    }
    PublishFrozenEventsInner(DelayedSingleton<CommonEventSubscriberManager>::GetInstance()->GetFrozenEvents(uid));
    return true;
}

bool CommonEventControlManager::PublishFreezeCommonEvent(std::set<int> pidList)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    EVENT_LOGD(LOG_TAG_FREEZED, "enter");

    if (!GetUnorderedEventHandler()) {
        EVENT_LOGE(LOG_TAG_FREEZED, "failed to get eventhandler");
        return false;
    }
    for (auto it = pidList.begin(); it != pidList.end(); it++) {
        PublishFrozenEventsInner(
            DelayedSingleton<CommonEventSubscriberManager>::GetInstance()->GetFrozenEventsMapByPid(*it));
    }
    return true;
}

bool CommonEventControlManager::PublishAllFreezeCommonEvents()
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    EVENT_LOGD(LOG_TAG_CES, "enter");

    if (!GetUnorderedEventHandler()) {
        EVENT_LOGE(LOG_TAG_CES, "failed to get eventhandler");
        return false;
    }

    std::map<uid_t, FrozenRecords> frozenEventRecords =
        DelayedSingleton<CommonEventSubscriberManager>::GetInstance()->GetAllFrozenEvents();
    for (auto record : frozenEventRecords) {
        PublishFrozenEventsInner(record.second);
    }

    std::map<pid_t, FrozenRecords> frozenEventRecordsMap =
        DelayedSingleton<CommonEventSubscriberManager>::GetInstance()->GetAllFrozenEventsMap();
    for (auto record : frozenEventRecordsMap) {
        PublishFrozenEventsInner(record.second);
    }
    return true;
}

void CommonEventControlManager::PublishFrozenEventsInner(const FrozenRecords &frozenRecords)
{
    for (auto record : frozenRecords) {
        for (auto vec : record.second) {
            if (!vec) {
                EVENT_LOGW(LOG_TAG_FREEZED, "failed to find record");
                continue;
            }

            EventSubscriberRecord subscriberRecord = record.first;
            CommonEventRecord eventRecord = *vec;
            std::weak_ptr<CommonEventControlManager> weak = shared_from_this();
            auto innerCallback = [weak, subscriberRecord, eventRecord]() {
                auto control = weak.lock();
                if (control == nullptr) {
                    EVENT_LOGE(LOG_TAG_FREEZED, "CommonEventControlManager is null");
                    return;
                }
                control->NotifyFreezeEvents(subscriberRecord, eventRecord);
            };
            unorderedImmediateQueue_->submit(innerCallback);
        }
    }
}

bool CommonEventControlManager::NotifyFreezeEvents(
    const EventSubscriberRecord &subscriberRecord, const CommonEventRecord &eventRecord)
{
    EVENT_LOGD(LOG_TAG_FREEZED, "enter");

    sptr<IEventReceive> commonEventListenerProxy = iface_cast<IEventReceive>(subscriberRecord.commonEventListener);
    if (!commonEventListenerProxy) {
        EVENT_LOGE(LOG_TAG_FREEZED, "Fail to get IEventReceive proxy");
        return false;
    }

    if (eventRecord.commonEventData == nullptr) {
        EVENT_LOGE(LOG_TAG_FREEZED, "commonEventData == nullptr");
        return false;
    }
    commonEventListenerProxy->NotifyEvent(*(eventRecord.commonEventData),
        false, eventRecord.publishInfo->IsSticky());
    AccessTokenHelper::RecordSensitivePermissionUsage(subscriberRecord.eventRecordInfo.callerToken,
        eventRecord.commonEventData->GetWant().GetAction());
    return true;
}

bool CommonEventControlManager::GetUnorderedEventHandler()
{
    if (!unorderedQueue_) {
        unorderedQueue_ = std::make_shared<ffrt::queue>("unordered_common_event");
    }

    if (!unorderedImmediateQueue_) {
        unorderedImmediateQueue_ = std::make_shared<ffrt::queue>("unordered_immediate_common_event",
            ffrt::queue_attr().qos(ffrt::qos_utility));
    }

    return true;
}

void CommonEventControlManager::NotifyUnorderedEventLocked(std::shared_ptr<OrderedEventRecord> &eventRecord)
{
    int32_t succCnt = 0;
    int32_t failCnt = 0;
    int32_t freezeCnt = 0;
    std::string freezedPidsLogger = "";
    for (auto vec : eventRecord->receivers) {
        if (vec == nullptr) {
            EVENT_LOGE(LOG_TAG_UNORDERED, "invalid vec");
            failCnt++;
            continue;
        }
        size_t index = eventRecord->nextReceiver++;
        if (vec->isFreeze) {
            eventRecord->deliveryState[index] = OrderedEventRecord::SKIPPED;
            DelayedSingleton<CommonEventSubscriberManager>::GetInstance()->InsertFrozenEvents(vec, *eventRecord);
            DelayedSingleton<CommonEventSubscriberManager>::GetInstance()->InsertFrozenEventsMap(
                vec, *eventRecord);
            if (freezedPidsLogger.empty()) {
                freezedPidsLogger.append(" freezePid[");
            }
            freezedPidsLogger.append(std::to_string(vec->eventRecordInfo.pid)).append(",");
            EVENT_LOGD(LOG_TAG_UNORDERED, "Notify %{public}s to freeze subscriber, subId = %{public}s",
                eventRecord->commonEventData->GetWant().GetAction().c_str(), vec->eventRecordInfo.subId.c_str());
            freezeCnt++;
            continue;
        }
        sptr<IEventReceive> commonEventListenerProxy = iface_cast<IEventReceive>(vec->commonEventListener);
        if (!commonEventListenerProxy) {
            eventRecord->deliveryState[index] = OrderedEventRecord::SKIPPED;
            EVENT_LOGE(LOG_TAG_UNORDERED, "Notify %{public}s to invalid proxy, subId = %{public}s",
                eventRecord->commonEventData->GetWant().GetAction().c_str(), vec->eventRecordInfo.subId.c_str());
            failCnt++;
            continue;
        }
        eventRecord->deliveryState[index] = OrderedEventRecord::DELIVERED;
        eventRecord->state = OrderedEventRecord::RECEIVING;
        int32_t result = commonEventListenerProxy->NotifyEvent(*(eventRecord->commonEventData), false,
            eventRecord->publishInfo->IsSticky());
        if (result != ERR_OK) {
            eventRecord->state = OrderedEventRecord::SKIPPED;
            failCnt++;
            EVENT_LOGE(LOG_TAG_UNORDERED, "Notify %{public}s fail, subId = %{public}s",
                eventRecord->commonEventData->GetWant().GetAction().c_str(), vec->eventRecordInfo.subId.c_str());
            continue;
        }
        eventRecord->state = OrderedEventRecord::RECEIVED;
        succCnt++;
        AccessTokenHelper::RecordSensitivePermissionUsage(vec->eventRecordInfo.callerToken,
            eventRecord->commonEventData->GetWant().GetAction());
    }
    if (!freezedPidsLogger.empty()) {
        freezedPidsLogger.append("]");
    }
    std::string event = eventRecord->commonEventData->GetWant().GetAction();
    if (CanLogUnorderedEvent(event)) {
        EVENT_LOGI(LOG_TAG_UNORDERED, "Pid %{public}d publish %{public}s to %{public}d end"
            "(%{public}zu,%{public}d,%{public}d,%{public}d)%{public}s",
            eventRecord->eventRecordInfo.pid, event.c_str(), eventRecord->userId,
            eventRecord->receivers.size(), succCnt, failCnt, freezeCnt, freezedPidsLogger.c_str());
    }
}

bool CommonEventControlManager::CanLogUnorderedEvent(const std::string &event)
{
    auto now = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
    std::lock_guard<ffrt::mutex> lock(logCacheMutex_);
    auto item = unorderedEventLogCache_.begin();
    bool canPrint = false;
    bool findEvent = false;
    while (item != unorderedEventLogCache_.end()) {
        auto last = item->second.first;
        auto duration = now - last;
        if (item->first != event) {
            if (duration.count() >= EVENT_LOG_EVENT_LIMIT_INTERVALS) {
                item = unorderedEventLogCache_.erase(item);
                continue;
            }
            item++;
            continue;
        }
        findEvent = true;
        auto supressed = item->second.second;
        if (duration.count() >= EVENT_LOG_EVENT_LIMIT_INTERVALS) {
            if (supressed != 0) {
                EVENT_LOGI(LOG_TAG_UNORDERED, "event %{public}s at %{public}lld log suppressed cnt %{public}u",
                    event.c_str(), last.time_since_epoch().count(), supressed);
            }
            canPrint = true;
            item = unorderedEventLogCache_.erase(item);
        } else {
            item->second = std::make_pair(last, supressed + 1);
            item++;
            canPrint = false;
        }
    }
    if (!findEvent) {
        unorderedEventLogCache_[event] = std::make_pair(now, 0);
        canPrint = true;
    }
    return canPrint;
}

bool CommonEventControlManager::NotifyUnorderedEvent(std::shared_ptr<OrderedEventRecord> &eventRecord)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (!eventRecord) {
        EVENT_LOGD(LOG_TAG_UNORDERED, "Invalid event record.");
        return false;
    }
    
    NotifyUnorderedEventLocked(eventRecord);

    std::lock_guard<ffrt::mutex> lock(unorderedMutex_);
    auto it = std::find(unorderedEventQueue_.begin(), unorderedEventQueue_.end(), eventRecord);
    if (it != unorderedEventQueue_.end()) {
        unorderedEventQueue_.erase(it);
    }
    return true;
}

bool CommonEventControlManager::ProcessUnorderedEvent(
    const CommonEventRecord &eventRecord, const std::shared_ptr<EventSubscriberRecord> &subscriberRecord)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    EVENT_LOGD(LOG_TAG_UNORDERED, "enter");

    bool ret = false;

    if (!GetUnorderedEventHandler()) {
        EVENT_LOGE(LOG_TAG_UNORDERED, "failed to get eventhandler");
        return ret;
    }

    std::shared_ptr<OrderedEventRecord> eventRecordPtr = std::make_shared<OrderedEventRecord>();
    if (eventRecordPtr == nullptr) {
        EVENT_LOGE(LOG_TAG_UNORDERED, "eventRecordPtr is null");
        return ret;
    }

    std::shared_ptr<CommonEventSubscriberManager> spinstance =
        DelayedSingleton<CommonEventSubscriberManager>::GetInstance();

    eventRecordPtr->FillCommonEventRecord(eventRecord);
    if (subscriberRecord) {
        eventRecordPtr->receivers.emplace_back(subscriberRecord);
    } else {
        eventRecordPtr->receivers = spinstance->GetSubscriberRecords(eventRecord);
    }

    for (auto vec : eventRecordPtr->receivers) {
        eventRecordPtr->deliveryState.emplace_back(OrderedEventRecord::PENDING);
    }

    EnqueueUnorderedRecord(eventRecordPtr);

    std::weak_ptr<CommonEventControlManager> weak = shared_from_this();
    auto innerCallback = [weak, eventRecordPtr]() {
        auto manager = weak.lock();
        if (manager == nullptr) {
            EVENT_LOGE(LOG_TAG_CES, "CommonEventControlManager is null");
            return;
        }
        std::shared_ptr<OrderedEventRecord> ordered = eventRecordPtr;
        manager->NotifyUnorderedEvent(ordered);
    };

    if (eventRecord.isSystemEvent) {
        unorderedImmediateQueue_->submit(innerCallback);
    } else {
        unorderedQueue_->submit(innerCallback);
    }

    return ret;
}

std::shared_ptr<OrderedEventRecord> CommonEventControlManager::GetMatchingOrderedReceiver(
    const sptr<IRemoteObject> &proxy)
{
    EVENT_LOGD(LOG_TAG_CES, "enter");

    std::lock_guard<ffrt::mutex> lock(orderedMutex_);

    if (!orderedEventQueue_.empty()) {
        std::shared_ptr<OrderedEventRecord> firstRecord = orderedEventQueue_.front();
        if ((firstRecord != nullptr) && (firstRecord->curReceiver == proxy)) {
            return firstRecord;
        }
    }

    return nullptr;
}

bool CommonEventControlManager::GetOrderedEventHandler()
{
    if (!orderedQueue_) {
        orderedQueue_ = std::make_shared<ffrt::queue>("ordered_common_event");
    }
    return true;
}

bool CommonEventControlManager::ProcessOrderedEvent(
    const CommonEventRecord &eventRecord, const sptr<IRemoteObject> &commonEventListener)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    EVENT_LOGD(LOG_TAG_ORDERED, "enter");

    bool ret = false;

    if (!GetOrderedEventHandler()) {
        EVENT_LOGE(LOG_TAG_ORDERED, "failed to get eventhandler");
        return ret;
    }

    std::shared_ptr<OrderedEventRecord> eventRecordPtr = std::make_shared<OrderedEventRecord>();
    if (eventRecordPtr == nullptr) {
        EVENT_LOGE(LOG_TAG_ORDERED, "eventRecordPtr is null");
        return ret;
    }

    std::shared_ptr<CommonEventSubscriberManager> spinstance =
        DelayedSingleton<CommonEventSubscriberManager>::GetInstance();
    auto subscribers = spinstance->GetSubscriberRecords(eventRecord);
    auto OrderedSubscriberCompareFunc = [] (
        std::shared_ptr<EventSubscriberRecord> fist,
        std::shared_ptr<EventSubscriberRecord> second) {
        return fist->eventSubscribeInfo->GetPriority() > second->eventSubscribeInfo->GetPriority();
    };
    std::sort(subscribers.begin(), subscribers.end(), OrderedSubscriberCompareFunc);
    eventRecordPtr->FillCommonEventRecord(eventRecord);
    eventRecordPtr->resultTo = commonEventListener;
    eventRecordPtr->state = OrderedEventRecord::IDLE;
    eventRecordPtr->nextReceiver = 0;
    eventRecordPtr->receivers = subscribers;
    for (auto vec : eventRecordPtr->receivers) {
        eventRecordPtr->deliveryState.emplace_back(OrderedEventRecord::PENDING);
    }

    EnqueueOrderedRecord(eventRecordPtr);

    ret = ScheduleOrderedCommonEvent();

    return ret;
}

bool CommonEventControlManager::EnqueueUnorderedRecord(const std::shared_ptr<OrderedEventRecord> &eventRecordPtr)
{
    if (eventRecordPtr == nullptr) {
        EVENT_LOGE(LOG_TAG_UNORDERED, "eventRecordPtr is null");
        return false;
    }

    std::lock_guard<ffrt::mutex> lock(unorderedMutex_);

    unorderedEventQueue_.emplace_back(eventRecordPtr);

    return true;
}

bool CommonEventControlManager::EnqueueOrderedRecord(const std::shared_ptr<OrderedEventRecord> &eventRecordPtr)
{
    if (eventRecordPtr == nullptr) {
        EVENT_LOGE(LOG_TAG_ORDERED, "eventRecordPtr is null");
        return false;
    }

    std::lock_guard<ffrt::mutex> lock(orderedMutex_);

    orderedEventQueue_.emplace_back(eventRecordPtr);

    return true;
}

bool CommonEventControlManager::ScheduleOrderedCommonEvent()
{
    EVENT_LOGD(LOG_TAG_ORDERED, "enter");

    if (scheduled_) {
        return true;
    }

    scheduled_ = true;

    std::weak_ptr<CommonEventControlManager> weak = shared_from_this();
    orderedQueue_->submit([weak]() {
        auto manager = weak.lock();
        if (manager == nullptr) {
            EVENT_LOGE(LOG_TAG_ORDERED, "CommonEventControlManager is null");
            return;
        }
        manager->ProcessNextOrderedEvent(true);
    });
    return true;
}

bool CommonEventControlManager::NotifyOrderedEvent(std::shared_ptr<OrderedEventRecord> &eventRecordPtr, size_t index)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    EVENT_LOGD(LOG_TAG_ORDERED, "enter with index %{public}zu", index);
    if (eventRecordPtr == nullptr) {
        EVENT_LOGE(LOG_TAG_ORDERED, "eventRecordPtr = nullptr");
        return false;
    }
    size_t receiverNum = eventRecordPtr->receivers.size();
    if ((index < 0) || (index >= receiverNum)) {
        EVENT_LOGE(LOG_TAG_ORDERED, "Invalid index (= %{public}zu)", index);
        return false;
    }
    if (eventRecordPtr->receivers[index]->isFreeze) {
        EVENT_LOGD(LOG_TAG_ORDERED, "vec isFreeze: %{public}d", eventRecordPtr->receivers[index]->isFreeze);
        DelayedSingleton<CommonEventSubscriberManager>::GetInstance()->InsertFrozenEvents(
            eventRecordPtr->receivers[index], *eventRecordPtr);
        DelayedSingleton<CommonEventSubscriberManager>::GetInstance()->InsertFrozenEventsMap(
            eventRecordPtr->receivers[index], *eventRecordPtr);
        eventRecordPtr->deliveryState[index] = OrderedEventRecord::SKIPPED;
        eventRecordPtr->curReceiver = nullptr;
        return true;
    }
    eventRecordPtr->deliveryState[index] = OrderedEventRecord::DELIVERED;
    eventRecordPtr->curReceiver = eventRecordPtr->receivers[index]->commonEventListener;
    eventRecordPtr->state = OrderedEventRecord::RECEIVING;
    sptr<IEventReceive> receiver = iface_cast<IEventReceive>(eventRecordPtr->curReceiver);
    if (!receiver) {
        EVENT_LOGE(LOG_TAG_ORDERED, "Failed to get IEventReceive proxy");
        eventRecordPtr->curReceiver = nullptr;
        return false;
    }
    eventRecordPtr->state = OrderedEventRecord::RECEIVED;
    int32_t result = receiver->NotifyEvent(*(eventRecordPtr->commonEventData), true,
        eventRecordPtr->publishInfo->IsSticky());
    if (result != ERR_OK) {
        eventRecordPtr->state = OrderedEventRecord::SKIPPED;
        EVENT_LOGE(LOG_TAG_ORDERED, "Notify %{public}s fail, subId = %{public}s",
            eventRecordPtr->commonEventData->GetWant().GetAction().c_str(),
            eventRecordPtr->receivers[index]->eventRecordInfo.subId.c_str());
        eventRecordPtr->curReceiver = nullptr;
        return false;
    }
    EVENT_LOGD(LOG_TAG_ORDERED, "NotifyOrderedEvent index = %{public}zu event = %{public}s success,"
        " subId = %{public}s", index, eventRecordPtr->commonEventData->GetWant().GetAction().c_str(),
        eventRecordPtr->receivers[index]->eventRecordInfo.subId.c_str());
    AccessTokenHelper::RecordSensitivePermissionUsage(
        eventRecordPtr->receivers[index]->eventRecordInfo.callerToken,
        eventRecordPtr->commonEventData->GetWant().GetAction());
    return true;
}

void CommonEventControlManager::ProcessNextOrderedEvent(bool isSendMsg)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    EVENT_LOGD(LOG_TAG_ORDERED, "enter");

    if (isSendMsg) {
        scheduled_ = false;
    }

    std::shared_ptr<OrderedEventRecord> sp = nullptr;
    {
        std::lock_guard<ffrt::mutex> lock(orderedMutex_);
        do {
            if (orderedEventQueue_.empty()) {
                EVENT_LOGD(LOG_TAG_ORDERED, "orderedEventQueue_ is empty");
                return;
            }

            sp = orderedEventQueue_.front();
            bool forceReceive = false;
            size_t numReceivers = sp->receivers.size();
            uint64_t nowSysTime = static_cast<uint64_t>(SystemTime::GetNowSysTime());

            if (sp->dispatchTime > 0) {
                if ((numReceivers > 0) && (nowSysTime > static_cast<uint64_t>(sp->dispatchTime) +
                    (DOUBLE * TIMEOUT * numReceivers))) {
                    CurrentOrderedEventTimeout(false);
                    forceReceive = true;
                    sp->state = OrderedEventRecord::IDLE;
                }
            }

            if (sp->state != OrderedEventRecord::IDLE) {
                return;
            }

            if ((sp->receivers.empty()) || (sp->nextReceiver >= numReceivers) || sp->resultAbort || forceReceive) {
                // No more receivers for this ordered common event, then process the final result receiver
                bool hasLastSubscribe = (sp->resultTo != nullptr) ? true : false;
                if (sp->resultTo != nullptr) {
                    EVENT_LOGD(LOG_TAG_ORDERED, "Process the final subscriber");
                    sptr<IEventReceive> receiver = iface_cast<IEventReceive>(sp->resultTo);
                    if (!receiver) {
                        EVENT_LOGE(LOG_TAG_ORDERED, "Failed to get IEventReceive proxy");
                        return;
                    }
                    int32_t result = receiver->NotifyEvent(*(sp->commonEventData), true, sp->publishInfo->IsSticky());
                    if (result != ERR_OK) {
                        EVENT_LOGE(LOG_TAG_ORDERED, "Notify %{public}s fail to final receiver",
                            sp->commonEventData->GetWant().GetAction().c_str());
                    }
                    sp->resultTo = nullptr;
                }
                EVENT_LOGI(LOG_TAG_ORDERED, "Pid %{public}d publish %{public}s to %{public}d end(%{public}zu,"
                    "%{public}zu)", sp->eventRecordInfo.pid, sp->commonEventData->GetWant().GetAction().c_str(),
                    sp->userId, numReceivers, sp->nextReceiver);
                CancelTimeout();

                orderedEventQueue_.erase(orderedEventQueue_.begin());

                sp = nullptr;
            }
        } while (sp == nullptr);
    }
    size_t recIdx = sp->nextReceiver++;
    SetTime(recIdx, sp, pendingTimeoutMessage_);

    NotifyOrderedEvent(sp, recIdx);
    if (sp->curReceiver == nullptr) {
        sp->state = OrderedEventRecord::IDLE;
        ScheduleOrderedCommonEvent();
    }
}

void CommonEventControlManager::SetTime(size_t recIdx, std::shared_ptr<OrderedEventRecord> &sp, bool timeoutMessage)
{
    EVENT_LOGD(LOG_TAG_ORDERED, "enter");

    sp->receiverTime = SystemTime::GetNowSysTime();

    if (recIdx == 0) {
        sp->dispatchTime = sp->receiverTime;
    }

    if (!timeoutMessage) {
        SetTimeout();
    }
}

bool CommonEventControlManager::SetTimeout()
{
    EVENT_LOGD(LOG_TAG_ORDERED, "enter");

    bool ret = true;

    if (!pendingTimeoutMessage_) {
        pendingTimeoutMessage_ = true;
        std::weak_ptr<CommonEventControlManager> weak = shared_from_this();
        orderedHandler = orderedQueue_->submit_h([weak]() {
            auto manager = weak.lock();
            if (manager == nullptr) {
                EVENT_LOGE(LOG_TAG_ORDERED, "CommonEventControlManager is null");
                return;
            }
            manager->CurrentOrderedEventTimeout(true);
        }, ffrt::task_attr().delay(TIMEOUT * TIME_UNIT_SIZE));
    }

    return ret;
}

bool CommonEventControlManager::CancelTimeout()
{
    EVENT_LOGD(LOG_TAG_ORDERED, "enter");

    if (pendingTimeoutMessage_) {
        pendingTimeoutMessage_ = false;
        orderedQueue_->cancel(orderedHandler);
    }

    return true;
}

void CommonEventControlManager::CurrentOrderedEventTimeout(bool isFromMsg)
{
    EVENT_LOGD(LOG_TAG_ORDERED, "enter");

    if (isFromMsg) {
        pendingTimeoutMessage_ = false;
    }

    if (orderedEventQueue_.empty()) {
        EVENT_LOGE(LOG_TAG_ORDERED, "empty orderedEventQueue_");
        return;
    }

    int64_t nowSysTime = SystemTime::GetNowSysTime();
    std::shared_ptr<OrderedEventRecord> sp = orderedEventQueue_.front();

    if (isFromMsg) {
        int64_t timeoutTime = sp->receiverTime + TIMEOUT;
        if (timeoutTime > nowSysTime) {
            SetTimeout();
            return;
        }
    }

    // The processing of current receiver has timeout
    sp->receiverTime = nowSysTime;

    if (sp->nextReceiver > 0) {
        std::shared_ptr<EventSubscriberRecord> subscriberRecord = sp->receivers[sp->nextReceiver - 1];
        EVENT_LOGW(LOG_TAG_ORDERED, "Timeout: When %{public}s process %{public}s",
            subscriberRecord->eventRecordInfo.subId.c_str(), sp->commonEventData->GetWant().GetAction().c_str());
        SendOrderedEventProcTimeoutHiSysEvent(subscriberRecord, sp->commonEventData->GetWant().GetAction());

        sp->deliveryState[sp->nextReceiver - 1] = OrderedEventRecord::TIMEOUT;
    }

    // Forced to finish the current receiver to process the next receiver
    int32_t code = sp->commonEventData->GetCode();
    const std::string &strRef = sp->commonEventData->GetData();
    bool abort = sp->resultAbort;
    FinishReceiver(sp, code, strRef, abort);

    ScheduleOrderedCommonEvent();

    return;
}

bool CommonEventControlManager::FinishReceiver(std::shared_ptr<OrderedEventRecord> recordPtr, const int32_t &code,
    const std::string &receiverData, const bool &abortEvent)
{
    EVENT_LOGD(LOG_TAG_ORDERED, "enter");

    if (recordPtr == nullptr) {
        EVENT_LOGE(LOG_TAG_ORDERED, "recordPtr is null");
        return false;
    }

    EVENT_LOGD(LOG_TAG_ORDERED, "enter recordPtr->state=%{public}d", recordPtr->state);

    int8_t state = recordPtr->state;
    recordPtr->state = OrderedEventRecord::IDLE;
    recordPtr->curReceiver = nullptr;
    recordPtr->commonEventData->SetCode(code);
    recordPtr->commonEventData->SetData(receiverData);
    recordPtr->resultAbort = abortEvent;

    return state == OrderedEventRecord::RECEIVED;
}

bool CommonEventControlManager::FinishReceiverAction(std::shared_ptr<OrderedEventRecord> recordPtr, const int32_t &code,
    const std::string &receiverData, const bool &abortEvent)
{
    EVENT_LOGD(LOG_TAG_CES, "enter");

    if (recordPtr == nullptr) {
        EVENT_LOGE(LOG_TAG_CES, "recordPtr is nullptr");
        return false;
    }

    bool doNext = false;
    doNext = FinishReceiver(recordPtr, code, receiverData, abortEvent);
    if (doNext) {
        std::weak_ptr<CommonEventControlManager> weak = shared_from_this();
        orderedQueue_->submit([weak]() {
            auto manager = weak.lock();
            if (manager == nullptr) {
                EVENT_LOGE(LOG_TAG_ORDERED, "CommonEventControlManager is null");
                return;
            }
            manager->ProcessNextOrderedEvent(false);
        });
    }

    return true;
}

void CommonEventControlManager::GetUnorderedEventRecords(
    const std::string &event, const int32_t &userId, std::vector<std::shared_ptr<OrderedEventRecord>> &records)
{
    EVENT_LOGD(LOG_TAG_CES, "enter");
    std::lock_guard<ffrt::mutex> unorderedLock(unorderedMutex_);
    if (event.empty() && userId == ALL_USER) {
        records = unorderedEventQueue_;
    } else if (event.empty()) {
        for (auto vec : unorderedEventQueue_) {
            if (vec->userId == userId) {
                records.emplace_back(vec);
            }
        }
    } else if (userId == ALL_USER) {
        for (auto vec : unorderedEventQueue_) {
            if (vec->commonEventData->GetWant().GetAction() == event) {
                records.emplace_back(vec);
            }
        }
    } else {
        for (auto vec : unorderedEventQueue_) {
            if (vec->commonEventData->GetWant().GetAction() == event && vec->userId == userId) {
                records.emplace_back(vec);
            }
        }
    }
}

void CommonEventControlManager::GetOrderedEventRecords(
    const std::string &event, const int32_t &userId, std::vector<std::shared_ptr<OrderedEventRecord>> &records)
{
    EVENT_LOGD(LOG_TAG_CES, "enter");
    std::lock_guard<ffrt::mutex> orderedLock(orderedMutex_);
    if (event.empty() && userId == ALL_USER) {
        records = orderedEventQueue_;
    } else if (event.empty()) {
        for (auto vec : orderedEventQueue_) {
            if (vec->userId == userId) {
                records.emplace_back(vec);
            }
        }
    } else if (userId == ALL_USER) {
        for (auto vec : orderedEventQueue_) {
            if (vec->commonEventData->GetWant().GetAction() == event) {
                records.emplace_back(vec);
            }
        }
    } else {
        for (auto vec : orderedEventQueue_) {
            if (vec->commonEventData->GetWant().GetAction() == event && vec->userId == userId) {
                records.emplace_back(vec);
            }
        }
    }
}

void CommonEventControlManager::DumpStateByCommonEventRecord(
    const std::shared_ptr<OrderedEventRecord> &record, std::string &dumpInfo)
{
    EVENT_LOGD(LOG_TAG_CES, "enter");

    char systime[LENGTH];
    strftime(systime, sizeof(char) * LENGTH, "%Y%m%d %I:%M %p", &record->recordTime);

    std::string recordTime = "\tTime: " + std::string(systime) + "\n";
    std::string pid = "\tPID: " + std::to_string(record->eventRecordInfo.pid) + "\n";
    std::string uid = "\tUID: " + std::to_string(record->eventRecordInfo.uid) + "\n";
    std::string userId;
    switch (record->userId) {
        case UNDEFINED_USER:
            userId = "UNDEFINED_USER";
            break;
        case ALL_USER:
            userId = "ALL_USER";
            break;
        default:
            userId = std::to_string(record->userId);
            break;
    }
    userId = "\tUSERID: " + userId + "\n";
    std::string bundleName = "\tBundleName: " + record->eventRecordInfo.bundleName + "\n";

    std::string permission = "\tRequiredPermission: ";
    std::string separator;
    size_t permissionNum = 0;
    for (auto permissionVec : record->publishInfo->GetSubscriberPermissions()) {
        if (permissionNum == 0) {
            separator = "";
        } else {
            separator = ", ";
        }
        permission = permission + separator + permissionVec;
        permissionNum++;
    }
    permission = permission + "\n";

    std::string isSticky;
    if (record->publishInfo->IsSticky()) {
        isSticky = "\tIsSticky: true\n";
    } else {
        isSticky = "\tIsSticky: false\n";
    }

    std::string isOrdered;
    if (record->publishInfo->IsOrdered()) {
        isOrdered = "\tIsOrdered: true\n";
    } else {
        isOrdered = "\tIsOrdered: false\n";
    }
    std::string isSystemApp = record->eventRecordInfo.isSystemApp ? "true" : "false";
    isSystemApp = "\tIsSystemApp: " + isSystemApp + "\n";
    std::string isSystemEvent = record->isSystemEvent ? "true" : "false";
    isSystemEvent = "\tIsSystemEvent: " + isSystemEvent + "\n";

    std::string action = "\t\tAction: " + record->commonEventData->GetWant().GetAction() + "\n";

    std::string entities = "\t\tEntity: ";
    size_t entityNum = 0;
    for (auto entitiesVec : record->commonEventData->GetWant().GetEntities()) {
        if (entityNum == 0) {
            separator = "";
        } else {
            separator = ", ";
        }
        entities = entities + separator + entitiesVec;
        entityNum++;
    }
    entities = entities + "\n";

    std::string scheme = "\t\tScheme: " + record->commonEventData->GetWant().GetScheme() + "\n";
    std::string uri = "\t\tUri: " + record->commonEventData->GetWant().GetUriString() + "\n";
    std::string flags = "\t\tFlags: " + std::to_string(record->commonEventData->GetWant().GetFlags()) + "\n";
    std::string type = "\t\tType: " + record->commonEventData->GetWant().GetType() + "\n";
    std::string bundle = "\t\tBundleName: " + record->commonEventData->GetWant().GetBundle() + "\n";
    std::string ability = "\t\tAbilityName: " + record->commonEventData->GetWant().GetElement().GetAbilityName() + "\n";

    std::string want = "\tWant:\n" + action + entities + scheme + uri + flags + type + bundle + ability;
    std::string code = "\tCode: " + std::to_string(record->commonEventData->GetCode()) + "\n";
    std::string data = "\tData: " + record->commonEventData->GetData() + "\n";

    std::string lastSubscriber;
    if (record->resultTo) {
        lastSubscriber = "\tHasLastSubscriber: true\n";
    } else {
        lastSubscriber = "\tHasLastSubscriber: false\n";
    }

    std::string state;
    switch (record->state) {
        case OrderedEventRecord::IDLE:
            state = "\tEventState: IDLE\n";
            break;
        case OrderedEventRecord::RECEIVING:
            state = "\tEventState: RECEIVING\n";
            break;
        case OrderedEventRecord::RECEIVED:
            state = "\tEventState: RECEIVED\n";
            break;
    }

    std::string dispatchTime = "\tDispatchTime: " + std::to_string(record->dispatchTime) + "\n";
    std::string receiverTime = "\tReceiverTime: " + std::to_string(record->receiverTime) + "\n";
    std::string resultAbort = record->resultAbort ? "true" : "false";
    resultAbort = "\tResultAbort: " + resultAbort + "\n";

    dumpInfo = recordTime + pid + uid + userId + bundleName + permission + isSticky + isOrdered + isSystemApp +
               isSystemEvent + want + code + data + lastSubscriber + state + receiverTime + dispatchTime + resultAbort;
}

void CommonEventControlManager::DumpStateBySubscriberRecord(
    const std::shared_ptr<OrderedEventRecord> &record, std::string &dumpInfo)
{
    EVENT_LOGD(LOG_TAG_CES, "enter");

    if (record->receivers.empty()) {
        dumpInfo = "\tSubscribers:\tNo information";
        return;
    }

    size_t num = 0;
    for (auto receiver : record->receivers) {
        num++;

        std::string title = std::to_string(num);
        if (num == 1) {
            title = "\tSubscribers:\tTotal " + std::to_string(record->receivers.size()) + " subscribers\n\tNO " +
                    title + "\n";
        } else {
            title = "\tNO " + title + "\n";
        }

        std::string dumpInfoBySubscriber;
        DelayedSingleton<CommonEventSubscriberManager>::GetInstance()->DumpDetailed(
            title, receiver, "\t\t", dumpInfoBySubscriber);

        std::string deliveryState;
        switch (record->deliveryState[num - 1]) {
            case OrderedEventRecord::PENDING:
                deliveryState = "\t\tEventState: PENDING\n";
                break;
            case OrderedEventRecord::DELIVERED:
                deliveryState = "\t\tEventState: DELIVERED\n";
                break;
            case OrderedEventRecord::SKIPPED:
                deliveryState = "\t\tEventState: SKIPPED\n";
                break;
            case OrderedEventRecord::TIMEOUT:
                deliveryState = "\t\tEventState: TIMEOUT\n";
                break;
        }
        dumpInfo = dumpInfo + dumpInfoBySubscriber + deliveryState;
    }
}

void CommonEventControlManager::DumpState(
    const std::string &event, const int32_t &userId, std::vector<std::string> &state)
{
    EVENT_LOGD(LOG_TAG_CES, "enter");
    std::vector<std::shared_ptr<OrderedEventRecord>> records;
    std::vector<std::shared_ptr<OrderedEventRecord>> unorderedRecords;
    std::vector<std::shared_ptr<OrderedEventRecord>> orderedRecords;
    GetUnorderedEventRecords(event, userId, unorderedRecords);
    GetOrderedEventRecords(event, userId, orderedRecords);
    records.insert(records.end(), unorderedRecords.begin(), unorderedRecords.end());
    records.insert(records.end(), orderedRecords.begin(), orderedRecords.end());

    if (records.empty()) {
        state.emplace_back("Pending Events:\tNo information");
        return;
    }

    size_t num = 0;
    for (auto record : records) {
        num++;

        std::string no = std::to_string(num);
        if (num == 1) {
            no = "Pending Events:\tTotal " + std::to_string(records.size()) + " information\nNO " + no + "\n";
        } else {
            no = "NO " + no + "\n";
        }
        std::string commonEventRecord;
        DumpStateByCommonEventRecord(record, commonEventRecord);
        std::string subscriberRecord;
        DumpStateBySubscriberRecord(record, subscriberRecord);
        std::string stateInfo = no + commonEventRecord + subscriberRecord;
        state.emplace_back(stateInfo);
    }
}

void CommonEventControlManager::SendOrderedEventProcTimeoutHiSysEvent(
    const std::shared_ptr<EventSubscriberRecord> &subscriberRecord, const std::string &eventName)
{
    if (subscriberRecord == nullptr) {
        return;
    }

    EventInfo eventInfo;
    if (subscriberRecord->eventSubscribeInfo != nullptr) {
        eventInfo.userId = subscriberRecord->eventSubscribeInfo->GetUserId();
    }
    eventInfo.subscriberName = subscriberRecord->eventRecordInfo.bundleName;
    eventInfo.pid = subscriberRecord->eventRecordInfo.pid;
    eventInfo.uid = static_cast<int32_t>(subscriberRecord->eventRecordInfo.uid);
    eventInfo.eventName = eventName;
    EventReport::SendHiSysEvent(ORDERED_EVENT_PROC_TIMEOUT, eventInfo);
}
}  // namespace EventFwk
}  // namespace OHOS