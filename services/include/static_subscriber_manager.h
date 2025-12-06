/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_EVENT_CESFWK_SERVICES_INCLUDE_STATIC_SUBSCRIBER_MANAGER_H
#define FOUNDATION_EVENT_CESFWK_SERVICES_INCLUDE_STATIC_SUBSCRIBER_MANAGER_H

#include <map>
#include <string>
#include <set>
#include <vector>

#include "nlohmann/json.hpp"

#include "accesstoken_kit.h"
#include "bundle_manager_helper.h"
#include "common_event_data.h"
#include "common_event_publish_info.h"
#include "singleton.h"
#include "ffrt.h"

namespace OHOS {
namespace EventFwk {
class StaticSubscriberManager : public DelayedSingleton<StaticSubscriberManager> {
public:
    StaticSubscriberManager();

    virtual ~StaticSubscriberManager();

    /**
     * Publishes common event to the static subscriber.
     * @param data Indicates the common event data.
     * @param publishInfo Indicates the publish informattion.
     * @param callerToken Indicates the caller token.
     * @param userId Indicates the ID of user.
     * @param service Indicates the service.
     */
    void PublishCommonEvent(const CommonEventData &data, const CommonEventPublishInfo &publishInfo,
        const Security::AccessToken::AccessTokenID &callerToken, const int32_t &userId,
        const sptr<IRemoteObject> &service, const std::string &bundleName);

    /**
     * Set Static Subscriber State.
     *
     * @param enable static subscriber state.
     * @return Returns ERR_OK if success; otherwise failed.
     */
    int32_t SetStaticSubscriberState(bool enable);

    /**
     * Set static subscriber state.
     *
     * @param events Static subscriber event name.
     * @param enable Static subscriber state.
     * @return Returns ERR_OK if success; otherwise failed.
     */
    int32_t SetStaticSubscriberState(const std::vector<std::string> &events, bool enable);

    using ParameterType = std::variant<bool, int32_t, double, std::string>;

private:
    struct StaticSubscriberInfo {
        std::string name;
        std::string bundleName;
        int32_t userId = -1;
        std::string permission;
        std::optional<int32_t> filterCode;
        std::optional<std::string> filterData;
        std::map<std::string, ParameterType> filterParameters;
        int32_t uid = -1;

        bool operator==(const StaticSubscriberInfo &that) const
        {
            return (name == that.name) && (bundleName == that.bundleName) && (userId == that.userId) &&
                (permission == that.permission);
        }
    };

    struct StaticSubscriber {
        std::set<std::string> events;
    };

    bool InitAllowList();
    bool InitValidSubscribers();
    void UpdateSubscriber(const CommonEventData &data);
    void ParseEvents(const std::string &extensionName, const std::string &extensionBundleName,
        const int32_t &extensionUid, const std::string &profile, bool enable = true);
    void AddSubscriber(const AppExecFwk::ExtensionAbilityInfo &extension);
    void AddToValidSubscribers(const std::string &eventName, const StaticSubscriberInfo &extension);
    void AddSubscriberWithBundleName(const std::string &bundleName, const int32_t &userId);
    void RemoveSubscriberWithBundleName(const std::string &bundleName, const int32_t &userId);
    bool VerifySubscriberPermission(const std::string &bundleName, const int32_t &userId,
        const std::vector<std::string> &permissions);
    bool VerifyPublisherPermission(const Security::AccessToken::AccessTokenID &callerToken,
        const std::string &permission);
    void SendStaticEventProcErrHiSysEvent(int32_t userId, const std::string &publisherName,
        const std::string &subscriberName, const std::string &eventName);
    bool IsDisableEvent(const std::string &bundleName, const std::string &event, int32_t uid);
    int32_t UpdateDisableEvents(const std::string &bundleName,
        const std::vector<std::string> &events, bool enable, int32_t uid);
    void PublishCommonEventConnecAbility(const CommonEventData &data, const sptr<IRemoteObject> &service,
        const int32_t &userId, const std::string &bundleName, const std::string &abilityName);
    void PublishCommonEventInner(const CommonEventData &data, const CommonEventPublishInfo &publishInfo,
        const Security::AccessToken::AccessTokenID &callerToken, const int32_t &userId,
        const sptr<IRemoteObject> &service, const std::string &bundleName);
    void SendStaticSubscriberStartHiSysEvent(int32_t userId, const std::string &publisherName,
        const std::string &subscriberName, const std::string &eventName);
    void ParseFilterObject(
        const nlohmann::json &filterObj, const std::string &eventName, StaticSubscriberInfo &subscriber);
    void ParseConditions(
        const nlohmann::json &conditions, const std::string &eventName, StaticSubscriberInfo &subscriber);
    void AddFilterParameter(const std::string &paramName, const nlohmann::json &paramValue,
        std::map<std::string, ParameterType> &filterParameters);
    bool IsFilterParameters(const StaticSubscriberInfo &staticSubscriberInfo, const CommonEventData &data) const;
    bool CheckFilterCodeAndData(const StaticSubscriberInfo &staticSubscriberInfo, const CommonEventData &data) const;
    bool CheckFilterParameters(const std::map<std::string, ParameterType> &filterParameters, const Want &want) const;
    template<typename T, typename QueryFunc, typename UnboxFunc>
    bool CheckSpecificParam(const std::string &paramName, const T &paramValue, const Want &want, QueryFunc queryFunc,
        UnboxFunc unboxFunc) const;
    bool CheckSubscriberWhetherMatched(const StaticSubscriberInfo &subscriber,
        const CommonEventPublishInfo &publishInfo);
    bool CheckSubscriberBySpecifiedUids(const int32_t &subscriberUid,
        const std::vector<int32_t> &specifiedSubscriberUids);
    std::map<std::string, std::vector<StaticSubscriberInfo>> validSubscribers_;
    std::map<std::string, StaticSubscriber> staticSubscribers_;
    // key is bundle, value is eventNames
    std::map<std::string, std::vector<std::string>> disableEvents_;
    bool hasInitAllowList_ = false;
    bool hasInitValidSubscribers_ = false;
    ffrt::mutex subscriberMutex_;
    ffrt::mutex disableEventsMutex_;
    std::shared_ptr<ffrt::queue> ffrt_ = nullptr;
};
}  // namespace EventFwk
}  // namespace OHOS

#endif  // FOUNDATION_EVENT_CESFWK_SERVICES_INCLUDE_STATIC_SUBSCRIBER_MANAGER_H
