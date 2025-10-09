/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_COMMON_EVENT_MANAGER_INCLUDE_ANI_COMMON_EVENT_UTILS_H
#define BASE_NOTIFICATION_COMMON_EVENT_MANAGER_INCLUDE_ANI_COMMON_EVENT_UTILS_H

#include <ani.h>
#include <array>
#include <iostream>
#include <unistd.h>

#include "ani_common_event.h"
#include "common_event_manager.h"

namespace OHOS {
namespace EventManagerFwkAni {
using CommonEventSubscribeInfo = OHOS::EventFwk::CommonEventSubscribeInfo;
using CommonEventSubscriber = OHOS::EventFwk::CommonEventSubscriber;
using CommonEventData = OHOS::EventFwk::CommonEventData;
constexpr const char *BUSINESS_ERROR_CLASS = "L@ohos/base/BusinessError;";
constexpr const char *ERROR_CLASS_NAME = "Lescompat/Error;";
constexpr int32_t ERROR_CODE_INTERNAL_ERROR = 1500001;
constexpr const char* ERROR_MSG_INTERNAL_ERROR =
    "Internal error.";

class AniCommonEventUtils {
public:
    static void GetStdString(ani_env* env, ani_string str, std::string& result);
    static ani_status GetAniString(ani_env* env, const std::string str, ani_string &aniStr);
    static void GetStdStringArrayClass(ani_env* env, ani_object arrayObj, std::vector<std::string>& strings);
    static void ConvertCommonEventPublishData(ani_env* env, ani_object optionsObject, EventFwk::Want& want,
        EventFwk::CommonEventData& commonEventData, EventFwk::CommonEventPublishInfo& commonEventPublishInfo);
    static void ConvertCommonEventSubscribeInfo(
        ani_env* env, ani_object infoObject, CommonEventSubscribeInfo& subscribeInfo);
    static void GetCommonEventSubscribeInfoToEts(
        ani_env* env, std::shared_ptr<SubscriberInstance> subscriber, ani_object &infoObject);
    static void ConvertCommonEventDataToEts(ani_env* env, ani_object& ani_data, const CommonEventData& commonEventData);
    static bool GetStringOrUndefined(ani_env* env, ani_object param, const char* name, std::string& res);
    static bool GetDoubleOrUndefined(ani_env* env, ani_object param, const char* name, int32_t& res);
    static bool GetIntOrUndefined(ani_env* env, ani_object param, const char* name, int32_t& res);
    static bool GetBooleanOrUndefined(ani_env* env, ani_object param, const char* name, bool& res);
    static bool GetStringArrayOrUndefined(
        ani_env* env, ani_object param, const char* name, std::vector<std::string>& res);
    static bool GetWantParamsOrUndefined(
        ani_env* env, ani_object param, const char* name, AAFwk::WantParams& wantParams);
    static void CreateNewObjectByClass(ani_env* env, const char* className, ani_class &cls, ani_object& ani_data);
    template<typename valueType>
    static void CallSetter(ani_env* env, ani_class cls, ani_object object, const char* setterName, valueType value);
    static void CreateAniIntObject(ani_env* env, ani_object &object, ani_int value);
    static void CreateBusinessErrorObject(ani_env* env, ani_object &object, int32_t code, const std::string &message);
    static ani_object GetAniStringArray(ani_env *env, std::vector<std::string> strs);
    static ani_object newArrayClass(ani_env *env, int length);
    static ani_object GetNullObject(ani_env *env);
    static void ThrowError(ani_env *env, int32_t errCode, const std::string &errorMsg);
};
} // namespace EventManagerFwkAni
} // namespace OHOS
#endif // BASE_NOTIFICATION_COMMON_EVENT_MANAGER_INCLUDE_ANI_COMMON_EVENT_UTILS_H