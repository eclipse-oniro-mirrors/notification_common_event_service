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

#include "common_event_manager.h"

namespace OHOS {
namespace EventManagerFwkAni {
using CommonEventSubscribeInfo = OHOS::EventFwk::CommonEventSubscribeInfo;
using CommonEventSubscriber = OHOS::EventFwk::CommonEventSubscriber;
using CommonEventData = OHOS::EventFwk::CommonEventData;
class AniCommonEventUtils {
public:
    static void GetStdString(ani_env* env, ani_string str, std::string& result);
    static void GetStdStringArrayClass(ani_env* env, ani_object arrayObj, std::vector<std::string>& strings);
    static void ConvertCommonEventPublishData(ani_env* env, ani_object optionsObject, EventFwk::Want& want,
        EventFwk::CommonEventData& commonEventData, EventFwk::CommonEventPublishInfo& commonEventPublishInfo);
    static void ConvertCommonEventSubscribeInfo(
        ani_env* env, ani_object infoObject, CommonEventSubscribeInfo& subscribeInfo);
    static void ConvertCommonEventDataToEts(ani_env* env, ani_object& ani_data, const CommonEventData& commonEventData);
    static bool GetStringOrUndefined(ani_env* env, ani_object param, const char* name, std::string& res);
    static bool GetIntOrUndefined(ani_env* env, ani_object param, const char* name, int32_t& res);
    static bool GetBooleanOrUndefined(ani_env* env, ani_object param, const char* name, bool& res);
    static bool GetStringArrayOrUndefined(
        ani_env* env, ani_object param, const char* name, std::vector<std::string>& res);
    static void CreateNewObjectByClass(ani_env* env, const char* className, ani_class &cls, ani_object& ani_data);
    template<typename valueType>
    static void CallSetter(ani_env* env, ani_class cls, ani_object object, const char* setterName, valueType value);
    static void CreateAniDoubleObject(ani_env* env, ani_object &object, ani_double value);
    static void CreateBusinessErrorObject(ani_env* env, ani_object &object, int32_t code, const std::string &message);
};
} // namespace EventManagerFwkAni
} // namespace OHOS
#endif // BASE_NOTIFICATION_COMMON_EVENT_MANAGER_INCLUDE_ANI_COMMON_EVENT_UTILS_H