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
#include "ani_common_event_utils.h"

#include "event_log_wrapper.h"

namespace OHOS {
namespace EventManagerFwkAni {

using namespace OHOS::EventFwk;

void AniCommonEventUtils::GetStdString(ani_env* env, ani_string str, std::string& result)
{
    auto ret = ANI_ERROR;
    ani_size sz {};
    ret = env->String_GetUTF8Size(str, &sz);
    if (ret != ANI_OK) {
        EVENT_LOGE("GetStdString String_GetUTF8Size error. result: %{public}d.", ret);
        return;
    }
    result.resize(sz + 1);
    ret = env->String_GetUTF8SubString(str, 0, sz, result.data(), result.size(), &sz);
    if (ret != ANI_OK) {
        EVENT_LOGE("GetStdString String_GetUTF8Size error. result: %{public}d.", ret);
        return;
    }
    result.resize(sz);
}

void AniCommonEventUtils::GetStdStringArrayClass(ani_env* env, ani_object arrayObj, std::vector<std::string>& strings)
{
    ani_double length;
    auto ret = ANI_ERROR;
    ret = env->Object_GetPropertyByName_Double(arrayObj, "length", &length);
    if (ret != ANI_OK) {
        EVENT_LOGE("GetStdStringArrayClass Object_GetPropertyByName_Double error. result: %{public}d.", ret);
        return;
    }

    for (ani_int i = 0; i < static_cast<ani_int>(length); i++) {
        ani_ref stringEntryRef;
        ret = env->Object_CallMethodByName_Ref(arrayObj, "$_get", "I:Lstd/core/Object;", &stringEntryRef, i);
        if (ret != ANI_OK) {
            EVENT_LOGE("GetStdStringArrayClass Object_CallMethodByName_Ref error. result: %{public}d.", ret);
            return;
        }

        std::string itemStr;
        GetStdString(env, static_cast<ani_string>(stringEntryRef), itemStr);
        strings.emplace_back(itemStr);
    }

    for (const auto& s : strings) {
        EVENT_LOGI("GetStdStringArrayClass Array String Content: %{public}s.", s.c_str());
    }
}

void AniCommonEventUtils::ConvertCommonEventPublishData(ani_env* env, ani_object optionsObject, Want& want,
    CommonEventData &commonEventData, CommonEventPublishInfo &commonEventPublishInfo)
{
    auto aniResult = ANI_OK;
    // Get the code.
    ani_int code {};
    aniResult = env->Object_GetFieldByName_Int(optionsObject, "code", &code);
    if (aniResult == ANI_OK) {
        commonEventData.SetCode(static_cast<int32_t>(code));
        EVENT_LOGI("ConvertCommonEventPublishData code: %{public}d.", code);
    } else {
        EVENT_LOGW("ConvertCommonEventPublishData get code error. result: %{public}d.", aniResult);
    }

    // Get the data.
    ani_ref dataRef {};
    aniResult = env->Object_GetFieldByName_Ref(optionsObject, "data", &dataRef);
    if (aniResult == ANI_OK) {
        ani_string data = static_cast<ani_string>(dataRef);
        std::string dataStr;
        GetStdString(env, data, dataStr);
        EVENT_LOGI("ConvertCommonEventPublishData data: %{public}s.", dataStr.c_str());
        commonEventData.SetData(dataStr);
    } else {
        EVENT_LOGI("ConvertCommonEventPublishData get data error. result: %{public}d.", aniResult);
    }

    // Get the isOrdered.
    ani_boolean isOrdered;
    aniResult = env->Object_GetFieldByName_Boolean(optionsObject, "isOrdered", &isOrdered);
    if (aniResult == ANI_OK) {
        EVENT_LOGI("ConvertCommonEventPublishData isOrdered: %{public}d.", isOrdered);
        commonEventPublishInfo.SetOrdered(isOrdered);
    } else {
        EVENT_LOGW("ConvertCommonEventPublishData get isOrdered error. result: %{public}d.", aniResult);
    }

    // Get the isSticky.
    ani_boolean isSticky;
    aniResult = env->Object_GetFieldByName_Boolean(optionsObject, "isSticky", &isSticky);
    if (aniResult == ANI_OK) {
        EVENT_LOGI("ConvertCommonEventPublishData isSticky: %{public}d.", isSticky);
        commonEventPublishInfo.SetSticky(isSticky);
    } else {
        EVENT_LOGW("ConvertCommonEventPublishData get isSticky error. result: %{public}d.", aniResult);
    }

    // Get the bundleName.
    ani_ref bundleNameRef {};
    aniResult = env->Object_GetFieldByName_Ref(optionsObject, "bundleName", &bundleNameRef);
    if (aniResult == ANI_OK) {
        ani_string bundleName = static_cast<ani_string>(bundleNameRef);
        std::string bundleNameStr;
        GetStdString(env, bundleName, bundleNameStr);
        EVENT_LOGI("ConvertCommonEventPublishData bundleName: %{public}s.", bundleNameStr.c_str());
        commonEventPublishInfo.SetBundleName(bundleNameStr);
    } else {
        EVENT_LOGW("ConvertCommonEventPublishData gat bundleName error. result: %{public}d.", aniResult);
    }

    // Get the subscriberPermissions.
    ani_ref subscriberPermissionsRef {};
    aniResult = env->Object_GetFieldByName_Ref(optionsObject, "subscriberPermissions", &subscriberPermissionsRef);
    if (aniResult == ANI_OK) {
        std::vector<std::string> subscriberPermissionsStr;
        GetStdStringArrayClass(env, static_cast<ani_object>(bundleNameRef), subscriberPermissionsStr);
        commonEventPublishInfo.SetSubscriberPermissions(subscriberPermissionsStr);
    } else {
        EVENT_LOGW("ConvertCommonEventPublishData gat bundleName error. result: %{public}d.", aniResult);
    }

    // Get the parameters.
}

void AniCommonEventUtils::ConvertCommonEventSubscribeInfo(
    ani_env* env, ani_object infoObject, CommonEventSubscribeInfo& subscribeInfo)
{
    auto aniResult = ANI_OK;
    // Get the events.
    MatchingSkills matchingSkills;
    CommonEventSubscribeInfo commonEventSubscribeInfo(matchingSkills);
    // Get the publisherPermission.
    ani_ref publisherPermissionRef {};
    aniResult = env->Object_GetFieldByName_Ref(infoObject, "publisherPermission", &publisherPermissionRef);
    if (aniResult == ANI_OK) {
        ani_string publisherPermission = static_cast<ani_string>(publisherPermissionRef);
        std::string publisherPermissionStr;
        GetStdString(env, publisherPermission, publisherPermissionStr);
        EVENT_LOGI("ConvertCommonEventSubscribeInfo publisherPermission: %{public}s.", publisherPermissionStr.c_str());
        commonEventSubscribeInfo.SetPermission(publisherPermissionStr);
    } else {
        EVENT_LOGI("ConvertCommonEventSubscribeInfo get publisherPermission error. result: %{public}d.", aniResult);
    }

    // Get the publisherDeviceId.
    ani_ref publisherDeviceIdRef {};
    aniResult = env->Object_GetFieldByName_Ref(infoObject, "publisherDeviceId", &publisherDeviceIdRef);
    if (aniResult == ANI_OK) {
        ani_string publisherDeviceId = static_cast<ani_string>(publisherDeviceIdRef);
        std::string publisherDeviceIdStr;
        GetStdString(env, publisherDeviceId, publisherDeviceIdStr);
        EVENT_LOGI("ConvertCommonEventSubscribeInfo publisherDeviceId: %{public}s.", publisherDeviceIdStr.c_str());
        commonEventSubscribeInfo.SetDeviceId(publisherDeviceIdStr);
    } else {
        EVENT_LOGI("ConvertCommonEventSubscribeInfo get publisherDeviceId error. result: %{public}d.", aniResult);
    }

    // Get the publisherBundleName.
    ani_ref publisherBundleNamedRef {};
    aniResult = env->Object_GetFieldByName_Ref(infoObject, "publisherBundleName", &publisherBundleNamedRef);
    if (aniResult == ANI_OK) {
        ani_string publisherBundleName = static_cast<ani_string>(publisherBundleNamedRef);
        std::string publisherBundleNameStr;
        GetStdString(env, publisherBundleName, publisherBundleNameStr);
        EVENT_LOGI("ConvertCommonEventSubscribeInfo publisherBundleName: %{public}s.", publisherBundleNameStr.c_str());
        commonEventSubscribeInfo.SetPublisherBundleName(publisherBundleNameStr);
    } else {
        EVENT_LOGI("ConvertCommonEventSubscribeInfo get publisherBundleName error. result: %{public}d.", aniResult);
    }

    // Get the userId.
    ani_int userId;
    aniResult = env->Object_GetFieldByName_Int(infoObject, "userId", &userId);
    if (aniResult == ANI_OK) {
        commonEventSubscribeInfo.SetUserId(static_cast<int32_t>(userId));
        EVENT_LOGI("ConvertCommonEventSubscribeInfo userId: %{public}d.", userId);
    } else {
        EVENT_LOGW("ConvertCommonEventSubscribeInfo get userId error. result: %{public}d.", aniResult);
    }

    // Get the priority.
    ani_int priority;
    aniResult = env->Object_GetFieldByName_Int(infoObject, "priority", &priority);
    if (aniResult == ANI_OK) {
        commonEventSubscribeInfo.SetPriority(static_cast<int32_t>(priority));
        EVENT_LOGI("ConvertCommonEventSubscribeInfo priority: %{public}d.", priority);
    } else {
        EVENT_LOGW("ConvertCommonEventSubscribeInfo get priority error. result: %{public}d.", aniResult);
    }
}

void AniCommonEventUtils::ConvertCommonEventDataToEts(
    ani_env* env, ani_object& ani_data, const CommonEventData& commonEventData)
{
    auto aniResult = ANI_OK;
    ani_class cls = nullptr;
    ani_field field = nullptr;
    ani_string string = nullptr;
    if ((aniResult = env->FindClass("L@ohos/event/commonEventData/CommonEventData;", &cls)) != ANI_OK) {
        EVENT_LOGE("ConvertCommonEventDataToEts findClass error. result: %{public}d.", aniResult);
    }
    if (cls == nullptr) {
        EVENT_LOGE("ConvertCommonEventDataToEts cls is null.");
        return;
    }
    if ((aniResult = env->Object_New(cls, nullptr, &ani_data)) != ANI_OK) {
        EVENT_LOGE("ConvertCommonEventDataToEts Object_New error. result: %{public}d.", aniResult);
    }
    if (ani_data == nullptr) {
        EVENT_LOGE("ConvertCommonEventDataToEts ani_data is null.");
        return;
    }

    env->Class_FindField(cls, "event", &field);
    env->String_NewUTF8(
        commonEventData.GetWant().GetAction().c_str(), commonEventData.GetWant().GetAction().size(), &string);
    env->Object_SetField_Ref(ani_data, field, string);

    env->Class_FindField(cls, "bundleName", &field);
    env->String_NewUTF8(
        commonEventData.GetWant().GetBundle().c_str(), commonEventData.GetWant().GetBundle().size(), &string);
    env->Object_SetField_Ref(ani_data, field, string);

    env->Class_FindField(cls, "data", &field);
    env->Object_SetField_Int(ani_data, field, commonEventData.GetCode());

    // Set the parameters.
}

std::string EnumConvertUtils::Support_ConvertSts2Native(const int index)
{
    if (index < 0 || index >= SupportArray.size()) {
        EVENT_LOGE("Support_ConvertSts2Native failed index:%{public}d", index);
        return 0;
    }
    return SupportArray[index];
}

int EnumConvertUtils::Support_ConvertNative2Sts(const std::string nativeValue)
{
    for (unsigned int index = 0; index < SupportArray.size(); index++) {
        if (nativeValue == SupportArray[index]) {
            return index;
        }
    }
    EVENT_LOGE("Support_ConvertSts2Native failed nativeValue:%{public}s", nativeValue.c_str());
    return 0;
}

} // namespace EventManagerFwkAni
} // namespace OHOS