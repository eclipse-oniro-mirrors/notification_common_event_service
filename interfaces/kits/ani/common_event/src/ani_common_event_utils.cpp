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

#include "ani_common_want.h"
#include "event_log_wrapper.h"

namespace OHOS {
namespace EventManagerFwkAni {

using namespace OHOS::EventFwk;
using namespace OHOS::AppExecFwk;
#define SETTER_METHOD_NAME(property) "<set>" #property

void AniCommonEventUtils::GetStdString(ani_env* env, ani_string str, std::string& result)
{
    auto ret = ANI_ERROR;
    ani_size sz {};
    ret = env->String_GetUTF8Size(str, &sz);
    if (ret != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "GetStdString String_GetUTF8Size result: %{public}d.", ret);
        return;
    }
    result.resize(sz + 1);
    ret = env->String_GetUTF8SubString(str, 0, sz, result.data(), result.size(), &sz);
    if (ret != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "GetStdString String_GetUTF8Size result: %{public}d.", ret);
        return;
    }
    result.resize(sz);
}

ani_status AniCommonEventUtils::GetAniString(ani_env* env, const std::string str, ani_string& aniStr)
{
    if (env == nullptr) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "GetAniStringByString fail, env is nullptr");
        return ANI_INVALID_ARGS;
    }
    ani_status status = env->String_NewUTF8(str.c_str(), str.size(), &aniStr);
    if (status != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "String_NewUTF8 failed %{public}d", status);
        return status;
    }
    return status;
}

void AniCommonEventUtils::GetStdStringArrayClass(ani_env* env, ani_object arrayObj, std::vector<std::string>& strings)
{
    ani_double length;
    auto ret = ANI_ERROR;
    ret = env->Object_GetPropertyByName_Double(arrayObj, "length", &length);
    if (ret != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "GetStdStringArrayClass Object_GetPropertyByName_Double result: %{public}d.", ret);
        return;
    }

    for (ani_int i = 0; i < static_cast<ani_int>(length); i++) {
        ani_ref stringEntryRef;
        ret = env->Object_CallMethodByName_Ref(arrayObj, "$_get", "I:Lstd/core/Object;", &stringEntryRef, i);
        if (ret != ANI_OK) {
            EVENT_LOGE(LOG_TAG_CES_ANI, "GetStdStringArrayClass Object_CallMethodByName_Ref result: %{public}d.", ret);
            return;
        }

        std::string itemStr;
        GetStdString(env, static_cast<ani_string>(stringEntryRef), itemStr);
        strings.emplace_back(itemStr);
    }

    for (const auto& s : strings) {
        EVENT_LOGD(LOG_TAG_CES_ANI, "GetStdStringArrayClass Array String Content: %{public}s.", s.c_str());
    }
}

bool AniCommonEventUtils::GetStringOrUndefined(ani_env* env, ani_object param, const char* name, std::string& res)
{
    ani_ref obj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status = ANI_ERROR;

    if ((status = env->Object_GetPropertyByName_Ref(param, name, &obj)) != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "status : %{public}d", status);
        return false;
    }
    if ((status = env->Reference_IsUndefined(obj, &isUndefined)) != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "status : %{public}d", status);
        return false;
    }
    if (isUndefined) {
        EVENT_LOGW(LOG_TAG_CES_ANI, "%{public}s : undefined", name);
        return false;
    }

    ani_ref str = nullptr;
    if ((status = env->Object_CallMethodByName_Ref(reinterpret_cast<ani_object>(obj), "toString", nullptr, &str)) !=
        ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "status : %{public}d", status);
        return false;
    }

    GetStdString(env, reinterpret_cast<ani_string>(str), res);
    return true;
}

bool AniCommonEventUtils::GetDoubleOrUndefined(ani_env* env, ani_object param, const char* name, int32_t& res)
{
    ani_ref obj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status = ANI_ERROR;

    if ((status = env->Object_GetPropertyByName_Ref(param, name, &obj)) != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "status : %{public}d", status);
        return false;
    }
    if ((status = env->Reference_IsUndefined(obj, &isUndefined)) != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "status : %{public}d", status);
        return false;
    }
    if (isUndefined) {
        EVENT_LOGW(LOG_TAG_CES_ANI, "%{public}s : undefined", name);
        return false;
    }

    ani_double result = 0;
    if ((status = env->Object_CallMethodByName_Double(reinterpret_cast<ani_object>(obj), "unboxed", nullptr, &result))
        != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "status : %{public}d", status);
        return false;
    }

    res = static_cast<int32_t>(result);
    return true;
}

bool AniCommonEventUtils::GetIntOrUndefined(ani_env* env, ani_object param, const char* name, int32_t& res)
{
    ani_ref obj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status = ANI_ERROR;

    if ((status = env->Object_GetPropertyByName_Ref(param, name, &obj)) != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "status : %{public}d", status);
        return false;
    }
    if ((status = env->Reference_IsUndefined(obj, &isUndefined)) != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "status : %{public}d", status);
        return false;
    }
    if (isUndefined) {
        EVENT_LOGW(LOG_TAG_CES_ANI, "%{public}s : undefined", name);
        return false;
    }

    ani_int result = 0;
    if ((status = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(obj), "unboxed", nullptr, &result)) !=
        ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "status : %{public}d", status);
        return false;
    }

    res = static_cast<int32_t>(result);
    return true;
}

bool AniCommonEventUtils::GetBooleanOrUndefined(ani_env* env, ani_object param, const char* name, bool& res)
{
    ani_ref obj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status = ANI_ERROR;

    if ((status = env->Object_GetPropertyByName_Ref(param, name, &obj)) != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "status : %{public}d", status);
        return false;
    }
    if ((status = env->Reference_IsUndefined(obj, &isUndefined)) != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "status : %{public}d", status);
        return false;
    }
    if (isUndefined) {
        EVENT_LOGW(LOG_TAG_CES_ANI, "%{public}s : undefined", name);
        return false;
    }

    ani_boolean result = 0;
    if ((status = env->Object_CallMethodByName_Boolean(
        reinterpret_cast<ani_object>(obj), "unboxed", nullptr, &result)) != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "status : %{public}d", status);
        return false;
    }

    res = static_cast<bool>(result);
    return true;
}

bool AniCommonEventUtils::GetStringArrayOrUndefined(
    ani_env* env, ani_object param, const char* name, std::vector<std::string>& res)
{
    ani_ref obj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status = ANI_ERROR;

    if ((status = env->Object_GetPropertyByName_Ref(param, name, &obj)) != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "status : %{public}d", status);
        return false;
    }
    if ((status = env->Reference_IsUndefined(obj, &isUndefined)) != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "status : %{public}d", status);
        return false;
    }
    if (isUndefined) {
        EVENT_LOGW(LOG_TAG_CES_ANI, "%{public}s : undefined", name);
        return false;
    }

    GetStdStringArrayClass(env, static_cast<ani_object>(obj), res);
    return true;
}

bool AniCommonEventUtils::GetWantParamsOrUndefined(
    ani_env* env, ani_object param, const char* name, AAFwk::WantParams& wantParams)
{
    ani_ref obj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status = ANI_ERROR;
    if ((status = env->Object_GetPropertyByName_Ref(param, name, &obj)) != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "status : %{public}d", status);
        return false;
    }
    if ((status = env->Reference_IsUndefined(obj, &isUndefined)) != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "status : %{public}d", status);
        return false;
    }
    if (isUndefined) {
        EVENT_LOGW(LOG_TAG_CES_ANI, "%{public}s : undefined", name);
        return false;
    }

    if (!UnwrapWantParams(env, obj, wantParams)) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "GetWantParamsOrUndefined UnwrapWantParams");
        return false;
    }

    return true;
}

void AniCommonEventUtils::ConvertCommonEventPublishData(ani_env* env, ani_object optionsObject, Want& want,
    CommonEventData &commonEventData, CommonEventPublishInfo &commonEventPublishInfo)
{
    // Get the code.
    int32_t code;
    if (GetDoubleOrUndefined(env, optionsObject, "code", code)) {
        EVENT_LOGD(LOG_TAG_CES_ANI, "ConvertCommonEventPublishData code: %{public}d.", code);
        commonEventData.SetCode(code);
    } else {
        EVENT_LOGD(LOG_TAG_CES_ANI, "ConvertCommonEventPublishData code not exit");
    }

    // Get the data.
    std::string dataStr;
    if (GetStringOrUndefined(env, optionsObject, "data", dataStr)) {
        EVENT_LOGD(LOG_TAG_CES_ANI, "ConvertCommonEventPublishData data: %{public}s.", dataStr.c_str());
        commonEventData.SetData(dataStr);
    } else {
        EVENT_LOGD(LOG_TAG_CES_ANI, "ConvertCommonEventPublishData data not exit");
    }

    // Get the isOrdered.
    bool isOrdered;
    if (GetBooleanOrUndefined(env, optionsObject, "isOrdered", isOrdered)) {
        EVENT_LOGD(LOG_TAG_CES_ANI, "ConvertCommonEventPublishData isOrdered: %{public}d.", isOrdered);
        commonEventPublishInfo.SetOrdered(isOrdered);
    } else {
        EVENT_LOGD(LOG_TAG_CES_ANI, "ConvertCommonEventPublishData isOrdered not exit");
    }

    // Get the isSticky.
    bool isSticky;
    if (GetBooleanOrUndefined(env, optionsObject, "isSticky", isSticky)) {
        EVENT_LOGD(LOG_TAG_CES_ANI, "ConvertCommonEventPublishData isSticky: %{public}d.", isSticky);
        commonEventPublishInfo.SetSticky(isSticky);
    } else {
        EVENT_LOGD(LOG_TAG_CES_ANI, "ConvertCommonEventPublishData isSticky not exit");
    }

    // Get the bundleName.
    std::string bundleNameStr;
    if (GetStringOrUndefined(env, optionsObject, "bundleName", bundleNameStr)) {
        EVENT_LOGD(LOG_TAG_CES_ANI, "ConvertCommonEventPublishData bundleName: %{public}s.", bundleNameStr.c_str());
        commonEventPublishInfo.SetBundleName(bundleNameStr);
    } else {
        EVENT_LOGD(LOG_TAG_CES_ANI, "ConvertCommonEventPublishData bundleName not exit");
    }

    // Get the subscriberPermissions.
    std::vector<std::string> subscriberPermissionsStr;
    if (GetStringArrayOrUndefined(env, optionsObject, "subscriberPermissions", subscriberPermissionsStr)) {
        EVENT_LOGD(LOG_TAG_CES_ANI, "ConvertCommonEventPublishData subscriberPermissionsStr success.");
        commonEventPublishInfo.SetSubscriberPermissions(subscriberPermissionsStr);
    } else {
        EVENT_LOGD(LOG_TAG_CES_ANI, "ConvertCommonEventPublishData bundleName not exit");
    }

    // Get the parameters [Record]
    AAFwk::WantParams wantParams;
    if (GetWantParamsOrUndefined(env, optionsObject, "parameters", wantParams)) {
        EVENT_LOGD(LOG_TAG_CES_ANI, "ConvertCommonEventPublishData parameters success.");
        want.SetParams(wantParams);
    } else {
        EVENT_LOGD(LOG_TAG_CES_ANI, "ConvertCommonEventPublishData parameters not exit");
    }
}

void AniCommonEventUtils::ConvertCommonEventSubscribeInfo(
    ani_env* env, ani_object infoObject, CommonEventSubscribeInfo& subscribeInfo)
{
    // Get the events.
    std::vector<std::string> eventsStr;
    if (GetStringArrayOrUndefined(env, infoObject, "events", eventsStr)) {
        EVENT_LOGD(LOG_TAG_CES_ANI, "ConvertCommonEventPublishData events success.");
    } else {
        EVENT_LOGD(LOG_TAG_CES_ANI, "ConvertCommonEventPublishData events not exit");
    }

    MatchingSkills matchingSkills;
    for (const auto &event : eventsStr) {
        matchingSkills.AddEvent(event);
    }
    CommonEventSubscribeInfo commonEventSubscribeInfo(matchingSkills);

    // Get the publisherPermission.
    std::string publisherPermissionStr;
    if (GetStringOrUndefined(env, infoObject, "publisherPermission", publisherPermissionStr)) {
        EVENT_LOGD(LOG_TAG_CES_ANI, "ConvertCommonEventSubscribeInfo publisherPermission: %{public}s.",
            publisherPermissionStr.c_str());
        commonEventSubscribeInfo.SetPermission(publisherPermissionStr);
    } else {
        EVENT_LOGD(LOG_TAG_CES_ANI, "ConvertCommonEventSubscribeInfo publisherPermission not exit");
    }

    // Get the publisherDeviceId.
    std::string publisherDeviceIdStr;
    if (GetStringOrUndefined(env, infoObject, "publisherDeviceId", publisherDeviceIdStr)) {
        EVENT_LOGD(LOG_TAG_CES_ANI, "ConvertCommonEventSubscribeInfo publisherDeviceId: %{public}s.",
            publisherDeviceIdStr.c_str());
        commonEventSubscribeInfo.SetDeviceId(publisherDeviceIdStr);
    } else {
        EVENT_LOGD(LOG_TAG_CES_ANI, "ConvertCommonEventSubscribeInfo publisherDeviceId not exit");
    }

    // Get the publisherBundleName.
    std::string publisherBundleNameStr;
    if (GetStringOrUndefined(env, infoObject, "publisherBundleName", publisherBundleNameStr)) {
        EVENT_LOGD(LOG_TAG_CES_ANI, "ConvertCommonEventSubscribeInfo publisherBundleName: %{public}s.",
            publisherBundleNameStr.c_str());
        commonEventSubscribeInfo.SetPublisherBundleName(publisherBundleNameStr);
    } else {
        EVENT_LOGD(LOG_TAG_CES_ANI, "ConvertCommonEventSubscribeInfo publisherBundleName not exit");
    }

    // Get the userId.
    int32_t userId;
    if (GetDoubleOrUndefined(env, infoObject, "userId", userId)) {
        EVENT_LOGD(LOG_TAG_CES_ANI, "ConvertCommonEventPublishData userId: %{public}d.", userId);
        commonEventSubscribeInfo.SetUserId(userId);
    } else {
        EVENT_LOGD(LOG_TAG_CES_ANI, "ConvertCommonEventPublishData userId not exit");
    }

    // Get the priority.
    int32_t priority;
    if (GetDoubleOrUndefined(env, infoObject, "priority", priority)) {
        EVENT_LOGD(LOG_TAG_CES_ANI, "ConvertCommonEventPublishData priority: %{public}d.", priority);
        commonEventSubscribeInfo.SetPriority(priority);
    } else {
        EVENT_LOGD(LOG_TAG_CES_ANI, "ConvertCommonEventPublishData priority not exit");
    }

    subscribeInfo = commonEventSubscribeInfo;
}

void AniCommonEventUtils::GetCommonEventSubscribeInfoToEts(
    ani_env* env, std::shared_ptr<SubscriberInstance> subscriber, ani_object &infoObject)
{
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    CreateNewObjectByClass(env, "LcommonEvent/commonEventSubscribeInfo/CommonEventSubscribeInfoImpl;", cls, infoObject);
    if ((infoObject == nullptr) || (cls == nullptr)) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "CommonEventSubscribeInfoToAni infoObject or cls is null.");
        return;
    }
    if (subscriber == nullptr) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "subscriber is null.");
        return;
    }

    // set events [Array<string>]
    ani_object eventsParamRef = GetAniStringArray(env, subscriber->GetSubscribeInfo().GetMatchingSkills().GetEvents());
    CallSetter(env, cls, infoObject, SETTER_METHOD_NAME(events), eventsParamRef);

    ani_string string = nullptr;
    // set publisherPermission [string]
    status = env->String_NewUTF8(
        subscriber->GetSubscribeInfo().GetPermission().c_str(),
        subscriber->GetSubscribeInfo().GetPermission().size(), &string);
    CallSetter(env, cls, infoObject, SETTER_METHOD_NAME(publisherPermission), string);

    // set publisherDeviceId [string]
    status = env->String_NewUTF8(
        subscriber->GetSubscribeInfo().GetDeviceId().c_str(),
        subscriber->GetSubscribeInfo().GetDeviceId().size(), &string);
    CallSetter(env, cls, infoObject, SETTER_METHOD_NAME(publisherDeviceId), string);

    // set publisherBundleName [string]
    status = env->String_NewUTF8(
        subscriber->GetSubscribeInfo().GetPublisherBundleName().c_str(),
        subscriber->GetSubscribeInfo().GetPublisherBundleName().size(), &string);
    CallSetter(env, cls, infoObject, SETTER_METHOD_NAME(publisherBundleName), string);

    // set userId [number]
    ani_object userIdObject;
    CreateAniDoubleObject(env, userIdObject, static_cast<ani_double>(subscriber->GetSubscribeInfo().GetUserId()));
    CallSetter(env, cls, infoObject, SETTER_METHOD_NAME(userId), userIdObject);

    // set priority [number]
    ani_object priorityObject;
    CreateAniDoubleObject(env, priorityObject, static_cast<ani_double>(subscriber->GetSubscribeInfo().GetPriority()));
    CallSetter(env, cls, infoObject, SETTER_METHOD_NAME(priority), priorityObject);
}

ani_object AniCommonEventUtils::GetAniStringArray(ani_env *env, std::vector<std::string> strs)
{
    if (env == nullptr) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "GetAniStringArray fail, env is nullptr or strs is empty");
        return nullptr;
    }
    int length = strs.size();
    ani_object arrayObj = newArrayClass(env, length);
    if (arrayObj == nullptr) {
        return nullptr;
    }
    ani_size i = 0;
    for (auto &str : strs) {
        EVENT_LOGD(LOG_TAG_CES_ANI, "GetAniStringArray: %{public}s", str.c_str());
        ani_string aniStr;
        if ((env->String_NewUTF8(str.c_str(),  str.size(), &aniStr) != ANI_OK) || aniStr == nullptr) {
            EVENT_LOGE(LOG_TAG_CES_ANI, "String_NewUTF8 faild");
            return nullptr;
        }
        ani_status status = env->Object_CallMethodByName_Void(arrayObj, "$_set", "ILstd/core/Object;:V", i, aniStr);
        if (status != ANI_OK) {
            EVENT_LOGE(LOG_TAG_CES_ANI, "Object_CallMethodByName_Void failed %{public}d", status);
            return nullptr;
        }
        i++;
    }
    return arrayObj;
}

ani_object AniCommonEventUtils::newArrayClass(ani_env *env, int length)
{
    EVENT_LOGD(LOG_TAG_CES_ANI, "newArrayClass call");
    if (env == nullptr || length < 0) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "CreateDouble fail, env is nullptr or length is less than zero");
        return nullptr;
    }
    ani_class arrayCls = nullptr;
    if (ANI_OK != env->FindClass("Lescompat/Array;", &arrayCls)) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "FindClass Lescompat/Array; Failed");
        return nullptr;
    }
    ani_method arrayCtor;
    if (ANI_OK != env->Class_FindMethod(arrayCls, "<ctor>", "I:V", &arrayCtor)) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "Class_FindMethod <ctor> Failed");
        return nullptr;
    }
    ani_object arrayObj = nullptr;
    if (ANI_OK != env->Object_New(arrayCls, arrayCtor, &arrayObj, length)) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "Object_New Array Faild");
        return nullptr;
    }
    EVENT_LOGD(LOG_TAG_CES_ANI, "newArrayClass end");
    return arrayObj;
}

void AniCommonEventUtils::CreateNewObjectByClass(
    ani_env* env, const char* className, ani_class& cls, ani_object& ani_data)
{
    auto aniResult = ANI_ERROR;
    ani_method ctor = nullptr;
    aniResult = env->FindClass(className, &cls);
    if (aniResult != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "CreateNewObjectByClass findClass result: %{public}d.", aniResult);
        return;
    }
    if (cls == nullptr) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "CreateNewObjectByClass cls is null.");
        return;
    }
    aniResult = env->Class_FindMethod(cls, "<ctor>", ":V", &ctor);
    if (aniResult != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "CreateNewObjectByClass Class_FindMethod result: %{public}d.", aniResult);
        return;
    }
    aniResult = env->Object_New(cls, ctor, &ani_data);
    if (aniResult != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "CreateNewObjectByClass Object_New result: %{public}d.", aniResult);
    }
    return;
}

void AniCommonEventUtils::CreateBusinessErrorObject(
    ani_env* env, ani_object& object, int32_t code, const std::string& message)
{
    EVENT_LOGD(LOG_TAG_CES_ANI, "CreateBusinessErrorObject called.");
    ani_status aniResult = ANI_ERROR;
    ani_class cls;
    ani_method ctor = nullptr;
    if (env == nullptr) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "CreateBusinessErrorObject env is null.");
        return;
    }

    aniResult = env->FindClass("L@ohos/base/BusinessError;", &cls);
    if (aniResult != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "CreateBusinessErrorObject findClass result: %{public}d.", aniResult);
        return;
    }
    if (cls == nullptr) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "CreateBusinessErrorObject cls is null.");
        return;
    }
    aniResult = env->Class_FindMethod(cls, "<ctor>", ":V", &ctor);
    if (aniResult != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "CreateBusinessErrorObject Class_FindMethod result: %{public}d.", aniResult);
        return;
    }
    aniResult = env->Object_New(cls, ctor, &object);
    if (aniResult != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "CreateBusinessErrorObject Object_New result: %{public}d.", aniResult);
    }

    ani_string string = nullptr;
    env->String_NewUTF8(message.c_str(), message.size(), &string);
    aniResult = env->Object_SetFieldByName_Double(object, "code", ani_double(code));
    aniResult = env->Object_SetFieldByName_Ref(object, "data", string);
}

template<typename valueType>
void AniCommonEventUtils::CallSetter(
    ani_env* env, ani_class cls, ani_object object, const char* setterName, valueType value)
{
    ani_status aniResult = ANI_ERROR;
    ani_method setter;
    aniResult = env->Class_FindMethod(cls, setterName, nullptr, &setter);
    if (aniResult != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "CallSetter Class_FindMethod result: %{public}d.", aniResult);
        return;
    }
    aniResult = env->Object_CallMethod_Void(object, setter, value);
    if (aniResult != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "CallSetter Object_CallMethod_Void result: %{public}d.", aniResult);
    }
    return;
}

void AniCommonEventUtils::CreateAniDoubleObject(ani_env* env, ani_object &object, ani_double value)
{
    ani_status aniResult = ANI_ERROR;
    ani_class clsDouble = nullptr;
    ani_method ctor;
    aniResult = env->FindClass("Lstd/core/Double;", &clsDouble);
    if (aniResult != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "CreateAniDoubleObject FindClass result: %{public}d.", aniResult);
        return;
    }
    aniResult = env->Class_FindMethod(clsDouble, "<ctor>", "D:V", &ctor);
    if (aniResult != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "CreateAniDoubleObject Class_FindMethod result: %{public}d.", aniResult);
        return;
    }
    aniResult = env->Object_New(clsDouble, ctor, &object, value);
    if (aniResult != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "CreateAniDoubleObject Object_New result: %{public}d.", aniResult);
        return;
    }
}

void AniCommonEventUtils::ConvertCommonEventDataToEts(
    ani_env* env, ani_object& ani_data, const CommonEventData& commonEventData)
{
    EVENT_LOGD(LOG_TAG_CES_ANI, "ConvertCommonEventDataToEts called");

    ani_class cls = nullptr;
    CreateNewObjectByClass(env, "LcommonEvent/commonEventData/CommonEventDataImpl;", cls, ani_data);
    if ((ani_data == nullptr) || (cls == nullptr)) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "ConvertCommonEventDataToEts ani_data or cls is null.");
        return;
    }

    ani_string string = nullptr;
    // set event [string]
    env->String_NewUTF8(
        commonEventData.GetWant().GetAction().c_str(), commonEventData.GetWant().GetAction().size(), &string);
    CallSetter(env, cls, ani_data, SETTER_METHOD_NAME(event), string);

    // set bundleName [string]
    env->String_NewUTF8(
        commonEventData.GetWant().GetBundle().c_str(), commonEventData.GetWant().GetBundle().size(), &string);
    CallSetter(env, cls, ani_data, SETTER_METHOD_NAME(bundleName), string);

    // set data [string]
    env->String_NewUTF8(commonEventData.GetData().c_str(), commonEventData.GetData().size(), &string);
    CallSetter(env, cls, ani_data, SETTER_METHOD_NAME(data), string);

    // set code [number]
    ani_object codeObject;
    CreateAniDoubleObject(env, codeObject, static_cast<ani_double>(commonEventData.GetCode()));
    CallSetter(env, cls, ani_data, SETTER_METHOD_NAME(code), codeObject);

    // set parameters [Record]
    ani_ref wantParamRef = WrapWantParams(env, commonEventData.GetWant().GetParams());
    CallSetter(env, cls, ani_data, SETTER_METHOD_NAME(parameters), wantParamRef);
}

} // namespace EventManagerFwkAni
} // namespace OHOS