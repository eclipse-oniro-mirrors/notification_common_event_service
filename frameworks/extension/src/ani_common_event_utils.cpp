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

void AniCommonEventUtils::CreateNewObjectByClass(
    ani_env* env, const char* className, ani_class& cls, ani_object& ani_data)
{
    auto aniResult = ANI_ERROR;
    ani_method ctor = nullptr;
    aniResult = env->FindClass(className, &cls);
    if (aniResult != ANI_OK) {
        EVENT_LOGE("CreateNewObjectByClass findClass error. result: %{public}d.", aniResult);
        return;
    }
    if (cls == nullptr) {
        EVENT_LOGE("CreateNewObjectByClass cls is null.");
        return;
    }
    aniResult = env->Class_FindMethod(cls, "<ctor>", ":", &ctor);
    if (aniResult != ANI_OK) {
        EVENT_LOGE("CreateNewObjectByClass Class_FindMethod error. result: %{public}d.", aniResult);
        return;
    }
    aniResult = env->Object_New(cls, ctor, &ani_data);
    if (aniResult != ANI_OK) {
        EVENT_LOGE("CreateNewObjectByClass Object_New error. result: %{public}d.", aniResult);
    }
    return;
}

template<typename valueType>
void AniCommonEventUtils::CallSetter(
    ani_env* env, ani_class cls, ani_object object, const char* setterName, valueType value)
{
    ani_status aniResult = ANI_ERROR;
    ani_method setter;
    aniResult = env->Class_FindMethod(cls, setterName, nullptr, &setter);
    if (aniResult != ANI_OK) {
        EVENT_LOGE("CallSetter Class_FindMethod error. result: %{public}d.", aniResult);
        return;
    }
    aniResult = env->Object_CallMethod_Void(object, setter, value);
    if (aniResult != ANI_OK) {
        EVENT_LOGE("CallSetter Object_CallMethod_Void error. result: %{public}d.", aniResult);
    }
    return;
}

void AniCommonEventUtils::CreateAniDoubleObject(ani_env* env, ani_object &object, ani_double value)
{
    ani_status aniResult = ANI_ERROR;
    ani_class clsDouble = nullptr;
    ani_method ctor;
    aniResult = env->FindClass("std.core.Double", &clsDouble);
    if (aniResult != ANI_OK) {
        EVENT_LOGE("CreateAniDoubleObject FindClass error. result: %{public}d.", aniResult);
        return;
    }
    aniResult = env->Class_FindMethod(clsDouble, "<ctor>", "d:", &ctor);
    if (aniResult != ANI_OK) {
        EVENT_LOGE("CreateAniDoubleObject Class_FindMethod error. result: %{public}d.", aniResult);
        return;
    }
    aniResult = env->Object_New(clsDouble, ctor, &object, value);
    if (aniResult != ANI_OK) {
        EVENT_LOGE("CreateAniDoubleObject Object_New error. result: %{public}d.", aniResult);
        return;
    }
}

void AniCommonEventUtils::ConvertCommonEventDataToEts(
    ani_env* env, ani_object& ani_data, const CommonEventData& commonEventData)
{
    EVENT_LOGI("ConvertCommonEventDataToEts called");

    ani_class cls = nullptr;
    CreateNewObjectByClass(env, "commonEvent.commonEventData.CommonEventDataImpl", cls, ani_data);
    if ((ani_data == nullptr) || (cls == nullptr)) {
        EVENT_LOGE("ConvertCommonEventDataToEts ani_data or cls is null.");
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
