/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OH_COMMON_EVENT_C_H
#define OH_COMMON_EVENT_C_H

#include "ces_inner_error_code.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum CommonEvent_ErrCode {
    /** @error Execution successful. */
    COMMONEVENT_ERR_OK = 0,
    /** @error Permission verification failed. */
    COMMONEVENT_ERR_PERMISSION_ERROR = 201,
    /** @error Invalid input parameter. */
    COMMONEVENT_ERR_INVALID_PARAMETER = 401,
    /** @error IPC request failed to send. */
    COMMONEVENT_ERR_FAIL_SEND_REQUEST = 1500007,
    /** @error Common event service not init. */
    COMMONEVENT_ERR_INIT_UNDONE = 1500008,
    /** @error System error. */
    COMMONEVENT_ERR_SYSTEM = 1500009,
    /** @error the subscriber number exceed system specification */
    COMMONEVENT_ERR_SUBSCRIBER_NUM_EXCEEDED = 1500010,
} CommonEvent_ErrCode;

/**
 * @brief the information of the subscriber
 *
 */
typedef struct CommonEventSubscribeInfo CommonEventSubscribeInfo;

/**
 * @brief the subscriber of common event
 *
 */
typedef void CommonEventSubscriber;

/**
 * @brief the data of the commonEvent callback
 *
 */
typedef struct CommonEventRcvData CommonEventRcvData;

/**
 * @brief The description of the parameters in a common event callback data.
 *
 */
typedef void CommonEventParameters;

/**
 * @brief Common event callback.
 *
 * @param data common event callback data.
 */
typedef void (*CommonEventReceiveCallback)(const CommonEventRcvData *data);


/**
 * @brief Create subscribe information.
 *
 * @param events Indicates the subscribed events.
 * @param eventsNum Indicates the subscribed events of number.
 * @return Returns the CommonEventSubscribeInfo, if create failed, returns null.
 */
CommonEventSubscribeInfo* OH_CommonEvent_CreateSubscribeInfo(const char* events[], int32_t eventsNum);

/**
 * @brief Set the subscribe information of permission.
 *
 * @param info Indicates the subscribed events.
 * @param permission Indicates the subscribed events of number.
 * @return Returns the error code.
 *         Returns {@link ERR_OK} if the operation is successful.
 *         Returns {@link ERR_INVALID_PARAMETER} if a parameter error occurs.
 */
CommonEvent_ErrCode OH_CommonEvent_SetPublisherPermission(CommonEventSubscribeInfo* info, const char* permission);

/**
 * @brief Set the subscribe information of bundleName.
 *
 * @param info Indicates the subscribed events.
 * @param bundleName Indicates the subscribed events of number.
 * @return Returns the error code.
 *         Returns {@link ERR_OK} if the operation is successful.
 *         Returns {@link ERR_INVALID_PARAMETER} if a parameter error occurs.
 */
CommonEvent_ErrCode OH_CommonEvent_SetPublisherBundleName(CommonEventSubscribeInfo* info, const char* bundleName);

/**
 * @brief Destroy the subscribe information.
 *
 * @param info Indicates the subscribe info.
 */
void OH_CommonEvent_DestroySubscribeInfo(CommonEventSubscribeInfo* info);

/**
 * @brief Create a subscriber.
 *
 * @param info Indicates the created subscribe Info.
 * @param callback Indicates the received common event callback.
 * @return Returns the CommonEventSubscriber, if create failed, returns null.
 */
CommonEventSubscriber* OH_CommonEvent_CreateSubscriber(const CommonEventSubscribeInfo* info, CommonEventReceiveCallback callback);

/**
 * @brief Destory the subscriber.
 *
 * @param subscriber Indicates the created subscriber.
 */
void OH_CommonEvent_DestroySubscriber(CommonEventSubscriber* subscriber);

/**
 * @brief Subscribe event by a subscriber.
 *
 * @param subscriber Indicates the subscriber.
 * @return Returns the error code.
 *         Returns {@link ERR_OK} if the operation is successful.
 *         Returns {@link ERR_PERMISSION_ERROR } if don't have some required permission.
 *         Returns {@link ERR_INVALID_PARAMETER } if the input parameter is invalid.
 *         Returns {@link ERR_FAIL_SEND_REQUEST } if IPC request failed to send.
 *         Returns {@link ERR_SYSTEM } others.
 */
CommonEvent_ErrCode OH_CommonEvent_Subscribe(const CommonEventSubscriber* subscriber);

/**
 * @brief Unsubscribe event by a subscriber.
 *
 * @param subscriber Indicates the subscriber.
 * @return Returns the error code.
 *         Returns {@link ERR_OK} if the operation is successful.
 *         Returns {@link ERR_INVALID_PARAMETER } if the input parameter is invalid.
 *         Returns {@link ERR_SUBSCRIBER_NOT_FOUND } if the subscriber is not subscribe.
 *         Returns {@link ERR_FAIL_SEND_REQUEST } if IPC request failed to send.
 *         Returns {@link ERR_SYSTEM } others.
 */
CommonEvent_ErrCode OH_CommonEvent_UnSubscribe(const CommonEventSubscriber* subscriber);

/**
 * @brief Get event name from callback data.
 *
 * @param rcvData Indicates the event of callback data.
 * @return Returns the event name.
 */
const char* OH_CommonEvent_GetEventFromRcvData(const CommonEventRcvData* rcvData);

/**
 * @brief Get event result code from callback data.
 *
 * @param rcvData Indicates the event of callback data.
 * @return Returns the event of result code, default is 0.
 */
int32_t OH_CommonEvent_GetCodeFromRcvData(const CommonEventRcvData* rcvData);

/**
 * @brief Get event result data from callback data.
 *
 * @param rcvData Indicates the event of callback data.
 * @return Returns the event of result data, default is null.
 */
const char* OH_CommonEvent_GetDataStrFromRcvData(const CommonEventRcvData* rcvData);

/**
 * @brief Get event bundlename from callback data.
 *
 * @param rcvData Indicates the event of callback data.
 * @return Returns the event of bundlename, default is null.
 */
const char* OH_CommonEvent_GetBundleNameFromRcvData(const CommonEventRcvData* rcvData);

/**
 * @brief Get event parameters data from callback data.
 *
 * @param rcvData Indicates the event of callback data.
 * @return Returns the event of parameters data, default is null.
 */
const CommonEventParameters* OH_CommonEvent_GetParametersFromRcvData(const CommonEventRcvData* rcvData);

/**
 * @brief Check whether the parameters contains a key.
 *
 * @param rcvData Indicates the event of callback data.
 * @param key Indicates the key of parameter.
 * @return Returns the result of check, true means it contains.
 */
bool OH_CommonEvent_HasKeyInParameters(const CommonEventParameters* para, const char* key);

/**
 * @brief Get int data from parameters data by key.
 *
 * @param rcvData Indicates the event of parameters data.
 * @param key Indicates the key of parameters data.
 * @param defaultValue Indicates default return value.
 * @return Returns the int data of the key in the parameters.
 */
int OH_CommonEvent_GetIntFromParameters(const CommonEventParameters* para, const char* key, const int defaultValue);

/**
 * @brief Get int array data from parameters data by key.
 *
 * @param rcvData Indicates the event of parameters data.
 * @param key Indicates the key of parameters data.
 * @param array Indicates the int array.
 * @return Returns the length of the array.
 */
int32_t OH_CommonEvent_GetIntArrayFromParameters(const CommonEventParameters* para, const char* key, int** array);

/**
 * @brief Get long data from parameters data by key.
 *
 * @param rcvData Indicates the event of parameters data.
 * @param key Indicates the key of parameters data.
 * @param defaultValue Indicates default return value.
 * @return Returns the long data of the key in the parameters.
 */
long OH_CommonEvent_GetLongFromParameters(const CommonEventParameters* para, const char* key, const long defaultValue);

/**
 * @brief Get long array data from parameters data by key.
 *
 * @param rcvData Indicates the event of parameters data.
 * @param key Indicates the key of parameters data.
 * @param array Indicates the long array.
 * @return Returns the length of the array.
 */
int32_t OH_CommonEvent_GetLongArrayFromParameters(const CommonEventParameters* para, const char* key, long** array);

/**
 * @brief Get bool data from parameters data by key.
 *
 * @param rcvData Indicates the event of parameters data.
 * @param key Indicates the key of parameters data.
 * @param defaultValue Indicates default return value.
 * @return Returns the bool data of the key in the parameters.
 */
bool OH_CommonEvent_GetBoolFromParameters(const CommonEventParameters* para, const char* key, const bool defaultValue);

/**
 * @brief Get bool array data from parameters data by key.
 *
 * @param rcvData Indicates the event of parameters data.
 * @param key Indicates the key of parameters data.
 * @param array Indicates the bool array.
 * @return Returns the length of the array.
 */
int32_t OH_CommonEvent_GetBoolArrayFromParameters(const CommonEventParameters* para, const char* key, bool** array);

/**
 * @brief Get char data from parameters data by key.
 *
 * @param rcvData Indicates the event of parameters data.
 * @param key Indicates the key of parameters data.
 * @param defaultValue Indicates default return value.
 * @return Returns the char data of the key in the parameters.
 */ 
char OH_CommonEvent_GetCharFromParameters(const CommonEventParameters* para, const char* key, const char defaultValue);

/**
 * @brief Get char array data from parameters data by key.
 *
 * @param rcvData Indicates the event of parameters data.
 * @param key Indicates the key of parameters data.
 * @param array Indicates the char array.
 * @return Returns the length of the array.
 */
int32_t OH_CommonEvent_GetCharArrayFromParameters(const CommonEventParameters* para, const char* key, char** array);

/**
 * @brief Get double data from parameters data by key.
 *
 * @param rcvData Indicates the event of parameters data.
 * @param key Indicates the key of parameters data.
 * @param defaultValue Indicates default return value.
 * @return Returns the double data of the key in the parameters.
 */
double OH_CommonEvent_GetDoubleFromParameters(const CommonEventParameters* para, const char* key,
    const char defaultValue);

/**
 * @brief Get double array data from parameters data by key.
 *
 * @param rcvData Indicates the event of parameters data.
 * @param key Indicates the key of parameters data.
 * @param array Indicates the double array.
 * @return Returns the length of the array, default is 0.
 */
int32_t OH_CommonEvent_GetDoubleArrayFromParameters(const CommonEventParameters* para, const char* key, double** array);

#ifdef __cplusplus
}
#endif
#endif // OH_COMMONEVENT_SUPPORT_CODE_H