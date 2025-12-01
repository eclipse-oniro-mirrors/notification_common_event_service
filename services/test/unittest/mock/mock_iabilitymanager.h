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

#ifndef BASE_COMMON_EVENT_SERVICE_TEST_UNITEST_MOCK_IABILITYMANAGER_H
#define BASE_COMMON_EVENT_SERVICE_TEST_UNITEST_MOCK_IABILITYMANAGER_H

#include <gmock/gmock.h>

#include "ability_manager_interface.h"

namespace OHOS {
namespace AAFwk {
class MockIAbilityManager : public IAbilityManager {
public:
    MOCK_METHOD(sptr<IRemoteObject>, AsObject, (), (override));
    MOCK_METHOD(int, StartAbility, (const Want &want, int32_t userId, int requestCode,
        uint64_t specifiedFullTokenId), (override));
    MOCK_METHOD(int, StartAbility, (const Want &want, const sptr<IRemoteObject> &callerToken, int32_t userId,
        int requestCode, uint64_t specifiedFullTokenId), (override));
    MOCK_METHOD(int, StartAbilityWithSpecifyTokenId,
        (const Want &want, const sptr<IRemoteObject> &callerToken, uint32_t specifyTokenId, int32_t userId,
            int requestCode),
        (override));
    MOCK_METHOD(int32_t, StartAbilityByInsightIntent,
        (const Want &want, const sptr<IRemoteObject> &callerToken, uint64_t intentId, int32_t userId), (override));
    MOCK_METHOD(int, StartAbility,
        (const Want &want, const AbilityStartSetting &abilityStartSetting, const sptr<IRemoteObject> &callerToken,
            int32_t userId, int requestCode),
        (override));
    MOCK_METHOD(int, StartAbility,
        (const Want &want, const StartOptions &startOptions, const sptr<IRemoteObject> &callerToken, int32_t userId,
            int requestCode),
        (override));
    MOCK_METHOD(
        int, TerminateAbility, (const sptr<IRemoteObject> &token, int resultCode, const Want *resultWant), (override));
    MOCK_METHOD(
        int, CloseAbility, (const sptr<IRemoteObject> &token, int resultCode, const Want *resultWant), (override));
    MOCK_METHOD(int, MinimizeAbility, (const sptr<IRemoteObject> &token, bool fromUser), (override));
    MOCK_METHOD(int32_t, ConnectAbility,
        (const Want &want, const sptr<IAbilityConnection> &connect, const sptr<IRemoteObject> &callerToken,
            int32_t userId),
        (override));
    MOCK_METHOD(int, DisconnectAbility, (sptr<IAbilityConnection> connect), (override));
    MOCK_METHOD(sptr<IAbilityScheduler>, AcquireDataAbility,
        (const Uri &uri, bool tryBind, const sptr<IRemoteObject> &callerToken), (override));
    MOCK_METHOD(int, ReleaseDataAbility,
        (sptr<IAbilityScheduler> dataAbilityScheduler, const sptr<IRemoteObject> &callerToken), (override));
    MOCK_METHOD(int, AttachAbilityThread, (const sptr<IAbilityScheduler> &scheduler, const sptr<IRemoteObject> &token),
        (override));
    MOCK_METHOD(
        int, AbilityTransitionDone, (const sptr<IRemoteObject> &token, int state, const PacMap &saveData), (override));
    MOCK_METHOD(int, ScheduleConnectAbilityDone,
        (const sptr<IRemoteObject> &token, const sptr<IRemoteObject> &remoteObject), (override));
    MOCK_METHOD(int, ScheduleDisconnectAbilityDone, (const sptr<IRemoteObject> &token), (override));
    MOCK_METHOD(int, ScheduleCommandAbilityDone, (const sptr<IRemoteObject> &token), (override));
    MOCK_METHOD(int, ScheduleCommandAbilityWindowDone,
        (const sptr<IRemoteObject> &token, const sptr<AAFwk::SessionInfo> &sessionInfo, AAFwk::WindowCommand winCmd,
            AAFwk::AbilityCommand abilityCmd),
        (override));
    MOCK_METHOD(void, DumpState, (const std::string &args, std::vector<std::string> &state), (override));
    MOCK_METHOD(void, DumpSysState,
        (const std::string &args, std::vector<std::string> &state, bool isClient, bool isUserID, int userID),
        (override));
    MOCK_METHOD(
        int, StopServiceAbility, (const Want &want, int32_t userId, const sptr<IRemoteObject> &token), (override));
    MOCK_METHOD(int, KillProcess, (const std::string &bundleName, bool clearPageStack, int32_t appIndex,
        const std::string &reason), (override));
#ifdef ABILITY_COMMAND_FOR_TEST
    MOCK_METHOD(int, ForceTimeoutForTest, (const std::string &abilityName, const std::string &state), (override));
#endif
    MOCK_METHOD(sptr<IWantSender>, GetWantSender,
        (const WantSenderInfo &wantSenderInfo, const sptr<IRemoteObject> &callerToken, int32_t uid), (override));
    MOCK_METHOD(int, SendWantSender, (sptr<IWantSender> target, SenderInfo &senderInfo), (override));
    MOCK_METHOD(void, CancelWantSender, (const sptr<IWantSender> &sender), (override));
    MOCK_METHOD(int, GetPendingWantUid, (const sptr<IWantSender> &target), (override));
    MOCK_METHOD(int, GetPendingWantUserId, (const sptr<IWantSender> &target), (override));
    MOCK_METHOD(std::string, GetPendingWantBundleName, (const sptr<IWantSender> &target), (override));
    MOCK_METHOD(int, GetPendingWantCode, (const sptr<IWantSender> &target), (override));
    MOCK_METHOD(int, GetPendingWantType, (const sptr<IWantSender> &target), (override));
    MOCK_METHOD(void, RegisterCancelListener, (const sptr<IWantSender> &sender, const sptr<IWantReceiver> &receiver),
        (override));
    MOCK_METHOD(void, UnregisterCancelListener, (const sptr<IWantSender> &sender, const sptr<IWantReceiver> &receiver),
        (override));
    MOCK_METHOD(int, GetPendingRequestWant, (const sptr<IWantSender> &target, std::shared_ptr<Want> &want), (override));
    MOCK_METHOD(
        int, GetWantSenderInfo, (const sptr<IWantSender> &target, std::shared_ptr<WantSenderInfo> &info), (override));
    MOCK_METHOD(int, ContinueMission,
        (const std::string &srcDeviceId, const std::string &dstDeviceId, int32_t missionId,
            const sptr<IRemoteObject> &callBack, AAFwk::WantParams &wantParams),
        (override));
    MOCK_METHOD(
        int, ContinueAbility, (const std::string &deviceId, int32_t missionId, uint32_t versionCode), (override));
    MOCK_METHOD(int, StartContinuation, (const Want &want, const sptr<IRemoteObject> &abilityToken, int32_t status),
        (override));
    MOCK_METHOD(
        void, NotifyCompleteContinuation, (const std::string &deviceId, int32_t sessionId, bool isSuccess), (override));
    MOCK_METHOD(int, NotifyContinuationResult, (int32_t missionId, int32_t result), (override));
    MOCK_METHOD(int, LockMissionForCleanup, (int32_t missionId), (override));
    MOCK_METHOD(int, UnlockMissionForCleanup, (int32_t missionId), (override));
    MOCK_METHOD(int, RegisterMissionListener, (const sptr<IMissionListener> &listener), (override));
    MOCK_METHOD(int, UnRegisterMissionListener, (const sptr<IMissionListener> &listener), (override));
    MOCK_METHOD(int, GetMissionInfos,
        (const std::string &deviceId, int32_t numMax, std::vector<MissionInfo> &missionInfos), (override));
    MOCK_METHOD(
        int, GetMissionInfo, (const std::string &deviceId, int32_t missionId, MissionInfo &missionInfo), (override));
    MOCK_METHOD(int, GetMissionSnapshot,
        (const std::string &deviceId, int32_t missionId, MissionSnapshot &snapshot, bool isLowResolution), (override));
    MOCK_METHOD(int, CleanMission, (int32_t missionId), (override));
    MOCK_METHOD(int, CleanAllMissions, (), (override));
    MOCK_METHOD(int, MoveMissionToFront, (int32_t missionId), (override));
    MOCK_METHOD(int, MoveMissionToFront, (int32_t missionId, const StartOptions &startOptions), (override));
    MOCK_METHOD(int, StartAbilityByCall,
        (const Want &want, const sptr<IAbilityConnection> &connect, const sptr<IRemoteObject> &callerToken,
            int32_t accountId, bool isSilent, bool promotePriority),
        (override));
    MOCK_METHOD(int, ReleaseCall, (const sptr<IAbilityConnection> &connect, const AppExecFwk::ElementName &element),
        (override));
    MOCK_METHOD(int, StartUser,
        (int userId, uint64_t displayId, sptr<IUserCallback> callback, bool isAppRecovery), (override));
    MOCK_METHOD(int, StopUser, (int userId, const sptr<IUserCallback> &callback), (override));
#ifdef SUPPORT_SCREEN
    MOCK_METHOD(int, SetMissionLabel, (const sptr<IRemoteObject> &abilityToken, const std::string &label), (override));
    MOCK_METHOD(int, SetMissionIcon,
        (const sptr<IRemoteObject> &token, const std::shared_ptr<OHOS::Media::PixelMap> &icon), (override));
    MOCK_METHOD(void, CompleteFirstFrameDrawing, (const sptr<IRemoteObject> &abilityToken), (override));
#endif
    MOCK_METHOD(int, GetAbilityRunningInfos, (std::vector<AbilityRunningInfo> & info), (override));
    MOCK_METHOD(int, GetExtensionRunningInfos, (int upperLimit, std::vector<ExtensionRunningInfo> &info), (override));
    MOCK_METHOD(int, GetProcessRunningInfos, (std::vector<AppExecFwk::RunningProcessInfo> & info), (override));
    MOCK_METHOD(int, StartSyncRemoteMissions, (const std::string &devId, bool fixConflict, int64_t tag), (override));
    MOCK_METHOD(int, StopSyncRemoteMissions, (const std::string &devId), (override));
    MOCK_METHOD(int, RegisterMissionListener,
        (const std::string &deviceId, const sptr<IRemoteMissionListener> &listener), (override));
    MOCK_METHOD(int, UnRegisterMissionListener,
        (const std::string &deviceId, const sptr<IRemoteMissionListener> &listener), (override));
    MOCK_METHOD(int, SetAbilityController,
        (const sptr<AppExecFwk::IAbilityController> &abilityController, bool imAStabilityTest), (override));
    MOCK_METHOD(bool, IsRunningInStabilityTest, (), (override));
    MOCK_METHOD(int, RegisterSnapshotHandler, (const sptr<ISnapshotHandler> &handler), (override));
    MOCK_METHOD(int, StartUserTest, (const Want &want, const sptr<IRemoteObject> &observer), (override));
    MOCK_METHOD(int, FinishUserTest, (const std::string &msg, const int64_t &resultCode, const std::string &bundleName),
        (override));
    MOCK_METHOD(int, GetTopAbility, (sptr<IRemoteObject> & token), (override));
    MOCK_METHOD(int, DelegatorDoAbilityForeground, (const sptr<IRemoteObject> &token), (override));
    MOCK_METHOD(int, DelegatorDoAbilityBackground, (const sptr<IRemoteObject> &token), (override));
    MOCK_METHOD(int, DoAbilityForeground, (const sptr<IRemoteObject> &token, uint32_t flag), (override));
    MOCK_METHOD(int, DoAbilityBackground, (const sptr<IRemoteObject> &token, uint32_t flag), (override));
    MOCK_METHOD(int32_t, GetMissionIdByToken, (const sptr<IRemoteObject> &token), (override));
    MOCK_METHOD(void, GetAbilityTokenByCalleeObj, (const sptr<IRemoteObject> &callStub, sptr<IRemoteObject> &token),
        (override));
    MOCK_METHOD(int32_t, IsValidMissionIds,
        (const std::vector<int32_t> &missionIds, std::vector<MissionValidResult> &results), (override));
    MOCK_METHOD(int32_t, ReportDrawnCompleted, (const sptr<IRemoteObject> &callerToken), (override));
    MOCK_METHOD(int32_t, RegisterAppDebugListener, (sptr<AppExecFwk::IAppDebugListener> listener), (override));
    MOCK_METHOD(int32_t, UnregisterAppDebugListener, (sptr<AppExecFwk::IAppDebugListener> listener), (override));
    MOCK_METHOD(int32_t, AttachAppDebug, (const std::string &bundleName, bool isDebugFromLocal), (override));
    MOCK_METHOD(int32_t, DetachAppDebug, (const std::string &bundleName, bool isDebugFromLocal), (override));
    MOCK_METHOD(int32_t, ExecuteIntent,
        (uint64_t key, const sptr<IRemoteObject> &callerToken, const InsightIntentExecuteParam &param), (override));
    MOCK_METHOD(int32_t, ExecuteInsightIntentDone,
        (const sptr<IRemoteObject> &token, uint64_t intentId, const InsightIntentExecuteResult &result), (override));
    MOCK_METHOD(int32_t, SetApplicationAutoStartupByEDM, (const AutoStartupInfo &info, bool flag), (override));
    MOCK_METHOD(int32_t, CancelApplicationAutoStartupByEDM, (const AutoStartupInfo &info, bool flag), (override));
    MOCK_METHOD(int32_t, GetForegroundUIAbilities, (std::vector<AppExecFwk::AbilityStateData> & list), (override));
    MOCK_METHOD(void, ScheduleClearRecoveryPageStack, (), (override));
    MOCK_METHOD(void, NotifyFrozenProcessByRSS, (const std::vector<int32_t> &pidList, int32_t uid), (override));
    MOCK_METHOD(void, KillProcessWithPrepareTerminateDone,
        (const std::string &moduleName, int32_t prepareTermination, bool isExist), (override));
    bool mockFunctionExcuted = false;
};
} // namespace AAFwk
} // namespace OHOS
#endif // BASE_COMMON_EVENT_SERVICE_TEST_UNITEST_MOCK_IABILITYMANAGER_H