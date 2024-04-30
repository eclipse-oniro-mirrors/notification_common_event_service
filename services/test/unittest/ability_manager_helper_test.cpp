/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <numeric>
#define private public
#include "ability_manager_helper.h"
#undef private
#include "mock_common_event_stub.h"
#include "static_subscriber_connection.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EventFwk;
using namespace OHOS::AppExecFwk;

namespace {
constexpr int32_t DEFAULT_INVAL_USRE = -1;
}  // namespace

class AbilityManagerHelperTest : public testing::Test {
public:
    AbilityManagerHelperTest()
    {}
    ~AbilityManagerHelperTest()
    {}

    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AbilityManagerHelperTest::SetUpTestCase(void)
{}

void AbilityManagerHelperTest::TearDownTestCase(void)
{}

void AbilityManagerHelperTest::SetUp(void)
{}

void AbilityManagerHelperTest::TearDown(void)
{}

using TestAbilityManager = AAFwk::IAbilityManager;

class TestAbilityMgr : public TestAbilityManager {
public:
    TestAbilityMgr() = default;
    virtual ~TestAbilityMgr()
    {};
    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }

    int StartAbility(const Want &want, int32_t userId, int requestCode) override
    {
        return 1;
    }

    int StartAbility(
        const Want &want, const sptr<IRemoteObject> &callerToken, int32_t userId, int requestCode) override
    {
        return 1;
    }

    int StartAbility(const Want &want, const AbilityStartSetting &abilityStartSetting,
        const sptr<IRemoteObject> &callerToken, int32_t userId, int requestCode) override
    {
        return 1;
    }

    int32_t StartAbilityByInsightIntent(const Want &want, const sptr<IRemoteObject> &callerToken,
        uint64_t intentId, int32_t userId = DEFAULT_INVAL_VALUE) override
    {
        return 1;
    }

    int StartAbility(const Want &want, const StartOptions &startOptions,
        const sptr<IRemoteObject> &callerToken, int32_t userId, int requestCode) override
    {
        return 1;
    }

    int TerminateAbility(
        const sptr<IRemoteObject> &token, int resultCode, const Want *resultWant = nullptr) override
    {
        return 1;
    }

    int CloseAbility(const sptr<IRemoteObject> &token, int resultCode = DEFAULT_INVAL_VALUE,
        const Want *resultWant = nullptr) override
    {
        return 1;
    }

    int MinimizeAbility(const sptr<IRemoteObject> &token, bool fromUser = false) override
    {
        return 1;
    }

    int ConnectAbility(const Want &want, const sptr<IAbilityConnection> &connect,
        const sptr<IRemoteObject> &callerToken, int32_t userId) override
    {
        return 1;
    }

    int DisconnectAbility(sptr<IAbilityConnection> connect) override
    {
        return 1;
    }

    sptr<IAbilityScheduler> AcquireDataAbility(
        const Uri &uri, bool tryBind, const sptr<IRemoteObject> &callerToken) override
    {
        return nullptr;
    }

    int ReleaseDataAbility(
        sptr<IAbilityScheduler> dataAbilityScheduler, const sptr<IRemoteObject> &callerToken) override
    {
        return 1;
    }

    int AttachAbilityThread(const sptr<IAbilityScheduler> &scheduler, const sptr<IRemoteObject> &token) override
    {
        return 1;
    }

    int AbilityTransitionDone(const sptr<IRemoteObject> &token, int state, const PacMap &saveData)override
    {
        return 1;
    }

    int ScheduleConnectAbilityDone(
        const sptr<IRemoteObject> &token, const sptr<IRemoteObject> &remoteObject) override
    {
        return 1;
    }

    int ScheduleDisconnectAbilityDone(const sptr<IRemoteObject> &token) override
    {
        return 1;
    }

    int ScheduleCommandAbilityDone(const sptr<IRemoteObject> &token) override
    {
        return 1;
    }

    int ScheduleCommandAbilityWindowDone(
        const sptr<IRemoteObject> &token,
        const sptr<AAFwk::SessionInfo> &sessionInfo,
        AAFwk::WindowCommand winCmd,
        AAFwk::AbilityCommand abilityCmd) override
    {
        return 1;
    }

    void DumpState(const std::string &args, std::vector<std::string> &state) override
    {}

    void DumpSysState(
        const std::string& args, std::vector<std::string>& state, bool isClient, bool isUserID, int UserID) override
    {}

    int StopServiceAbility(const Want &want, int32_t userId, const sptr<IRemoteObject> &token = nullptr) override
    {
        return 1;
    }

    int KillProcess(const std::string &bundleName) override
    {
        return 1;
    }

    int ClearUpApplicationData(const std::string &bundleName, const int32_t userId = DEFAULT_INVAL_USRE) override
    {
        return 1;
    }

    int UninstallApp(const std::string &bundleName, int32_t uid) override
    {
        return 1;
    }

    sptr<IWantSender> GetWantSender(
        const WantSenderInfo &wantSenderInfo, const sptr<IRemoteObject> &callerToken) override
    {
        return nullptr;
    }

    int SendWantSender(sptr<IWantSender> target, const SenderInfo &senderInfo) override
    {
        return 1;
    }

    void CancelWantSender(const sptr<IWantSender> &sender) override
    {}

    int GetPendingWantUid(const sptr<IWantSender> &target) override
    {
        return 1;
    }

    int GetPendingWantUserId(const sptr<IWantSender> &target) override
    {
        return 1;
    }

    std::string GetPendingWantBundleName(const sptr<IWantSender> &target) override
    {
        return "";
    }

    int GetPendingWantCode(const sptr<IWantSender> &target) override
    {
        return 1;
    }

    int GetPendingWantType(const sptr<IWantSender> &target) override
    {
        return 1;
    }

    void RegisterCancelListener(const sptr<IWantSender> &sender, const sptr<IWantReceiver> &receiver) override
    {}

    void UnregisterCancelListener(const sptr<IWantSender> &sender, const sptr<IWantReceiver> &receiver) override
    {}

    int GetPendingRequestWant(const sptr<IWantSender> &target, std::shared_ptr<Want> &want) override
    {
        return 1;
    }

    int GetWantSenderInfo(const sptr<IWantSender> &target, std::shared_ptr<WantSenderInfo> &info) override
    {
        return 1;
    }

    int ContinueMission(const std::string &srcDeviceId, const std::string &dstDeviceId, int32_t missionId,
        const sptr<IRemoteObject> &callBack, AAFwk::WantParams &wantParams) override
    {
        return 1;
    }

    int ContinueAbility(const std::string &deviceId, int32_t missionId, uint32_t versionCode) override
    {
        return 1;
    }

    int StartContinuation(const Want &want, const sptr<IRemoteObject> &abilityToken, int32_t status) override
    {
        return 1;
    }

    void NotifyCompleteContinuation(const std::string &deviceId, int32_t sessionId, bool isSuccess) override
    {}

    int NotifyContinuationResult(int32_t missionId, int32_t result) override
    {
        return 1;
    }

    int LockMissionForCleanup(int32_t missionId) override
    {
        return 1;
    }

    int UnlockMissionForCleanup(int32_t missionId) override
    {
        return 1;
    }

    int RegisterMissionListener(const sptr<IMissionListener> &listener) override
    {
        return 1;
    }

    int UnRegisterMissionListener(const sptr<IMissionListener> &listener) override
    {
        return 1;
    }

    int GetMissionInfos(
        const std::string &deviceId, int32_t numMax, std::vector<MissionInfo> &missionInfos) override
    {
        return 1;
    }

    int GetMissionInfo(const std::string &deviceId, int32_t missionId, MissionInfo &missionInfo) override
    {
        return 1;
    }

    int GetMissionSnapshot(const std::string& deviceId, int32_t missionId,
        MissionSnapshot& snapshot, bool isLowResolution) override
    {
        return 1;
    }

    int CleanMission(int32_t missionId) override
    {
        return 1;
    }

    int CleanAllMissions() override
    {
        return 1;
    }

    int MoveMissionToFront(int32_t missionId) override
    {
        return 1;
    }

    int MoveMissionToFront(int32_t missionId, const StartOptions &startOptions) override
    {
        return 1;
    }

    int StartAbilityByCall(const Want &want, const sptr<IAbilityConnection> &connect,
        const sptr<IRemoteObject> &callerToken, int32_t accountId) override
    {
        return 1;
    }

    int ReleaseCall(const sptr<IAbilityConnection> &connect, const AppExecFwk::ElementName &element) override
    {
        return 1;
    }

    int StartUser(int userId, sptr<IUserCallback> callback) override
    {
        return 1;
    }

    int StopUser(int userId, const sptr<IUserCallback> &callback) override
    {
        return 1;
    }

    int SetMissionLabel(const sptr<IRemoteObject> &abilityToken, const std::string &label) override
    {
        return 1;
    }

    int SetMissionIcon(const sptr<IRemoteObject> &token,
        const std::shared_ptr<OHOS::Media::PixelMap> &icon) override
    {
        return 1;
    }

    int RegisterWindowManagerServiceHandler(const sptr<IWindowManagerServiceHandler>& handler) override
    {
        return 1;
    }

    void CompleteFirstFrameDrawing(const sptr<IRemoteObject> &abilityToken) override
    {}

    int GetAbilityRunningInfos(std::vector<AbilityRunningInfo> &info) override
    {
        return 1;
    }

    int GetExtensionRunningInfos(int upperLimit, std::vector<ExtensionRunningInfo> &info) override
    {
        return 1;
    }

    int GetProcessRunningInfos(std::vector<AppExecFwk::RunningProcessInfo> &info) override
    {
        return 1;
    }

    int StartSyncRemoteMissions(const std::string &devId, bool fixConflict, int64_t tag) override
    {
        return 1;
    }

    int StopSyncRemoteMissions(const std::string &devId) override
    {
        return 1;
    }

    int RegisterMissionListener(const std::string &deviceId, const sptr<IRemoteMissionListener> &listener) override
    {
        return 1;
    }

    int UnRegisterMissionListener(const std::string &deviceId,
        const sptr<IRemoteMissionListener> &listener) override
    {
        return 1;
    }

    int SetAbilityController(const sptr<AppExecFwk::IAbilityController> &abilityController,
        bool imAStabilityTest) override
    {
        return 1;
    }

    bool IsRunningInStabilityTest() override
    {
        return false;
    }

    int RegisterSnapshotHandler(const sptr<ISnapshotHandler>& handler) override
    {
        return 1;
    }

    int StartUserTest(const Want &want, const sptr<IRemoteObject> &observer) override
    {
        return 1;
    }

    int FinishUserTest(const std::string &msg, const int64_t &resultCode, const std::string &bundleName) override
    {
        return 1;
    }

    int GetTopAbility(sptr<IRemoteObject> &token) override
    {
        return 1;
    }

    int DelegatorDoAbilityForeground(const sptr<IRemoteObject> &token) override
    {
        return 1;
    }

    int DelegatorDoAbilityBackground(const sptr<IRemoteObject> &token) override
    {
        return 1;
    }

    int DoAbilityForeground(const sptr<IRemoteObject> &token, uint32_t flag) override
    {
        return 1;
    }

    int DoAbilityBackground(const sptr<IRemoteObject> &token, uint32_t flag) override
    {
        return 1;
    }

    int32_t GetMissionIdByToken(const sptr<IRemoteObject> &token) override
    {
        return 1;
    }

    void GetAbilityTokenByCalleeObj(const sptr<IRemoteObject> &callStub, sptr<IRemoteObject> &token) override
    {}

    int32_t IsValidMissionIds(
        const std::vector<int32_t> &missionIds, std::vector<MissionValidResult> &results) override
    {
        return 1;
    }

    int32_t ReportDrawnCompleted(const sptr<IRemoteObject> &callerToken) override
    {
        return 1;
    }

    int32_t RegisterAppDebugListener(sptr<AppExecFwk::IAppDebugListener> listener) override
    {
        return 1;
    }

    int32_t UnregisterAppDebugListener(sptr<AppExecFwk::IAppDebugListener> listener) override
    {
        return 1;
    }

    int32_t AttachAppDebug(const std::string &bundleName) override
    {
        return 1;
    }

    int32_t DetachAppDebug(const std::string &bundleName) override
    {
        return 1;
    }

    int32_t ExecuteIntent(uint64_t key, const sptr<IRemoteObject> &callerToken,
        const InsightIntentExecuteParam &param) override
    {
        return 1;
    }

    int32_t ExecuteInsightIntentDone(const sptr<IRemoteObject> &token, uint64_t intentId,
        const InsightIntentExecuteResult &result) override
    {
        return 1;
    }

    int32_t SetApplicationAutoStartupByEDM(const AutoStartupInfo &info, bool flag) override
    {
        return 0;
    }

    int32_t CancelApplicationAutoStartupByEDM(const AutoStartupInfo &info, bool flag) override
    {
        return 0;
    }

    int32_t GetForegroundUIAbilities(std::vector<AppExecFwk::AbilityStateData> &list) override
    {
        return 1;
    }

    int32_t StartAbilityWithSpecifyTokenId(const Want& want,
        const sptr<IRemoteObject>& callerToken,
        uint32_t specifyTokenId,
        int32_t userId = DEFAULT_INVAL_VALUE,
        int requestCode = DEFAULT_INVAL_VALUE) override
    {
        return 1;
    }
};

/**
 * @tc.name: AbilityManagerHelper_0100
 * @tc.desc: test GetAbilityMgrProxy function and abilityMgr_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_0100, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0100 start";
    AbilityManagerHelper abilityManagerHelper;
    abilityManagerHelper.abilityMgr_ = new (std::nothrow) TestAbilityMgr();
    EXPECT_EQ(true, abilityManagerHelper.GetAbilityMgrProxy());
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0100 end";
}

/**
 * @tc.name: AbilityManagerHelper_0200
 * @tc.desc: test GetAbilityMgrProxy function and abilityMgr_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_0200, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0200 start";
    AbilityManagerHelper abilityManagerHelper;
    abilityManagerHelper.abilityMgr_ = nullptr;
    EXPECT_EQ(false, abilityManagerHelper.GetAbilityMgrProxy());
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0200 end";
}

/**
 * @tc.name: AbilityManagerHelper_0300
 * @tc.desc: test ConnectAbility function and GetAbilityMgrProxy is false.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_0300, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0300 start";
    AbilityManagerHelper abilityManagerHelper;
    abilityManagerHelper.abilityMgr_ = nullptr;
    Want want;
    CommonEventData event;
    sptr<IRemoteObject> callerToken = nullptr;
    const int32_t userId = 1;
    EXPECT_EQ(-1, abilityManagerHelper.ConnectAbility(want, event, callerToken, userId));
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0300 end";
}

/**
 * @tc.name: AbilityManagerHelper_0400
 * @tc.desc: test Clear function and abilityMgr_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_0400, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0400 start";
    std::shared_ptr<AbilityManagerHelper> abilityManagerHelper = std::make_shared<AbilityManagerHelper>();
    ASSERT_NE(nullptr, abilityManagerHelper);
    abilityManagerHelper->abilityMgr_ = nullptr;
    abilityManagerHelper->Clear();
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0400 end";
}

/**
 * @tc.name: AbilityManagerHelper_0500
 * @tc.desc: test Clear function and abilityMgr_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_0500, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0500 start";
    std::shared_ptr<AbilityManagerHelper> abilityManagerHelper = std::make_shared<AbilityManagerHelper>();
    ASSERT_NE(nullptr, abilityManagerHelper);
    sptr<IRemoteObject> remoteObject = sptr<IRemoteObject>(new MockCommonEventStub());
    abilityManagerHelper->abilityMgr_ = iface_cast<AAFwk::IAbilityManager>(remoteObject);
    abilityManagerHelper->Clear();
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0500 end";
}

/**
 * @tc.name  : test SetEventHandler
 * @tc.number: AbilityManagerHelper_0600
 * @tc.desc  : Test SetEventHandler succeeded.
 */
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_0600, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0600 start";
    auto abilityManagerHelper = std::make_shared<AbilityManagerHelper>();
    CommonEventData data;
    sptr<StaticSubscriberConnection> connection = new (std::nothrow) StaticSubscriberConnection(data);
    abilityManagerHelper->subscriberConnection_.emplace(connection);
    auto handler = std::make_shared<EventHandler>(EventRunner::Create());
    abilityManagerHelper->SetEventHandler(handler);
    EXPECT_NE(abilityManagerHelper->subscriberConnection_.size(), 0);
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0600 end";
}

/**
 * @tc.name  : test DisconnectAbility
 * @tc.number: AbilityManagerHelper_0700
 * @tc.desc  : Test the DisconnectAbility function when the connection is nullptr.
 */
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_0700, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0700 start";
    auto abilityManagerHelper = std::make_shared<AbilityManagerHelper>();
    CommonEventData data;
    sptr<StaticSubscriberConnection> connection = new (std::nothrow) StaticSubscriberConnection(data);
    abilityManagerHelper->subscriberConnection_.emplace(connection);
    abilityManagerHelper->DisconnectAbility(nullptr);
    EXPECT_NE(abilityManagerHelper->subscriberConnection_.size(), 0);
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0700 end";
}

/**
 * @tc.name  : test DisconnectAbility
 * @tc.number: AbilityManagerHelper_0800
 * @tc.desc  : Test the DisconnectAbility function when the connection is not nullptr.
 */
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_0800, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0800 start";
    auto abilityManagerHelper = std::make_shared<AbilityManagerHelper>();
    CommonEventData data;
    sptr<StaticSubscriberConnection> connection = new (std::nothrow) StaticSubscriberConnection(data);
    abilityManagerHelper->subscriberConnection_.emplace(connection);
    abilityManagerHelper->DisconnectAbility(connection);
    EXPECT_NE(abilityManagerHelper->subscriberConnection_.size(), 0);
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0800 end";
}

/**
 * @tc.name  : test DisconnectServiceAbilityDelay
 * @tc.number: AbilityManagerHelper_0900
 * @tc.desc  : Test the DisconnectServiceAbilityDelay function when the connection is nullptr.
 */
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_0900, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0900 start";
    auto abilityManagerHelper = std::make_shared<AbilityManagerHelper>();
    auto handler = std::make_shared<EventHandler>(EventRunner::Create());
    abilityManagerHelper->SetEventHandler(handler);
    CommonEventData data;
    sptr<StaticSubscriberConnection> connection = new (std::nothrow) StaticSubscriberConnection(data);
    abilityManagerHelper->subscriberConnection_.emplace(connection);
    abilityManagerHelper->DisconnectServiceAbilityDelay(nullptr);
    EXPECT_NE(abilityManagerHelper->subscriberConnection_.size(), 0);
    GTEST_LOG_(INFO) << "AbilityManagerHelper_0900 end";
}

/**
 * @tc.name  : test DisconnectServiceAbilityDelay
 * @tc.number: AbilityManagerHelper_1000
 * @tc.desc  : Test the DisconnectServiceAbilityDelay function when the eventHandler_ is nullptr.
 */
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_1000, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_1000 start";
    auto abilityManagerHelper = std::make_shared<AbilityManagerHelper>();
    CommonEventData data;
    sptr<StaticSubscriberConnection> connection = new (std::nothrow) StaticSubscriberConnection(data);
    abilityManagerHelper->subscriberConnection_.emplace(connection);
    abilityManagerHelper->DisconnectServiceAbilityDelay(connection);
    EXPECT_NE(abilityManagerHelper->subscriberConnection_.size(), 0);
    GTEST_LOG_(INFO) << "AbilityManagerHelper_1000 end";
}

/**
 * @tc.name  : test DisconnectServiceAbilityDelay
 * @tc.number: AbilityManagerHelper_1100
 * @tc.desc  : Test the DisconnectServiceAbilityDelay function when the input parameters meet the requirements.
 */
HWTEST_F(AbilityManagerHelperTest, AbilityManagerHelper_1100, Level1)
{
    GTEST_LOG_(INFO) << "AbilityManagerHelper_1100 start";
    auto abilityManagerHelper = std::make_shared<AbilityManagerHelper>();
    CommonEventData data;
    sptr<StaticSubscriberConnection> firstConnection = new (std::nothrow) StaticSubscriberConnection(data);
    abilityManagerHelper->subscriberConnection_.emplace(firstConnection);
    auto handler = std::make_shared<EventHandler>(EventRunner::Create());
    abilityManagerHelper->SetEventHandler(handler);
    sptr<StaticSubscriberConnection> SecondConnection = new (std::nothrow) StaticSubscriberConnection(data);
    abilityManagerHelper->DisconnectServiceAbilityDelay(SecondConnection);
    EXPECT_NE(abilityManagerHelper->subscriberConnection_.size(), 0);
    GTEST_LOG_(INFO) << "AbilityManagerHelper_1100 end";
}