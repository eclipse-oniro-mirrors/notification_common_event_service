/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#define private public
#define protected public
#include "bundle_manager_helper.h"
#include "common_event_subscriber_manager.h"
#include "static_subscriber_manager.h"
#include "ability_manager_helper.h"
#undef private
#undef protected

#include "ces_inner_error_code.h"
#include "common_event_listener.h"
#include "common_event_stub.h"
#include "common_event_subscriber.h"
#include "inner_common_event_manager.h"
#include "mock_bundle_manager.h"
#include "bundle_manager_helper.h"
#include "common_event_manager_service.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EventFwk;
using namespace OHOS::AppExecFwk;

namespace {
const std::string EVENT = "com.ces.test.event";
const std::string ENTITY = "com.ces.test.entity";
const std::string SCHEME = "com.ces.test.scheme";
const std::string PERMISSION = "com.ces.test.permission";
const std::string DEVICEDID = "deviceId";
constexpr int32_t ERR_COMMON = -1;
constexpr int32_t DEFAULT_INVAL_USRE = -1;
}  // namespace

static OHOS::sptr<OHOS::IRemoteObject> bundleObject = nullptr;
class CommonEventSubscribeUnitTest : public testing::Test {
public:
    CommonEventSubscribeUnitTest()
    {}
    ~CommonEventSubscribeUnitTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

class SubscriberTest : public CommonEventSubscriber {
public:
    SubscriberTest(const CommonEventSubscribeInfo &sp) : CommonEventSubscriber(sp)
    {}

    ~SubscriberTest()
    {}

    virtual void OnReceiveEvent(const CommonEventData &data)
    {}
};

class CommonEventStubTest : public CommonEventStub {
public:
    CommonEventStubTest()
    {}

    virtual int32_t PublishCommonEvent(const CommonEventData &event, const CommonEventPublishInfo &publishinfo,
        const OHOS::sptr<OHOS::IRemoteObject> &commonEventListener, const int32_t &userId)
    {
        return ERR_COMMON;
    }

    virtual int32_t SubscribeCommonEvent(
        const CommonEventSubscribeInfo &subscribeInfo, const OHOS::sptr<OHOS::IRemoteObject> &commonEventListener)
    {
        return ERR_COMMON;
    }

    virtual int32_t UnsubscribeCommonEvent(const OHOS::sptr<OHOS::IRemoteObject> &commonEventListener)
    {
        return ERR_COMMON;
    }

    virtual bool DumpState(const uint8_t &dumpType, const std::string &event, const int32_t &userId,
        std::vector<std::string> &state)
    {
        return false;
    }

    virtual ~CommonEventStubTest()
    {}

    virtual bool FinishReceiver(const OHOS::sptr<OHOS::IRemoteObject> &proxy, const int &code,
        const std::string &receiverData, const bool &abortEvent)
    {
        return false;
    }
};

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
        return 2097177;
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

class EventReceiveStubTest : public EventReceiveStub {
public:
    EventReceiveStubTest()
    {}

    ~EventReceiveStubTest()
    {}

    virtual void NotifyEvent(const CommonEventData &commonEventData, const bool &ordered, const bool &sticky)
    {}
};

void CommonEventSubscribeUnitTest::SetUpTestCase(void)
{
    bundleObject = new MockBundleMgrService();
    OHOS::DelayedSingleton<BundleManagerHelper>::GetInstance()->sptrBundleMgr_ =
        OHOS::iface_cast<OHOS::AppExecFwk::IBundleMgr>(bundleObject);
}

void CommonEventSubscribeUnitTest::TearDownTestCase(void)
{}

void CommonEventSubscribeUnitTest::SetUp(void)
{}

void CommonEventSubscribeUnitTest::TearDown(void)
{}

/*
 * @tc.number: CommonEventSubscribeUnitTest_0300
 * @tc.name: test subscribe event
 * @tc.desc: InnerCommonEventManager subscribe common event success
 */
HWTEST_F(CommonEventSubscribeUnitTest, CommonEventSubscribeUnitTest_0300, Function | MediumTest | Level1)
{
    // make subscriber info
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    // make subscriber
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);

    // make common event listener
    OHOS::sptr<CommonEventListener> commonEventListener = new CommonEventListener(subscriber);
    OHOS::sptr<OHOS::IRemoteObject> commonEventListenerPtr(commonEventListener);

    // SubscribeCommonEvent
    struct tm curTime {0};
    OHOS::Security::AccessToken::AccessTokenID tokenID = 0;
    InnerCommonEventManager innerCommonEventManager;
    const pid_t pid = 0;
    const uid_t uid = 0;
    EXPECT_TRUE(innerCommonEventManager.SubscribeCommonEvent(
        subscribeInfo, commonEventListenerPtr, curTime, pid, uid, tokenID, ""));
}

/*
 * @tc.number: CommonEventSubscribeUnitTest_0400
 * @tc.name: test subscribe event
 * @tc.desc: InnerCommonEventManager subscribe common event fail because subscribeInfo has not event
 */
HWTEST_F(CommonEventSubscribeUnitTest, CommonEventSubscribeUnitTest_0400, Function | MediumTest | Level1)
{
    // make subscriber info
    MatchingSkills matchingSkills;
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    // make subscriber
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);

    // make common event listener
    OHOS::sptr<CommonEventListener> commonEventListener = new CommonEventListener(subscriber);
    OHOS::sptr<OHOS::IRemoteObject> commonEventListenerPtr(commonEventListener);

    // SubscribeCommonEvent
    struct tm curTime {0};
    OHOS::Security::AccessToken::AccessTokenID tokenID = 0;
    InnerCommonEventManager innerCommonEventManager;
    const pid_t pid = 0;
    const uid_t uid = 0;
    EXPECT_FALSE(innerCommonEventManager.SubscribeCommonEvent(
        subscribeInfo, commonEventListenerPtr, curTime, pid, uid, tokenID, ""));
}

/*
 * @tc.number: CommonEventSubscribeUnitTest_0500
 * @tc.name: test subscribe event
 * @tc.desc: 1. subscribe common event
 *                      2. fail subscribe common event, inner common event manager
 *                          common event listener is null
 */
HWTEST_F(CommonEventSubscribeUnitTest, CommonEventSubscribeUnitTest_0500, Function | MediumTest | Level1)
{
    // make subscriber info
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    // SubscribeCommonEvent
    OHOS::sptr<OHOS::IRemoteObject> sp(nullptr);
    struct tm curTime {0};
    OHOS::Security::AccessToken::AccessTokenID tokenID = 0;
    InnerCommonEventManager innerCommonEventManager;
    const pid_t pid = 0;
    const uid_t uid = 0;
    EXPECT_FALSE(innerCommonEventManager.SubscribeCommonEvent(subscribeInfo, sp, curTime, pid, uid, tokenID, ""));
}

/*
 * @tc.number: CommonEventSubscribeUnitTest_0600
 * @tc.name: test subscribe event
 * @tc.desc: subscribe common event success
 */
HWTEST_F(CommonEventSubscribeUnitTest, CommonEventSubscribeUnitTest_0600, Function | MediumTest | Level1)
{
    // make subscriber info
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<CommonEventSubscribeInfo> subscribeInfoPtr =
        std::make_shared<CommonEventSubscribeInfo>(subscribeInfo);

    // make subscriber
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);

    // make common event listener
    OHOS::sptr<CommonEventListener> commonEventListener = new CommonEventListener(subscriber);
    OHOS::sptr<OHOS::IRemoteObject> commonEventListenerPtr(commonEventListener);

    // InsertSubscriber
    struct tm curTime {0};
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.pid = 0;
    eventRecordInfo.uid = 0;
    eventRecordInfo.bundleName = "bundleName";
    CommonEventSubscriberManager commonEventSubscriberManager;
    auto result = commonEventSubscriberManager.InsertSubscriber(
        subscribeInfoPtr, commonEventListener, curTime, eventRecordInfo);
    EXPECT_NE(nullptr, result);
}

/*
 * @tc.number: CommonEventSubscribeUnitTest_0700
 * @tc.name: test subscribe event
 * @tc.desc: 1. subscribe common event
 *                      2. fail subscribe common event , common event subscriber manager
 *                          event subscriber info is null
 */
HWTEST_F(CommonEventSubscribeUnitTest, CommonEventSubscribeUnitTest_0700, Function | MediumTest | Level1)
{
    // make subscriber info
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    // make subscriber
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);

    // make common event listener
    OHOS::sptr<CommonEventListener> commonEventListener = new CommonEventListener(subscriber);
    OHOS::sptr<OHOS::IRemoteObject> commonEventListenerPtr(commonEventListener);

    // InsertSubscriber
    struct tm curTime {0};
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.pid = 0;
    eventRecordInfo.uid = 0;
    eventRecordInfo.bundleName = "bundleName";
    CommonEventSubscriberManager commonEventSubscriberManager;
    auto result =
        commonEventSubscriberManager.InsertSubscriber(nullptr, commonEventListenerPtr, curTime, eventRecordInfo);
    EXPECT_EQ(nullptr, result);
}

/*
 * @tc.number: CommonEventSubscribeUnitTest_0800
 * @tc.name: test subscribe event
 * @tc.desc: 1. subscribe common event
 *                      2. fail subscribe common event , common event subscriber manager
 *                          event common event listener is null
 */
HWTEST_F(CommonEventSubscribeUnitTest, CommonEventSubscribeUnitTest_0800, Function | MediumTest | Level1)
{
    // make subscriber info
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<CommonEventSubscribeInfo> subscribeInfoPtr =
        std::make_shared<CommonEventSubscribeInfo>(subscribeInfo);

    // make subscriber
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);

    // InsertSubscriber
    struct tm curTime {0};
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.pid = 0;
    eventRecordInfo.uid = 0;
    eventRecordInfo.bundleName = "bundleName";
    CommonEventSubscriberManager commonEventSubscriberManager;
    auto result = commonEventSubscriberManager.InsertSubscriber(subscribeInfoPtr, nullptr, curTime, eventRecordInfo);
    EXPECT_EQ(nullptr, result);
}

/*
 * @tc.number: CommonEventSubscribeUnitTest_0900
 * @tc.name: test subscribe event
 * @tc.desc: 1. subscribe common event
 *                      2. fail subscribe common event , common event subscriber manager
 *                          event size is null
 */
HWTEST_F(CommonEventSubscribeUnitTest, CommonEventSubscribeUnitTest_0900, Function | MediumTest | Level1)
{
    // make subscriber info
    MatchingSkills matchingSkills;
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<CommonEventSubscribeInfo> subscribeInfoPtr =
        std::make_shared<CommonEventSubscribeInfo>(subscribeInfo);

    // make subscriber
    CommonEventStubTest CommonEventStubTest;
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);

    // make common event listener
    OHOS::sptr<CommonEventListener> commonEventListener = new CommonEventListener(subscriber);
    std::shared_ptr<InnerCommonEventManager> innerCommonEventManager = std::make_shared<InnerCommonEventManager>();
    OHOS::sptr<OHOS::IRemoteObject> commonEventListenerPtr(commonEventListener);

    // InsertSubscriber
    struct tm curTime {0};
    EventRecordInfo eventRecordInfo;
    eventRecordInfo.pid = 0;
    eventRecordInfo.uid = 0;
    eventRecordInfo.bundleName = "bundleName";
    CommonEventSubscriberManager commonEventSubscriberManager;
    auto result = commonEventSubscriberManager.InsertSubscriber(
        subscribeInfoPtr, commonEventListenerPtr, curTime, eventRecordInfo);
    EXPECT_EQ(nullptr, result);
}

/*
 * @tc.number: CommonEventSubscribeUnitTest_1000
 * @tc.name: ttest subscribe event
 * @tc.desc:  insert subscriber record locked success
 */
HWTEST_F(CommonEventSubscribeUnitTest, CommonEventSubscribeUnitTest_1000, Function | MediumTest | Level1)
{
    // make subscriber info
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT);
    matchingSkills.AddEvent(ENTITY);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    // make subscriber
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);

    // make common event listener
    OHOS::sptr<CommonEventListener> commonEventListener = new CommonEventListener(subscriber);
    OHOS::sptr<OHOS::IRemoteObject> commonEventListenerPtr(commonEventListener);

    // make events
    std::vector<std::string> events = subscribeInfo.GetMatchingSkills().GetEvents();

    // make record
    struct tm recordTime {0};
    auto record = std::make_shared<EventSubscriberRecord>();
    record->eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>(subscribeInfo);
    record->commonEventListener = commonEventListenerPtr;
    record->recordTime = recordTime;
    record->eventRecordInfo.pid = 0;
    record->eventRecordInfo.uid = 0;
    record->eventRecordInfo.bundleName = "bundleName";

    // InsertSubscriberRecordLocked
    CommonEventSubscriberManager commonEventSubscriberManager;
    EXPECT_TRUE(commonEventSubscriberManager.InsertSubscriberRecordLocked(events, record));
}

/*
 * @tc.number: CommonEventSubscribeUnitTest_1100
 * @tc.name: test subscribe event
 * @tc.desc:  insert subscriber record locked fail because events size is 0
 */
HWTEST_F(CommonEventSubscribeUnitTest, CommonEventSubscribeUnitTest_1100, Function | MediumTest | Level1)
{
    // make subscriber info
    MatchingSkills matchingSkills;
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    // make subscriber
    std::shared_ptr<SubscriberTest> subscriber = std::make_shared<SubscriberTest>(subscribeInfo);

    // make common event listener
    OHOS::sptr<CommonEventListener> commonEventListener = new CommonEventListener(subscriber);
    OHOS::sptr<OHOS::IRemoteObject> commonEventListenerPtr(commonEventListener);

    // make events
    std::vector<std::string> events = subscribeInfo.GetMatchingSkills().GetEvents();

    // make record
    struct tm recordTime {0};
    auto record = std::make_shared<EventSubscriberRecord>();
    record->eventSubscribeInfo = std::make_shared<CommonEventSubscribeInfo>(subscribeInfo);
    record->commonEventListener = commonEventListenerPtr;
    record->recordTime = recordTime;
    record->eventRecordInfo.pid = 0;
    record->eventRecordInfo.uid = 0;
    record->eventRecordInfo.bundleName = "bundleName";

    // InsertSubscriberRecordLocked
    CommonEventSubscriberManager commonEventSubscriberManager;
    EXPECT_FALSE(commonEventSubscriberManager.InsertSubscriberRecordLocked(events, record));
}

/*
 * @tc.number: CommonEventSubscribeUnitTest_1200
 * @tc.name: test subscribe event
 * @tc.desc:  insert subscriber record locked fail because record is nullptr
 */
HWTEST_F(CommonEventSubscribeUnitTest, CommonEventSubscribeUnitTest_1200, Function | MediumTest | Level1)
{
    // make subscriber info
    MatchingSkills matchingSkills;
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    // make events
    std::vector<std::string> events = subscribeInfo.GetMatchingSkills().GetEvents();
    CommonEventSubscriberManager commonEventSubscriberManager;

    // InsertSubscriberRecordLocked
    EXPECT_FALSE(commonEventSubscriberManager.InsertSubscriberRecordLocked(events, nullptr));
}

/**
 * @tc.name: AbilityManagerHelper_0001
 * @tc.desc: GetAbilityMgrProxy
 * @tc.type: FUNC
 * @tc.require: I5R11Y
 */
HWTEST_F(CommonEventSubscribeUnitTest, AbilityManagerHelper_0001, Function | MediumTest | Level1)
{
    AbilityManagerHelper abilityManagerHelper;
    abilityManagerHelper.abilityMgr_ = new (std::nothrow) TestAbilityMgr();
    bool result = abilityManagerHelper.GetAbilityMgrProxy();
    abilityManagerHelper.Clear();
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: AbilityManagerHelper_0002
 * @tc.desc: ConnectAbility
 * @tc.type: FUNC
 * @tc.require: I5R11Y
 */
HWTEST_F(CommonEventSubscribeUnitTest, AbilityManagerHelper_0002, Function | MediumTest | Level1)
{
    // make a want
    Want want;
    want.SetAction(EVENT);

    // make common event data
    CommonEventData event;
    OHOS::sptr<OHOS::IRemoteObject> callerToken(nullptr);
    const int32_t userId = 1;
    AbilityManagerHelper abilityManagerHelper;
    abilityManagerHelper.abilityMgr_ = new (std::nothrow) TestAbilityMgr();
    int result = abilityManagerHelper.ConnectAbility(want, event, callerToken, userId);
    EXPECT_EQ(result, 2097177);
}

/**
 * @tc.name: BundleManagerHelper_0001
 * @tc.desc: QueryExtensionInfos
 * @tc.type: FUNC
 * @tc.require: I5R11Y
 */
HWTEST_F(CommonEventSubscribeUnitTest, BundleManagerHelper_0001, Function | MediumTest | Level1)
{
    std::vector<OHOS::AppExecFwk::ExtensionAbilityInfo> extensionInfos;
    const int32_t userId = 3;
    BundleManagerHelper bundleManagerHelper;
    bundleManagerHelper.QueryExtensionInfos(extensionInfos, userId);
}

/**
 * @tc.name: BundleManagerHelper_0002
 * @tc.desc: GetResConfigFile
 * @tc.type: FUNC
 * @tc.require: I5R11Y
 */
HWTEST_F(CommonEventSubscribeUnitTest, BundleManagerHelper_0002, Function | MediumTest | Level1)
{
    OHOS::AppExecFwk::ExtensionAbilityInfo extension;
    std::vector<std::string> profileInfos;
    BundleManagerHelper bundleManagerHelper;
    bool result = bundleManagerHelper.GetResConfigFile(extension, profileInfos);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: CommonEventManagerService_0001
 * @tc.desc: PublishCommonEvent
 * @tc.type: FUNC
 * @tc.require: I5R11Y
 */
HWTEST_F(CommonEventSubscribeUnitTest, CommonEventManagerService_0001, Function | MediumTest | Level1)
{
    // make a want
    Want want;
    want.SetAction(EVENT);
    // make common event data
    CommonEventData event;
    // make publish info
    CommonEventPublishInfo publishinfo;
    OHOS::sptr<OHOS::IRemoteObject> commonEventListener(nullptr);
    const uid_t uid = 1;
    const int32_t userId = 1;
    const int32_t tokenId = 0;
    CommonEventManagerService commonEventManagerService;
    bool result = commonEventManagerService.PublishCommonEvent(event, publishinfo, commonEventListener, uid,
        tokenId, userId);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: CommonEventManagerService_0002
 * @tc.desc: DumpState
 * @tc.type: FUNC
 * @tc.require: I5R11Y
 */
HWTEST_F(CommonEventSubscribeUnitTest, CommonEventManagerService_0002, Function | MediumTest | Level1)
{
    uint8_t dumpType = 1;
    std::string event = "Event";
    const int32_t userId =2;
    std::vector<std::string> state;
    CommonEventManagerService commonEventManagerService;
    bool result = commonEventManagerService.DumpState(dumpType, event, userId, state);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: CommonEventManagerService_0003
 * @tc.desc: FinishReceiver
 * @tc.type: FUNC
 * @tc.require: I5R11Y
 */
HWTEST_F(CommonEventSubscribeUnitTest, CommonEventManagerService_0003, Function | MediumTest | Level1)
{
    OHOS::sptr<OHOS::IRemoteObject> proxy(nullptr);
    int32_t code = 0;
    std::string receiverData = "receiverData";
    CommonEventManagerService commonEventManagerService;
    bool result = commonEventManagerService.FinishReceiver(proxy, code, receiverData, false);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: CommonEventManagerService_0004
 * @tc.desc: Dump
 * @tc.type: FUNC
 * @tc.require: I5R11Y
 */
HWTEST_F(CommonEventSubscribeUnitTest, CommonEventManagerService_0004, Function | MediumTest | Level1)
{
    int fd = 1;
    std::vector<std::u16string> args;
    CommonEventManagerService commonEventManagerService;
    int result = commonEventManagerService.Dump(fd, args);
    EXPECT_EQ(result, int(OHOS::ERR_INVALID_VALUE));
}
