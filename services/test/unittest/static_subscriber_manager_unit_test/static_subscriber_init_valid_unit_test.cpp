/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "ces_inner_error_code.h"
#include "user_app_test_mock_apis.h"

#define private public  // NOLINT
#include "static_subscriber_data_manager.h"
#include "static_subscriber_manager.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EventFwk;

namespace {
const int32_t TEST_USER_ID = 100;
const std::string TEST_EVENT = "usual.event.TIME_TICK";
const std::string LEGACY_BUNDLE = "com.ces.test.legacy";
const std::string UNKNOWN_BUNDLE = "com.ces.test.unknown";
const std::string EXPLICIT_BUNDLE = "com.ces.test.explicit";
const std::string INVALID_BUNDLE = "com.ces.test.invalid";
const std::string IS_UPDATED_KEY = "is_updated_key";
const std::string IS_UPDATED_VALUE = "true";
const std::string LEGACY_VALUE = "0";
const std::string INVALID_VALUE = "events1";
const std::string EXPLICIT_VALUE = "[\"usual.event.TIME_TICK\"]";

class StaticSubscriberInitValidUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

std::string BuildBundleKey(const std::string &bundleName)
{
    return std::to_string(TEST_USER_ID) + "_" + bundleName;
}

bool PutKvEntry(StaticSubscriberDataManager &dataManager, const std::string &key, const std::string &value)
{
    if (!dataManager.CheckKvStore() || dataManager.kvStorePtr_ == nullptr) {
        return false;
    }
    return dataManager.kvStorePtr_->Put(DistributedKv::Key(key), DistributedKv::Value(value)) ==
        DistributedKv::Status::SUCCESS;
}

bool PrepareKvData(StaticSubscriberDataManager &dataManager, const std::string &key, const std::string &value)
{
    return PutKvEntry(dataManager, IS_UPDATED_KEY, IS_UPDATED_VALUE) &&
        PutKvEntry(dataManager, key, value);
}

void DeleteKvData(StaticSubscriberDataManager &dataManager, const std::string &key)
{
    if (!dataManager.CheckKvStore() || dataManager.kvStorePtr_ == nullptr) {
        return;
    }
    dataManager.kvStorePtr_->Delete(DistributedKv::Key(key));
}

void AddStaticSubscriber(StaticSubscriberManager &manager, const std::string &bundleName)
{
    StaticSubscriberManager::StaticSubscriber subscriber;
    subscriber.events = { TEST_EVENT };
    manager.staticSubscribers_.emplace(BuildBundleKey(bundleName), subscriber);
}
}  // namespace

/*
 * @tc.name: LoadDisableEventsUnionTest_0100
 * @tc.desc: test that explicit entries and legacy entries are merged instead of replacing each other.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberInitValidUnitTest, LoadDisableEventsUnionTest_0100,
    Function | MediumTest | Level1)
{
    std::string explicitKey = BuildBundleKey(EXPLICIT_BUNDLE);
    std::string legacyKey = BuildBundleKey(LEGACY_BUNDLE);
    std::string unknownKey = BuildBundleKey(UNKNOWN_BUNDLE);
    auto dataManager = std::make_shared<StaticSubscriberDataManager>();
    ASSERT_NE(nullptr, dataManager);
    if (!PrepareKvData(*dataManager, explicitKey, EXPLICIT_VALUE)) {
        GTEST_SKIP() << "kv store is not available";
    }
    ASSERT_TRUE(PutKvEntry(*dataManager, legacyKey, LEGACY_VALUE));
    ASSERT_TRUE(PutKvEntry(*dataManager, unknownKey, LEGACY_VALUE));
    auto manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    AddStaticSubscriber(*manager, LEGACY_BUNDLE);

    EXPECT_TRUE(manager->LoadDisableEvents());
    EXPECT_TRUE(manager->disableEventsLoaded_);
    EXPECT_EQ(2, manager->disableEvents_.size());
    EXPECT_EQ(1, manager->disableEvents_.count(explicitKey));
    EXPECT_EQ(1, manager->disableEvents_.count(legacyKey));
    // A legacy entry without a matching static subscriber is dropped.
    EXPECT_EQ(0, manager->disableEvents_.count(unknownKey));

    DeleteKvData(*dataManager, explicitKey);
    DeleteKvData(*dataManager, legacyKey);
    DeleteKvData(*dataManager, unknownKey);
}

/*
 * @tc.name: LoadDisableEventsExplicitOnlyTest_0100
 * @tc.desc: test that an explicit-only snapshot is loaded without a migration writeback.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberInitValidUnitTest, LoadDisableEventsExplicitOnlyTest_0100,
    Function | MediumTest | Level1)
{
    std::string explicitKey = BuildBundleKey(EXPLICIT_BUNDLE);
    auto dataManager = std::make_shared<StaticSubscriberDataManager>();
    ASSERT_NE(nullptr, dataManager);
    if (!PrepareKvData(*dataManager, explicitKey, EXPLICIT_VALUE)) {
        GTEST_SKIP() << "kv store is not available";
    }
    auto manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);

    EXPECT_TRUE(manager->LoadDisableEvents());
    EXPECT_TRUE(manager->disableEventsLoaded_);
    EXPECT_EQ(1, manager->disableEvents_.size());
    EXPECT_EQ(1, manager->disableEvents_.count(explicitKey));
    DeleteKvData(*dataManager, explicitKey);
}

/*
 * @tc.name: LoadDisableEventsLegacyMigrateTest_0100
 * @tc.desc: test that a legacy entry is expanded and written back in the current format.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberInitValidUnitTest, LoadDisableEventsLegacyMigrateTest_0100,
    Function | MediumTest | Level1)
{
    std::string legacyKey = BuildBundleKey(LEGACY_BUNDLE);
    auto dataManager = std::make_shared<StaticSubscriberDataManager>();
    ASSERT_NE(nullptr, dataManager);
    if (!PrepareKvData(*dataManager, legacyKey, LEGACY_VALUE)) {
        GTEST_SKIP() << "kv store is not available";
    }
    auto manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    AddStaticSubscriber(*manager, LEGACY_BUNDLE);

    EXPECT_TRUE(manager->LoadDisableEvents());
    EXPECT_EQ(1, manager->disableEvents_.count(legacyKey));

    std::map<std::string, std::vector<std::string>> migratedEvents;
    std::set<std::string> bundleList;
    ASSERT_EQ(ERR_OK, dataManager->QueryStaticSubscriberStateData(migratedEvents, bundleList));
    EXPECT_TRUE(bundleList.empty());
    EXPECT_EQ(1, migratedEvents.count(legacyKey));
    DeleteKvData(*dataManager, legacyKey);
}

/*
 * @tc.name: LoadDisableEventsQueryFailTest_0100
 * @tc.desc: test that a failed kv query keeps the manager unloaded and the state untouched.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberInitValidUnitTest, LoadDisableEventsQueryFailTest_0100,
    Function | MediumTest | Level1)
{
    std::string key = BuildBundleKey(INVALID_BUNDLE);
    auto dataManager = std::make_shared<StaticSubscriberDataManager>();
    ASSERT_NE(nullptr, dataManager);
    if (!PrepareKvData(*dataManager, key, INVALID_VALUE)) {
        GTEST_SKIP() << "kv store is not available";
    }
    auto manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);

    EXPECT_FALSE(manager->LoadDisableEvents());
    EXPECT_FALSE(manager->disableEventsLoaded_);
    EXPECT_TRUE(manager->disableEvents_.empty());
    DeleteKvData(*dataManager, key);
}

/*
 * @tc.name: UpdateDisableEventsBeforeLoadTest_0100
 * @tc.desc: test that the update path loads the persisted state before writing, so no entry is lost.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberInitValidUnitTest, UpdateDisableEventsBeforeLoadTest_0100,
    Function | MediumTest | Level1)
{
    std::string legacyKey = BuildBundleKey(LEGACY_BUNDLE);
    auto dataManager = std::make_shared<StaticSubscriberDataManager>();
    ASSERT_NE(nullptr, dataManager);
    if (!PrepareKvData(*dataManager, legacyKey, LEGACY_VALUE)) {
        GTEST_SKIP() << "kv store is not available";
    }
    auto manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    AddStaticSubscriber(*manager, LEGACY_BUNDLE);

    EXPECT_EQ(ERR_OK, manager->UpdateDisableEvents(EXPLICIT_BUNDLE, { TEST_EVENT }, false, TEST_USER_ID));
    EXPECT_TRUE(manager->disableEventsLoaded_);
    EXPECT_EQ(1, manager->disableEvents_.count(legacyKey));
    EXPECT_EQ(1, manager->disableEvents_.count(BuildBundleKey(EXPLICIT_BUNDLE)));
    DeleteKvData(*dataManager, legacyKey);
    DeleteKvData(*dataManager, BuildBundleKey(EXPLICIT_BUNDLE));
}

/*
 * @tc.name: RemoveSubscriberWithBundleNameBeforeLoadTest_0100
 * @tc.desc: test that the remove path loads the persisted state before modifying it.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberInitValidUnitTest, RemoveSubscriberWithBundleNameBeforeLoadTest_0100,
    Function | MediumTest | Level1)
{
    std::string legacyKey = BuildBundleKey(LEGACY_BUNDLE);
    auto dataManager = std::make_shared<StaticSubscriberDataManager>();
    ASSERT_NE(nullptr, dataManager);
    if (!PrepareKvData(*dataManager, legacyKey, LEGACY_VALUE)) {
        GTEST_SKIP() << "kv store is not available";
    }
    auto manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    AddStaticSubscriber(*manager, LEGACY_BUNDLE);

    manager->RemoveSubscriberWithBundleName(LEGACY_BUNDLE, TEST_USER_ID);
    EXPECT_TRUE(manager->disableEventsLoaded_);
    EXPECT_TRUE(manager->disableEvents_.empty());
    DeleteKvData(*dataManager, legacyKey);
}

/*
 * @tc.name: InitValidSubscribersAllowListFailTest_0100
 * @tc.desc: test that a failed allow list keeps the previous disable state untouched.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberInitValidUnitTest, InitValidSubscribersAllowListFailTest_0100,
    Function | MediumTest | Level1)
{
    std::shared_ptr<StaticSubscriberManager> manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);
    std::string key = BuildBundleKey(EXPLICIT_BUNDLE);
    manager->disableEvents_.emplace(key, std::vector<std::string>{ TEST_EVENT });
    manager->disableEventsLoaded_ = true;

    MockGetApplicationInfosRet(false);
    bool initResult = manager->InitValidSubscribers();
    MockGetApplicationInfosRet(true);

    EXPECT_FALSE(initResult);
    EXPECT_EQ(1, manager->disableEvents_.size());
    EXPECT_TRUE(manager->disableEventsLoaded_);
    EXPECT_FALSE(manager->hasInitValidSubscribers_);
}

/*
 * @tc.name: UpdateDisableEventsLegacyNotExpandedTest_0100
 * @tc.desc: test that enabling a legacy entry that can not be expanded yet reports an error
 *           instead of returning a silent success.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberInitValidUnitTest, UpdateDisableEventsLegacyNotExpandedTest_0100,
    Function | MediumTest | Level1)
{
    std::string legacyKey = BuildBundleKey(LEGACY_BUNDLE);
    auto dataManager = std::make_shared<StaticSubscriberDataManager>();
    ASSERT_NE(nullptr, dataManager);
    if (!PrepareKvData(*dataManager, legacyKey, LEGACY_VALUE)) {
        GTEST_SKIP() << "kv store is not available";
    }
    auto manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);

    // The allowlist is not initialized, so the legacy entry can not be resolved to events.
    EXPECT_EQ(ERR_NO_INIT, manager->UpdateDisableEvents(LEGACY_BUNDLE, { TEST_EVENT }, true, TEST_USER_ID));
    EXPECT_EQ(0, manager->disableEvents_.count(legacyKey));
    EXPECT_EQ(1, manager->unexpandedLegacyKeys_.count(legacyKey));
    DeleteKvData(*dataManager, legacyKey);
}

/*
 * @tc.name: InitValidSubscribersDisableLoadFailTest_0100
 * @tc.desc: test that a failed disable-events load keeps the valid subscribers ready but leaves the
 *           disable state unloaded, and that the next init restores it.
 * @tc.type: FUNC
 */
HWTEST_F(StaticSubscriberInitValidUnitTest, InitValidSubscribersDisableLoadFailTest_0100,
    Function | MediumTest | Level1)
{
    std::string key = BuildBundleKey(INVALID_BUNDLE);
    auto dataManager = std::make_shared<StaticSubscriberDataManager>();
    ASSERT_NE(nullptr, dataManager);
    if (!PrepareKvData(*dataManager, key, INVALID_VALUE)) {
        GTEST_SKIP() << "kv store is not available";
    }
    auto manager = std::make_shared<StaticSubscriberManager>();
    ASSERT_NE(nullptr, manager);

    EXPECT_TRUE(manager->InitValidSubscribers());
    EXPECT_TRUE(manager->hasInitValidSubscribers_);
    EXPECT_FALSE(manager->disableEventsLoaded_);

    // Once the broken entry is removed, the next init restores the persisted disable state.
    DeleteKvData(*dataManager, key);
    EXPECT_TRUE(manager->InitValidSubscribers());
    EXPECT_TRUE(manager->disableEventsLoaded_);
}
