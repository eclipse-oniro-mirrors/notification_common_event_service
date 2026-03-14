# Common Event Service - Agent Guidelines

This document provides guidelines for AI agents working with the Common Event Service (CES) codebase.

## Build Commands

### Full Build
```bash
# Build the entire subsystem (run from OpenHarmony root)
./build.sh --product-name rk3568 --build-target common_event_service
```
### Build Test

```bash
# Build the entire subsystem (run from OpenHarmony root)
./build.sh --product-name rk3568 --build-target common_event_service_test
```

## Code Style Guidelines

### Line Length

Maximum line width is 120 characters.

### File Headers
All source files must include the Apache 2.0 license header:
```cpp
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
```

### Naming Conventions
- **Files**: snake_case (e.g., `common_event_manager.cpp`)
- **Classes**: PascalCase (e.g., `CommonEventManager`)
- **Functions**: snake_case (e.g., `PublishCommonEvent`)
- **Constants**: UPPER_SNAKE_CASE (e.g., `MAX_SUBSCRIBERS`)
- **Member variables**: trailing underscore (e.g., `serviceRunningState_`)
- **Namespaces**: Use `OHOS::EventFwk` for CES code

### Includes
Order includes as follows:
1. System headers (e.g., `<mutex>`, `<new>`)
2. Project headers (use quotes)
3. Third-party headers

Example:
```cpp
#include <mutex>
#include <new>

#include "common_event_manager.h"
#include "event_log_wrapper.h"
```

### Error Handling
- Use `ErrCode` or `int32_t` for return values
- Return `ERR_OK` (0) for success
- Use error codes from `ces_inner_error_code.h`
- Check for null pointers before dereferencing
- Log errors using `EVENT_LOGE` macro

```cpp
if (!innerCommonEventManager_) {
    EVENT_LOGE(LOG_TAG_CES, "innerCommonEventManager is null");
    return ERR_INVALID_OPERATION;
}
```

### Logging
Use the logging macros from `event_log_wrapper.h`:
- `EVENT_LOGD(LOG_TAG_CES, ...)` - Debug
- `EVENT_LOGI(LOG_TAG_CES, ...)` - Info
- `EVENT_LOGW(LOG_TAG_CES, ...)` - Warning
- `EVENT_LOGE(LOG_TAG_CES, ...)` - Error

### Smart Pointers
- Use `sptr<T>` for IPC-related objects (from OpenHarmony)
- Use `std::shared_ptr<T>` for regular objects
- Use `std::make_shared<T>()` to create shared pointers

### Threading
- Use `ffrt::mutex` for mutexes (not std::mutex)
- Use `ffrt::queue` for task queues
- Use `std::lock_guard` for RAII-style locking

```cpp
ffrt::mutex instanceMutex_;
std::lock_guard<ffrt::mutex> lock(instanceMutex_);
```

### Test Guidelines
- Use `HWTEST_F(ClassName, TestName, Function | SmallTest | Level1)` macro for test cases
- Test naming: `FunctionName_ScenarioNumber` (e.g., `GetBundleName_00001`)
- Use `#define private public` and `#define protected public` before includes if testing private members
- Remember to `#undef` after includes
- Add test documentation comments:
  ```cpp
  /**
   * @tc.name: TestName
   * @tc.desc: Description of what the test does
   * @tc.type: FUNC
   * @tc.require: issueNumber
   */
  ```
- Use `EXPECT_EQ`, `EXPECT_NE`, `ASSERT_EQ`, etc. for assertions
- Create test fixtures with `SetUpTestCase()`, `TearDownTestCase()`, `SetUp()`, `TearDown()`
```cpp
#define private public
#define protected public
#include "common_event_manager.h"
#undef private
#undef protected
```

### Header Guards
Use traditional header guards:
```cpp
#ifndef FOUNDATION_EVENT_CESFWK_KITS_NATIVE_INCLUDE_COMMON_EVENT_MANAGER_H
#define FOUNDATION_EVENT_CESFWK_KITS_NATIVE_INCLUDE_COMMON_EVENT_MANAGER_H

// Content

#endif  // FOUNDATION_EVENT_CESFWK_KITS_NATIVE_INCLUDE_COMMON_EVENT_MANAGER_H
```

### GN Build Files
- Import `event.gni` for common paths
- Use `ohos_unittest` for unit tests
- Specify `module_out_path` for test output location
- List dependencies in `deps` (internal) and `external_deps` (external)

## Project Structure

```
base/notification/common_event_service/
├── frameworks/                 # Framework implementation
│   ├── common/                  # Common utilities (logging, etc.)
│   │   └── log/                 # Logging wrapper
│   ├── core/                    # Core IPC implementation
│   │   ├── include/             # Core headers
│   │   └── src/                 # Core source files
│   ├── native/                  # Native API implementation
│   │   ├── include/             # Native API headers
│   │   └── src/                 # Native API source
│   └── extension/               # Extension modules
│       └── static_subscriber/   # Static subscriber support
├── interfaces/                 # Public interfaces
│   ├── inner_api/               # Internal API headers
│   └── kits/                    # Language bindings
│       ├── napi/                # JavaScript/NAPI bindings
│       ├── ndk/                 # Native Development Kit
│       ├── ani/                 # Ark Native Interface
│       └── cj/                  # Cangjie bindings
├── services/                   # Service implementation
│   ├── include/                 # Service headers
│   └── src/                    # Service source files
├── tools/                      # CLI tools
│   └── cem/                    # Common Event Manager CLI
├── sa_profile/                 # System ability profile
├── test/                       # Test code
│   ├── unittest/               # Unit tests
│   ├── moduletest/             # Module tests
│   ├── systemtest/             # System tests
│   ├── fuzztest/               # Fuzz tests
│   ├── benchmarktest/          # Benchmark tests
│   └── mock/                   # Mock objects
├── event.gni                   # GN build configuration
├── BUILD.gn                    # GN build file
└── bundle.json                 # Component metadata
```

### Key Components

**Core Classes:**
- `CommonEventManagerService` - Main service singleton
- `InnerCommonEventManager` - Internal event manager
- `CommonEventSubscriberManager` - Manages event subscribers
- `CommonEventControlManager` - Controls event flow
- `CommonEventStickyManager` - Manages sticky events
- `PublishManager` - Handles event publishing

**Key Files:**
- `services/src/common_event_manager_service.cpp` - Main service entry point
- `services/src/inner_common_event_manager.cpp` - Core event handling logic
- `interfaces/inner_api/common_event_manager.h` - Public API header

### Common Dependencies
- `ability_base:want` - Want parameter handling
- `access_token:libaccesstoken_sdk` - Permission checking
- `eventhandler:libeventhandler` - Event handling
- `hilog:libhilog` - Logging
- `ipc:ipc_core` - IPC communication
- `ffrt:libffrt` - Foundation framework runtime

### Key Patterns
- Singleton pattern for service instances (e.g., `CommonEventManagerService::GetInstance()`)
- RAII for resource management
- Weak attributes for optional features: `__attribute__((weak))`
- Use `std::nothrow` with `new` to avoid exceptions

## Commit Messages

Follow the OpenHarmony commit message format. End your commit message with:

```
Co-Authored-By: Agent
```

Example:
```
Add TDD test cases for notification slot filtering

Co-Authored-By: Agent
```

When committing, use the `--signoff` flag:
```bash
git commit --signoff -m "Your commit message

Co-Authored-By: Agent"
```