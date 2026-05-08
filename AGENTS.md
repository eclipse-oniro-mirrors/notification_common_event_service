# Common Event Service - Agent Guidelines

## Build

Run from the OpenHarmony repository root:
```bash
# Full subsystem build
./build.sh --product-name rk3568 --build-target common_event_service

# Build tests
./build.sh --product-name rk3568 --build-target common_event_service_test
```

The subsystem is organized into two build groups (defined in `bundle.json`):
- **`fwk_group`** — frameworks/core, frameworks/native, frameworks/extension, plus all language bindings (napi, ani, cj, ndk)
- **`service_group`** — services, sa_profile, tools

## Conventions

### Code style

- **Line width**: 120 characters max
- **Copyright headers**: Apache 2.0. Match the year range from sibling files (e.g., `2021-2025`), not a hardcoded year.
- **Namespace**: `OHOS::EventFwk`
- **Member variables**: trailing underscore (`serviceRunningState_`)
- **Constants**: `UPPER_SNAKE_CASE`
- **Files**: `snake_case.cpp`

### Threading and memory

- Use `ffrt::mutex` with `std::lock_guard` — **never** `std::mutex`
- Task queues use `ffrt::queue` — **note**: `ffrt` is the runtime, bringer of both `mutex` and `queue`. Read up.
- Use `sptr<T>` for IPC / ref-counted OpenHarmony objects (not `std::shared_ptr`)
- Create std shared pointers with `std::make_shared<T>()`
- Allocate with `new (std::nothrow)` to avoid exceptions

### Logging

Log macros from `event_log_wrapper.h`. Use the appropriate tag from `common_event_constant.h`:

| Tag | Use |
|-----|-----|
| `LOG_TAG_CES` | General CES |
| `LOG_TAG_CES_ANI` | Ark Native Interface |
| `LOG_TAG_CES_NAPI` | JavaScript/NAPI |
| `LOG_TAG_CES_CAPI` | C API |
| `LOG_TAG_CES_CJ` | Cangjie |
| `LOG_TAG_ORDERED` | Ordered events |
| `LOG_TAG_UNORDERED` | Unordered events |
| `LOG_TAG_FREEZED` | Frozen events |
| `LOG_TAG_STICKY` | Sticky events |
| `LOG_TAG_STATIC` | Static subscriber |
| `LOG_TAG_SUBSCRIBER` | Subscriber ops |

```cpp
EVENT_LOGE(LOG_TAG_CES, "innerCommonEventManager is null");
```

### Error codes

Use error codes from `ces_inner_error_code.h`. Return `ERR_OK` (0) on success.

## Tests

Tests use the **OpenHarmony gtest extensions** (`gtest/gtest.h` with `testing::ext`).

### Test target macro
```cpp
HWTEST_F(ClassName, TestName, Function | SmallTest | Level1)
```
Test naming: `FunctionName_ScenarioNumber` (e.g., `GetBundleName_00001`).

### Accessing private members
```cpp
#define private public
#define protected public
#include "common_event_subscriber_manager.h"
#undef private
#undef protected
```
Place these defines **before** the `#include` for the class under test, **after** `<gtest/gtest.h>`.

### Test mocks

Mock helpers live in `test/mock/include/` and `test/mock/`. Common mocks: `mock_access_token_helper.cpp`, `mock_bundle_manager.cpp`.

### GN for tests

Tests use `ohos_unittest`. Specify `module_out_path` (e.g., `"common_event_service/common_event_service/services"`). Tests frequently depend on `${services_path}:cesfwk_services_static` (the static library variant), not `cesfwk_services`.

Dependencies go in `deps` (internal) and `external_deps` (external, in `component:target` format, e.g., `"ability_base:want"`, `"googletest:gtest_main"`).

## Architecture

### Key entrypoints
- `services/src/common_event_manager_service.cpp` — service singleton, system ability entrypoint
- `services/src/inner_common_event_manager.cpp` — core publish/subscribe logic
- `interfaces/inner_api/common_event_manager.h` — public C++ API

### Core service classes
- `CommonEventManagerService` — singleton, system ability
- `InnerCommonEventManager` — internal event routing
- `CommonEventSubscriberManager` — subscriber lifecycle
- `CommonEventControlManager` — event flow control (ordered/unordered)
- `CommonEventStickyManager` — sticky event cache
- `PublishManager` — publish dispatch

### Language binding layers
- `interfaces/kits/napi/` — JavaScript (N-API)
- `interfaces/kits/ani/` — Ark Native Interface
- `interfaces/kits/cj/` — Cangjie FFI
- `interfaces/kits/ndk/` — Native Dev Kit (C API)

## Commit Messages

Use `--signoff` and append `Co-Authored-By: Agent`:
```bash
git commit --signoff -m "Short summary

Co-Authored-By: Agent"
```
