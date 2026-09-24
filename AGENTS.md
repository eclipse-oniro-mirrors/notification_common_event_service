# AGENTS.md — OpenHarmony 公共事件服务（CES）

适用范围：本文件是本仓库（公共事件服务，CES）根级 Agent 指导，适用于仓库内所有目录的编码任务。

## 1. 代码地图

本仓库实现 OpenHarmony 公共事件服务（CES, Common Event Service），核心职责是为应用提供公共事件的订阅、发布、退订能力，支持有序/无序分发、粘性事件缓存与静态订阅拉起。最重要的架构边界是**客户端 SDK 通过 IPC 调用服务端（SA 3299，运行在 foundation 进程），客户端不持有业务状态；服务端入口只做轻量校验，业务统一提交到 ffrt 队列 "CesSrvMain" 串行执行**。

### 关键区域

- `interfaces/inner_api/`：对外 C++ API 纯头文件目录（`common_event_manager.h` 门面 + `CommonEventData`/`CommonEventPublishInfo`/`CommonEventSubscribeInfo`/`MatchingSkills`/`CommonEventSubscriber`/`AsyncCommonEventResult` 数据模型），所有 C++ 消费者依赖此层，变更影响面最大
- `frameworks/core/`：客户端 IPC 层（`common_event.cpp` 单例门面持有 ICommonEvent proxy、`common_event_listener.cpp` 接收服务端回调、死亡重连）+ IDL 接口定义（`ICommonEvent.idl`、`IEventReceive.idl`）+ 公共基础设施（日志、错误码、常量）
- `frameworks/native/`：inner_api 实现与数据模型 Parcelable 序列化（`common_event_manager.cpp` 静态门面 + 各数据模型 `Marshalling`/`Unmarshalling`）
- `frameworks/extension/`：静态订阅扩展运行时（`StaticSubscriberExtension` + `IStaticSubscriber.idl`），供应用侧静态订阅 Ability 使用
- `interfaces/kits/napi/`：ArkTS NAPI 绑定（旧 `@ohos.common.event` 与新 `@ohos.commonEventManager` 两套）
- `interfaces/kits/ani/`：Ark Native Interface（ArkTS 静态绑定）
- `interfaces/kits/cj/`：仓颉语言 FFI 绑定（`common_event_manager_ffi`）
- `interfaces/kits/ndk/`：NDK 纯 C 接口（`oh_commonevent.h`，target `ohcommonevent`）
- `services/`：服务端全部业务逻辑（跑在 foundation 进程）：订阅管理、有序/无序分发、粘性事件、静态订阅、权限校验、洪泛检测
- `services/include/` + `services/src/`：服务端 20+ 核心类（见下方架构分层）
- `tools/cem/`：`cem` 命令行工具（发布/转储调试）
- `test/`：`fuzztest/`、`systemtest/`、`benchmarktest/`、`mock/`（顶层无 BUILD.gn，各模块 test 目录独立组织）
- `event.gni`：全部特性开关（`declare_args()`）定义，新增特性先看这里
- `hisysevent.yaml`：COMMONEVENT 域打点事件定义（FAULT + STATISTIC）
- `.opencode/kb/feature/`：仓库级专题知识文档（内存优化设计方案、有序事件多线程竞态修复设计），改容器选型或有序事件并发逻辑前必读

### Where to look

| 任务类型 | 先看哪里 |
|---|---|
| 公共 API 变更 | `interfaces/inner_api/` → `frameworks/native/src/`（实现）→ `interfaces/kits/napi/`（ArkTS 绑定）→ `interfaces/kits/ani|cj|ndk/`（其他三套绑定） |
| 发布/订阅主流程 | `services/src/common_event_manager_service.cpp` + `services/src/inner_common_event_manager.cpp` |
| 有序/无序分发 | `services/src/common_event_control_manager.cpp`（双队列 + 三条 ffrt 队列 + 超时调度） |
| 订阅者生命周期 | `services/src/common_event_subscriber_manager.cpp` + `services/src/subscriber_death_recipient.cpp` |
| 粘性事件 | `services/src/common_event_sticky_manager.cpp`（纯内存，不持久化） |
| 静态订阅 | `services/src/static_subscriber_manager.cpp` + `services/src/static_subscriber_connection.cpp` + `frameworks/extension/` |
| 数据模型序列化 | `frameworks/native/src/common_event_data.cpp` 等（Parcelable 实现） |
| 客户端 SDK 行为 | `frameworks/core/src/common_event.cpp`（proxy 获取、参数校验、服务死亡重连重订阅） |
| IPC 接口变更 | `frameworks/core/ICommonEvent.idl` + `IEventReceive.idl` + `frameworks/extension/IStaticSubscriber.idl` |
| 权限/安全 | `services/src/common_event_permission_manager.cpp`（系统事件订阅权限映射）+ `services/src/access_token_helper.cpp` |
| 洪泛/频控 | `services/src/publish_manager.cpp`（单 uid 5 秒 20 次上限） |
| DFX/打点事件 | 根目录 `hisysevent.yaml` + `services/src/event_report.cpp` |
| 调试工具 | `tools/cem/`（`cem publish`、root 版本 `cem dump`） |
| 特性开关 | `event.gni` |
| 新增/修改测试 | 对应模块的 `services/test/unittest/`、`frameworks/*/test/unittest/`、`test/fuzztest/` |

### 架构分层

```
应用层
  ├─ ArkTS 应用 → interfaces/kits/napi（@ohos.commonEventManager）
  │                ├─ interfaces/kits/ani（ArkTS 静态绑定）
  │                └─ interfaces/kits/cj（仓颉 FFI）
  ├─ C++ 应用/系统组件 → interfaces/inner_api（CommonEventManager 门面）
  └─ 原生 C 应用 → interfaces/kits/ndk（oh_commonevent）
           ↓
客户端 SDK（frameworks，不持有业务状态）
  CommonEventManager（frameworks/native，静态门面）
    → CommonEvent（frameworks/core，单例，proxy 获取 + 参数校验 + 死亡重连）
      → ICommonEvent proxy（frameworks/core/ICommonEvent.idl 生成）
           ↓ IPC（SA 3299, foundation 进程）
服务端
  CommonEventManagerServiceAbility（SystemAbility 装载入口）
    → CommonEventManagerService（CommonEventStub 单例，入口校验后提交 ffrt 队列 CesSrvMain）
      → InnerCommonEventManager（核心业务：权限/系统事件/粘性判定）
        ├─ 发布 → PublishManager（洪泛检测）→ CommonEventControlManager（有序/无序分发）
        │           ├─ 无序：匹配订阅者 → unordered 队列 → 直接 NotifyEvent（oneway）
        │           └─ 有序：ordered 队列 → 逐个订阅者 → 等待 FinishReceiver（10s 超时）
        ├─ 订阅 → CommonEventSubscriberManager（记录管理 + 死亡清理 + 冻结）
        │           └─ 补发匹配的粘性事件（CommonEventStickyManager，纯内存）
        └─ 静态订阅分发 → StaticSubscriberManager → AMS ConnectAbility
                            → IStaticSubscriber::OnReceiveEvent（拉起应用扩展 Ability）

事件回流（服务端 → 客户端）
  IEventReceive proxy → CommonEventListener（frameworks/core，Stub 实现）
    → 经 EventHandler/EventRunner 回调到应用 CommonEventSubscriber::OnReceiveEvent
```

## 2. 知识路由

在规划或编辑前，先对任务分类，读取对应的代码路径和文档。

### Task-based routing

| 任务类型 | 读取 |
|---|---|
| 公共 API 新增/修改 | `interfaces/inner_api/` 头文件 + `frameworks/native/src/` 实现 + 四套绑定（`interfaces/kits/napi|ani|cj|ndk/`）同步检查 + 对应 `*.map` 版本脚本 |
| IPC 接口变更 | `frameworks/core/ICommonEvent.idl`（或 `IEventReceive.idl`）+ 生成的 `icommon_event_proxy.cpp/.h`、`icommon_event_stub.cpp/.h` |
| 发布流程变更 | `services/src/common_event_manager_service.cpp` → `services/src/inner_common_event_manager.cpp` → `services/src/common_event_control_manager.cpp` |
| 订阅/退订流程变更 | `services/src/common_event_subscriber_manager.cpp` + `frameworks/core/src/common_event.cpp`（客户端重连重订阅） |
| 粘性事件变更 | `services/src/common_event_sticky_manager.cpp` + `inner_common_event_manager.cpp` 中 `ProcessStickyEvent`（注意需 `ohos.permission.COMMONEVENT_STICKY` + 系统应用） |
| 静态订阅变更 | `services/src/static_subscriber_manager.cpp` + `services/src/static_subscriber_connection.cpp` + `frameworks/extension/`（注意走 AMS ConnectAbility，与动态订阅完全独立） |
| 权限/安全变更 | `services/src/common_event_permission_manager.cpp`（`COMMON_EVENT_MAP` 订阅权限映射）+ `services/src/access_token_helper.cpp` |
| 新增系统公共事件 | `interfaces/inner_api/common_event_support.h` + `frameworks/native/src/common_event_support.cpp` + README_zh.md 事件-权限表 + `services/src/common_event_permission_manager.cpp`（如需订阅权限） |
| DFX/事件定义变更 | 根目录 `hisysevent.yaml` + `services/include/event_report.h` |
| 错误码变更 | `frameworks/core/include/ces_inner_error_code.h`（注意：错误码定义在 `OHOS::Notification` 命名空间，非 `OHOS::EventFwk`） |
| 特性开关变更 | `event.gni` → 条件编译包裹代码 |
| 有序事件并发/锁变更 | `.opencode/kb/feature/有序事件多线程竞态修复设计.md` + `common_event_control_manager.cpp`（先理解 IPC 线程/orderedQueue_ 串行线程/Dump 线程三方竞态边界） |
| 容器选型/内存优化 | `.opencode/kb/feature/CES内存优化设计方案.md` + 对应 manager 头文件 |
| 新增/修改测试 | 对应模块 test 目录 + 其 `BUILD.gn`（单测 target 在 `services/test/unittest/BUILD.gn` 等） |

### Path-based routing

| 修改路径 | 需了解的上下文 |
|---|---|
| `frameworks/core/` | 客户端 IPC 层 + IDL 源文件 + 公共基础设施，被 native/extension 与四套绑定共同依赖，修改影响面大 |
| `interfaces/inner_api/` | 所有 C++ 消费者的 API 头文件，需同步检查四套语言绑定 |
| `frameworks/core/*.idl` | IDL 变更触发 proxy/stub 重新生成，接口码枚举自动生成，不可手改生成代码 |
| `frameworks/native/src/` | 数据模型 Parcelable 实现，序列化字段顺序即兼容性契约 |
| `services/src/inner_common_event_manager.cpp` | 服务端核心业务（500+ 行），修改前需理解发布/订阅/粘性/静态订阅四条流 |
| `services/src/common_event_control_manager.cpp` | 有序/无序分发与超时调度，修改需理解 ordered record 状态机（RECEIVING/RECEIVED、PENDING/DELIVERED/SKIPPED/TIMEOUT） |
| `services/etc/` | 系统参数（`ces.para`/`ces.para.dac`）；发布管控 JSON 在设备侧 `etc/notification/common_event_config.json`，不在本仓 |
| `interfaces/kits/napi/common_event/` 与 `napi_common_event/` | 新旧两套 NAPI 模块并存（`@ohos.common.event` 与 `@ohos.commonEventManager`），勿混淆 |
| `services/BUILD.gn` | `cesfwk_services`（动态库）与 `cesfwk_services_static`（仅供测试）双目标共享源文件列表 |

### Vocabulary-based routing

当任务、issue、日志、API 名称中出现以下术语时，先理解其含义和风险再动手：

| 术语 | 含义与风险 | 读取 |
|---|---|---|
| CES | Common Event Service，本子系统简称 | 本文件 |
| 有序/无序事件（ordered/unordered） | 有序事件逐订阅者分发并等待 `FinishReceiver`（10 秒超时），无序事件并发直发；发布无序事件携带 subscriber 会被拒绝 | `services/include/ordered_event_record.h` + `services/src/common_event_control_manager.cpp` |
| 粘性事件（sticky） | 发布后缓存、新订阅者订阅时补发；纯内存不持久化，服务重启即丢失；发布需 `COMMONEVENT_STICKY` 权限 | `services/src/common_event_sticky_manager.cpp` |
| 静态订阅（static subscriber） | 应用在 module.json5 声明、事件发生时由 AMS 拉起扩展 Ability，不占动态订阅配额、不受冻结机制约束 | `services/src/static_subscriber_manager.cpp` + `frameworks/extension/` |
| 系统公共事件 | `usual.event.*` 命名空间事件，仅系统应用/子系统可发布，订阅可能需要权限 | `frameworks/native/src/common_event_support.cpp` + `services/src/common_event_permission_manager.cpp` |
| 洪泛检测 | `PublishManager` 对单 uid 5 秒内超 20 次发布判定为攻击 | `services/src/publish_manager.cpp` |
| userId 特殊值 | -1（ALL_USER）/-2（CURRENT_USER）/-3（UNDEFINED_USER）是保留值，存在隐式改写逻辑 | `frameworks/core/include/common_event_constant.h` + `inner_common_event_manager.cpp` |
| cem | 公共事件调试命令行工具 | `tools/cem/` |
| CesSrvMain | 服务端业务 ffrt 队列名，IPC 入口校验后统一提交至此串行执行 | `services/src/common_event_manager_service.cpp` |

### 编辑前必做声明

开始编辑任何代码前，先在回复中声明以下四项，缺一不可：

1. 任务分类（对应上表哪一行）
2. 已读取的代码路径和文档
3. 发现的约束（本文件第 3 节中适用的条目）
4. 是否需要同步修改其他层（如 API 变更需同步四套绑定 napi/ani/cj/ndk）

## 3. 约束边界

### 架构不变量

- 客户端 SDK（`frameworks/`）不持有业务状态，所有业务逻辑在服务端（`services/`）执行
- 服务端 IPC 入口只做轻量校验（权限/参数/洪泛），业务统一提交 `CesSrvMain` ffrt 队列串行执行，不要在 binder 线程做重活
- 权限校验必须在服务端入口完成，不能仅依赖客户端
- 所有跨进程传输的数据模型必须实现 `Parcelable`（`Marshalling`/`Unmarshalling`）
- 静态订阅与动态订阅是两条独立链路：静态订阅走 AMS ConnectAbility，不进入 `CommonEventSubscriberManager`
- DFX（日志、打点、错误码）必须观测业务关键状态变更

### 禁止事项

- 不要修改公共 API 签名、错误码、权限行为或生命周期语义，除非任务明确要求
- 不要为通过测试而删除日志、事件、错误码或诊断信息
- 不要直接修改 IDL 生成的 proxy/stub 代码，应修改 `.idl` 源文件后由 `idl_gen_interface` 重新生成
- 不要修改 `*.map` 版本脚本中已有符号的可见性
- 不要在 `Marshalling`/`Unmarshalling` 中间插入字段或调整既有字段顺序
- 不要给粘性事件引入持久化（当前设计即内存态，由发布者负责重播）
- 不要绕过 `PublishManager` 洪泛检测或 `CommonEventPermissionManager` 权限校验
- 不要引入新的生产依赖而不经过确认

### 需确认后再修改

- 公共 API 签名变更（需确认兼容性影响和版本策略）
- 有序事件超时时长（当前 10000ms）或分发语义变更（需确认所有依赖有序事件的系统服务）
- 订阅上限（客户端进程 200、单事件 255、全局 5000）调整（需确认内存与配额策略）
- 洪泛阈值（5 秒 20 次）调整（需确认对高频合法发布者的影响）
- `event.gni` 中 `ces_hitrace_usage` 相关分支（该处变量名与开关名不一致，疑似历史笔误，改动前务必核对）
- 新增外部依赖（需确认许可证和包大小影响）

### 已知陷阱与常见失败模式

- `sptr` 不是 `std::shared_ptr`：引用计数语义不同，不要混用；IPC 对象用 `sptr`/`wptr` + `new (std::nothrow)`，进程内共享才用 `std::shared_ptr`
- 错误码命名空间错位：错误码定义在 `OHOS::Notification`（`ces_inner_error_code.h`）而非 `OHOS::EventFwk`，引用时需 `using namespace OHOS::Notification` 或全限定
- IDL 生成代码不可手改：`ICommonEvent.idl` 等变更后 proxy/stub 由工具重新生成，手改会被覆盖
- 序列化字段顺序即兼容性契约：`CommonEventData`/`CommonEventPublishInfo`/`CommonEventSubscribeInfo`/`MatchingSkills` 的 Parcelable 实现在 `frameworks/native/src/`，新增字段必须成对追加在末尾
- 四套绑定（napi/ani/cj/ndk）全部收敛到 inner_api 层，改数据模型必须四套同步检查；ANI 层与 NAPI 层存在订阅者互操作（`GetTransferRelation`），不是简单转发
- 粘性事件不持久化：foundation 重启即丢失，由发布者重播；而静态订阅禁用状态经 `StaticSubscriberDataManager` 持久化到分布式 KV，两者不要混淆
- 发布无序事件携带 subscriber 会被直接拒绝（`inner_common_event_manager.cpp` 中显式判定）
- userId 保留值（-1/-2/-3）存在 `SetSystemUserId`/`CheckUserIdParams` 隐式改写，改 userId 相关逻辑必须过这条链
- 服务端单例大量使用 `DelayedSingleton`；`CommonEventManagerService` 自身也是单例（`ffrt::mutex` 保护）
- 服务端线程统一 `ffrt::mutex` + `std::lock_guard`（不要用 `std::mutex`）；延迟任务用 `submit_h` + `ffrt::task_attr().delay()`
- 测试依赖 `${services_path}:cesfwk_services_static`（静态库版本），不是 `cesfwk_services`；新增服务端源文件进 `cesfwk_services_sources` 后两个 target 都会生效，但特性宏有差异，需对照 BUILD.gn
- 单测访问私有成员用 `#define private public`（放在 `#include` 之前、`<gtest/gtest.h>` 之后）；mock 在 `test/mock/` 与 `services/test/unittest/mock/`、`tools/test/mock/` 三处
- `cem publish` 在用户版本被拒绝（仅 root/debug 版本可用）；`cem dump` 需 `CEM_SUPPORT_DUMP` 宏（root 版本编译）

## 4. 验证闭环

### 最小验证

```bash
# 构建整个公共事件服务组件（从 OpenHarmony 根目录执行）
./build.sh --product-name rk3568 --build-target common_event_service

# 构建服务端单元测试（任选一个实际 target）
./build.sh --product-name rk3568 --build-target common_event_manager_service_test

# 构建全部模糊测试（fuzz 组在 test/fuzztest/BUILD.gn）
./build.sh --product-name rk3568 --build-target CommonEventFuzzTest
```

代码风格：行宽 120 字符、Apache 2.0 版权头（年份范围随同级文件）、命名空间 `OHOS::EventFwk`、成员变量尾下划线、`snake_case` 文件名；日志用 `event_log_wrapper.h` 的 `EVENT_LOGX` 宏 + `common_event_constant.h` 的 tag 常量；遵循 OpenHarmony 根目录 `.clang-format`。

### 分任务验证

| 变更类型 | 必须验证 |
|---|---|
| 公共 API 变更 | 最小验证 + 四套绑定（napi/ani/cj/ndk）编译通过 + `*.map` 新符号可见性正确 |
| IPC 接口变更 | IDL 重新生成 proxy/stub 后编译通过 + 序列化新旧行为兼容 |
| 服务端业务逻辑 | 最小验证 + 新增/更新 `services/test/unittest/` 对应用例 |
| 客户端 SDK | 最小验证 + 服务死亡重连/重订阅场景不回归（`frameworks/core/test/unittest/`） |
| 有序/无序分发 | 最小验证 + `common_event_control_manager_test` + 有序超时场景不回归 |
| 数据模型变更 | 最小验证 + 对应 `frameworks/native/test/unittest/` Parcelable 用例 |
| 新增测试 | 对应 `BUILD.gn` target 编译通过（`module_output_path` 遵循 `common_event_service/common_event_service/<层级路径>` 约定） |

### Done 定义

- 构建通过（组件 + 相关单元测试 + 模糊测试）
- 无新增编译警告
- 变更范围与任务要求一致（无顺手修改无关文件）

### 最终回复要求

任务完成回复必须包含：

1. 变更文件清单（新增/修改/删除）
2. 执行过的验证命令及结果（通过/失败/跳过）
3. 未执行的验证项及原因

### 无法验证时

如果构建环境不可用，不要声称已完成验证。在最终回复中列出应执行的命令、预期结果，并明确标注"未验证"。
