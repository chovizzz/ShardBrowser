# ShardX Fleet — 真实 ARM 设备农场（"云手机"）设计文档

在现有桌面反检测浏览器之外，新增一条**移动端**能力线：自建真实 Android 设备农场，
供团队多人共享操作，用于运行原生 App（TikTok / Facebook 等）多账号业务。

> **本文档是设计草案，尚未实现。** 代码尚未落地，编号章节即后续实施与验收的依据。
> 立项前必须先通过 §8 Phase −1 的物理 Spike——若其中任一硬门禁不通过，整条路线的前提不成立。

---

## 实现状态

| 阶段 | 内容 | 状态 |
|---|---|---|
| Phase −1 | 物理 Spike：10–20 台真机，验证 enrollment / 网络层代理 / 目标 App 检测 | ⬜ 未开始（**硬门禁**） |
| Phase 0 | 领域模型定稿、现有 env lock 并发测试补齐、audit 泛化设计、Rack Agent 协议与威胁模型 | ⬜ 未开始 |
| Phase 1 | 控制面 MVP：设备目录 + 锁 + 任务 + 串流 + FleetView | ⬜ 未开始 |
| Phase 2 | 规模化到百台：多 Rack Agent、容灾、OTA、burn-in | ⬜ 未开始 |

**决策依据**：本方案经两轮方案评审（含对现有 `server/` 锁与 ACL 实现的逐条代码核实）后定稿，
关键分歧与结论记录在 §2（领域模型）、§4（锁与 fencing）、§6（网络层代理）。

---

## 0. 范围与非目标

### 做什么

- 自建**真实** Android 设备农场（真机 / ARM 开发板），设备的"真实性"来自它本来就是真机。
- 团队协作，目标规模上百台。独占控制锁、ACL、审计、批量任务**从第一天就有**。
- 复用现有 `server/`（team-server）的用户/角色/JWT/审计基础设施。

### 明确不做

- **不自研防关联 AOSP / Magisk 指纹层。** 那是独立的 AOSP + HAL + 硬件证明工程，
  与本仓库"改 Chromium C++"是两套技能栈、两套发布链路。
- **不接第三方云手机厂商**（该路线已评估并否决：风控能力外包给供应商，无控制权也无差异化）。
- **不扩展 `ProfileMeta` / 不加 `ProfileKind`**。理由见 §2.3。
- **不把 Android 数据塞进 `shared::snapshot`** —— 那是 Chromium user-data-dir 专用
  （`shared/src/snapshot.rs:1`）。
- 不做对外多租户 SaaS、不做计费、不做跨地域调度。

---

## 1. 总体架构

```
┌───────────┐   ┌───────────┐             ← 成员桌面客户端(本仓库 src-tauri + FleetView)
│ Launcher A│   │ Launcher B│
└─────┬─────┘   └─────┬─────┘
      │  HTTPS + 用户 Token │
      └──────────┬─────────┘
                 ▼
      ┌────────────────────────┐
      │   Central Team Server  │   ← 扩展现有 crate `server/`
      │  · 用户/角色/鉴权/审计  │
      │  · 设备目录 + 代际      │
      │  · 锁(env + device)    │
      │  · 任务编排 + ACL       │
      │  存储: SQLite + ./blobs│
      └───────┬────────────────┘
              │ WS 控制通道(每机架一条，非每设备一条)
      ┌───────▼────────────────┐        ┌──────────────────┐
      │  Rack Agent / Gateway  │───────▶│   Media Relay    │
      │  · USB / ADB 设备发现   │  共置   │ · scrcpy 视频中继 │
      │  · 命令执行 + fencing   │        │ · 鉴权/带宽治理   │
      │  · 断网缓冲 + 本地恢复  │        └──────────────────┘
      │  · AP / 网关策略配置    │
      └───────┬────────────────┘
              │ USB (ADB)          ┌─────────────────────┐
      ┌───────▼───────┐            │  Network Gateway    │
      │  真机 × N/机架 │◀─── Wi-Fi ─│ 每设备独立出口/透明代理│
      └───────────────┘            └─────────────────────┘
```

**三层进程边界（关键设计）**：中央 server **不直接**建立上百条 ADB 隧道。
USB 拓扑天然属于具体机架主机；媒体 worker 与 USB host 共置，视频不绕中央控制面。

与现有的**本机自动化 HTTP API**（`src-tauri/src/api.rs`，默认 `127.0.0.1:40325`，
端口可配置——默认值见 `src-tauri/src/settings.rs:61`）无关，两者并存。

---

## 2. 领域模型

### 2.1 核心对象

桌面侧 profile 与 user-data-dir 是 1:1 永久绑定。设备农场不是——设备是物理资源、
账号是逻辑资产、二者多对多且有时间维度。因此定义：

| 对象 | 含义 | 关键字段 |
|---|---|---|
| `Rack` | 一个机架/一台 Rack Agent 主机 | 位置、agent 证书、所辖设备、上线状态 |
| `Device` | 物理资产 | asset_tag、型号、机柜位置、固定硬件标识、rack_id |
| `DeviceIncarnation` | **一次刷机/恢复出厂后的设备代际** | device_id、generation、build_fingerprint、enrollment_cert、退役原因、**fence_epoch（权威计数器，§4.2）** |
| `MobileEnvironment` | 团队拥有的逻辑运行环境 | 名称、平台、代理策略、语言/时区/GPS 策略、恢复策略、风险标签、preferred_device_group_id |
| `Assignment` | 某 environment 当前部署在哪个 incarnation 上 | active_from/active_to、status、fence_epoch 快照（仅审计） |
| `ControlSession` | 某操作者的一段控制区间 | 引用 assignment / device / environment / lock |
| `Task` / `TaskAttempt` | 批量任务及其每设备一次的执行 | 见 §9 任务执行模型 |

> `Rack` 和 `Task` 是**第一版就要建表的核心聚合**，不是附属概念——
> §1 架构图里的 Rack Agent 需要身份、证书轮换、吊销和设备归属，
> `/racks/:id/agent` 端点依赖它。

**`ExternalAccount`（业务账号身份）暂不进入第一版。**
Phase 1 只管理设备与 App 运行环境；账号身份先作为 `MobileEnvironment` 上的
自由文本备注承载。若后续要独立建模，必须先回答：一个环境可绑几个账号 / 账号可否
绑多个环境、迁移历史与 `relogin_required` 状态落在哪个对象上、唯一键与标识规范化、
删除语义、以及**凭据与恢复材料进独立 secret store 而非该表**（§5.3）。
在这些问题有答案前，一个只有"可选关联"的空对象支撑不起 §2.2"账号身份可以迁移"的主张。

### 2.2 两条不可违反的规则

**① 账号身份可以迁移，登录态默认不可迁移。**
第三方 App 的登录态位于该 App 私有数据目录，可能绑定 Android Keystore、设备标识、
Play 服务状态或服务端风险模型；Android 备份机制允许 App 排除数据，Keystore 密钥
尤其不能按普通文件快照迁移。因此 `MobileEnvironment` 从设备 A 移到 B 时
**默认进入 `relogin_required`**，不得假装恢复了原会话。
若某 App 经实测支持官方备份恢复，可为它单独增加 `StateArtifact` + 专用恢复器，
但**不作为平台通用承诺**。

**② 刷机必须创建新代际。**
恢复出厂后即使是同一块硬件，ADB 授权、设备证书、Agent 数据、Device Owner、
Google 账号和 App 数据都会变化。新注册生成新的 `DeviceIncarnation.id` 和更高的
`generation`，旧任务/旧锁/旧控制命令一律失效。
否则刷机前排队的"卸载 App""恢复出厂"可能在重新入池后错误执行。

`pinned_device_id` 不存在任何对象上——当前绑定由唯一的 active `Assignment` 推导。

### 2.3 为什么不复用 `ProfileMeta`

现有 profile 语义高度绑定 Chromium，逐条不可迁移：

- `ProfileMeta` 是 Chromium profile 列表投影 —— `src-tauri/src/profile.rs:9`
- `StoredProfile` 用 `#[serde(flatten)]` 承载 FingerprintConfig —— `profile.rs:30`
- 远程 env id 与锁 token 直接写入 profile `_meta` —— `profile.rs:67`、`:71`
- `launch_profile()`（`launch.rs:41`）固定串起：UDD 解析（`:48`）、远程 env checkout（`:66`）、
  代理解析（`:94`）与 SOCKS5 UDP 探测（`:102`）、fingerprint 写盘（`:126`）、
  Chromium 命令构造（`:141`）、子进程 spawn（`:252`）
- `Tracker` 以 `profile_id` 管理本机 `tokio::process::Child` —— `process.rs:39`
- 前端 `BrowsersView`（`src/App.tsx:1320`）消费 `ProfileMeta`（`:1321`），
  代理视图另行加载 profiles 做统计（`:2706`）

给它加 `kind` 会在 `list_all()` / `save_raw()` 的 noise-seed 填充 / `clone_profile()` 的
随机化等多处制造条件分支，漏一处就是静默污染。**新建 `FleetView` 的迁移成本远低于此。**

---

## 3. 数据面：控制通道与设备内 Agent

### 3.1 默认不安装设备内 Agent

常驻 Agent 本身就是可检测特征：前台服务必有常驻通知；Accessibility Service 可被系统 API
枚举；Play Integrity 的 app access risk 专门覆盖"可捕获屏幕、显示 overlay 或控制设备的
其他 App"；mock location 有标准 `Location.isMock()` 标记。

**因此控制通道默认走机架侧 USB/ADB：**

| 能力 | 实现 |
|---|---|
| APK 安装/卸载/清数据/启动/停止/重启 | `adb` 命令 |
| 基础输入 | `adb shell input`（**不启用 Accessibility**） |
| 截图 / 日志 | `adb exec-out screencap` / `logcat` |
| 屏幕串流 | scrcpy server 经 ADB **临时推送**并以 `app_process` 运行，会话结束即停止，**不安装常驻 APK** |

只有确实需要"断开 USB 后仍运行"的后台遥测时，才安装最小 Agent；
且**绝不授予 Accessibility、VPN 或 overlay 权限**。

### 3.2 仍然残留的可检测面（必须黑盒验证）

- 开发者模式 / USB debugging 开启本身可能是风险信号。
- scrcpy 的屏幕捕获或控制行为可能进入目标 App / Play Integrity 的风险判断。
- Device Owner / DPC 提供设置时区等能力，但"受管理设备"本身也可能可见。

> **验收必须用目标 App 做黑盒验证，而不是只检查系统 UI。** 见 §8 Phase −1 门禁。

---

## 4. 锁、fencing 与并发安全

### 4.1 现有 env 锁的既有语义（已代码核实，不改行为）

`checkout` 的抢占是**单条条件 upsert**，原子性无问题：只有空闲、持有正确旧 token 的
同一 session、或租约已过期，才能更新（`server/src/routes/locks.rs:171-190`），
`lock_token` 在 SQL 内比较，无先读后写窗口。`checkin` 通过事务内条件 DELETE
裁决所有权（`locks.rs:357`）。

但 `lease`（`locks.rs:273`）、`checkin`（`:358`）、`release`（`:443`）以及前置检查
`session_holds_lock`（`:71`）**均不比较 `lease_expires_at`**。

实际语义因此是**软租约：过期只代表"可被抢占"，未被抢占则仍属于原持有者**。
一旦他人 checkout 成功，token 轮换（`locks.rs:174-176`），此后**在新锁行存在期间，
旧 token 发起的 lease / checkin / release / download 都无法再通过所有权检查**。

> ⚠️ **注意：这是实现与已声明意图的分歧，不是"未言明的设计"。**
> 模块注释明确写着 stale session（含 expired lease）"can no longer touch the
> environment"（`locks.rs:7-8`），错误文案 `"expired, taken over, or bad token"`
> （`locks.rs:285`）表达同样意图——但代码没有实现它。

**本设计的决定：把现状正式固化为软租约，并修正注释与文案，而不是改行为。**
理由是桌面端加过期校验会让"租约过期但无人抢占"的用户丢失本地未推送的
user-data-dir；软租约对该场景是更安全的取舍。Phase 0 落实：改注释、改文案、补测试。

两点精确化，避免后人据此文档做出错误推论：

- **不是"所有后续操作立即失败"。** 已通过 `session_holds_lock` 前置检查的
  snapshot download 会继续流式传输完毕（检查在 `locks.rs:524`，之后才构造响应体
  `locks.rs:564`）——token 轮换不会中断已建立的响应。
- **旧 session 也不是永久失效。** 若新持有者 release 或管理员 force-unlock 清掉锁行，
  旧客户端可以作为**新的请求者**重新 checkout 并拿到新 token。

### 4.2 设备锁必须是硬租约 + fencing

物理设备控制**不能**沿用软租约。事故场景：

```
A 持有设备锁 → A 提交"恢复出厂"任务 → A 租约过期 → B 抢占设备锁
→ A 的任务晚到 Rack Agent → 设备被错误恢复出厂
```

注意**软租约挡不住这个**——它是命令投递的时序问题。解法是 fencing：

**epoch 的存放位置（关键，不能照搬 env 锁）**：现有 env 锁在 checkin / release /
force-unlock 时**删除锁行**（`locks.rs:357`、`:443`、`:467`）。若 `device_locks` 沿用这一点，
epoch 会随行消失、下次 checkout 从头开始，随后被 Rack Agent 永久拒绝（它只认更高的 epoch）。

因此 **`fence_epoch` 必须存在 `device_incarnations` 的永久单调计数列上**，
checkout 在**同一事务内**递增该列并创建锁行。锁行可以照常删除，epoch 不受影响。
（备选方案"锁行永不删除、release 只清 holder/token"也可行，但会让锁表语义与 env 侧差更远，不采用。）

规则：

- 每次 device checkout 在事务内 **原子递增** `device_incarnations.fence_epoch`。
- 所有设备命令携带：`device_incarnation_id / assignment_id / lock_token / fence_epoch / expires_at / idempotency_key`。
- **release 与 force-unlock 必须立即令旧 epoch 失效**（同样递增计数器），
  否则旧 holder 在其原 `expires_at` 之前发出的同 epoch 命令仍会被 Agent 接受。
- 设备重入池后 `DeviceIncarnation` 改变，即使 epoch 碰巧相同也不得执行。
- device 的 `lease` / 控制操作必须额外要求 `lease_expires_at > now`（硬租约）。

**Rack Agent 侧必须独立校验，不能只靠 server**（事故本身就是"已下发命令晚到 Agent"，
server 端检查挡不住队列里的旧命令）：

- 持久化每台设备"已接受的最高 fence_epoch"，拒绝更旧代次。
- 校验 `device_incarnation_id` 匹配、命令自带的 `expires_at` 未过期。
- 基于持久化的 `idempotency_key` 去重，防同 epoch 命令重复投递。
- **断网时 fail-closed**（不执行，不缓冲后补执行）。
- 明确时钟策略：命令有效期用单调时钟判定，并定义可容忍的时钟偏差上限。

### 4.3 锁表：分表，不做字符串多态

**决定：新建独立的 `device_locks` 表，保留 `locks` 不动。**

否决了"把 `locks` 泛化成 `object_locks(object_kind, object_id)`"，理由：

1. 多态 `kind + id` 无法引用多张业务表，会失去外键完整性、对象删除时的锁级联清理、
   类型与 ID 匹配保证。要补回来就得引入 `resources(id, kind)` 注册表，复杂度更高。
2. **设备锁是硬租约 + fencing，env 锁是软租约**，语义本就不同。
   强行共用一个 handler 会诱导后人写出错误的通用逻辑。

> **这个否决只针对锁存储。** 未来的 generic ACL、audit、task target 仍可能受益于
> 一个强类型的资源标识层——不要把本条扩大解读成"全系统拒绝 resource catalog"。

代价是锁逻辑有两份实现。**缓解方式不是抽取 SQL**：设备锁需要永久 epoch、硬过期、
force-unlock fencing，其 SQL 状态机与 env 锁已本质不同，强行抽公共 SQL 反而会
制造错误耦合。正确做法是共享**周边**并用测试防漂移：

- 共享：token 生成、错误映射、审计辅助函数。
- **一套 contract test matrix**，对两种锁分别断言各自的语义（软 / 硬租约），
  用例表共用、期望值分开——语义分歧因此是被测试显式记录的，而不是隐式漂移的。

另注：`checkout` 在锁到手后读 `environments.current_version` + `snapshot_url()`
（`locks.rs:211-215`）、`load_accessible()`（`server/src/routes/envs.rs:119`）直接
`SELECT * FROM environments`（`:125`）——这些都是 env 专属，设备侧需要独立实现。

### 4.4 双重排他

设备锁和环境锁**都要持有**，否则同一账号可能被同时部署到两台设备。

现有 `locks` 表的 `env_id` 外键指向桌面 `environments`（`0001_init.sql:58`），**不可复用**。
因此需要**两张锁表**：`device_locks` 和 `mobile_environment_locks`，均为硬租约。

规则（Phase 0 定稿，Phase 1 实现）：

- 两把锁在**同一个 SQLite 事务内**取得，避免半持有状态。
- 固定获取顺序（先 device 后 environment），避免死锁；任一失败整体回滚。
- release / 超时 / force-unlock / server 重启后的处理必须对称——**任一把锁的释放
  都要触发另一把的清理**，否则会留下孤儿锁。

**但排他性不能只靠锁。** §2.1 说"当前绑定由唯一的 active Assignment 推导"，
这个"唯一"必须由**数据库约束**保证，否则导入、管理员操作、任务重试或 reconciliation
都能绕过锁制造双部署。至少需要两个 partial unique index：

```sql
-- 同一 incarnation 最多一个 active assignment
CREATE UNIQUE INDEX ux_assignment_active_device
  ON assignments(device_incarnation_id) WHERE active_to IS NULL;
-- 同一 MobileEnvironment 最多一个 active assignment
CREATE UNIQUE INDEX ux_assignment_active_env
  ON assignments(mobile_environment_id) WHERE active_to IS NULL;
```

> `fence_epoch` 的**唯一来源是 `device_incarnations`**（§4.2）。§2.1 的 Assignment
> 表里记录的是它创建时的 epoch 快照，仅供审计追溯，**不得**作为第二份可漂移的权威值。

### 4.5 必须补齐的并发测试

> ✅ **已完成**（Phase 0）。原状：`e2e_sync.rs` 的锁测试全是顺序请求，`tokio::spawn` /
> `join!` / `Barrier` 零命中。现已由 `server/tests/e2e_locks_concurrent.rs` 覆盖下列
> 前四项 + 一条软租约确定性回归，共 5 个测试。
>
> 实施中发现的一点，后续写并发测试需注意：**纯 Barrier 同时放行不足以制造有意义的竞争**——
> checkin 要传 256 KiB 且走事务（约 11ms），对手是单条 SQL，导致"checkin 先赢"分支
> 60 轮中 0 次出现、断言沦为死代码。需按轮次错开对手发起时刻才能扫过在途窗口。
> 这类测试证明的是"**实际采样到的排序都维持了状态机不变量**"，不是"每次 CI 都覆盖了所有排序"。

原计划新增项：

- 两个 checkout 同时争抢空锁 → 恰好一个成功。
- 过期 holder 的 lease 与新 holder 的 checkout 并发。
- 旧 holder 的 checkin 与抢占并发。
- force-unlock 与 checkin 并发。
- 同一 UUID 分别作为 env / device ID，不发生 kind 冲突。
- 对象删除后锁与 ACL 无残留。
- 从"只执行到 migration 0003"的真实旧库升级测试。
- fencing epoch 单调递增，旧代次任务被拒。

---

## 5. 权限与审计

### 5.1 ACL 现状与缺口（已核实）

- `grant()` 的表名拼接目前安全，因为只在两个**静态字面值**间选择（`server/src/routes/acl.rs:35`）。
  扩展时必须写成**穷举 `match` 映射**，绝不可 `format!("{kind}s")` 或插入请求值。
- **`revoke()` 没有调用 `valid_kind()`**（`acl.rs:75` 直接 bind 请求值）——现有疏漏，顺手修。
- **ACL 只认 env / folder 两种 kind**（`acl.rs:11` 的 `valid_kind()`、
  `0001_init.sql:50` 的列注释），且 folder 继承只覆盖 environments——
  `can_access()` 签名即 `&Environment`，SQL 里 `object_kind` 硬编码
  `'env'`（`envs.rs:35`）/ `'folder'`（`envs.rs:55`）。
- 现有 `use|edit` 两级**不足以**表达设备权限。设备至少需要 `view / control / maintain / admin`
  ——批量任务和刷机不能等同于普通 use。

**方向**：不要继续堆字符串分支，做统一的 `authorize(subject, action, resource)` 层。

### 5.2 审计必须从 best-effort 升级

现状 `audit::log` 用 `let _ = ...` 吞掉数据库错误（`server/src/audit.rs:16`，
模块文档第 3 行自陈 "failures are swallowed"），且 `audit_log` 只有 `env_id` 列
（`server/migrations/0001_init.sql:80`）。这与"审计从第一天就必须有"冲突。

要求：

- 刷机、锁抢占、ACL 变更、密钥操作的审计**与操作同事务提交**，或走可靠 outbox；
  审计失败时高风险操作应失败。
- `audit_log` 泛化为 `subject_kind/subject_id`、`actor_kind/actor_id`、`request_id`、
  `task_id`、`outcome`、`detail_json`、`source_ip`。
- **detail 中不得写入**代理密码、Google 凭据或设备密钥。

### 5.3 密钥管理

现状代理密码是 SQLite 明文列（`server/src/routes/proxies.rs:51`、`0001_init.sql:26`）。
设备证书、代理凭据、账号恢复材料**不得沿用同一模式**。

---

## 6. 网络层代理注入

### 6.1 为什么走网络层

真机农场相对第三方云手机的**最大优势**：可以在网络出口做 per-device 策略路由，
设备上完全不装 VPN App。Android 因此不会把网络标记为 `TRANSPORT_VPN`，设备上也没有 `tun0`。

### 6.2 但"每台一条 SNAT"是过度简化

**SNAT 只适用于你自己控制的公网出口。** 若 `proxy_id` 指向 SOCKS5/HTTP 上游，需要
TPROXY、tun2socks、或每设备 network namespace 中的透明代理，并逐项确认 TCP/UDP/IPv6/DNS 支持。

**必须逐项封堵的泄漏面：**

| 泄漏面 | 说明 |
|---|---|
| IPv6 | 未进入代理路径则直接从 ISP 出口泄漏 |
| QUIC / HTTP3 / STUN | 上游代理可能不支持 UDP |
| Private DNS (DoT) / App 自带 DoH | 绕过普通 UDP/53 重定向 |
| captive portal 检测 / NTP / Play 服务 | 可能走了不同策略路径 |
| 地理一致性 | 出口 IP 的地理位置须与时区、语言、SIM MCC/MNC、GPS 一致 |
| ASN 矛盾 | 手机侧显示普通 Wi-Fi + 本地 ISP DNS，公网 IP 却是移动/住宅 ASN |

> App 可读取当前网络的 DNS、路由和 LinkProperties——**不需要检测 VPN 就能发现异常**。

### 6.3 代理切换不是"改条规则就行"

不需要重启整台设备，但旧 TCP/QUIC 连接和 conntrack 映射不会自动迁移。
切换流程必须是：**force-stop 目标 App → 清理该设备的 conntrack zone → 切换策略
→ 验证出口 → 再启动 App**。

### 6.4 百台的实际拓扑

不要真的"一台设备一个 VLAN"——手机不会自行打 VLAN tag。可选：

- WPA2-Enterprise / RADIUS 动态 VLAN
- 每组设备一个 SSID/VLAN，再按保留 DHCP IP 做 policy routing
- 独立 AP / BSSID 映射
- 有线 ARM 板则直接按交换机端口 / VLAN

Android 的 Wi-Fi MAC 随机化会影响单纯按 MAC 绑定，需管理"每网络持久随机 MAC"
及恢复出厂后的重新登记。

**真实瓶颈**通常不是 nftables 规则数，而是：AP 空口容量与 2.4/5 GHz 干扰、
上游代理的 UDP 能力、conntrack 与透明代理进程、媒体总带宽、网关单点故障、
规则切换期间的连接排空。

---

## 7. 存储与容量

### 7.1 SQLite 可以撑到百台，但当前配置不能直接用

现状（已核实）：

- `max_connections(8)`、`busy_timeout(5s)` —— `server/src/db.rs:22`、`:20`
- **初始化代码从不启用也从不校验 WAL** —— sqlx 0.8 不再默认下发 `journal_mode`
  （`sqlx-sqlite-0.8.6/src/options/mod.rs:177-181` 明确 "Don't set journal_mode unless
  the user requested it"），`db.rs:15` 的 `from_str` 也未设置 →
  **新建的库默认使用 rollback journal**。
  （**WAL 是唯一会粘在数据库文件上的模式**，rollback 各模式只是每连接的默认值——
  所以既有部署仍可能被外部工具设成过 WAL，"线上现在是什么模式"必须实测确认，
  不能仅由代码推断。）这是与云手机无关的**现有隐患**。
  已实现：启动时读 `PRAGMA main.journal_mode` + `sqlite_version()` 并告警，不自动切换。
- `AppState` 无在线设备 registry / WS session registry —— `server/src/state.rs:9`
- `axum` 未启用 `ws` feature —— `server/Cargo.toml:12` 仅 `["multipart"]`

> ⚠️ WAL 是**会持久化到数据库文件、跨连接与重启保留**的模式（直到被显式切回），
> 切换需要排他锁且无法用 `sqlite3_busy_timeout()` 等待——必须规划停机窗口 + 备份，不能热切。
> 具体步骤见 `server/README.md` 的 "Database journal mode (WAL)"。

### 7.2 心跳绝不能全部同步写库

100 台 × 每 10 秒 = 稳定 10 writes/s；若每次还写 audit + device 状态 + task ack，
写事务会进一步放大，批量任务回报还会形成突发。

要求：

- WS 在线状态存**内存 registry**，只有状态**变化**才立即落库。
- `last_seen` 每 30–60 秒批量刷新一次。
- telemetry 单独表并限频，**不写 audit**。
- **WS handler 绝不长期持有 SQLx connection。**
- task ack 用批量事务。
- 启用 WAL + `synchronous=NORMAL` + 合理 checkpoint，具体值实测后定。
- 保留 SQLite，但预留 repository abstraction；不要为了规模数字过早换 Postgres。

---

## 8. 分阶段与验收

### Phase −1：物理 Spike（4–6 周，不含采购等待）— **硬门禁**

**10–20 台真机**（5 台无法暴露 AP、USB hub、供电和 conntrack 的实际竞争）。
**控制面一行不写。**

必须验证：

1. 恢复出厂后的**无人值守重新 enrollment**；ADB key、Device Owner、Wi-Fi、证书重配。
2. **目标 App 对 ADB debugging / scrcpy / managed device 的黑盒检测**。
3. IPv4/IPv6、TCP/UDP/QUIC、Private DNS、DoH 全部走代理不泄漏。
4. 代理切换后的旧连接清理确实生效。
5. 20 路 USB、供电、散热、AP 并发。
6. Google Play Integrity 与 Play 商店可用性。
7. 手机恢复出厂保护（FRP）流程可控。

> **门禁**：第 2 项失败 ⇒ 整条路线前提不成立，必须回到路线选择。
> 第 3 项失败 ⇒ 退回设备侧 VPN，防关联优势打折，需重新评估收益。
> **只验证"出口 IP 正确"远远不够。**

**"控制面一行不写"的准确含义**：不写将来要长期维护的 server / launcher 代码。
Spike **允许且应当**写一次性的 Rack harness、脚本和抓包工具——否则无法完成验证。

> 📋 **可执行版本见 `docs/fleet-phase-minus-1-runbook.md`** —— 变量表、对照组矩阵、
> 量化门槛、pass/fail 判据、证据清单、签字页，可直接照着执行。以下是要点摘要。

**开工前必须先固定一张验证矩阵**（否则本节不可执行）：

- **固定变量**：设备型号、Android 版本、目标 App 版本、账号样本、AP / USB hub / 电源型号、代理供应商。
- **量化门槛**：每场景重复次数、成功率、最大 enrollment 时长、USB 断连率、温度与功耗阈值。
- **对照组**：有/无 ADB debugging、有/无 scrcpy、有/无 DPC 的分组对比——
  **"未观察到检测"不等于"未被检测"**，必须有对照才能得出结论。
- **证据产物**：IPv4/IPv6/TCP/UDP/QUIC/DoT/DoH 各自的抓包位置与留存文件。
- **明确的 pass/fail 判据**：factory-reset、reboot、断网恢复三个场景各自的通过条件。

### Phase 0：模型与地基（1–2 周，可与 Phase −1 并行）

1. 领域模型定稿（§2）：Rack / Device / DeviceIncarnation / MobileEnvironment /
   Assignment / ControlSession / Task / TaskAttempt。
   （`ExternalAccount` 是否独立建模一并在此决定——见 §2.1 的前置问题。）
2. ✅ **已完成** — 补齐 env lock 并发测试（§4.5），固化软租约语义 + 修正错误文案。
3. 设计 generic audit（§5.2）。
4. 完成 Rack Agent 协议与威胁模型（§3、§9）。
5. ✅ **已完成** — 修 `revoke()` 缺 `valid_kind()`（§5.1）。

**不动 `locks` 表。** 在设备领域模型定稿前提前迁表，只会先固化错误抽象。

> 注：不做 `Tracker` 更名。它本就是浏览器子进程 tracker，改名无收益；
> 若将来要改，`BrowserProcessTracker` 比 `DesktopProcessTracker` 更准确。

### Phase 1：控制面 MVP（8–12 周，3–4 名熟悉 Rust/Kotlin/网络的工程师）

server 侧新增：

```
racks / devices / device_incarnations / mobile_environments
assignments / control_sessions / tasks / task_attempts
device_locks / mobile_environment_locks 表

所有 Fleet 端点带 /fleet 命名空间，避免与桌面侧 environments 概念在
OpenAPI / SDK / 日志中混淆：

POST /fleet/racks/register            Rack Agent 注册（rack-agent 凭据，非用户 JWT）
WS   /fleet/racks/:id/agent           Rack Agent 长连接（心跳 + 命令下发）
POST /fleet/devices/:id/enroll        incarnation 入池（enrollment cert）
GET  /fleet/devices                   列表 + 状态 + 锁持有者（走 ACL 过滤）
POST /fleet/devices/:id/checkout      硬租约 + fence_epoch 递增
POST /fleet/mobile-environments       MobileEnvironment CRUD
POST /fleet/assignments               把 environment 部署到 incarnation
POST /fleet/tasks                     批量任务下发
GET  /fleet/tasks/:id                 含每设备 task_attempt 状态
```

> **认证主体必须分清**：默认模式下没有设备内 Agent（§3.1），HTTP/WS 的主体是
> **Rack Agent**，用 rack-agent 凭据；**设备**侧的身份是 incarnation 的
> enrollment certificate，在入池时签发。恢复出厂后由谁重新签发、证书如何轮换与吊销，
> 属于 Phase 0 必须定稿的内容（§9）。

launcher 侧：新增 `src-tauri/src/fleet/`（gateway HTTP/WS client）、
`fleet_*` Tauri commands、`src/App.tsx` 新增 `FleetView`。
串流用**独立 Tauri window**（不 iframe）。

**任务重试、幂等、离线 reconciliation、基本监控不得后置**——Phase 1 已要做批量任务与 20 台验收。

**验收**：20 台规模下 3 人并发操作锁不冲突、审计完整、批量装 APK 成功率 >95%、
server/Rack Agent/launcher 任一重启后能按设备**实际状态** reconciliation（不能只信数据库）。

### Phase 2：规模化到百台（8–12 周）

多 Rack Agent、网关与 AP 容灾、Rack Agent OTA、任务限流、媒体容量治理、
设备退役/换机、备件与 USB hub/电源故障处置、24–72 小时 burn-in、操作手册与告警闭环。

---

## 9. 仍需补齐的设计点

### 必须在 **Phase 0** 定稿（直接决定第一版 migration 与 API，不能等 Phase 1 开工）

- **设备身份三分离**：asset tag / 硬件身份 / enrollment cert + incarnation generation。
- **任务执行模型**：一个批量 task 拆成每设备 `task_attempt`，支持幂等、超时、取消、
  部分成功、重试。
- **时区 / 语言 / GPS**：桌面 `launch.rs` 的 auto tz/locale/geo 解析是 Chromium 启动参数
  逻辑，**不能移植**。Android 侧 GPS 软件注入会被 `Location.isMock()` 标记；
  语言和全局设置通常需要 shell、Device Owner 或重启/force-stop。
- **SIM / eSIM**：SIM、号码、MCC/MNC、IMEI、运营商必须与代理地理位置一起进入
  环境一致性模型。
- **命令认证 / 重放 / 时钟偏差 / 离线策略**（§4.2 Rack Agent 侧规则的具体参数）。
- **active Assignment 的唯一约束**与 `ExternalAccount` 是否进入模型（§2.1、§4.4）。
- **Rack Agent 身份**：凭据签发、证书轮换与吊销、设备归属变更。

> **Google 生态**（Google 账号设备数上限、FRP、Play Protect、认证状态、
> Play Integrity、bootloader 状态）由 **Phase −1 产出实测结论**，再回填 Phase 0 的模型设计。
- **App 制品管理**：APK 来源、SHA256、签名证书、版本、回滚、灰度安装。
- **删除语义**：删除 device / environment / account 前如何处理 active session、
  lock、pending task 与 audit 留存。

### 可以后置

Profile 与 Fleet 的统一搜索/首页；对外 SDK；MCP 的设备 UI 自动化工具；
自动健康评分算法；计费；跨地域多机房调度；
**通用 App 登录态迁移框架**（在没有单 App 实测前不要承诺，见 §2.2）。

---

## 10. 风险登记

| # | 风险 | 影响 | 缓解 |
|---|---|---|---|
| R1 | 目标 App 能识别 ADB debugging + scrcpy | **路线前提不成立** | Phase −1 门禁；必要时改为最小 Agent 或纯视觉方案 |
| R2 | 网络层代理无法覆盖 IPv6/QUIC/DoH | 防关联优势打折 | Phase −1 逐项验证；退路是设备侧 VPN（有 `tun0` 特征） |
| R3 | 设备运维成本 | 上百台真机的刷机/换机/损耗需专人 | Phase 2 的 burn-in 与操作手册；备件预算 |
| R4 | 登录态不可迁移 | 换设备即需重新登录，影响业务连续性 | §2.2 明确为产品约束，不做虚假承诺 |
| R5 | 媒体带宽 | 百路并发串流的硬成本 | 编码在设备侧分摊；Media Relay 与 USB host 共置 |
| R6 | fencing 遗漏导致误刷机 | 数据不可恢复 | §4.2；Rack Agent 侧持久化最高 epoch |
| R7 | 现有 server 无 WAL | 写入争用影响 API 响应 | 独立于本项目修复，需停机窗口 + 备份 |

---

## 附：对现有代码的既有问题清单（与本项目独立）

以下为设计评审中经代码核实的现有问题，**不依赖 Fleet 立项即可单独处理**：

| 问题 | 位置 | 状态 |
|---|---|---|
| 初始化不启用/不校验 WAL | `server/src/db.rs` | ✅ **已处理** — 启动时读 `PRAGMA main.journal_mode` + `sqlite_version()` 并告警，**不自动切换**；停机迁移步骤见 `server/README.md`。<br>✅ 前置依赖也已解决：原先 bundled 的是 SQLite 3.46.0，落在 WAL-reset 损坏 bug 影响区间（3.7.0–3.51.2）；现已升到 **3.51.3**（修复版本），启动告警会明确告知是否满足该前置条件 |
| `revoke()` 缺 `valid_kind()` | `server/src/routes/acl.rs` | ✅ **已修** — 补校验（在 `require_admin()` 之后），`openapi.yaml` 同步 400，回归测试见 `server/tests/e2e_acl.rs` |
| 锁测试无并发用例 | `server/tests/` | ✅ **已补** — `server/tests/e2e_locks_concurrent.rs`，5 个测试 |
| 租约过期后仍可 lease/checkin/release，与模块注释声明的意图不符 | `locks.rs:273/358/443` | ✅ **已固化为软租约**（改注释 + 4 处错误文案 + 补测试），**行为未改**——改行为有数据丢失风险。契约已同步到 `openapi.yaml`、`server/README.md`、`docs/team-server.md` |
| audit 吞错误 | `server/src/audit.rs:16` | ⬜ 现有取舍；Fleet 立项时必改 |
| proxy 密码明文 | `server/src/routes/proxies.rs:51` | ⬜ 现有取舍；Fleet 立项时必改 |
| ACL 只覆盖 env/folder | `server/src/routes/acl.rs:11`、`0001_init.sql:50` | ⬜ 现有取舍；Fleet 立项时必改 |
