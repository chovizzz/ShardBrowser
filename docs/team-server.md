# ShardX Team Server — 设计文档

让多名成员共享同一批反检测环境(profile)的自建团队服务。在现有的单机
launcher 之外新增一个**自建中心服务器**:集中存放环境配置 + 代理 + 环境数据
(整目录快照),提供用户/角色管理,并用**独占借出锁**保证同一环境同一时刻只有
一个人运行。

> 适用规模:中等(10~50 人,上千环境)。单机部署,SQLite + 本地 blob 目录起步,
> 存储层做抽象以便日后换 Postgres / S3。

---

## 实现状态(全部完成)

| 阶段 | 内容 | 状态 |
|---|---|---|
| Phase 1 | `server/` 骨架:用户/角色/登录、env/folder/proxy CRUD、ACL | ✅ 验收+回归 |
| Phase 2 | 独占借出锁(checkout/lease/checkin/release/force-unlock)+ 快照 blob + 保留 GC | ✅ 验收+回归 |
| Phase 3 | `shared/`(`shardx-core`):os_crypt v10 加解密 + 跨机重加密 + 快照打包(排缓存) | ✅ 9/9 单测 |
| Phase 4 | 启动器接入:`sync.rs`(pull/push/lease)、launch/退出钩子、`remote_*` 命令、`App.tsx` Team 视图 | ✅ build + e2e |
| Phase 5 | TeamView 占用状态展示 + 管理员 Force-unlock、文档收尾 | ✅ build 门禁 |

**端到端自动化测试**:`server/tests/e2e_sync.rs` 拉起真实 server,用与 `sync.rs` 一致的
reqwest multipart + `shardx_core` 跑通 checkout→checkin→download→unpack,断言 cookie 跨 udd 存活、缓存排除。

**仍需人工验收(超出无头环境能力)**:带真实 ShardX 引擎的 GUI 实启动 pull/push、
多成员并发占用演练、Windows 机器上 DPAPI 加密路径实测(代码已 `cfg(windows)` 镜像 src-tauri/cookies.rs)。

代码位置:`server/`(团队服务器)、`shared/`(跨机加密+快照)、`src-tauri/src/sync.rs`(启动器同步客户端)、
`src-tauri/src/{launch,process,profile,settings,lib}.rs`(钩子+命令)、`src/App.tsx`(`TeamView`)。

---

## 1. 总体架构

```
┌───────────┐   ┌───────────┐   ┌───────────┐
│ Launcher A│   │ Launcher B│   │ Launcher C│   ← 成员桌面客户端(本仓库)
└─────┬─────┘   └─────┬─────┘   └─────┬─────┘
      │   HTTPS + 用户 Token           │
      └──────────┬────┴────────────────┘
                 ▼
      ┌────────────────────────┐
      │   ShardX Team Server   │   ← 新增 crate `server/`,自建单容器
      │  · 用户 / 角色 / 鉴权   │
      │  · 环境配置 + 代理      │
      │  · 环境数据(整目录快照)│
      │  · 独占借出锁(lease)  │
      │  存储: SQLite + ./blobs│
      └────────────────────────┘
```

- 团队服务器与现有**本机自动化 HTTP API(`api.rs`,127.0.0.1:40325)**是两回事:
  后者是单机自动化用的本地接口,前者是新增的跨成员中心服务。两者并存。
- 客户端保留**单机模式**;"远程工作区"是叠加的可选模式,登录后环境列表来自服务器。

---

## 2. 共享什么:整目录快照(排除缓存)

每个环境的数据 = Chromium `user-data/<id>/` 目录。整目录同步,但:

**包含(状态,需同步)**
- `Default/Local Storage/`、`Default/Session Storage/`、`Default/IndexedDB/`、
  `Default/databases/`
- `Default/Preferences`、`Default/Secure Preferences`、`Default/Web Data*`
- `Default/Network/`(Network Persistent State、Trust Tokens 等)
- 扩展相关目录

**排除(纯缓存/临时,不同步)**
- `Default/Cache/`、`Default/Code Cache/`、`GPUCache/`、
  `Default/Service Worker/CacheStorage/`、`Crashpad/`、`*-journal`、锁文件

排除缓存后单环境快照通常几 MB。打包用 `tar` + `zstd`(仓库已有 `flate2`/`tar`/`zip`)。
服务器每个环境保留最近 **N=5** 个版本用于回滚/恢复,旧版本 GC。

### 2.1 加密表的跨机可移植性(关键)

`Default/Cookies`、`Default/Login Data` 是加密的,且密钥跨机器不通用:

| 平台 | 加密 | 密钥来源 | 跨机可移植 |
|---|---|---|---|
| macOS | AES-128-CBC | mock-keychain 固定口令(PBKDF2) | mac/linux 间可移植 |
| Linux | AES-128-CBC | `peanuts` 固定口令 | mac/linux 间可移植 |
| Windows | AES-256-GCM | **DPAPI**(绑用户+机器)解出的 key | ❌ 任意机器间都不通用 |

**统一方案:快照里不存加密后的 Cookies/Login Data 文件,只存可移植的明文值。**

- **checkin**:用 `cookies::export`(已实现,内部解密为明文 `Cookie` 结构)→ 写
  `snapshot/cookies.json`;`Login Data`(保存的密码)同理(需给 `cookies.rs` 补
  Login Data 表的解密)→ `snapshot/logins.json`。其余非加密目录原样打包。
- **checkout**:解压目录后,用 `cookies::import`(已实现)按**本机密钥**重新加密
  写回本地 `Cookies` DB;`logins.json` 同理写回 `Login Data`。

这样 mac→win / win→mac / win-A→win-B 全走同一路径,无需判断源/目标 OS。

> 实现注意:`cookies::import` 需确认能在不存在 Cookies DB 时新建;`cookies.rs`
> 当前只处理 `cookies` 表,需扩展同样的 per-OS 加解密到 `Login Data` 的 `logins` 表
> (`password_value` blob 与 cookie 的 `encrypted_value` 用同一 os_crypt 方案)。

---

## 3. 并发:独占借出锁(checkout / checkin)

同一环境同一时刻只允许一人运行,否则并发登录会让登录态互相覆盖、触发风控。

**租约式锁(防客户端崩溃死锁)**
- `checkout` 原子加锁,返回带 TTL 的租约(默认 90s)+ 最新快照版本/下载地址。
- 客户端运行期间每 30s 调 `/lease` 续租。
- 客户端崩溃 → 租约到期 → 管理员可 `force-unlock`,或自动回收;回收时环境标记
  "可能有未提交改动",由原借出方确认。
- `checkin` 上传新快照 → version+1 → 释放锁;`release` 丢弃改动并释放锁。

环境列表对所有人展示"使用中 / 被谁占用"。

---

## 4. 服务器实现

**栈**:Rust + axum,作为本仓库新增 crate `server/`,复用 `src-tauri` 的
`profile` / `proxy` / `cookies` serde 类型。鉴权:argon2 口令哈希 + Bearer Token
(JWT 或不透明 token,DB 存角色)。

**存储**:SQLite(`./data/shardx.db`)+ blob 目录(`./data/blobs/<env_id>/<version>.tar.zst`)。
DB 与 blob 各做一层 trait 抽象,日后可换 Postgres / S3 而不动业务代码。

### 4.1 数据模型

```
users(id, username, pw_hash, role[admin|member], created_at)
folders(id, name, parent_id)
environments(id, name, folder_id, config_json, proxy_id, host_os,
             current_version, updated_by, updated_at)
acl(subject_user_id, object_id, object_kind[env|folder], perm)
locks(env_id PK, owner_user_id, owner_client_id, acquired_at, lease_expires_at)
snapshots(env_id, version, blob_path, sha256, size, created_by, created_at)
proxies(id, name, kind, host, port, username, password, ...)   -- 复用 ProxyEntry
audit_log(id, actor_user_id, action, env_id, at, detail)
```

### 4.2 API

```
POST /auth/login                  → { token, role }
GET  /me

# 管理员
GET  /users ; POST /users ; DELETE /users/{id}
PATCH /users/{id}/role
POST /acl                         → 给用户分配 env / folder 访问权
POST /envs/{id}/force-unlock

# 文件夹 / 代理
GET/POST/PATCH/DELETE /folders
GET/POST/DELETE /proxies

# 环境
GET  /envs                        → 按 ACL 过滤
GET  /envs/{id}
POST /envs ; PATCH /envs/{id} ; DELETE /envs/{id}

# 借出 / 归还(核心)
POST /envs/{id}/checkout          → 加锁 + { version, snapshot_url };占用中→409+占用人
POST /envs/{id}/lease             → 续租心跳
POST /envs/{id}/checkin (multipart)→ 上传快照 → version+1 → 解锁
POST /envs/{id}/release           → 丢弃改动并解锁
GET  /envs/{id}/snapshot/{version}
```

### 4.3 部署

单 Docker 容器,挂载一个数据卷(`./data`)。配置走环境变量:监听地址、
Token 签名密钥、存储路径、(可选)S3 端点。

---

## 5. 客户端改造(增量,不破坏单机模式)

- `src/App.tsx`:新增"远程工作区"登录入口(服务器地址 + 账号);登录后环境列表来自
  服务器,展示占用状态。
- `store.rs`:新增 remote workspace 配置;单机模式保留,二选一。
- `launch.rs::launch_profile`:**start 前** → `checkout`(加锁 + 下载快照 + 解压进本地
  `user-data/<id>/`,按 §2.1 重加密 cookies/logins),失败/被占用则中止启动。
- `process.rs`(已有监听子进程退出的 task):**进程退出时** → 按 §2 打包快照 →
  `checkin` 推回并解锁;运行期间起续租定时器。

---

## 6. 分阶段落地

1. **Phase 1 — 服务器骨架**:`server/` crate,SQLite + 用户/角色/登录 + 环境 CRUD +
   ACL + Docker 化。客户端能登录并看到分配给自己的环境列表。
2. **Phase 2 — 借出锁 + 快照**:checkout/lease/checkin + blob 存储 + 快照打包与排除
   规则(先做 mac/linux 裸搬验证闭环)。
3. **Phase 3 — 加密归一化** ✅:实现于独立 crate `shared/`(`shardx-core`):§2.1 的
   明文 cookies 方案 + 跨机重加密(`oscrypt`/`cookies`/`snapshot`,9 单测通过)。
   `logins` 目前只读提取;Login Data 重建按 §7 延后。Windows GCM/DPAPI 路径已镜像实现。
   接入 src-tauri + 去重原 `cookies.rs` 在 Phase 4 完成。
4. **Phase 4 — 客户端集成**:App.tsx 登录入口 + launch/stop 钩子 + 续租定时器。
5. **Phase 5 — 收尾**:审计日志、force-unlock UI、快照 GC、版本回滚。

---

## 7. 已知风险 / 待定

- **Login Data 范围**:多数站点登录态在 cookie 里,保存的密码(Login Data)优先级低,
  可在 Phase 3 视情况决定是否纳入首版。
- **快照体积**:若某些环境 IndexedDB 很大,可在 Phase 2 后引入增量/分块(内容寻址)
  降低上传量;首版用整包压缩。
- **跨 OS 指纹一致性**:一个环境的指纹固定声明某个 OS;成员在不同 host OS 上运行同一
  环境由引擎层的指纹伪装保证一致,与本服务无关。本服务只负责数据与锁。
