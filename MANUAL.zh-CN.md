# ShadowEdge 使用手册

[English manual](MANUAL.md) · [README](README.zh-CN.md)

本手册覆盖安装、日常操作、管理、MCP 与主从同步。产品简介见 README。

## 1. ShadowEdge 是什么

ShadowEdge 是面向授权红队测试的自托管工作区。一个项目保存目标、服务、漏洞、凭据、证据、命令记录、任务、备注和 DAG 连线。团队通过阶段作战板和攻击图维护同一份作战视图。

ShadowEdge 不执行漏洞利用，也不自动攻击；它记录和整理团队已经完成的工作。

## 2. 环境要求

- 从源码构建需要 Go 1.27.1 或更高版本
- 现代浏览器
- SQLite 已内嵌，不需要外部数据库
- 支持 Windows、Linux、macOS

## 3. 构建与启动

构建单文件二进制：

```bash
go build -trimpath -o shadowedge ./cmd/shadowedge
```

启动单机实例：

```bash
export SHADOWEDGE_ADMIN_PASSWORD='ChangeMe-Str0ng!'
./shadowedge serve
```

打开 <http://127.0.0.1:5000>。

Windows PowerShell：

```powershell
$env:SHADOWEDGE_ADMIN_PASSWORD = "ChangeMe-Str0ng!"
.\shadowedge.exe serve
```

如果 `SHADOWEDGE_ADMIN_PASSWORD` 为空，ShadowEdge 会生成随机管理员口令，并在启动时打印一次。

### 配置

| 变量 | 默认值 | 说明 |
|---|---|---|
| `SHADOWEDGE_DATA_DIR` | `./data` | 数据目录；SQLite 数据库为 `data/shadowedge.db` |
| `SHADOWEDGE_LISTEN` | `0.0.0.0:5000` | 监听地址（所有 IPv4 网卡） |
| `SHADOWEDGE_ADMIN_USERNAME` | `admin` | 初始化管理员用户名 |
| `SHADOWEDGE_ADMIN_PASSWORD` | 空 | 初始化管理员口令；为空则随机生成 |
| `SHADOWEDGE_SECURE_COOKIES` | `false` | HTTPS 部署时设为 `true` |
| `SHADOWEDGE_SESSION_TTL` | `168h` | 登录会话有效期 |

`SHADOWEDGE_ADMIN_PASSWORD` 只在用户表为空时生效。已有管理员后，请在界面使用 **修改密码**。

默认监听所有 IPv4 网卡。只在本机使用时设置 `SHADOWEDGE_LISTEN=127.0.0.1:5000`；对外暴露时请在反向代理终止 TLS，并设置 `SHADOWEDGE_SECURE_COOKIES=true`。

## 4. 账号与审批

1. 第一次启动会创建初始化管理员。
2. 访客在登录页点击 **申请注册**。
3. 管理员打开 **Admin → Registration requests**，批准或拒绝申请。
4. 只有已批准的账号可以登录；被禁用的账号不能登录。

口令要求：8–128 个字符。口令使用 Argon2id 哈希存储。

修改密码会撤销该账号的其他登录会话和全部 API Token；当前会话保留。

## 5. 项目与角色

在 **Projects → New project** 创建项目。创建者自动成为项目 owner 并加入成员。

| 角色 | 权限 |
|---|---|
| `owner` | 项目设置、成员、删除项目、全部项目数据 |
| `operator` | 读写实体、DAG 连线、报告 |
| `viewer` | 只读项目数据 |
| `auditor` | 只读项目数据（审计用途） |

平台管理员可以访问所有项目，并管理用户、注册申请和 API Token。

项目 owner 可以按用户名添加已有用户。一个项目不能有第二个 owner，owner 不能被移除。

## 6. 阶段作战板

项目工作区默认打开 **Phase board**。实体按 11 个标准阶段分组：

1. Reconnaissance（侦察）
2. Scanning & Enumeration（扫描与枚举）
3. Initial Access（初始访问）
4. Foothold / C2（立足点）
5. Privilege Escalation（提权）
6. Credential Access（凭据获取）
7. Lateral Movement（横向移动）
8. Persistence（持久化）
9. Collection & Exfiltration（收集与外传）
10. Objective / Impact（目标达成）
11. Reporting（报告）

### 资产中心

项目工作区还提供 **Hosts**、**Services**、**Findings** 三个视图。主机保存
IP/主机名/OS/重要性；服务关联主机并保存端口/协议/产品/版本/Banner；漏洞关联
主机或服务，保存完整的漏洞记录。DAG 使用同一套节点，因此可以把资产和漏洞串成
攻击路径。

点击 **Add entity** 添加条目，选择类型、阶段、标题和该类型对应的字段。每个
阶段列还带有 **+** 按钮：它会预选该阶段，并显示该阶段的专用字段。服务、漏洞、
命令可以不填目标，目标选择器是可选的。

### 实体类型与字段

| 类型 | 字段 |
|---|---|
| `target` | IP/主机名、hostname、OS、tags、description、importance |
| `service` | target（可选）、port、protocol、服务名、product、version、banner |
| `finding` | target/service、漏洞类型、severity、CVE、CWE、CVSS/向量、endpoint、parameter、Payload、description、impact、复现步骤、evidence、修复建议、参考链接、tags |
| `credential` | target/service（可选）、protocol、username、secret、source |
| `evidence` | filename、SHA-256、storage path、size |
| `command` | target（可选）、command、output、exit code |
| `task` | assignee、text |
| `note` | text |
| `action` | text |

状态：`new`、`confirmed`、`exploited`、`fixed`、`false_positive`。

表中字段是内置快捷项。每种实体都可以追加任意自定义字段；字段保存在实体 JSON 中，并在详情弹窗和报告中展示。

### 阶段专用字段

| 阶段 | 默认实体 | 专用字段 |
|---|---|---|
| Reconnaissance（侦察） | target | scope、source、contacts、notes |
| Scanning & Enumeration（扫描与枚举） | service | scan type、tool、ports、banner、result |
| Initial Access（初始访问） | finding | vector、endpoint、parameter、payload、result |
| Foothold / C2（立足点） | action | implant、listener、host、result |
| Privilege Escalation（提权） | finding | technique、from user、to user、result |
| Credential Access（凭据获取） | credential | account、secret type、validated、source |
| Lateral Movement（横向移动） | action | source host、destination host、protocol、technique、result |
| Persistence（持久化） | action | mechanism、location、trigger、result |
| Collection & Exfiltration（收集与外传） | evidence | data type、volume、channel、destination、result |
| Objective / Impact（目标达成） | note | objective、impact、achieved、result |
| Reporting（报告） | note | summary、recommendations、references |

部分阶段字段也会出现在实体类型字段中；表单会去重，只显示一次。

### 漏洞生命周期

漏洞是资产级记录。身份由主机/服务 + CVE 决定；没有 CVE 时由主机/服务 + 类型 + 标题 + 端点 + 参数决定。同一漏洞在另一个阶段再次录入会合并到同一条记录，并追加阶段历史。作战板显示当前阶段，详情弹窗显示完整生命周期。存在依赖漏洞的主机或服务不能直接删除，需要先处理这些记录。

实体列表和详情弹窗会以带标签的字段展示；只有需要原始数据时才展开 **Advanced JSON**。

## 7. 攻击图

打开 **DAG** 标签查看项目实体和连线。节点按实体类型着色，边可以带说明。

创建连线：

1. 从作战板或实体列表打开一个实体。
2. 在详情弹窗选择目标实体并填写可选说明。
3. 点击 **Link**。

删除连线：在源实体详情中删除对应出边，或在图中删除。

图使用物理布局。节点位置不保存在服务端，每个浏览器本地布局。

## 8. 报告

打开 **Reports** 标签：

- **Open HTML report** — 新标签页打开完整 HTML 报告
- **Download Markdown** — 下载 Markdown 文件

报告包含执行摘要、阶段覆盖、实体详情和 DAG 攻击链。HTML 在服务端转义。

## 9. API Token 与 MCP

在 **Admin → API tokens** 创建 Token。明文只显示一次；数据库只保存 SHA-256 哈希。

Token 选项：

- 名称
- 权限：`read`、`write` 或 `read,write`（`admin` 作为宽权限被接受）
- 可选项目范围

项目级 Token 只能访问该项目，不能使用平台管理 API。只读 Token 不能执行写操作。

### MCP 端点

- URL：`POST /mcp`
- 请求头：`Authorization: Bearer <token>` 或 `X-API-Key: <token>`
- 协议：JSON-RPC 2.0，支持 `initialize`、`tools/list`、`tools/call`

列出工具：

```bash
curl -s http://127.0.0.1:5000/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

调用工具：

```bash
curl -s http://127.0.0.1:5000/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_projects","arguments":{}}}'
```

可用工具：

`list_projects`、`get_project`、`list_entities`、`get_phase_board`、`get_attack_graph`、`create_project`、`add_entity`、`add_edge`、`generate_report`。

## 10. 主从同步

同步角色按项目配置，一个进程可以同时承载 standalone、master 和 edge 项目。master 权威；edge 保存本地 SQLite 副本，并与 master 交换变更。

### 概念

- **Master** — 拥有项目事件序列，接受写入。
- **Edge** — 运行本地工作区，把本地修改放入 `sync_outbox` 并推送到 master。
- **游标** — `sync_state.last_seq` 记录 edge 已应用的最后一个 master 事件。
- **冲突** — 基于旧 `base_version` 的写入会被 master 拒绝，并在 edge 记录。
- **Stream** — master 暴露 `GET /api/v1/projects/{id}/stream`；edge 和浏览器订阅，收到变更后立即刷新/同步。

### 启动服务并设置项目角色

```bash
SHADOWEDGE_LISTEN=0.0.0.0:5000 \
SHADOWEDGE_SECURE_COOKIES=true \
./shadowedge serve
```

打开项目，进入 **同步** 页，把项目角色设为 **master**。角色按项目生效；`serve --master` 仍可作为可选标签使用，但以项目 Sync 页为准。

### 创建同步 Token

在 **Admin → API tokens** 创建带 `read,write` 权限、项目范围为将要加入的项目的 Token。

### 在 Web 中配置 edge

打开项目并进入 **同步** 页。项目 owner 可以把项目设为 `standalone` 或 `master`；只有平台管理员可以配置 `edge` 副本。

1. 将角色设为 `standalone` 或 `master`（平台管理员还可以设置 `edge`）。
2. 选择 `edge` 时，填写 master 地址、远端项目 ID 和同步 Token。
3. 保存。ShadowEdge 会拉取 master 快照、替换本地项目数据并开始同步。
4. 使用 **立即同步** 执行一次立即推送/拉取。

切换 master 地址或远端项目需要确认，并会用新 master 快照替换本地实体。API 不会返回 Token；Token 会先用本地 `data/sync.key` 加密，再写入 SQLite。edge 实例保留自己的本地用户；master 用户和项目成员不会复制到 edge。

### 通过 CLI 加入 edge

```bash
./shadowedge join \
  --master https://master.example.com \
  --project <project-id> \
  --token <token> \
  --listen 127.0.0.1:5001 \
  --data ./edge-data
```

打开 <http://127.0.0.1:5001> 使用 edge 工作区。

Join 参数：

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--master` | 必填 | master 基础 URL |
| `--project` | 必填 | 远端项目 ID |
| `--token` | `SHADOWEDGE_SYNC_TOKEN` | 项目 API Token |
| `--listen` | `127.0.0.1:5001` | 本地 edge 监听地址 |
| `--data` | `edge-data` | edge 数据目录 |
| `--admin-username` | `admin` | 本地 edge 管理员 |
| `--admin-password` | `SHADOWEDGE_ADMIN_PASSWORD` | 本地 edge 管理员口令 |
| `--interval` | `1s` | 同步间隔 |

第一次 join 会拉取 master 快照、创建本地项目并初始化副本。之后启动会复用本地 `sync_state`，因此即使 master 不可达，本地 edge UI 也可以先启动。Token 使用本地 `data/sync.key` 加密后存入 `sync_state`。`join` 初始化一个 edge 项目；更多 edge 项目可以在项目的 **同步** 页配置，进程内的 Manager 会同步所有 edge 项目。

### 离线行为

- edge 本地读写继续可用。
- 实体和连线写入会追加到 `sync_outbox`。
- WebSocket 通知会立即触发推送/拉取；1 秒轮询作为兜底。
- 同步器按间隔重试；master 可达时推送 outbox，并按游标拉取事件。
- 损坏的 outbox 行会被记录为冲突并移除，避免阻塞整个队列。

### Sync 页

项目 **Sync** 标签显示：

- 模式：standalone、master 或 edge
- master 地址和远端项目 ID
- 最后事件序号
- 待推送 outbox 操作数
- 冲突数与最近冲突详情
- owner/管理员可修改角色和 edge 连接
- edge 项目提供 **立即同步** 按钮

### 冲突策略

master 权威。如果 edge 更新基于旧版本，master 会拒绝并返回冲突。edge 记录冲突后拉取 master 状态。冲突的 edge 修改不会自动合并；如需要，请在 master 上重新应用。

## 11. CLI 参考

```text
shadowedge version
shadowedge help
shadowedge serve [--master]
shadowedge migrate
shadowedge join --master URL --project ID --token TOKEN [flags]
```

`migrate` 应用内嵌 SQLite 迁移后退出。

## 12. 数据与备份

运行数据位于 `SHADOWEDGE_DATA_DIR`：

- `shadowedge.db` — SQLite 数据库
- `shadowedge.db-wal`、`shadowedge.db-shm` — WAL 文件
- `sync.key` — 加密 edge 同步 Token 的本地 AES-GCM 密钥
- 上传/报告目录会按需创建

备份整个数据目录。数据库使用 WAL 模式；复制前请停止进程，或使用 SQLite 备份 API。

恢复时停止进程、替换数据目录，再用同一二进制启动。

## 13. 安全与部署

- 默认只监听 `127.0.0.1`。
- 对外访问时在反向代理终止 TLS，并设置 `SHADOWEDGE_SECURE_COOKIES=true`。
- 口令使用 Argon2id。
- API Token 使用 SHA-256 哈希存储，可随时撤销。
- 项目级 Token 不能访问其他项目或管理 API。
- Cookie 会话使用 HttpOnly/SameSite，并有 CSRF 检查。
- 登录和注册申请有限速。

## 14. 排查

| 现象 | 检查 |
|---|---|
| 登录 `401` | 用户名/口令正确；账号已批准且启用 |
| MCP `401` | Bearer Token 存在、未撤销、未过期 |
| 项目 `403` | 是项目成员；Token 项目范围匹配 |
| 管理 API `403` | 是平台管理员；项目级 Token 不能使用管理 API |
| 写入 `403` | 角色为 owner/operator；Token 有 `write` scope |
| Edge UI 正常但看不到远端新数据 | master 可达；Token 有效；查看 Sync 页游标和待推送数 |
| 同步冲突 | 查看 Sync 页；master 优先；在 master 上重新应用 |
| 端口被占用 | 修改 `SHADOWEDGE_LISTEN` 或 `--listen` |
| 忘记管理员口令 | 没有 CLI 重置；使用另一个管理员会话、恢复备份，或重置数据库（会丢数据） |