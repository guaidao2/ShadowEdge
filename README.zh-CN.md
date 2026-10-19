# ShadowEdge

**红队协同作战平台**

[English](README.md) · [使用手册](MANUAL.zh-CN.md)

ShadowEdge 是面向授权红队测试的自托管工作区。它把目标、服务、漏洞、凭据、证据、命令历史和攻击路径集中到一个地方，让团队基于同一份作战视图协作，而不是散落在笔记和聊天记录里。

## 功能

### 工作区

- 项目与 owner、operator、viewer、auditor 角色
- 类型化实体：目标、服务、漏洞、凭据、证据、命令、任务、备注、行动；内置字段只是快捷项，每种实体都可以追加任意自定义字段
- 资产中心：Hosts、Services、Findings 三个视图，支持主机/服务/漏洞关联
- 结构化漏洞字段：类型、严重性、CVE/CWE、CVSS/向量、端点、参数、Payload、影响、复现、证据、修复、参考和自定义字段
- 漏洞是资产级生命周期记录；同一漏洞在另一个阶段再次录入会合并，并追加阶段历史
- 人类可读的卡片、列表和详情视图；原始数据放在 `Advanced JSON` 中

### 渗透阶段作战板

- 从侦察到报告的 11 个标准阶段
- 实体按阶段分列，显示类型与状态
- 每个阶段列都有独立入口，按该阶段显示默认实体类型和专用字段
- 状态：新发现、已确认、已利用、已修复、误报

### 攻击图

- 在项目实体之间手工创建 DAG 连线
- 使用同一套主机/服务/漏洞节点，可以把资产和漏洞串成攻击路径
- 节点按实体类型着色，边可带说明
- 支持缩放、拖拽和点击节点查看详情

### 主从同步

- 同步角色按项目配置：standalone、master 或 edge；一个实例可以混合运行
- 在项目的 **同步** 页配置角色和 edge 连接
- `shadowedge join` 可以从 master 快照初始化一个独立的本地 edge 工作区
- edge 的修改先进入本地队列，master 可达时自动推送
- master 权威；版本冲突会记录并在项目的“同步”页展示
- edge 默认每秒同步一次（`join --interval`）；edge Token 使用 `data/sync.key` 加密存储
- edge 与浏览器支持 WebSocket 变更通知；edge 同步保留 1 秒轮询兜底

### 报告

- HTML 与 Markdown 报告
- 包含执行摘要、阶段覆盖、实体详情和 DAG 攻击链
- 服务端 HTML 转义

### 访问控制

- 注册申请制，管理员审批后激活
- Argon2id 口令哈希
- HttpOnly Cookie 会话、CSRF 防护、登录限速
- 项目级 API Token，支持 read/write scope
- 修改密码会撤销其他会话和 API Token

### MCP

- 端点：`POST /mcp`
- 认证：`Authorization: Bearer <token>` 或 `X-API-Key: <token>`
- 工具：`list_projects`、`get_project`、`list_entities`、`get_phase_board`、`get_attack_graph`、`create_project`、`add_entity`、`add_edge`、`generate_report`

### 部署

- 单个 Go 二进制，SPA 内嵌
- 仅 SQLite（WAL 模式），不依赖外部数据库
- 英文优先界面，可切换简体中文
- 支持 Windows、Linux、macOS

## 快速开始

环境要求：Go 1.27.1 或更高版本。

```bash
export SHADOWEDGE_ADMIN_PASSWORD='ChangeMe-Str0ng!'
go run ./cmd/shadowedge serve
```

打开 <http://127.0.0.1:5000>。

如果未设置 `SHADOWEDGE_ADMIN_PASSWORD`，ShadowEdge 会生成随机管理员口令，并在启动时打印一次。

构建二进制：

```bash
go build -trimpath -o shadowedge ./cmd/shadowedge
```

运行测试：

```bash
go test ./...
```

## 配置

| 变量 | 默认值 | 说明 |
|---|---|---|
| `SHADOWEDGE_DATA_DIR` | `./data` | 数据目录；SQLite 数据库位于 `data/shadowedge.db` |
| `SHADOWEDGE_LISTEN` | `0.0.0.0:5000` | 监听地址（所有 IPv4 网卡） |
| `SHADOWEDGE_ADMIN_USERNAME` | `admin` | 初始化管理员用户名 |
| `SHADOWEDGE_ADMIN_PASSWORD` | 空 | 初始化管理员口令；为空则随机生成 |
| `SHADOWEDGE_SECURE_COOKIES` | `false` | HTTPS 部署时设为 `true` |
| `SHADOWEDGE_SESSION_TTL` | `168h` | 登录会话有效期 |

`SHADOWEDGE_ADMIN_PASSWORD` 只在用户表为空时生效。数据库中已有管理员后，请在界面修改口令。

默认监听所有 IPv4 网卡。只在本机使用时设置 `SHADOWEDGE_LISTEN=127.0.0.1:5000`；对外暴露时请在反向代理终止 TLS，并设置 `SHADOWEDGE_SECURE_COOKIES=true`。

## 使用流程

1. 使用初始化管理员登录。
2. 创建项目，并按角色添加成员。
3. 在阶段作战板记录目标和发现。
4. 在攻击图中连接实体，描述攻击链。
5. 在项目工作区生成 HTML 或 Markdown 报告。

## 主从部署

启动服务：

```bash
SHADOWEDGE_LISTEN=0.0.0.0:5000 SHADOWEDGE_SECURE_COOKIES=true ./shadowedge serve
```

打开项目，进入 **同步** 页，把项目角色设为 **master**。角色按项目生效，因此同一个实例可以同时承载 master、standalone 和 edge 项目。Web 端的 edge 配置仅限平台管理员。

在 **Admin → API tokens** 创建带 read/write 权限的项目级 Token。然后在项目“同步”页配置 edge，或启动一个独立的本地 edge 工作区：

```bash
./shadowedge join \
  --master https://master.example.com \
  --project <project-id> \
  --token <token> \
  --listen 127.0.0.1:5001 \
  --data ./edge-data
```

第一次 join 会拉取 master 快照。之后启动复用本地 `sync_state`；master 不可达时 edge 继续工作，恢复连接后自动推送本地队列。“同步”页显示 master 地址、事件游标、待推送操作和冲突。项目视图与 edge 节点也会收到 WebSocket 变更通知；edge 同步保留 1 秒轮询兜底，浏览器视图也可以手动刷新。edge 实例保留自己的本地用户；master 用户和项目成员不会复制。同步 Token 使用 `data/sync.key` 加密存储在 SQLite 中，备份数据库时一并备份该密钥。

## 角色

| 角色 | 权限 |
|---|---|
| `owner` | 项目设置、成员、删除项目、全部项目数据 |
| `operator` | 读写项目数据、DAG 连线、报告 |
| `viewer` | 只读项目数据 |
| `auditor` | 只读项目数据（审计用途） |

平台管理员可以访问所有项目，并管理用户、注册申请和 API Token。

## MCP 示例

在 **Admin → API tokens** 创建 Token，明文只显示一次。

```bash
curl -s http://127.0.0.1:5000/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

## 数据与备份

运行数据位于 `SHADOWEDGE_DATA_DIR`。备份整个目录即可。数据库使用 WAL 模式；复制前请停止进程，或使用 SQLite 备份 API。

## 安全

- 默认只监听 `127.0.0.1`。
- 对外暴露时，在反向代理处终止 TLS，并设置 `SHADOWEDGE_SECURE_COOKIES=true`。
- 口令使用 Argon2id 哈希存储。
- API Token 使用 SHA-256 哈希存储，可随时撤销。
- 项目级 Token 不能访问其他项目或平台管理 API。

## 文档

- [使用手册](MANUAL.zh-CN.md) — 安装、日常操作、管理、MCP 与主从同步

## 许可证

MIT License，详见 [LICENSE](LICENSE)。

## 作者

- guaidao2 & coolmoon
