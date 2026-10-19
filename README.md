# ShadowEdge

**Collaborative red team operations platform**

[中文文档](README.zh-CN.md) · [User manual](MANUAL.md)

ShadowEdge is a self-hosted workspace for authorized red team engagements. It
keeps targets, services, findings, credentials, evidence, command history and
attack paths in one place, so a team works from the same picture instead of
scattered notes and chat threads.

## Features

### Workspace

- Projects with owner, operator, viewer and auditor roles
- Typed entities: target, service, finding, credential, evidence, command, task, note and action; built-in fields are shortcuts, and every entity can add arbitrary custom fields
- Asset center: Hosts, Services and Findings views with host/service relationships
- Structured vulnerability fields: type, severity, CVE/CWE, CVSS/vector, endpoint, parameter, payload, impact, reproduction, evidence, remediation, references and custom fields
- Findings are asset-scoped lifecycle records; capturing the same finding in another phase merges it and appends phase history
- Human-readable cards, tables and detail views; raw payloads stay behind `Advanced JSON`

### Penetration phase board

- 11 standard phases from reconnaissance to reporting
- Entities grouped by phase with type and status badges
- Each phase column opens a phase-specific entry form with its own default entity type and fields
- Status: new, confirmed, exploited, fixed, false positive

### Attack graph

- Manual DAG links between project entities
- Uses the same host/service/finding nodes, so assets and findings can be chained into attack paths
- Node colors by entity type and labeled edges
- Interactive graph with zoom, drag and click-through to entity details

### Master/edge sync

- Sync roles are per project: standalone, master, or edge; one instance can mix them
- Configure roles and edge connections in the project **Sync** tab
- `shadowedge join` can seed a separate local edge workspace from a master snapshot
- Edge edits are queued locally and pushed when the master is reachable
- The master is authoritative; version conflicts are recorded and shown in the project Sync tab
- Edge sync runs every second by default (`join --interval`); edge tokens are encrypted at rest with `data/sync.key`
- WebSocket change notifications for edge nodes and browsers; edge sync keeps a 1-second polling fallback

### Reports

- HTML and Markdown reports
- Executive summary, phase coverage, entity details and DAG attack chain
- Server-side HTML escaping

### Access control

- Account requests with administrator approval
- Argon2id password hashing
- HttpOnly cookie sessions, CSRF protection and login rate limiting
- Project-scoped API tokens with read/write scopes
- Password changes revoke other sessions and API tokens

### MCP

- Endpoint: `POST /mcp`
- Authentication: `Authorization: Bearer <token>` or `X-API-Key: <token>`
- Tools: `list_projects`, `get_project`, `list_entities`, `get_phase_board`, `get_attack_graph`, `create_project`, `add_entity`, `add_edge`, `generate_report`

### Deployment

- Single Go binary with the SPA embedded
- SQLite only (WAL mode), no external database
- English-first interface with a Simplified Chinese switch
- Windows, Linux and macOS builds

## Quick start

Requirements: Go 1.27.1 or newer.

```bash
export SHADOWEDGE_ADMIN_PASSWORD='ChangeMe-Str0ng!'
go run ./cmd/shadowedge serve
```

Open <http://127.0.0.1:5000>.

If `SHADOWEDGE_ADMIN_PASSWORD` is empty, ShadowEdge generates a random
administrator password and prints it once at startup.

Build a binary:

```bash
go build -trimpath -o shadowedge ./cmd/shadowedge
```

Run the test suite:

```bash
go test ./...
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `SHADOWEDGE_DATA_DIR` | `./data` | Data directory; the SQLite database is `data/shadowedge.db` |
| `SHADOWEDGE_LISTEN` | `0.0.0.0:5000` | Listen address (all IPv4 interfaces) |
| `SHADOWEDGE_ADMIN_USERNAME` | `admin` | Bootstrap administrator username |
| `SHADOWEDGE_ADMIN_PASSWORD` | empty | Bootstrap administrator password; random if empty |
| `SHADOWEDGE_SECURE_COOKIES` | `false` | Set to `true` when served over HTTPS |
| `SHADOWEDGE_SESSION_TTL` | `168h` | Login session lifetime |

`SHADOWEDGE_ADMIN_PASSWORD` is used only when the users table is empty. Once an
administrator exists, change the password from the UI.

The default listener accepts connections on all IPv4 interfaces. Set
`SHADOWEDGE_LISTEN=127.0.0.1:5000` for a local-only instance; when exposed,
terminate TLS and set `SHADOWEDGE_SECURE_COOKIES=true`.

## Usage

1. Sign in as the bootstrap administrator.
2. Create a project and add members with the appropriate role.
3. Record targets and findings on the phase board.
4. Link entities in the attack graph to describe the kill chain.
5. Generate an HTML or Markdown report from the project workspace.

## Master/edge deployment

Start a server:

```bash
SHADOWEDGE_LISTEN=0.0.0.0:5000 SHADOWEDGE_SECURE_COOKIES=true ./shadowedge serve
```

Open a project, switch to **Sync**, and set its role to **master**. The role is
per project, so the same instance can host master, standalone and edge projects.
Web edge configuration is restricted to platform administrators.

Create a project-scoped API token in **Admin → API tokens** with read/write
scopes. Then configure the edge in the project **Sync** tab, or run a separate
local edge workspace:

```bash
./shadowedge join \
  --master https://master.example.com \
  --project <project-id> \
  --token <token> \
  --listen 127.0.0.1:5001 \
  --data ./edge-data
```

The first join fetches a master snapshot. Later starts reuse the local
`sync_state`; the edge UI works offline and pushes queued changes when the
master returns. The Sync tab shows the master URL, cursor, pending operations
and conflicts. Project views and edge nodes also receive WebSocket change
notifications; edge sync keeps a 1-second polling fallback, and browser views
can be refreshed manually. Edge instances keep their own local users; master
users and project members are not replicated. The sync token is encrypted in
SQLite with `data/sync.key`; back up the key with the database.

## Roles

| Role | Permissions |
|---|---|
| `owner` | Project settings, members, delete project, all project data |
| `operator` | Read and write project data, DAG links, reports |
| `viewer` | Read-only project data |
| `auditor` | Read-only project data (audit access) |

Platform administrators can access every project and manage users, registration
requests and API tokens.

## MCP example

Create a token under **Admin → API tokens**. The plaintext token is shown once.

```bash
curl -s http://127.0.0.1:5000/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

## Data and backup

Runtime data lives in `SHADOWEDGE_DATA_DIR`. Back up the whole directory. The
database uses WAL mode; stop the process before copying it, or use SQLite's
backup API.

## Security

- The default listen address is `127.0.0.1`.
- When exposing ShadowEdge publicly, terminate TLS at a reverse proxy and set
  `SHADOWEDGE_SECURE_COOKIES=true`.
- Passwords are stored as Argon2id hashes.
- API tokens are stored as SHA-256 hashes and can be revoked at any time.
- Project-scoped tokens cannot access other projects or the platform admin API.

## Documentation

- [User manual](MANUAL.md) — installation, daily operation, admin, MCP and master/edge sync

## License

MIT License. See [LICENSE](LICENSE).

## Authors

- guaidao2 & coolmoon
