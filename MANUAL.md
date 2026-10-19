# ShadowEdge User Manual

[中文使用手册](MANUAL.zh-CN.md) · [README](README.md)

This manual covers installation, daily operation, administration, MCP and
master/edge sync. For a shorter product overview, see the README.

## 1. What ShadowEdge does

ShadowEdge is a self-hosted workspace for authorized red team engagements. A
project holds targets, services, findings, credentials, evidence, command
records, tasks, notes and DAG links. A team uses the phase board and attack
graph to keep one shared picture of the engagement.

ShadowEdge does not run exploits or automated attacks. It records and organizes
work performed by the team.

## 2. Requirements

- Go 1.27.1 or newer to build from source
- A current browser
- SQLite is embedded; no external database is required
- Windows, Linux or macOS

## 3. Build and start

Build a single binary:

```bash
go build -trimpath -o shadowedge ./cmd/shadowedge
```

Start a standalone instance:

```bash
export SHADOWEDGE_ADMIN_PASSWORD='ChangeMe-Str0ng!'
./shadowedge serve
```

Open <http://127.0.0.1:5000>.

On Windows PowerShell:

```powershell
$env:SHADOWEDGE_ADMIN_PASSWORD = "ChangeMe-Str0ng!"
.\shadowedge.exe serve
```

If `SHADOWEDGE_ADMIN_PASSWORD` is empty, ShadowEdge generates a random
administrator password and prints it once at startup.

### Configuration

| Variable | Default | Description |
|---|---|---|
| `SHADOWEDGE_DATA_DIR` | `./data` | Data directory; SQLite database is `data/shadowedge.db` |
| `SHADOWEDGE_LISTEN` | `0.0.0.0:5000` | Listen address (all IPv4 interfaces) |
| `SHADOWEDGE_ADMIN_USERNAME` | `admin` | Bootstrap administrator username |
| `SHADOWEDGE_ADMIN_PASSWORD` | empty | Bootstrap administrator password; random if empty |
| `SHADOWEDGE_SECURE_COOKIES` | `false` | Set to `true` when served over HTTPS |
| `SHADOWEDGE_SESSION_TTL` | `168h` | Login session lifetime |

`SHADOWEDGE_ADMIN_PASSWORD` only applies when the users table is empty. Once an
administrator exists, use **Change password** in the UI.

The default listener accepts connections on all IPv4 interfaces. Set
`SHADOWEDGE_LISTEN=127.0.0.1:5000` for a local-only instance; when exposed,
terminate TLS and set `SHADOWEDGE_SECURE_COOKIES=true`.

## 4. Accounts and approval

1. The first start creates the bootstrap administrator.
2. A visitor uses **Request access** on the login page.
3. An administrator opens **Admin → Registration requests** and approves or
   rejects the request.
4. Only approved accounts can sign in. Disabled accounts cannot sign in.

Password rules: 8–128 characters. Passwords are stored as Argon2id hashes.

Changing a password revokes other login sessions and all API tokens for that
account. The current session remains valid.

## 5. Projects and roles

Create a project from **Projects → New project**. The creator becomes the project
owner and is added as a member.

| Role | Permissions |
|---|---|
| `owner` | Project settings, members, delete project, all project data |
| `operator` | Read/write entities, DAG links, reports |
| `viewer` | Read-only project data |
| `auditor` | Read-only project data (audit use) |

Platform administrators can access every project and manage users, registration
requests and API tokens.

The project owner can add existing users by username. A project cannot have a
second owner, and the owner cannot be removed.

## 6. Phase board

The project workspace opens on the **Phase board**. Entities are grouped into 11
standard phases:

1. Reconnaissance
2. Scanning & Enumeration
3. Initial Access
4. Foothold / C2
5. Privilege Escalation
6. Credential Access
7. Lateral Movement
8. Persistence
9. Collection & Exfiltration
10. Objective / Impact
11. Reporting

### Asset center

The project workspace also has **Hosts**, **Services** and **Findings** views.
Hosts store IP/hostname/OS/importance; services link to a host and store
port/protocol/product/version/banner; findings link to a host or service and
store the full vulnerability record. The DAG uses the same nodes, so assets and
findings can be chained into attack paths.

Use **Add entity** to record an item. Choose a kind, phase, title and the
kind-specific fields. Each phase column also has a **+** button: it opens the
form with that phase preselected and the phase-specific fields below. Services,
findings and commands can be created without a target; the target selector is
optional.

### Entity kinds and fields

| Kind | Fields |
|---|---|
| `target` | IP/hostname, hostname, OS, tags, description, importance |
| `service` | target (optional), port, protocol, service name, product, version, banner |
| `finding` | target/service, vulnerability type, severity, CVE, CWE, CVSS/vector, endpoint, parameter, payload, description, impact, reproduction, evidence, remediation, references, tags |
| `credential` | target/service (optional), protocol, username, secret, source |
| `evidence` | filename, SHA-256, storage path, size |
| `command` | target (optional), command, output, exit code |
| `task` | assignee, text |
| `note` | text |
| `action` | text |

Statuses are `new`, `confirmed`, `exploited`, `fixed` and `false_positive`.

The table lists built-in shortcuts. Every entity can also add arbitrary custom
fields; they are stored in the entity JSON and shown in the detail dialog and
reports.

### Phase-specific fields

| Phase | Default entity | Extra fields |
|---|---|---|
| Reconnaissance | target | scope, source, contacts, notes |
| Scanning & Enumeration | service | scan type, tool, ports, banner, result |
| Initial Access | finding | vector, endpoint, parameter, payload, result |
| Foothold / C2 | action | implant, listener, host, result |
| Privilege Escalation | finding | technique, from user, to user, result |
| Credential Access | credential | account, secret type, validated, source |
| Lateral Movement | action | source host, destination host, protocol, technique, result |
| Persistence | action | mechanism, location, trigger, result |
| Collection & Exfiltration | evidence | data type, volume, channel, destination, result |
| Objective / Impact | note | objective, impact, achieved, result |
| Reporting | note | summary, recommendations, references |

Some phase fields also exist in the entity kind; the form shows each field once.

### Finding lifecycle

Findings are asset-scoped records. A finding is identified by its host/service
plus CVE; when no CVE is present, by host/service + type + title + endpoint +
parameter. Capturing the same finding in another phase merges it into the same
record and appends to its phase history. The phase board shows the current
phase; the detail dialog shows the full lifecycle. A host or service with
dependent findings cannot be deleted until those records are removed.

The entity list and detail dialog render labeled fields. Use **Advanced JSON**
only when you need the raw payload.

## 7. Attack graph

Open the **DAG** tab to see all project entities and links. Nodes are colored by
entity type; edges can carry a label.

To create a link:

1. Open an entity from the board or entity list.
2. In the detail dialog choose a target entity and enter an optional label.
3. Click **Link**.

To remove a link, open the source entity and delete the outgoing link in the
detail dialog or the graph dialog.

The graph uses a physics layout. Node positions are not stored on the server;
each browser lays out the graph locally.

## 8. Reports

Open the **Reports** tab and choose:

- **Open HTML report** — full report in a new tab
- **Download Markdown** — Markdown file for tickets or notes

The report contains an executive summary, phase coverage, entity details and the
DAG attack chain. HTML is escaped server-side.

## 9. API tokens and MCP

Create a token under **Admin → API tokens**. The plaintext token is shown once;
only its SHA-256 hash is stored.

Token options:

- Name
- Scopes: `read`, `write`, or `read,write` (`admin` is accepted as a broad
  scope)
- Optional project scope

A project-scoped token can only access that project and cannot use the platform
admin API. A read-only token cannot perform writes.

### MCP endpoint

- URL: `POST /mcp`
- Headers: `Authorization: Bearer <token>` or `X-API-Key: <token>`
- Protocol: JSON-RPC 2.0 with `initialize`, `tools/list` and `tools/call`

List tools:

```bash
curl -s http://127.0.0.1:5000/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

Call a tool:

```bash
curl -s http://127.0.0.1:5000/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_projects","arguments":{}}}'
```

Available tools:

`list_projects`, `get_project`, `list_entities`, `get_phase_board`,
`get_attack_graph`, `create_project`, `add_entity`, `add_edge`,
`generate_report`.

## 10. Master/edge sync

A project can run on a master node and on edge nodes. Sync roles are configured
per project, so one process can host standalone, master and edge projects at the
same time. The master is authoritative; edge nodes keep a local SQLite replica
and exchange changes with the master.

### Concepts

- **Master** — owns the project event sequence and accepts writes.
- **Edge** — runs a local workspace, queues local changes in `sync_outbox`, and
  pushes them to the master.
- **Cursor** — `sync_state.last_seq` records the last master event applied by
  the edge.
- **Conflict** — a write based on an outdated `base_version` is rejected by the
  master and recorded on the edge.
- **Stream** — master exposes `GET /api/v1/projects/{id}/stream`; edge nodes and
  browsers subscribe for immediate change notifications.

### Start the server and set a project role

```bash
SHADOWEDGE_LISTEN=0.0.0.0:5000 \
SHADOWEDGE_SECURE_COOKIES=true \
./shadowedge serve
```

Open the project, go to **Sync**, and set its role to **master**. Roles are per
project. `serve --master` is still accepted as an optional label, but the
project Sync tab is authoritative.

### Create a sync token

In **Admin → API tokens**, create a token with `read,write` scopes and the
project scope set to the project that edge nodes will join.

### Configure an edge in the web UI

Open the project and switch to **Sync**. A project owner can set the role to
`standalone` or `master`; only a platform administrator can configure an
`edge` replica.

1. Set the role to `standalone` or `master` (platform administrators can also
   set `edge`).
2. For `edge`, enter the master URL, remote project ID and sync token.
3. Save. ShadowEdge fetches a master snapshot, replaces local project data and
   starts syncing.
4. Use **Force sync** to run an immediate push/pull pass.

Changing the master URL or remote project requires confirmation and replaces
local entities with the new master snapshot. The token is never returned by the
API; it is encrypted with the local `data/sync.key` before being stored in
SQLite. Each edge instance keeps its own local users; master users and project
members are not replicated to the edge.

### Join an edge from the CLI

```bash
./shadowedge join \
  --master https://master.example.com \
  --project <project-id> \
  --token <token> \
  --listen 127.0.0.1:5001 \
  --data ./edge-data
```

Open <http://127.0.0.1:5001> for the edge workspace.

Join flags:

| Flag | Default | Description |
|---|---|---|
| `--master` | required | Master base URL |
| `--project` | required | Remote project ID |
| `--token` | `SHADOWEDGE_SYNC_TOKEN` | Project API token |
| `--listen` | `127.0.0.1:5001` | Local edge listen address |
| `--data` | `edge-data` | Edge data directory |
| `--admin-username` | `admin` | Local edge administrator |
| `--admin-password` | `SHADOWEDGE_ADMIN_PASSWORD` | Local edge administrator password |
| `--interval` | `1s` | Sync interval |

The first join fetches a master snapshot, creates a local project and seeds the
local replica. Later starts reuse the local `sync_state`, so the local edge UI
can start even when the master is unreachable. The token is encrypted with the
local `data/sync.key` and stored in `sync_state`. `join` bootstraps one edge
project; additional edge projects can be configured in the project **Sync**
tab, and the process Manager syncs all edge projects.

### Offline behavior

- Edge reads and writes continue locally.
- Entity and edge writes are appended to `sync_outbox`.
- WebSocket notifications trigger an immediate push/pull; the 1-second poll
  remains a fallback.
- The syncer retries every interval; when the master is reachable it pushes the
  outbox and pulls events since the cursor.
- A malformed outbox row is recorded as a conflict and removed so it cannot
  block the rest of the queue.

### Sync tab

The project **Sync** tab shows:

- Mode: standalone, master or edge
- Master URL and remote project ID
- Last event sequence
- Pending outbox operations
- Conflict count and recent conflict details
- An owner/admin form to change the role and edge connection
- A **Force sync** button for edge projects

### Conflict policy

The master is authoritative. If an edge update is based on an older entity
version, the master rejects it and returns the conflict. The edge records the
conflict, then pulls the master state. The conflicting edge edit is not
automatically merged; re-apply the intended change on the master if needed.

## 11. CLI reference

```text
shadowedge version
shadowedge help
shadowedge serve [--master]
shadowedge migrate
shadowedge join --master URL --project ID --token TOKEN [flags]
```

`migrate` applies embedded SQLite migrations and exits.

## 12. Data and backup

Runtime data is stored in `SHADOWEDGE_DATA_DIR`:

- `shadowedge.db` — SQLite database
- `shadowedge.db-wal`, `shadowedge.db-shm` — WAL files
- `sync.key` — local AES-GCM key for encrypted edge sync tokens
- upload/report directories are created if used

Back up the whole data directory. The database uses WAL mode; stop the process
before copying the files, or use SQLite's backup API.

To restore, stop the process and replace the data directory, then start the same
binary.

## 13. Security and deployment

- Default listen address is `127.0.0.1`.
- For public access, terminate TLS at a reverse proxy and set
  `SHADOWEDGE_SECURE_COOKIES=true`.
- Passwords use Argon2id.
- API tokens are stored as SHA-256 hashes and can be revoked.
- Project-scoped tokens cannot access other projects or the admin API.
- Cookie sessions use HttpOnly/SameSite cookies and CSRF checks.
- Login and registration requests are rate limited.

## 14. Troubleshooting

| Symptom | Check |
|---|---|
| `401` on login | Username/password correct; account approved and active |
| `401` on MCP | Bearer token present, not revoked, not expired |
| `403` on project | You are a project member; token project scope matches |
| `403` on admin API | Platform administrator; project-scoped tokens cannot use admin APIs |
| `403` on write | Role is owner/operator; token has `write` scope |
| Edge UI works but no new remote data | Master reachable; token valid; check Sync tab cursor and pending count |
| Sync conflicts | Inspect the Sync tab; master wins; re-apply on master |
| Port already in use | Change `SHADOWEDGE_LISTEN` or `--listen` |
| Cannot reset admin password | There is no CLI reset; use another administrator session, restore a backup, or reset the database (data loss) |