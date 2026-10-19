package domain

// SyncState maps a local edge project to a remote master project.
type SyncState struct {
	LocalProjectID  string `json:"local_project_id"`
	RemoteProjectID string `json:"remote_project_id"`
	MasterURL       string `json:"master_url"`
	NodeID          string `json:"node_id"`
	LastSeq         int    `json:"last_seq"`
	Role            string `json:"role"`
	TokenCipher     string `json:"-"`
	UpdatedAt       string `json:"updated_at"`
}

// SyncOutbox is a local edge operation waiting to be pushed.
type SyncOutbox struct {
	ID          string `json:"id"`
	ProjectID   string `json:"project_id"`
	Op          string `json:"op"`
	EntityType  string `json:"entity_type"`
	EntityID    string `json:"entity_id"`
	BaseVersion *int   `json:"base_version,omitempty"`
	Payload     any    `json:"payload"`
	CreatedAt   string `json:"created_at"`
	Attempts    int    `json:"attempts"`
	LastError   string `json:"last_error"`
}

// SyncOperation is one master-side write submitted by an edge.
type SyncOperation struct {
	Op          string  `json:"op"`
	Entity      *Entity `json:"entity,omitempty"`
	Edge        *Edge   `json:"edge,omitempty"`
	EntityID    string  `json:"entity_id,omitempty"`
	EdgeID      string  `json:"edge_id,omitempty"`
	BaseVersion *int    `json:"base_version,omitempty"`
}

type SyncConflict struct {
	EntityID string `json:"entity_id"`
	Op       string `json:"op"`
	Detail   string `json:"detail"`
}

type SyncPushRequest struct {
	NodeID     string          `json:"node_id"`
	Operations []SyncOperation `json:"operations"`
}

type SyncPushResponse struct {
	Accepted  int            `json:"accepted"`
	Conflicts []SyncConflict `json:"conflicts"`
	LastSeq   int            `json:"last_seq"`
}

// SyncSnapshot seeds an edge from a master project.
type SyncSnapshot struct {
	Project  PackageProject `json:"project"`
	Phases   []Phase        `json:"phases"`
	Entities []Entity       `json:"entities"`
	Edges    []Edge         `json:"edges"`
	LastSeq  int            `json:"last_seq"`
}

// PackageProject alias keeps the snapshot JSON stable if Project gains fields.
type PackageProject = Project

// SyncStatus is returned by the project sync status endpoint.
type SyncStatus struct {
	Mode            string         `json:"mode"`
	MasterURL       string         `json:"master_url,omitempty"`
	RemoteProjectID string         `json:"remote_project_id,omitempty"`
	LastSeq         int            `json:"last_seq"`
	Pending         int            `json:"pending_events"`
	Conflicts       int            `json:"conflicts"`
	ConflictItems   []SyncConflict `json:"conflict_items,omitempty"`
}

// SyncConfig is the web-facing per-project sync configuration. The token is
// never returned; HasToken indicates whether one is stored.
type SyncConfig struct {
	Role            string         `json:"role"`
	MasterURL       string         `json:"master_url"`
	RemoteProjectID string         `json:"remote_project_id"`
	HasToken        bool           `json:"has_token"`
	LastSeq         int            `json:"last_seq"`
	Pending         int            `json:"pending_events"`
	Conflicts       int            `json:"conflicts"`
	ConflictItems   []SyncConflict `json:"conflict_items,omitempty"`
}

type SyncConfigRequest struct {
	Role            string `json:"role"`
	MasterURL       string `json:"master_url"`
	RemoteProjectID string `json:"remote_project_id"`
	Token           string `json:"token"`
	Reset           bool   `json:"reset"`
}
