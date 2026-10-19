// Package domain contains ShadowEdge's core types and invariants.
package domain

import "strings"

type EntityKind string

const (
	KindTarget     EntityKind = "target"
	KindService    EntityKind = "service"
	KindFinding    EntityKind = "finding"
	KindCredential EntityKind = "credential"
	KindEvidence   EntityKind = "evidence"
	KindCommand    EntityKind = "command"
	KindTask       EntityKind = "task"
	KindNote       EntityKind = "note"
	KindAction     EntityKind = "action"
)

var entityKinds = map[EntityKind]bool{
	KindTarget: true, KindService: true, KindFinding: true, KindCredential: true,
	KindEvidence: true, KindCommand: true, KindTask: true, KindNote: true, KindAction: true,
}

func (k EntityKind) Valid() bool { return entityKinds[k] }

type EntityStatus string

const (
	StatusNew           EntityStatus = "new"
	StatusConfirmed     EntityStatus = "confirmed"
	StatusExploited     EntityStatus = "exploited"
	StatusFixed         EntityStatus = "fixed"
	StatusFalsePositive EntityStatus = "false_positive"
)

var entityStatuses = map[EntityStatus]bool{
	StatusNew: true, StatusConfirmed: true, StatusExploited: true,
	StatusFixed: true, StatusFalsePositive: true,
}

func (s EntityStatus) Valid() bool { return entityStatuses[s] }

type Role string

const (
	RoleOwner    Role = "owner"
	RoleOperator Role = "operator"
	RoleViewer   Role = "viewer"
	RoleAuditor  Role = "auditor"
)

var roles = map[Role]bool{
	RoleOwner: true, RoleOperator: true, RoleViewer: true, RoleAuditor: true,
}

func (r Role) Valid() bool { return roles[r] }

func (r Role) CanWrite() bool  { return r == RoleOwner || r == RoleOperator }
func (r Role) CanManage() bool { return r == RoleOwner }

type RegistrationStatus string

const (
	RegistrationPending  RegistrationStatus = "pending"
	RegistrationApproved RegistrationStatus = "approved"
	RegistrationRejected RegistrationStatus = "rejected"
)

type UserStatus string

const (
	UserActive   UserStatus = "active"
	UserDisabled UserStatus = "disabled"
)

type Phase struct {
	Key      string `json:"key"`
	NameEN   string `json:"name_en"`
	NameZH   string `json:"name_zh"`
	Position int    `json:"position"`
	Color    string `json:"color"`
}

// DefaultPhases is the standard penetration-testing phase board. Projects copy
// this list at creation time and may customize their copy.
var DefaultPhases = []Phase{
	{Key: "recon", NameEN: "Reconnaissance", NameZH: "侦察", Position: 0, Color: "#3b82f6"},
	{Key: "scan", NameEN: "Scanning & Enumeration", NameZH: "扫描与枚举", Position: 1, Color: "#8b5cf6"},
	{Key: "initial_access", NameEN: "Initial Access", NameZH: "初始访问", Position: 2, Color: "#ef4444"},
	{Key: "foothold", NameEN: "Foothold / C2", NameZH: "立足点", Position: 3, Color: "#f97316"},
	{Key: "privesc", NameEN: "Privilege Escalation", NameZH: "提权", Position: 4, Color: "#eab308"},
	{Key: "credential_access", NameEN: "Credential Access", NameZH: "凭据获取", Position: 5, Color: "#d97706"},
	{Key: "lateral", NameEN: "Lateral Movement", NameZH: "横向移动", Position: 6, Color: "#14b8a6"},
	{Key: "persistence", NameEN: "Persistence", NameZH: "持久化", Position: 7, Color: "#6366f1"},
	{Key: "collection", NameEN: "Collection & Exfiltration", NameZH: "收集与外传", Position: 8, Color: "#0ea5e9"},
	{Key: "objective", NameEN: "Objective / Impact", NameZH: "目标达成", Position: 9, Color: "#22c55e"},
	{Key: "reporting", NameEN: "Reporting", NameZH: "报告", Position: 10, Color: "#6b7280"},
}

func ValidPhase(phases []Phase, key string) bool {
	for _, p := range phases {
		if p.Key == key {
			return true
		}
	}
	return false
}

func NormalizePhase(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return "recon"
	}
	return key
}

type User struct {
	ID              string     `json:"id"`
	Username        string     `json:"username"`
	DisplayName     string     `json:"display_name"`
	Locale          string     `json:"locale"`
	Status          UserStatus `json:"status"`
	IsPlatformAdmin bool       `json:"is_platform_admin"`
	CreatedAt       string     `json:"created_at"`
	UpdatedAt       string     `json:"updated_at"`
}

type Registration struct {
	ID          string             `json:"id"`
	Username    string             `json:"username"`
	DisplayName string             `json:"display_name"`
	Email       string             `json:"email"`
	Reason      string             `json:"reason"`
	Status      RegistrationStatus `json:"status"`
	ReviewedBy  string             `json:"reviewed_by,omitempty"`
	ReviewedAt  string             `json:"reviewed_at,omitempty"`
	CreatedAt   string             `json:"created_at"`
}

type Session struct {
	ID         string `json:"id"`
	UserID     string `json:"user_id"`
	CSRFToken  string `json:"csrf_token"`
	ExpiresAt  string `json:"expires_at"`
	CreatedAt  string `json:"created_at"`
	LastSeenAt string `json:"last_seen_at"`
}

type Project struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Status      string       `json:"status"`
	OwnerID     string       `json:"owner_id"`
	CreatedAt   string       `json:"created_at"`
	UpdatedAt   string       `json:"updated_at"`
	Stats       ProjectStats `json:"stats"`
}

type ProjectStats struct {
	Targets  int `json:"targets"`
	Entities int `json:"entities"`
	Findings int `json:"findings"`
}

type Member struct {
	UserID      string `json:"user_id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Role        Role   `json:"role"`
	JoinedAt    string `json:"joined_at"`
}

type Entity struct {
	ID        string         `json:"id"`
	ProjectID string         `json:"project_id"`
	Kind      EntityKind     `json:"kind"`
	Title     string         `json:"title"`
	Status    EntityStatus   `json:"status"`
	Phase     string         `json:"phase"`
	Data      map[string]any `json:"data"`
	Version   int            `json:"version"`
	CreatedBy string         `json:"created_by"`
	UpdatedBy string         `json:"updated_by"`
	CreatedAt string         `json:"created_at"`
	UpdatedAt string         `json:"updated_at"`
	Merged    bool           `json:"merged,omitempty"`
}

type Edge struct {
	ID           string `json:"id"`
	ProjectID    string `json:"project_id"`
	FromEntityID string `json:"from_entity_id"`
	ToEntityID   string `json:"to_entity_id"`
	Label        string `json:"label"`
	CreatedBy    string `json:"created_by"`
	CreatedAt    string `json:"created_at"`
}

type BoardColumn struct {
	Phase        Phase          `json:"phase"`
	Entities     []Entity       `json:"entities"`
	StatusCounts map[string]int `json:"status_counts"`
}

type GraphNode struct {
	Entity
}

type Graph struct {
	Nodes []Entity `json:"nodes"`
	Edges []Edge   `json:"edges"`
}

type EntityFilter struct {
	Kind     EntityKind
	Status   EntityStatus
	Phase    string
	TargetID string
	Query    string
}

type APIToken struct {
	ID         string `json:"id"`
	UserID     string `json:"user_id"`
	Name       string `json:"name"`
	Scopes     string `json:"scopes"`
	ProjectID  string `json:"project_id,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	LastUsedAt string `json:"last_used_at,omitempty"`
	CreatedAt  string `json:"created_at"`
}

type Event struct {
	ProjectID   string `json:"project_id"`
	Seq         int    `json:"seq"`
	EventID     string `json:"event_id"`
	ActorID     string `json:"actor_id"`
	NodeID      string `json:"node_id"`
	EntityType  string `json:"entity_type"`
	EntityID    string `json:"entity_id"`
	Op          string `json:"op"`
	BaseVersion *int   `json:"base_version,omitempty"`
	Payload     any    `json:"payload"`
	HLC         string `json:"hlc"`
	CreatedAt   string `json:"created_at"`
}
