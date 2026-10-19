package report

import (
	"strings"
	"testing"

	"shadowedge/internal/domain"
)

func TestHumanReadableFieldsAndReports(t *testing.T) {
	target := domain.Entity{
		ID: "e1", Kind: domain.KindTarget, Title: "dc01", Status: domain.StatusNew, Phase: "recon",
		Data: map[string]any{"ip": "10.0.0.10", "hostname": "dc01", "os": "Windows Server 2022", "tags": "dc"},
	}
	service := domain.Entity{
		ID: "e2", Kind: domain.KindService, Title: "80/tcp http", Status: domain.StatusConfirmed, Phase: "scan",
		Data: map[string]any{"target_id": "e1", "port": float64(80), "protocol": "tcp", "name": "http"},
	}
	data := &Data{
		Project:     domain.Project{Name: "Demo", Description: "smoke test"},
		Columns:     []domain.BoardColumn{{Phase: domain.DefaultPhases[0], Entities: []domain.Entity{target}}, {Phase: domain.DefaultPhases[1], Entities: []domain.Entity{service}}},
		Graph:       &domain.Graph{Nodes: []domain.Entity{target, service}, Edges: []domain.Edge{{ID: "x", FromEntityID: "e1", ToEntityID: "e2", Label: "exposes"}}},
		GeneratedAt: "2026-10-19T00:00:00Z", GeneratedBy: "admin",
		nodeTitles: map[string]string{"e1": "dc01", "e2": "80/tcp http"},
	}

	fields := data.Fields(target)
	if len(fields) != 4 {
		t.Fatalf("target fields = %d, want 4: %+v", len(fields), fields)
	}
	if fields[0].Label != "IP" || fields[0].Value != "10.0.0.10" {
		t.Fatalf("first field = %+v", fields[0])
	}
	serviceFields := data.Fields(service)
	if serviceFields[0].Label != "Target" || serviceFields[0].Value != "dc01" {
		t.Fatalf("target_id was not resolved: %+v", serviceFields[0])
	}

	html, err := HTML(data)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	for _, want := range []string{"Demo", "dc01", "IP", "10.0.0.10", "80/tcp http", "exposes"} {
		if !strings.Contains(html, want) {
			t.Fatalf("HTML missing %q", want)
		}
	}
	if strings.Contains(html, `{"ip"`) {
		t.Fatal("HTML leaked raw JSON instead of rendered fields")
	}

	markdown := Markdown(data)
	for _, want := range []string{"**IP:** 10.0.0.10", "**Service:** http", "exposes"} {
		if !strings.Contains(markdown, want) {
			t.Fatalf("Markdown missing %q:\n%s", want, markdown)
		}
	}
	if strings.Contains(markdown, `{"ip"`) {
		t.Fatal("Markdown leaked raw JSON instead of rendered fields")
	}
}

func TestFieldsResolveServiceAndKeepMultiline(t *testing.T) {
	d := &Data{nodeTitles: map[string]string{"svc-1": "80/tcp http"}}
	e := domain.Entity{
		Kind: domain.KindFinding,
		Data: map[string]any{
			"service_id": "svc-1",
			"vuln_type":  "SQL Injection",
			"payload":    "id=1'\nUNION SELECT",
			"repro":      "1. login\n2. inject",
			"phase_history": []any{
				map[string]any{"phase": "scan", "status": "new"},
				map[string]any{"phase": "initial_access", "status": "confirmed"},
			},
		},
	}
	fields := d.Fields(e)
	byLabel := map[string]Field{}
	for _, field := range fields {
		byLabel[field.Label] = field
	}
	if _, ok := byLabel["Phase history"]; !ok {
		t.Fatalf("phase history field missing: %+v", fields)
	}
	if got := byLabel["Phase history"].Value; got != "scan: new → initial_access: confirmed" {
		t.Fatalf("phase history = %q", got)
	}
	service, ok := byLabel["Service"]
	if !ok || service.Value != "80/tcp http" {
		t.Fatalf("service_id not resolved: %+v", service)
	}
	payload, ok := byLabel["Payload"]
	if !ok || !payload.Multiline {
		t.Fatalf("payload should be multiline: %+v", payload)
	}
	repro, ok := byLabel["Reproduction"]
	if !ok || !repro.Multiline {
		t.Fatalf("repro should be multiline: %+v", repro)
	}
	data := &Data{
		Project:    domain.Project{Name: "Demo"},
		Columns:    []domain.BoardColumn{{Phase: domain.DefaultPhases[0], Entities: []domain.Entity{e}}},
		Graph:      &domain.Graph{Nodes: []domain.Entity{e}},
		nodeTitles: map[string]string{"svc-1": "80/tcp http"},
	}
	markdown := Markdown(data)
	if !strings.Contains(markdown, "        UNION SELECT") {
		t.Fatalf("Markdown flattened multiline payload:\n%s", markdown)
	}
}

func TestSeverityTotals(t *testing.T) {
	got := severityTotals([]domain.Entity{
		{Kind: domain.KindFinding, Data: map[string]any{"severity": "high"}},
		{Kind: domain.KindFinding, Data: map[string]any{"severity": "High"}},
		{Kind: domain.KindFinding, Data: map[string]any{"severity": "low"}},
		{Kind: domain.KindFinding, Data: map[string]any{"severity": "bogus"}},
		{Kind: domain.KindFinding, Data: map[string]any{}},
		{Kind: domain.KindTarget, Data: map[string]any{}},
	})
	byLabel := map[string]int{}
	total := 0
	for _, count := range got {
		byLabel[count.Label] = count.Count
		total += count.Count
	}
	if byLabel["High"] != 2 || byLabel["Low"] != 1 || byLabel["Unclassified"] != 1 || byLabel["bogus"] != 1 {
		t.Fatalf("severity totals = %+v", got)
	}
	if total != 5 {
		t.Fatalf("severity total = %d, want 5", total)
	}
	if byLabel["Critical"] != 0 {
		t.Fatalf("critical should be zero: %+v", got)
	}
}
