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
