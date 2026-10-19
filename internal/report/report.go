// Package report renders project snapshots as HTML or Markdown.
package report

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"sort"
	"strings"
	"time"

	"shadowedge/internal/domain"
	"shadowedge/internal/store"
)

type Totals struct {
	Entities    int `json:"entities"`
	Targets     int `json:"targets"`
	Findings    int `json:"findings"`
	Credentials int `json:"credentials"`
	Commands    int `json:"commands"`
	Edges       int `json:"edges"`
}

type Field struct {
	Label     string
	Value     string
	Multiline bool
}

type Data struct {
	Project     domain.Project
	Columns     []domain.BoardColumn
	Graph       *domain.Graph
	GeneratedAt string
	GeneratedBy string
	Totals      Totals
	nodeTitles  map[string]string
}

// NodeTitle resolves an entity ID to its title for the attack-chain section.
func (d *Data) NodeTitle(id string) string {
	if title, ok := d.nodeTitles[id]; ok {
		return title
	}
	return id
}

var fieldLabels = map[string]string{
	"ip": "IP", "hostname": "Hostname", "os": "OS", "tags": "Tags",
	"target_id": "Target", "port": "Port", "protocol": "Protocol", "name": "Service",
	"product": "Product", "version": "Version", "severity": "Severity", "cve": "CVE",
	"cvss": "CVSS", "description": "Description", "evidence": "Evidence",
	"username": "Username", "secret": "Secret", "source": "Source",
	"filename": "Filename", "sha256": "SHA-256", "storage_path": "Storage path", "size": "Size",
	"command": "Command", "output": "Output", "exit_code": "Exit code",
	"assignee": "Assignee", "due_at": "Due", "done_at": "Done", "text": "Text",
}

var fieldOrder = map[domain.EntityKind][]string{
	domain.KindTarget:     {"ip", "hostname", "os", "tags"},
	domain.KindService:    {"target_id", "port", "protocol", "name", "product", "version"},
	domain.KindFinding:    {"target_id", "severity", "cve", "cvss", "description", "evidence"},
	domain.KindCredential: {"protocol", "username", "secret", "source"},
	domain.KindEvidence:   {"filename", "sha256", "storage_path", "size"},
	domain.KindCommand:    {"target_id", "command", "output", "exit_code"},
	domain.KindTask:       {"assignee", "due_at", "done_at", "text"},
	domain.KindNote:       {"text"},
	domain.KindAction:     {"text"},
}

// Fields turns an entity's JSON payload into human-readable label/value rows.
func (d *Data) Fields(e domain.Entity) []Field {
	if e.Data == nil {
		return nil
	}
	keys := make([]string, 0, len(e.Data))
	seen := map[string]bool{}
	for _, key := range fieldOrder[e.Kind] {
		if _, ok := e.Data[key]; ok {
			keys = append(keys, key)
			seen[key] = true
		}
	}
	var rest []string
	for key := range e.Data {
		if !seen[key] {
			rest = append(rest, key)
		}
	}
	sort.Strings(rest)
	keys = append(keys, rest...)

	fields := make([]Field, 0, len(keys))
	for _, key := range keys {
		value := e.Data[key]
		if value == nil || fmt.Sprint(value) == "" {
			continue
		}
		text := fmt.Sprint(value)
		if key == "target_id" {
			text = d.NodeTitle(text)
		}
		label := fieldLabels[key]
		if label == "" {
			label = key
		}
		fields = append(fields, Field{
			Label: label, Value: text,
			Multiline: key == "command" || key == "output" || key == "description" ||
				key == "evidence" || key == "text",
		})
	}
	return fields
}

func Build(ctx context.Context, st *store.Store, projectID, generatedBy string) (*Data, error) {
	project, err := st.GetProject(ctx, projectID)
	if err != nil {
		return nil, err
	}
	columns, err := st.Board(ctx, projectID)
	if err != nil {
		return nil, err
	}
	graph, err := st.Graph(ctx, projectID)
	if err != nil {
		return nil, err
	}

	d := &Data{
		Project: *project, Columns: columns, Graph: graph,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		GeneratedBy: generatedBy, nodeTitles: map[string]string{},
	}
	for _, n := range graph.Nodes {
		d.nodeTitles[n.ID] = n.Title
		d.Totals.Entities++
		switch n.Kind {
		case domain.KindTarget:
			d.Totals.Targets++
		case domain.KindFinding:
			d.Totals.Findings++
		case domain.KindCredential:
			d.Totals.Credentials++
		case domain.KindCommand:
			d.Totals.Commands++
		}
	}
	d.Totals.Edges = len(graph.Edges)
	return d, nil
}

var reportTemplate = template.Must(template.New("report").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ShadowEdge Report - {{.Project.Name}}</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;max-width:980px;margin:0 auto;padding:32px;color:#111827;line-height:1.55;background:#fff}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin-top:28px;border-bottom:2px solid #1f2937;padding-bottom:6px}
h3{font-size:14px;margin:18px 0 6px;color:#374151}
.meta{color:#6b7280;font-size:12px;margin-bottom:20px}
table{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:12px}
th,td{border:1px solid #e5e7eb;padding:6px 8px;text-align:left;vertical-align:top}
th{background:#f3f4f6}
code{font-size:11px;word-break:break-word}
.edge{margin:4px 0;font-size:13px}
.f{font-size:11px;margin:3px 0}
.f span{color:#6b7280;text-transform:uppercase;font-size:9px;letter-spacing:.5px;margin-right:4px}
.f pre{margin:2px 0;padding:6px;font-size:10px;background:#f8fafc;border:1px solid #e5e7eb;white-space:pre-wrap}
.footer{margin-top:36px;padding-top:12px;border-top:1px solid #e5e7eb;color:#9ca3af;font-size:11px;text-align:center}
</style>
</head>
<body>
<h1>ShadowEdge Report</h1>
<div class="meta">{{.Project.Name}} · generated {{.GeneratedAt}} by {{.GeneratedBy}}</div>

<h2>Executive summary</h2>
<table>
<tr><th>Description</th><td>{{.Project.Description}}</td></tr>
<tr><th>Entities</th><td>{{.Totals.Entities}}</td></tr>
<tr><th>Targets</th><td>{{.Totals.Targets}}</td></tr>
<tr><th>Findings</th><td>{{.Totals.Findings}}</td></tr>
<tr><th>Credentials</th><td>{{.Totals.Credentials}}</td></tr>
<tr><th>Commands</th><td>{{.Totals.Commands}}</td></tr>
<tr><th>DAG links</th><td>{{.Totals.Edges}}</td></tr>
</table>

<h2>Phase coverage</h2>
{{range .Columns}}
<h3>{{.Phase.NameEN}} ({{len .Entities}})</h3>
{{if .Entities}}
<table>
<tr><th>Title</th><th>Kind</th><th>Status</th><th>Details</th></tr>
{{range .Entities}}<tr><td>{{.Title}}</td><td>{{.Kind}}</td><td>{{.Status}}</td><td>{{range $.Fields .}}<div class="f"><span>{{.Label}}</span>{{if .Multiline}}<pre>{{.Value}}</pre>{{else}} {{.Value}}{{end}}</div>{{end}}</td></tr>{{end}}
</table>
{{else}}<div class="meta">No entities in this phase.</div>{{end}}
{{end}}

<h2>Attack chain</h2>
{{if .Graph.Edges}}
{{range .Graph.Edges}}<div class="edge">{{$.NodeTitle .FromEntityID}} &rarr; {{$.NodeTitle .ToEntityID}}{{if .Label}} <span class="meta">({{.Label}})</span>{{end}}</div>{{end}}
{{else}}<div class="meta">No DAG links recorded.</div>{{end}}

<div class="footer">Generated by ShadowEdge · authorized testing only</div>
</body>
</html>`))

func HTML(data *Data) (string, error) {
	var buf bytes.Buffer
	if err := reportTemplate.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func Markdown(data *Data) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# ShadowEdge Report - %s\n\n", md(data.Project.Name))
	fmt.Fprintf(&b, "Generated: %s by %s\n\n", data.GeneratedAt, md(data.GeneratedBy))

	b.WriteString("## Executive summary\n\n")
	b.WriteString("| Item | Value |\n|---|---|\n")
	fmt.Fprintf(&b, "| Description | %s |\n", md(data.Project.Description))
	fmt.Fprintf(&b, "| Entities | %d |\n", data.Totals.Entities)
	fmt.Fprintf(&b, "| Targets | %d |\n", data.Totals.Targets)
	fmt.Fprintf(&b, "| Findings | %d |\n", data.Totals.Findings)
	fmt.Fprintf(&b, "| Credentials | %d |\n", data.Totals.Credentials)
	fmt.Fprintf(&b, "| Commands | %d |\n", data.Totals.Commands)
	fmt.Fprintf(&b, "| DAG links | %d |\n\n", data.Totals.Edges)

	b.WriteString("## Phase coverage\n\n")
	for _, col := range data.Columns {
		b.WriteString("### " + md(col.Phase.NameEN) + fmt.Sprintf(" (%d)\n\n", len(col.Entities)))
		if len(col.Entities) == 0 {
			b.WriteString("_No entities in this phase._\n\n")
			continue
		}
		for _, e := range col.Entities {
			fmt.Fprintf(&b, "- **%s** — %s / %s\n", md(e.Title), e.Kind, e.Status)
			for _, f := range data.Fields(e) {
				fmt.Fprintf(&b, "  - **%s:** %s\n", md(f.Label), md(f.Value))
			}
		}
		b.WriteString("\n")
	}

	b.WriteString("## Attack chain\n\n")
	if len(data.Graph.Edges) == 0 {
		b.WriteString("_No DAG links recorded._\n")
	} else {
		for _, edge := range data.Graph.Edges {
			fmt.Fprintf(&b, "- %s → %s", md(data.NodeTitle(edge.FromEntityID)), md(data.NodeTitle(edge.ToEntityID)))
			if edge.Label != "" {
				fmt.Fprintf(&b, " _(%s)_", md(edge.Label))
			}
			b.WriteString("\n")
		}
	}
	b.WriteString("\n---\nGenerated by ShadowEdge · authorized testing only\n")
	return b.String()
}

func md(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
