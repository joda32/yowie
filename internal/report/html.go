package report

import (
	"html/template"
	"io"
	"sort"
	"time"

	"github.com/joda32/yowie/internal/model"
)

// HTML writes a self-contained report suitable for handing to a stakeholder.
// Everything is inlined: no external CSS, fonts or scripts, so the file works
// from a mail attachment or a share drive.
func HTML(w io.Writer, r *model.Result) error {
	high, medium, low := countByConfidence(r.Findings)

	byCategory := map[string]int{}
	for _, f := range r.Findings {
		c := f.Category
		if c == "" {
			c = "Uncategorised"
		}
		byCategory[c]++
	}
	categories := make([]categoryCount, 0, len(byCategory))
	for name, n := range byCategory {
		categories = append(categories, categoryCount{Name: name, Count: n})
	}
	sort.Slice(categories, func(i, j int) bool {
		if categories[i].Count != categories[j].Count {
			return categories[i].Count > categories[j].Count
		}
		return categories[i].Name < categories[j].Name
	})

	groups := make([]confidenceGroup, 0, 3)
	grouped := groupByConfidence(r.Findings)
	for _, c := range confidenceOrder {
		if len(grouped[c]) == 0 {
			continue
		}
		groups = append(groups, confidenceGroup{
			Confidence: string(c),
			Label:      confidenceLabel(c),
			Findings:   grouped[c],
		})
	}

	return htmlTemplate.Execute(w, htmlData{
		Result:     r,
		Generated:  time.Now().Format("2 January 2006, 15:04 MST"),
		High:       high,
		Medium:     medium,
		Low:        low,
		Categories: categories,
		Groups:     groups,
		DurationMS: r.Duration.Round(time.Millisecond).String(),
	})
}

type htmlData struct {
	Result     *model.Result
	Generated  string
	High       int
	Medium     int
	Low        int
	Categories []categoryCount
	Groups     []confidenceGroup
	DurationMS string
}

type categoryCount struct {
	Name  string
	Count int
}

type confidenceGroup struct {
	Confidence string
	Label      string
	Findings   []model.Finding
}

var htmlTemplate = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SaaS discovery — {{.Result.Domain}}</title>
<style>
  :root {
    --bg: #ffffff; --panel: #f6f7f9; --border: #e2e5ea; --ink: #14171c;
    --muted: #666e7a; --high: #17714a; --high-bg: #e6f4ec;
    --medium: #8a5a00; --medium-bg: #fdf1dc; --low: #4a5261; --low-bg: #eef0f3;
    --accent: #0b4f9e;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #14171c; --panel: #1c2029; --border: #2c313b; --ink: #e8eaee;
      --muted: #99a1ad; --high: #6ddba4; --high-bg: #12291f;
      --medium: #e8b757; --medium-bg: #2c2415; --low: #99a1ad; --low-bg: #21252d;
      --accent: #6fb0f5;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 2rem 1.25rem 4rem; background: var(--bg); color: var(--ink);
    font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }
  .wrap { max-width: 1000px; margin: 0 auto; }
  header { border-bottom: 2px solid var(--border); padding-bottom: 1.25rem; margin-bottom: 1.75rem; }
  h1 { margin: 0 0 .35rem; font-size: 1.6rem; letter-spacing: -.01em; }
  h1 span { color: var(--accent); }
  .sub { color: var(--muted); font-size: .875rem; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: .75rem; margin: 1.5rem 0; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: .9rem 1rem; }
  .card .n { font-size: 1.75rem; font-weight: 650; line-height: 1.1; }
  .card .l { color: var(--muted); font-size: .78rem; text-transform: uppercase; letter-spacing: .05em; margin-top: .2rem; }
  .card.high .n { color: var(--high); } .card.medium .n { color: var(--medium); } .card.low .n { color: var(--low); }
  h2 { font-size: 1.05rem; margin: 2rem 0 .3rem; display: flex; align-items: center; gap: .6rem; }
  .pill { font-size: .7rem; font-weight: 600; text-transform: uppercase; letter-spacing: .05em;
          padding: .18rem .5rem; border-radius: 999px; }
  .pill.high { color: var(--high); background: var(--high-bg); }
  .pill.medium { color: var(--medium); background: var(--medium-bg); }
  .pill.low { color: var(--low); background: var(--low-bg); }
  .blurb { color: var(--muted); font-size: .85rem; margin: 0 0 .9rem; }
  .finding { border: 1px solid var(--border); border-radius: 10px; margin-bottom: .6rem; background: var(--panel); overflow: hidden; }
  .finding > summary { cursor: pointer; padding: .75rem 1rem; display: flex; align-items: baseline;
                       gap: .75rem; flex-wrap: wrap; list-style: none; }
  .finding > summary::-webkit-details-marker { display: none; }
  .finding > summary::before { content: "▸"; color: var(--muted); font-size: .8rem; }
  .finding[open] > summary::before { content: "▾"; }
  .vendor { font-weight: 620; }
  .cat { color: var(--muted); font-size: .8rem; }
  .count { margin-left: auto; color: var(--muted); font-size: .78rem; }
  .body { padding: 0 1rem 1rem 2rem; }
  table { width: 100%; border-collapse: collapse; font-size: .82rem; }
  th { text-align: left; color: var(--muted); font-weight: 600; padding: .3rem .5rem .3rem 0;
       border-bottom: 1px solid var(--border); text-transform: uppercase; font-size: .7rem; letter-spacing: .04em; }
  td { padding: .35rem .5rem .35rem 0; border-bottom: 1px solid var(--border); vertical-align: top;
       font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; word-break: break-word; }
  td.m { color: var(--accent); white-space: nowrap; }
  .note { margin-top: .7rem; padding: .55rem .75rem; border-left: 3px solid var(--medium);
          background: var(--medium-bg); border-radius: 0 6px 6px 0; font-size: .82rem; }
  .cats { display: flex; flex-wrap: wrap; gap: .4rem; margin: 1rem 0 0; }
  .cats span { font-size: .78rem; background: var(--panel); border: 1px solid var(--border);
               border-radius: 999px; padding: .2rem .6rem; }
  footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border);
           color: var(--muted); font-size: .78rem; }
  details.warnings { margin-top: 1.5rem; }
  details.warnings summary { cursor: pointer; color: var(--muted); font-size: .85rem; }
  details.warnings ul { font-size: .8rem; color: var(--muted); }
  .empty { padding: 2rem; text-align: center; color: var(--muted); background: var(--panel);
           border: 1px dashed var(--border); border-radius: 10px; }
  @media print { body { padding: 0; } .finding { break-inside: avoid; } .finding > summary::before { content: ""; } }
</style>
</head>
<body>
<div class="wrap">

<header>
  <h1>SaaS discovery — <span>{{.Result.Domain}}</span></h1>
  <div class="sub">
    Generated {{.Generated}}
    {{if .Result.Candidates}}· Candidates: {{range $i, $c := .Result.Candidates}}{{if $i}}, {{end}}{{$c}}{{end}}{{end}}
  </div>
</header>

<div class="cards">
  <div class="card"><div class="n">{{len .Result.Findings}}</div><div class="l">Services</div></div>
  <div class="card high"><div class="n">{{.High}}</div><div class="l">Confirmed</div></div>
  <div class="card medium"><div class="n">{{.Medium}}</div><div class="l">Probable</div></div>
  <div class="card low"><div class="n">{{.Low}}</div><div class="l">Leads</div></div>
</div>

{{if .Categories}}
<div class="cats">
  {{range .Categories}}<span>{{.Name}} · {{.Count}}</span>{{end}}
</div>
{{end}}

{{if not .Result.Findings}}
  <div class="empty">
    No SaaS services were identified. {{.Result.Stats.Signatures}} signatures were evaluated
    across {{.Result.Stats.DNSQueries}} DNS queries and {{.Result.Stats.HTTPRequests}} HTTP requests.
  </div>
{{end}}

{{range .Groups}}
  <h2>{{.Label}} <span class="pill {{.Confidence}}">{{.Confidence}}</span></h2>
  <p class="blurb">
    {{if eq .Confidence "high"}}Vendor-issued, domain-scoped indicators. Treat these as in use.
    {{else if eq .Confidence "medium"}}Strong indicators that could also be explained by shared infrastructure or a namespace claimed by someone else. Confirm before acting.
    {{else}}Weak or unattributed indicators, including senders and hosts matching no known vendor. These are the most likely place to find something nobody told you about — and the most likely to be noise.{{end}}
  </p>

  {{range .Findings}}
  <details class="finding">
    <summary>
      <span class="vendor">{{.Vendor}}</span>
      {{if .Category}}<span class="cat">{{.Category}}</span>{{end}}
      <span class="count">{{len .Evidence}} item{{if ne (len .Evidence) 1}}s{{end}} of evidence</span>
    </summary>
    <div class="body">
      <table>
        <thead><tr><th>Method</th><th>Query</th><th>Observed</th></tr></thead>
        <tbody>
        {{range .Evidence}}
          <tr>
            <td class="m">{{.Method}}</td>
            <td>{{.Query}}</td>
            <td>{{.Value}}{{if .Detail}}<br><span class="cat">{{.Detail}}</span>{{end}}</td>
          </tr>
        {{end}}
        </tbody>
      </table>
      {{range .Notes}}<div class="note">{{.}}</div>{{end}}
    </div>
  </details>
  {{end}}
{{end}}

{{if .Result.Errors}}
<details class="warnings">
  <summary>{{len .Result.Errors}} warning(s) during the scan — the result may be incomplete</summary>
  <ul>{{range .Result.Errors}}<li>{{.}}</li>{{end}}</ul>
</details>
{{end}}

<footer>
  Yowie · {{.Result.Stats.Signatures}} signatures ·
  {{.Result.Stats.DNSQueries}} DNS queries ({{.Result.Stats.DNSCacheHits}} cached) ·
  {{.Result.Stats.HTTPRequests}} HTTP requests · {{.DurationMS}}
  <br>All findings derive from publicly observable data. Confirm before acting on anything below "Confirmed".
</footer>

</div>
</body>
</html>
`))
