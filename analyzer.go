// Package webtech implements the Website Technology Detector: technologies
// behind a public website, end-of-life and vulnerable front-end libraries,
// and stale-site signals, all from the Website Snapshot.
package webtech

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/capybari/capybari-core/analyzer"
	"github.com/capybari/capybari-core/facts"
	"github.com/capybari/capybari-core/finding"
	"github.com/capybari/capybari-core/lifecycle"
)

//go:embed capability.yaml
var capabilityYAML []byte

//go:embed rules/signatures.yaml
var signaturesYAML []byte

var capability = analyzer.MustParseCapability(capabilityYAML)

// Rule is one detection pattern.
type Rule struct {
	Where   string `yaml:"where"`
	Pattern string `yaml:"pattern"`
	re      *regexp.Regexp
}

// Signature describes one technology.
type Signature struct {
	Name     string `yaml:"name"`
	Category string `yaml:"category"`
	NPM      string `yaml:"npm"` // npm package name for vulnerability lookup
	Rules    []Rule `yaml:"rules"`
}

var signatures = func() []Signature {
	var sigs []Signature
	if err := yaml.Unmarshal(signaturesYAML, &sigs); err != nil {
		panic(err)
	}
	for i := range sigs {
		for j := range sigs[i].Rules {
			sigs[i].Rules[j].re = regexp.MustCompile(sigs[i].Rules[j].Pattern)
		}
	}
	return sigs
}()

// Analyzer implements the capability.
type Analyzer struct {
	// OSVBaseURL overrides the OSV endpoint (tests).
	OSVBaseURL string
}

// New returns the capability.
func New() *Analyzer { return &Analyzer{} }

// Capability implements analyzer.Analyzer.
func (*Analyzer) Capability() analyzer.Capability { return capability }

type hit struct {
	sig      *Signature
	version  string
	evidence []string
}

// Analyze implements analyzer.Analyzer.
func (a *Analyzer) Analyze(ctx context.Context, in *analyzer.Input) (*analyzer.Result, error) {
	var ws facts.WebSnapshot
	if _, err := in.Evidence.Get(facts.KeyWebSnapshot, &ws); err != nil {
		return nil, err
	}
	hits := detect(&ws)

	var items []facts.Technology
	var findings []finding.Finding
	today := in.Now()
	for _, h := range hits {
		t := facts.Technology{Name: h.sig.Name, Category: h.sig.Category, Version: h.version, Confidence: "high", Evidence: h.evidence}
		if st, ok := lifecycle.Check(t.Name, t.Version, today); ok {
			t.EOL = st.Date
			findings = append(findings, eolFinding(t, st, ws.FinalURL))
		}
		items = append(items, t)
	}

	var limits []string
	if in.HTTP != nil {
		vf, err := a.vulnerableLibraries(ctx, in.HTTP, hits, ws.FinalURL)
		if err != nil {
			limits = append(limits, "Front-end library vulnerability lookup failed: "+err.Error())
		}
		findings = append(findings, vf...)
	} else {
		limits = append(limits, "Offline: front-end library versions were not checked for known vulnerabilities.")
	}
	findings = append(findings, maintenanceSignals(&ws, today)...)
	limits = append(limits, "Detection uses the front page only. Technologies used only on other pages, or hidden server-side, are not visible.")

	names := make([]string, 0, len(items))
	for _, t := range items {
		names = append(names, t.Name)
	}
	return &analyzer.Result{
		Evidence:    map[string]any{facts.KeyTechnologies: &facts.Technologies{Items: items}},
		Findings:    findings,
		Summary:     fmt.Sprintf("%d technologies: %s", len(items), strings.Join(names, ", ")),
		Limitations: limits,
	}, nil
}

// detect runs every signature against the snapshot.
func detect(ws *facts.WebSnapshot) []hit {
	var cookies []string
	for _, c := range ws.Cookies {
		cookies = append(cookies, c.Name)
	}
	var resources []string
	for _, r := range ws.Resources {
		resources = append(resources, r.URL)
	}
	var out []hit
	for i := range signatures {
		sig := &signatures[i]
		var h *hit
		for _, r := range sig.Rules {
			var subjects []string
			switch {
			case strings.HasPrefix(r.Where, "header:"):
				if v := ws.Header(strings.TrimPrefix(r.Where, "header:")); v != "" {
					subjects = []string{v}
				}
			case strings.HasPrefix(r.Where, "meta:"):
				if v := ws.Meta[strings.TrimPrefix(r.Where, "meta:")]; v != "" {
					subjects = []string{v}
				}
			case r.Where == "cookie":
				subjects = cookies
			case r.Where == "script":
				subjects = resources
			case r.Where == "html":
				subjects = []string{ws.Body}
			case r.Where == "url":
				subjects = []string{ws.FinalURL}
			}
			for _, s := range subjects {
				m := r.re.FindStringSubmatch(s)
				if m == nil {
					continue
				}
				if h == nil {
					h = &hit{sig: sig}
				}
				for gi, name := range r.re.SubexpNames() {
					if name == "version" && m[gi] != "" && h.version == "" {
						h.version = strings.Trim(m[gi], ".")
					}
				}
				ev := r.Where
				if r.Where == "script" || r.Where == "cookie" {
					ev = r.Where + ": " + truncate(s, 120)
				} else if r.Where != "html" {
					ev = r.Where + ": " + truncate(s, 80)
				}
				if len(h.evidence) < 3 && !contains(h.evidence, ev) {
					h.evidence = append(h.evidence, ev)
				}
			}
		}
		if h != nil {
			out = append(out, *h)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].sig.Category < out[j].sig.Category })
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func eolFinding(t facts.Technology, st *lifecycle.Status, url string) finding.Finding {
	sev := finding.Medium
	switch st.Product.Kind {
	case "runtime":
		sev = finding.High
	case "library":
		sev = finding.Low
	}
	when := "reached end-of-life on " + st.Date
	if st.Date == "unsupported" {
		when = "is no longer supported by its maintainers"
	}
	var ev []finding.Evidence
	for _, e := range t.Evidence {
		ev = append(ev, finding.Evidence{Location: finding.Location{URL: url}, Detail: e})
	}
	return finding.Finding{
		Dimension: finding.DimEvolution, Category: "end-of-life", Severity: sev, Confidence: finding.ConfidenceHigh,
		Title:       fmt.Sprintf("Website runs %s %s, which is end-of-life", t.Name, st.Cycle),
		Description: fmt.Sprintf("%s %s %s and no longer receives security fixes.", t.Name, t.Version, when),
		Evidence:    ev,
		Component:   t.Name,
		Rule:        &finding.Rule{ID: "web-eol-" + strings.ToLower(strings.ReplaceAll(t.Name, " ", "-")), References: []string{st.Product.Source}},
		Remediation: &finding.Remediation{Summary: fmt.Sprintf("Upgrade %s to a supported release.", t.Name), Automatable: false},
	}
}

// vulnerableLibraries looks up detected, versioned front-end libraries in OSV.
func (a *Analyzer) vulnerableLibraries(ctx context.Context, c *http.Client, hits []hit, url string) ([]finding.Finding, error) {
	type q struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Version string `json:"version"`
	}
	var queries []q
	var libs []hit
	for _, h := range hits {
		if h.sig.NPM == "" || h.version == "" || strings.Count(h.version, ".") < 2 {
			continue
		}
		var x q
		x.Package.Name, x.Package.Ecosystem, x.Version = h.sig.NPM, "npm", h.version
		queries = append(queries, x)
		libs = append(libs, h)
	}
	if len(queries) == 0 {
		return nil, nil
	}
	base := a.OSVBaseURL
	if base == "" {
		base = "https://api.osv.dev"
	}
	body, _ := json.Marshal(map[string]any{"queries": queries})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/querybatch", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("OSV HTTP %d", resp.StatusCode)
	}
	var out struct {
		Results []struct {
			Vulns []struct {
				ID string `json:"id"`
			} `json:"vulns"`
		} `json:"results"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&out); err != nil {
		return nil, err
	}
	var fs []finding.Finding
	for i, r := range out.Results {
		if i >= len(libs) || len(r.Vulns) == 0 {
			continue
		}
		h := libs[i]
		var ids, refs []string
		for _, v := range r.Vulns {
			ids = append(ids, v.ID)
			if len(refs) < 5 {
				refs = append(refs, "https://osv.dev/vulnerability/"+v.ID)
			}
		}
		sev := finding.Medium
		if len(ids) >= 3 {
			sev = finding.High
		}
		fs = append(fs, finding.Finding{
			Dimension: finding.DimSecurity, Category: "vulnerable-library", Severity: sev, Confidence: finding.ConfidenceMedium,
			Title:                 fmt.Sprintf("Website loads %s %s with %d known vulnerabilit%s", h.sig.Name, h.version, len(ids), map[bool]string{true: "y", false: "ies"}[len(ids) == 1]),
			Description:           fmt.Sprintf("Advisories: %s. Client-side library vulnerabilities (typically XSS or prototype pollution) are exploitable when the affected functions process attacker-controlled input.", strings.Join(ids, ", ")),
			Evidence:              []finding.Evidence{{Location: finding.Location{URL: url}, Detail: strings.Join(h.evidence, "; ")}},
			Component:             h.sig.NPM + "@" + h.version,
			Related:               ids,
			Rule:                  &finding.Rule{ID: ids[0], References: refs},
			Remediation:           &finding.Remediation{Summary: fmt.Sprintf("Upgrade %s to the latest release and serve it with Subresource Integrity.", h.sig.Name), Automatable: false},
			FalsePositiveGuidance: "The version is read from the script URL. Self-hosted, patched copies with the original file name can be misidentified.",
		})
	}
	return fs, nil
}

var (
	copyrightRe = regexp.MustCompile(`(?i)(?:©|&copy;|copyright)\s*(?:\d{4}\s*[-–]\s*)?((?:19|20)\d{2})`)
	tagRe       = regexp.MustCompile(`<[^>]+>`)
)

// maintenanceSignals flags indicators that a site is no longer maintained.
func maintenanceSignals(ws *facts.WebSnapshot, today time.Time) []finding.Finding {
	var out []finding.Finding
	text := tagRe.ReplaceAllString(ws.Body, " ")
	latest := 0
	for _, m := range copyrightRe.FindAllStringSubmatch(text, -1) {
		if y, err := strconv.Atoi(m[1]); err == nil && y > latest && y <= today.Year() {
			latest = y
		}
	}
	if latest > 0 && today.Year()-latest >= 3 {
		out = append(out, finding.Finding{
			Dimension: finding.DimEvolution, Category: "maintenance-signal", Severity: finding.Low, Confidence: finding.ConfidenceLow,
			Title:       fmt.Sprintf("Copyright notice last updated in %d", latest),
			Description: fmt.Sprintf("The most recent year in the page's copyright notice is %d, %d years ago. That often (not always) means nobody is actively maintaining the site.", latest, today.Year()-latest),
			Evidence:    []finding.Evidence{{Location: finding.Location{URL: ws.FinalURL}, Detail: fmt.Sprintf("© %d", latest)}},
			Rule:        &finding.Rule{ID: "stale-copyright"},
			Remediation: &finding.Remediation{Summary: "Confirm who maintains the site and when its software was last updated.", Automatable: false},
		})
	}
	return out
}
