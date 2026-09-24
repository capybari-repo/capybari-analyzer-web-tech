package webtech_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	webtech "github.com/capybari-repo/capybari-analyzer-web-tech"
	"github.com/capybari-repo/capybari-core/analyzer"
	"github.com/capybari-repo/capybari-core/analyzertest"
	"github.com/capybari-repo/capybari-core/facts"
	"github.com/capybari-repo/capybari-schemas"
	"gopkg.in/yaml.v3"
)

func TestCapabilityMetadata(t *testing.T) {
	b, err := os.ReadFile("capability.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := analyzer.ParseCapability(b); err != nil {
		t.Fatal(err)
	}
	var doc any
	yaml.Unmarshal(b, &doc)
	if err := schemas.ValidateValue("capability.schema.json", doc); err != nil {
		t.Fatal(err)
	}
}

// site serves the static-site fixture with WordPress-style headers.
func site(t *testing.T) *httptest.Server {
	body, err := os.ReadFile("../capybari-fixtures/static-site/index.html")
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.Header().Set("X-Powered-By", "PHP/7.4.3")
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "x"})
		w.Header().Set("Content-Type", "text/html")
		w.Write(body)
	}))
}

func TestDetectsStackEOLAndStaleness(t *testing.T) {
	s := site(t)
	defer s.Close()
	r := analyzertest.Run(t, webtech.New(), analyzertest.Website(s.URL), analyzertest.Options{Online: true})
	tech := analyzertest.Fact[facts.Technologies](t, r, facts.KeyTechnologies)
	got := map[string]string{}
	for _, it := range tech.Items {
		got[it.Name] = it.Version
	}
	for name, ver := range map[string]string{"Nginx": "1.18.0", "PHP": "7.4.3", "WordPress": "5.8.1", "jQuery": "1.12.4", "Google Analytics": ""} {
		if v, ok := got[name]; !ok || v != ver {
			t.Errorf("%s: got %q (present %v), want %q", name, v, ok, ver)
		}
	}
	var titles []string
	for _, f := range r.Findings {
		titles = append(titles, f.Title)
	}
	joined := strings.Join(titles, "|")
	for _, want := range []string{"PHP 7.4, which is end-of-life", "jQuery 1, which is end-of-life", "WordPress 5, which is end-of-life", "Copyright notice last updated in 2019"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing finding %q in %v", want, titles)
		}
	}
}

func TestVulnerableLibraryLookup(t *testing.T) {
	osv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Queries []struct {
				Package struct{ Name string } `json:"package"`
				Version string                `json:"version"`
			} `json:"queries"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		var res []map[string]any
		for _, q := range body.Queries {
			if q.Package.Name == "jquery" && q.Version == "1.12.4" {
				res = append(res, map[string]any{"vulns": []map[string]string{{"id": "GHSA-a"}, {"id": "GHSA-b"}, {"id": "GHSA-c"}}})
			} else {
				res = append(res, map[string]any{})
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"results": res})
	}))
	defer osv.Close()
	s := site(t)
	defer s.Close()
	// Take a real snapshot, then run the analyzer directly with an HTTP
	// client pointed at the mock OSV (the engine only allows api.osv.dev).
	_, st := analyzertest.RunState(t, webtech.New(), analyzertest.Website(s.URL), analyzertest.Options{Online: true})
	a := &webtech.Analyzer{OSVBaseURL: osv.URL}
	in := &analyzer.Input{Target: analyzertest.Website(s.URL), Evidence: st, HTTP: osv.Client(), Now: func() time.Time { return analyzertest.FixedTime }}
	res, err := a.Analyze(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range res.Findings {
		if f.Category == "vulnerable-library" {
			found = true
			if f.Component != "jquery@1.12.4" || f.Severity != "high" || len(f.Related) != 3 {
				t.Fatalf("vulnerable library finding: %+v", f)
			}
		}
	}
	if !found {
		t.Fatal("no vulnerable-library finding")
	}
}
