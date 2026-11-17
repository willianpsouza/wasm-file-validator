package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestRouterRoutes(t *testing.T) {
	dir := t.TempDir()
	must := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must("index.html", "<!doctype html><title>t</title>")
	must("app.wasm", "\x00asm")

	srv := httptest.NewServer(newRouter(dir))
	defer srv.Close()

	cases := []struct {
		path        string
		wantStatus  int
		wantCTHas   string
	}{
		{"/", http.StatusOK, "text/html"},
		{"/app.wasm", http.StatusOK, "application/wasm"},
		{"/api/health", http.StatusOK, "text/plain"},
	}
	for _, c := range cases {
		resp, err := http.Get(srv.URL + c.path)
		if err != nil {
			t.Fatalf("%s: %v", c.path, err)
		}
		if resp.StatusCode != c.wantStatus {
			t.Errorf("%s: status %d want %d", c.path, resp.StatusCode, c.wantStatus)
		}
		if ct := resp.Header.Get("Content-Type"); c.wantCTHas != "" && !contains(ct, c.wantCTHas) {
			t.Errorf("%s: content-type %q missing %q", c.path, ct, c.wantCTHas)
		}
		resp.Body.Close()
	}
}

func TestHealthBody(t *testing.T) {
	srv := httptest.NewServer(newRouter(t.TempDir()))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/api/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 8)
	n, _ := resp.Body.Read(buf)
	if string(buf[:n]) != "ok" {
		t.Errorf("health body = %q want ok", buf[:n])
	}
}

func TestEnv(t *testing.T) {
	if got := env("FV_NONEXISTENT_VAR", "fallback"); got != "fallback" {
		t.Errorf("env fallback = %q", got)
	}
	t.Setenv("FV_SET_VAR", "value")
	if got := env("FV_SET_VAR", "fallback"); got != "value" {
		t.Errorf("env value = %q", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
