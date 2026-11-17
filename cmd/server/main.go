// Command server serves the upload SPA, the compiled WASM artifact, and a
// /api/verify endpoint that decrypts + verifies the sealed verdict produced
// client-side by the WASM module.
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	staticDir := env("STATIC_DIR", "web/static")
	addr := env("ADDR", ":8099")

	log.Printf("serving %s on %s", staticDir, addr)
	srv := &http.Server{
		Addr:              addr,
		Handler:           newRouter(staticDir),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

// newRouter wires the SPA, the WASM artifact, and the verify API.
func newRouter(staticDir string) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	// API first so it isn't shadowed by the static catch-all.
	r.Post("/api/verify", handleVerify)
	r.Get("/api/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})

	// Static SPA + /pkg/*.wasm + JS glue. Serve .wasm with the correct type.
	fs := http.FileServer(http.Dir(staticDir))
	r.Handle("/*", wasmContentType(fs))
	return r
}

// wasmContentType ensures .wasm is served as application/wasm so the browser
// can stream-compile it (required by WebAssembly.instantiateStreaming).
func wasmContentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if len(req.URL.Path) > 5 && req.URL.Path[len(req.URL.Path)-5:] == ".wasm" {
			w.Header().Set("Content-Type", "application/wasm")
		}
		next.ServeHTTP(w, req)
	})
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
