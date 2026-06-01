package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

//go:embed static/*
var staticFiles embed.FS

func main() {
	addr := firstNonEmpty(os.Getenv("ZERO_DASHBOARD_ADDR"), "127.0.0.1:8090")
	apiBase := strings.TrimRight(firstNonEmpty(os.Getenv("ZERO_DASHBOARD_API_BASE_URL"), "http://127.0.0.1:8080"), "/")
	apiToken := strings.TrimSpace(os.Getenv("ZERO_API_TOKEN"))

	parsedBase, err := url.Parse(apiBase)
	if err != nil || parsedBase.Scheme == "" || parsedBase.Host == "" {
		log.Fatalf("invalid ZERO_DASHBOARD_API_BASE_URL %q", apiBase)
	}
	staticRoot, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatal(err)
	}

	client := &http.Client{Timeout: 20 * time.Second}
	mux := http.NewServeMux()
	mux.Handle("/", noStore(http.FileServer(http.FS(staticRoot))))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		proxyAPI(w, r, client, parsedBase, apiToken)
	})

	log.Printf("zero dashboard listening on %s, proxying %s", addr, apiBase)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func proxyAPI(w http.ResponseWriter, r *http.Request, client *http.Client, apiBase *url.URL, apiToken string) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	apiPath := strings.TrimPrefix(r.URL.Path, "/api")
	if !strings.HasPrefix(apiPath, "/v1/") && apiPath != "/healthz" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported api path"})
		return
	}
	target := *apiBase
	target.Path = strings.TrimRight(apiBase.Path, "/") + apiPath
	target.RawQuery = r.URL.RawQuery

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target.String(), nil)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if apiToken != "" {
		req.Header.Set("Authorization", "Bearer "+apiToken)
	}
	req.Header.Set("Accept", "application/json")

	res, err := client.Do(req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": fmt.Sprintf("api proxy failed: %v", err)})
		return
	}
	defer res.Body.Close()

	var body bytes.Buffer
	_, _ = io.Copy(&body, io.LimitReader(res.Body, 16<<20))
	w.Header().Set("Content-Type", firstNonEmpty(res.Header.Get("Content-Type"), "application/json"))
	w.WriteHeader(res.StatusCode)
	_, _ = w.Write(body.Bytes())
}

func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
