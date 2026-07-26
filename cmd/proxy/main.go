package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// Secret proxy sidecar.
// Runs outside the agent's cgroup, listens on localhost:9999.
// Replaces {{SECRET:NAME}} in request bodies/headers with real values.

var secrets map[string]string

func main() {
	secrets = loadSecrets()
	addr := ":9999"
	if v := os.Getenv("PROXY_ADDR"); v != "" {
		addr = v
	}
	log.Printf("aibpf-proxy listening on %s (%d secrets loaded)", addr, len(secrets))
	http.HandleFunc("/", handleProxy)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func loadSecrets() map[string]string {
	m := make(map[string]string)
	file := os.Getenv("SECRETS_FILE")
	if file == "" {
		file = "/run/secrets/env"
	}
	data, err := os.ReadFile(file)
	if err != nil {
		log.Printf("warning: cannot read secrets file %s: %v", file, err)
		return m
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if ok {
			m[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return m
}

func handleProxy(w http.ResponseWriter, r *http.Request) {
	// Target URL comes from X-Target-URL header or query param
	target := r.Header.Get("X-Target-URL")
	if target == "" {
		target = r.URL.Query().Get("target")
	}
	if target == "" {
		http.Error(w, "missing X-Target-URL header or ?target= param", 400)
		return
	}

	targetURL, err := url.Parse(target)
	if err != nil {
		http.Error(w, "invalid target URL: "+err.Error(), 400)
		return
	}

	// Read and substitute body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "reading body: "+err.Error(), 500)
		return
	}
	body = []byte(substituteSecrets(string(body)))

	// Build outbound request
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL.String(), strings.NewReader(string(body)))
	if err != nil {
		http.Error(w, "creating request: "+err.Error(), 500)
		return
	}

	// Copy and substitute headers
	for k, vs := range r.Header {
		if strings.EqualFold(k, "X-Target-URL") {
			continue
		}
		for _, v := range vs {
			outReq.Header.Add(k, substituteSecrets(v))
		}
	}

	resp, err := http.DefaultClient.Do(outReq)
	if err != nil {
		http.Error(w, "upstream: "+err.Error(), 502)
		return
	}
	defer resp.Body.Close()

	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func substituteSecrets(s string) string {
	for name, value := range secrets {
		placeholder := fmt.Sprintf("{{SECRET:%s}}", name)
		s = strings.ReplaceAll(s, placeholder, value)
	}
	return s
}
