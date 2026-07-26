// Credential service sidecar.
// Runs in a separate container, shares a unix socket with the agent container.
// Reads real secrets from /run/secrets/env, checks repo allowlist from policy,
// returns credentials only for approved repos.

package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
)

const (
	socketPath  = "/var/run/aibpf/cred.sock"
	policyPath  = "/etc/aibpf/policy.yaml"
)

func getSecretsPath() string {
	if p := os.Getenv("SECRETS_PATH"); p != "" {
		return p
	}
	return "/run/secrets/env"
}

var (
	secrets      map[string]string
	allowedRepos []string
	credential   string
)

func main() {
	secrets = loadSecrets(getSecretsPath())
	allowedRepos, credential = loadPolicy()

	log.Printf("credential-service: %d secrets, %d allowed repos, credential=%s",
		len(secrets), len(allowedRepos), credential)

	// Remove stale socket
	os.Remove(socketPath)
	os.MkdirAll(filepath.Dir(socketPath), 0755)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	// Make socket accessible to agent container
	os.Chmod(socketPath, 0666)

	log.Printf("listening on %s", socketPath)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	// Read git credential protocol input
	input := make(map[string]string)
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, "=")
		if ok {
			input[k] = v
		}
	}

	host := input["host"]
	path := input["path"]
	protocol := input["protocol"]

	if host == "" {
		log.Printf("DENIED: empty host")
		fmt.Fprintf(conn, "\n")
		return
	}

	repoURL := host + "/" + path

	if !isAllowed(repoURL) {
		log.Printf("DENIED: %s://%s/%s (not in allowlist)", protocol, host, path)
		fmt.Fprintf(conn, "\n")
		return
	}

	token := secrets[credential]
	if token == "" {
		log.Printf("ERROR: secret %q not found", credential)
		fmt.Fprintf(conn, "\n")
		return
	}

	log.Printf("ALLOWED: %s://%s/%s", protocol, host, path)
	fmt.Fprintf(conn, "protocol=%s\n", protocol)
	fmt.Fprintf(conn, "host=%s\n", host)
	fmt.Fprintf(conn, "username=oauth2\n")
	fmt.Fprintf(conn, "password=%s\n", token)
	fmt.Fprintf(conn, "\n")
}

func isAllowed(repoURL string) bool {
	if len(allowedRepos) == 0 {
		return false
	}
	for _, pattern := range allowedRepos {
		matched, _ := filepath.Match(pattern, repoURL)
		if matched {
			return true
		}
		if strings.HasSuffix(pattern, "/*") {
			prefix := strings.TrimSuffix(pattern, "/*")
			if strings.HasPrefix(repoURL, prefix+"/") {
				return true
			}
		}
		if pattern == repoURL {
			return true
		}
	}
	return false
}

func loadSecrets(secretsPath string) map[string]string {
	m := make(map[string]string)
	data, err := os.ReadFile(secretsPath)
	if err != nil {
		log.Printf("warning: cannot read %s: %v", secretsPath, err)
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

func loadPolicy() ([]string, string) {
	data, err := os.ReadFile(policyPath)
	if err != nil {
		log.Printf("warning: cannot read %s: %v", policyPath, err)
		return nil, "GITLAB_TOKEN"
	}

	var repos []string
	cred := "GITLAB_TOKEN"
	inGit := false
	inRepos := false

	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "git:" {
			inGit = true
			continue
		}
		if inGit && strings.HasPrefix(trimmed, "credential:") {
			cred = strings.TrimSpace(strings.TrimPrefix(trimmed, "credential:"))
			continue
		}
		if inGit && trimmed == "allowed_repos:" {
			inRepos = true
			continue
		}
		if inRepos && strings.HasPrefix(trimmed, "- ") {
			repo := strings.TrimPrefix(trimmed, "- ")
			repo = strings.Trim(repo, "\"' ")
			repos = append(repos, repo)
			continue
		}
		if inRepos && !strings.HasPrefix(trimmed, "- ") && trimmed != "" {
			break
		}
	}
	return repos, cred
}
