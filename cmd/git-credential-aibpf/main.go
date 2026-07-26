// git-credential-aibpf: Git credential helper with repo-level allowlist.
//
// Only provides credentials for repos matching the policy.
// Installed in the container's read-only layer at:
//   /usr/lib/aibpf/git-credential-aibpf
//
// Git config (also in RO layer):
//   [credential]
//       helper = /usr/lib/aibpf/git-credential-aibpf
//
// The agent cannot override this because:
//   1. /usr/lib/aibpf/ is in the read-only image layer
//   2. .gitconfig is in the read-only layer
//   3. Even if agent sets credential.helper in .git/config (writable),
//      our helper checks the repo URL before providing any credential
//
// Protocol: git credential helper protocol (stdin/stdout key=value pairs)
//   Input:  protocol=https\nhost=gitlab.com\npath=our-org/repo\n\n
//   Output: protocol=https\nhost=gitlab.com\nusername=oauth2\npassword=<token>\n\n
//   Or:     empty (no credential) if repo not allowed

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	policyPath  = "/etc/aibpf/policy.yaml"
	secretsPath = "/run/secrets/env"
)

// Config loaded from policy or env
type config struct {
	allowedRepos []string // glob patterns: "gitlab.com/org/*"
	credential   string   // secret name to use
	allowPush    bool
}

func main() {
	if len(os.Args) < 2 {
		os.Exit(0)
	}

	action := os.Args[1]

	// Only respond to "get" requests (provide credentials)
	// Ignore "store" and "erase"
	if action != "get" {
		os.Exit(0)
	}

	// Parse input from git
	input := parseInput()
	host := input["host"]
	path := input["path"]
	protocol := input["protocol"]

	if host == "" {
		os.Exit(0)
	}

	// Load config
	cfg := loadConfig()

	// Check if this repo is allowed
	repoURL := host + "/" + path
	if !isAllowed(repoURL, cfg.allowedRepos) {
		// Log the denial
		fmt.Fprintf(os.Stderr, "aibpf-credential: DENIED %s://%s/%s (not in allowlist)\n",
			protocol, host, path)
		os.Exit(0) // empty response = no credential
	}

	// Load the secret value
	token := loadSecret(cfg.credential)
	if token == "" {
		fmt.Fprintf(os.Stderr, "aibpf-credential: secret %q not found\n", cfg.credential)
		os.Exit(0)
	}

	// Provide credential
	fmt.Fprintf(os.Stderr, "aibpf-credential: ALLOWED %s://%s/%s\n", protocol, host, path)
	fmt.Printf("protocol=%s\n", protocol)
	fmt.Printf("host=%s\n", host)
	fmt.Printf("username=oauth2\n")
	fmt.Printf("password=%s\n", token)
	fmt.Println()
}

func parseInput() map[string]string {
	m := make(map[string]string)
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, "=")
		if ok {
			m[k] = v
		}
	}
	return m
}

func loadConfig() config {
	cfg := config{}

	// Try loading from env (for testing) or policy file
	if repos := os.Getenv("AIBPF_ALLOWED_REPOS"); repos != "" {
		cfg.allowedRepos = strings.Split(repos, ",")
	} else {
		// Load from policy file
		cfg.allowedRepos = loadAllowedReposFromPolicy()
	}

	if cred := os.Getenv("AIBPF_CREDENTIAL"); cred != "" {
		cfg.credential = cred
	} else {
		cfg.credential = "GITLAB_TOKEN" // default
	}

	return cfg
}

func loadAllowedReposFromPolicy() []string {
	// Simple: read policy.yaml and extract git.allowed_repos
	// In production this would use the policy package, but we keep
	// the credential helper minimal (no heavy dependencies)
	data, err := os.ReadFile(policyPath)
	if err != nil {
		return nil
	}

	var repos []string
	inGit := false
	inRepos := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "git:" {
			inGit = true
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
			inRepos = false
			inGit = false
		}
	}
	return repos
}

func isAllowed(repoURL string, patterns []string) bool {
	if len(patterns) == 0 {
		return false // fail-closed: no allowlist = deny all
	}

	for _, pattern := range patterns {
		matched, _ := filepath.Match(pattern, repoURL)
		if matched {
			return true
		}
		// Also try with trailing /* for org-level patterns
		if strings.HasSuffix(pattern, "/*") {
			prefix := strings.TrimSuffix(pattern, "/*")
			if strings.HasPrefix(repoURL, prefix+"/") {
				return true
			}
		}
		// Exact match
		if pattern == repoURL {
			return true
		}
	}
	return false
}

func loadSecret(name string) string {
	// Read from secrets file
	data, err := os.ReadFile(secretsPath)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if ok && strings.TrimSpace(k) == name {
			return strings.TrimSpace(v)
		}
	}
	// Fallback: environment variable
	return os.Getenv(name)
}
