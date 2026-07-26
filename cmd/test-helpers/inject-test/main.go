// inject-test: simulates an agent writing a secret placeholder to a socket.
// Used in integration tests to verify BPF rewrites the placeholder.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18080", "target address")
	flag.Parse()

	// The agent has GITLAB_TOKEN={{SECRET:GITLAB_TOKEN}} in its env.
	// It constructs an HTTP request using that env var.
	token := os.Getenv("GITLAB_TOKEN")
	if token == "" {
		token = "{{SECRET:GITLAB_TOKEN}}"
	}

	// Simulate what git/curl/requests would do: write the token to a socket
	payload := fmt.Sprintf("GET /api/v4/projects HTTP/1.1\r\nHost: gitlab.com\r\nAuthorization: Bearer %s\r\n\r\n", token)

	conn, err := net.Dial("tcp", *addr)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer conn.Close()

	n, err := conn.Write([]byte(payload))
	if err != nil {
		log.Fatalf("write: %v", err)
	}

	fmt.Printf("Wrote %d bytes to %s\n", n, *addr)
	fmt.Printf("Token in agent memory: %s\n", token)
	fmt.Println("(If BPF is loaded, the server received the REAL token, not this placeholder)")
}
