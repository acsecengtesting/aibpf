// Echo server for integration tests.
// Accepts TCP connections and logs received data to a file.
package main

import (
	"flag"
	"io"
	"log"
	"net"
	"os"
)

func main() {
	addr := flag.String("addr", ":18080", "listen address")
	logFile := flag.String("log", "/tmp/echo_received.txt", "file to write received data")
	flag.Parse()

	f, err := os.Create(*logFile)
	if err != nil {
		log.Fatalf("creating log file: %v", err)
	}
	defer f.Close()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("echo-server listening on %s, logging to %s", *addr, *logFile)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			data, _ := io.ReadAll(c)
			f.Write(data)
			f.Write([]byte("\n"))
			log.Printf("received %d bytes", len(data))
		}(conn)
	}
}
