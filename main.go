package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/msteinert/pam"
)

func pamAuth(username, password string) bool {
	tx, err := pam.StartFunc("login", username, func(s pam.Style, msg string) (string, error) {
		switch s {
		case pam.PromptEchoOff:
			return password, nil
		case pam.PromptEchoOn:
			return password, nil
		case pam.ErrorMsg, pam.TextInfo:
			return "", nil
		default:
			return "", fmt.Errorf("unrecognized PAM message style")
		}
	})
	if err != nil {
		return false
	}
	if err := tx.Authenticate(pam.DisallowNullAuthtok); err != nil {
		log.Printf("=> Authentication failed: %v\n", err)
		return false
	}
	return true
}

func handler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	pair := strings.SplitN(string(payload), ":", 2)
	if len(pair) != 2 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	username, password := pair[0], pair[1]
	log.Println("Checking authentication for", username)
	if !pamAuth(username, password) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func listen(listenStr string) (net.Listener, error) {
	if !strings.HasPrefix(listenStr, "unix://") {
		return net.Listen("tcp", listenStr)
	}

	socketPath := strings.TrimPrefix(listenStr, "unix://")
	if err := os.MkdirAll(filepath.Dir(socketPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create socket directory: %v", err)
	}
	os.Remove(socketPath) // Remove existing socket if it exists
	return net.Listen("unix", socketPath)
}

func main() {
	listenStr := flag.String("listen", "unix://pam.sock", "Port or socket to listen on")
	flag.Parse()

	listener, err := listen(*listenStr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", *listenStr, err)
		return
	}
	defer listener.Close()

	http.HandleFunc("/", handler)
	log.Println("Listening on", *listenStr)
	http.Serve(listener, nil)
}
