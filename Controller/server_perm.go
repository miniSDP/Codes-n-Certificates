package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

type User struct {
	Username    string   `json:"username"`
	Permissions []string `json:"permissions"`
}

var users map[string][]string

func loadPermissions() {
	filePath := "permissions/users.json"
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Failed to open users.json: %v", err)
	}
	defer file.Close()

	var loadedUsers []User
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&loadedUsers); err != nil {
		log.Fatalf("Failed to parse users.json: %v", err)
	}

	users = make(map[string][]string)
	for _, user := range loadedUsers {
		users[user.Username] = user.Permissions
	}
}

type Request struct {
	Username string `json:"username"`
	Service  string `json:"service"`
}

func HelloServer(w http.ResponseWriter, req *http.Request) {
	var requestData Request
	err := json.NewDecoder(req.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		log.Println("Error decoding JSON request body:", err)
		return
	}

	if requestData.Username == "" || requestData.Service == "" {
		http.Error(w, "Username or service cannot be empty", http.StatusBadRequest)
		log.Println("Empty username or service field")
		return
	}

	permissions, exists := users[requestData.Username]
	if !exists {
		http.Error(w, "User not found", http.StatusUnauthorized)
		log.Println("Unauthorized access attempt: User not found -", requestData.Username)
		return
	}

	hasPermission := false
	for _, permission := range permissions {
		if permission == requestData.Service {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		http.Error(w, "Unauthorized access: User does not have permission for this service", http.StatusUnauthorized)
		log.Println("Unauthorized service access attempt by user:", requestData.Username, "for service:", requestData.Service)
		return
	}

	response := map[string]interface{}{
		"message":     "User authorized",
		"permissions": permissions,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleError(err error) {
	if err != nil {
		log.Fatalf("Fatal: %v", err)
	}
}

func main() {
	loadPermissions()

	absPathServerCrt, err := filepath.Abs("certs/server.crt")
	handleError(err)
	absPathServerKey, err := filepath.Abs("certs/server.key")
	handleError(err)

	absPathClientCACert, err := filepath.Abs("certs/server.crt")
	handleError(err)
	clientCACert, err := ioutil.ReadFile(absPathClientCACert)
	handleError(err)

	clientCertPool := x509.NewCertPool()
	clientCertPool.AppendCertsFromPEM(clientCACert)

	tlsConfig := &tls.Config{
		ClientAuth:               tls.RequireAndVerifyClientCert,
		ClientCAs:                clientCertPool,
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
	}

	httpServer := &http.Server{
		Addr:      "192.168.1.4:443",
		TLSConfig: tlsConfig,
	}

	http.HandleFunc("/", HelloServer)

	fmt.Println("Running Server on 192.168.1.4:443...")
	err = httpServer.ListenAndServeTLS(absPathServerCrt, absPathServerKey)
	handleError(err)
}
