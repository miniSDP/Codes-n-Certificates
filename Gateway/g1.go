package main

import (
	"strings"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"
	"path/filepath"
)

type ClientAccess struct {
	ClientIP string            `json:"client_ip"`
	Services map[string]int    `json:"services"` // map service names to ports (string to int)
}

func handleError(err error) {
	if err != nil {
		log.Fatalf("Fatal: %v", err)
	}
}

func updateFirewall(clientIP string, port int) {
	// Construct the iptables command
	rule := fmt.Sprintf("sudo /sbin/iptables -A INPUT -p tcp -s %s --dport %d -j ACCEPT", strings.Split(clientIP, ":")[0], port)
	log.Printf("Executing command: %s", rule)

	// Execute the command
	cmd := exec.Command("bash", "-c", rule)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("Error updating firewall: %v, Output: %s", err, string(output))
	}

	log.Printf("Firewall updated: Allow %s access to port %d", clientIP, port)
}

func removeFirewall(clientIP string, port int) {
	// Construct the iptables command to remove the rule
	rule := fmt.Sprintf("sudo /sbin/iptables -D INPUT -p tcp -s %s --dport %d -j ACCEPT", strings.Split(clientIP, ":")[0], port)
	log.Printf("Executing command to remove rule: %s", rule)

	// Execute the command
	cmd := exec.Command("bash", "-c", rule)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Error removing firewall rule: %v, Output: %s", err, string(output))
	} else {
		log.Printf("Firewall rule removed: Deny %s access to port %d", clientIP, port)
	}
}

func receiveHandler(w http.ResponseWriter, r *http.Request) {
	var clientAccess ClientAccess
	err := json.NewDecoder(r.Body).Decode(&clientAccess)
	if err != nil {
		http.Error(w, "Invalid JSON data", http.StatusBadRequest)
		log.Println("Error decoding request:", err)
		return
	}

	log.Printf("Received data: ClientIP=%s", clientAccess.ClientIP)

	// Update firewall rules for each service
	for serviceName, port := range clientAccess.Services {
		log.Printf("Allowing client %s access to service %s on port %d", clientAccess.ClientIP, serviceName, port)
		updateFirewall(clientAccess.ClientIP, port)

		// Defer the removal of the firewall rule
		//defer removeFirewall(clientAccess.ClientIP, port)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Firewall rules updated.\n"))
}

func simpleHTTPService() {
	// Simple HTTP service that the client can connect to for testing
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Welcome to the Gateway's Awesome 0_0 !! HTTP Service"))
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func main() {
	// Start simple HTTP service in a separate goroutine
	go simpleHTTPService()

	// Load the certificate files for mTLS (mutual TLS)
	absPathGatewayCrt, err := filepath.Abs("certs/gateway.crt")
	handleError(err)
	absPathGatewayKey, err := filepath.Abs("certs/gateway.key")
	handleError(err)
	absPathServerCrt, err := filepath.Abs("certs/server.crt")
	handleError(err)

	// Load the server CA certificate (this is used to verify the client's certificate)
	serverCACert, err := ioutil.ReadFile(absPathServerCrt)
	handleError(err)

	clientCertPool := x509.NewCertPool()
	clientCertPool.AppendCertsFromPEM(serverCACert)

	// Load the gateway's certificate and key
	gatewayCert, err := tls.LoadX509KeyPair(absPathGatewayCrt, absPathGatewayKey)
	handleError(err)

	// Set up the TLS configuration for the gateway
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{gatewayCert},  // Gateway's certificate
		ClientAuth:   tls.RequireAndVerifyClientCert, // Enforce client certificate validation
		ClientCAs:    clientCertPool,                  // Client CA certificate pool for verification
	}

	// Set up the HTTP server with mTLS
	httpServer := &http.Server{
		Addr:      ":8443", // HTTPS port for mTLS
		TLSConfig: tlsConfig,
	}

	// Handle the /receive endpoint to update firewall rules
	http.HandleFunc("/receive", receiveHandler)

	// Start the HTTPS server
	fmt.Println("Gateway running on 192.168.1.6:8443")
	err = httpServer.ListenAndServeTLS(absPathGatewayCrt, absPathGatewayKey)
	if err != nil && err != http.ErrServerClosed {
		handleError(err)
	}
}
