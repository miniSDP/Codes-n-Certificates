package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
)

var authorizedClients = map[string]string{}

func handleError(err error) {
	if err != nil {
		log.Fatalf("Fatal: %v", err)
	}
}

func serveHTMLPage(w http.ResponseWriter, req *http.Request) {
	clientCert := req.TLS.PeerCertificates[0]
	clientName := clientCert.Subject.CommonName

	if _, authorized := authorizedClients[clientName]; !authorized {
		http.Error(w, "Unauthorized client", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`
		<html>
		<head><title>Access Granted</title></head>
		<body>
			<h1>Client successfully accessed the gateway!</h1>
			<p>mTLS handshake completed. You are now accessing a protected resource.</p>
		</body>
		</html>
	`))
	log.Println("HTML page served to client.")
}

func authorizeClient(w http.ResponseWriter, r *http.Request) {
	var clientData map[string]string
	err := json.NewDecoder(r.Body).Decode(&clientData)
	if err != nil {
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		return
	}

	username := clientData["username"]
	service := clientData["service"]

	authorizedClients[username] = service
	fmt.Printf("Client %s authorized for service %s\n", username, service)
	w.WriteHeader(http.StatusOK)
}

func main() {
	absPathGatewayCrt, err := filepath.Abs("certs/gateway.crt")
	handleError(err)
	absPathGatewayKey, err := filepath.Abs("certs/gateway.key")
	handleError(err)

	absPathServerCrt, err := filepath.Abs("certs/server.crt")
	handleError(err)

	serverCACert, err := ioutil.ReadFile(absPathServerCrt)
	handleError(err)

	clientCertPool := x509.NewCertPool()
	clientCertPool.AppendCertsFromPEM(serverCACert)

	gatewayCert, err := tls.LoadX509KeyPair(absPathGatewayCrt, absPathGatewayKey)
	handleError(err)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{gatewayCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCertPool,
		MinVersion:   tls.VersionTLS12,
	}

	httpServer := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}

	http.HandleFunc("/", serveHTMLPage)
	http.HandleFunc("/authorize", authorizeClient)

	fmt.Println("Gateway running on 192.168.1.6:8443 and serving HTML page...")

	err = httpServer.ListenAndServeTLS(absPathGatewayCrt, absPathGatewayKey)
	if err != nil && err != http.ErrServerClosed {
		handleError(err)
	}

	fmt.Println("Gateway shut down successfully.")
}
