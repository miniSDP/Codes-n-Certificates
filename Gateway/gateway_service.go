package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
)

func handleError(err error) {
	if err != nil {
		log.Fatalf("Fatal: %v", err)
	}
}

func serveHTMLPage(w http.ResponseWriter, req *http.Request) {
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

	fmt.Println("Gateway running on 192.168.1.6:8443 and serving HTML page...")

	err = httpServer.ListenAndServeTLS(absPathGatewayCrt, absPathGatewayKey)
	if err != nil && err != http.ErrServerClosed {
		handleError(err)
	}

	fmt.Println("Gateway shut down successfully.")
}
