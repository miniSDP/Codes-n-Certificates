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

func gatewayHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Handling request on Gateway")
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("mTLS connection established with Gateway!\nClient successfully authorized and accessing service.\n"))
}

func main() {
	absPathGatewayCrt, err := filepath.Abs("certs/gateway.crt")
	handleError(err)
	absPathGatewayKey, err := filepath.Abs("certs/gateway.key")
	handleError(err)

	absPathControllerCACert, err := filepath.Abs("certs/server.crt") // Ensure this is the controller's CA certificate
	handleError(err)

	controllerCACert, err := ioutil.ReadFile(absPathControllerCACert)
	handleError(err)

	clientCertPool := x509.NewCertPool()
	clientCertPool.AppendCertsFromPEM(controllerCACert)

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

	http.HandleFunc("/", gatewayHandler)

	fmt.Println("Gateway is running on 192.168.1.6:8443 and waiting for requests...")

	err = httpServer.ListenAndServeTLS(absPathGatewayCrt, absPathGatewayKey)
	if err != nil && err != http.ErrServerClosed {
		handleError(err)
	}

	fmt.Println("Gateway shut down successfully.")
}
