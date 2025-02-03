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
    w.Write([]byte("mTLS connection established with Gateway!\n"))
}

func main() {
    absPathGatewayCrt, err := filepath.Abs("certs/gateway.crt")
    handleError(err)
    absPathGatewayKey, err := filepath.Abs("certs/gateway.key")
    handleError(err)

    absPathCACrt, err := filepath.Abs("certs/server.crt")
    handleError(err)

    caCert, err := ioutil.ReadFile(absPathCACrt)
    handleError(err)

    clientCertPool := x509.NewCertPool()
    clientCertPool.AppendCertsFromPEM(caCert)

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

    fmt.Println("Gateway is running and waiting for clients on port 8443...")

    err = httpServer.ListenAndServeTLS(absPathGatewayCrt, absPathGatewayKey)
    if err != nil && err != http.ErrServerClosed {
        handleError(err)
    }
}
