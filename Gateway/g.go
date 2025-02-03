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

func forwardRequest(w http.ResponseWriter, req *http.Request) {
    w.Header().Set("Content-Type", "text/plain")
    w.Write([]byte("mTLS connection established with Gateway!\n"))
}

func gatewayHandler(w http.ResponseWriter, r *http.Request) {
    fmt.Println("Handling request on Gateway")
    forwardRequest(w, r)
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

    http.HandleFunc("/", gatewayHandler)

    fmt.Println("mTLS established between controller and Gateway.")
    fmt.Println("Gateway is running and waiting for clients...")

    err = httpServer.ListenAndServeTLS(absPathGatewayCrt, absPathGatewayKey)
    if err != nil && err != http.ErrServerClosed {
        handleError(err)
    }

    fmt.Println("Gateway shut down successfully.")
}
