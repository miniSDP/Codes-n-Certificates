package main

import (
    "context"
    "crypto/tls"
    "crypto/x509"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "path/filepath"
    "time"
)

func HelloServer(w http.ResponseWriter, req *http.Request, server *http.Server) {
    w.Header().Set("Content-Type", "text/plain")
    w.Write([]byte("certificates verified..\n"))
    w.Write([]byte("mTLS connection established!\n"))
    
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    go func() {
        fmt.Println("Shutting down server...")
        if err := server.Shutdown(ctx); err != nil {
            log.Printf("Server Shutdown Failed: %+v", err)
        } else {
            fmt.Println("Server successfully shut down")
        }
    }()
}

func handleError(err error) {
    if err != nil {
        log.Fatalf("Fatal: %v", err)
    }
}

func main() {
    absPathServerCrt, err := filepath.Abs("certs/server.crt")
    handleError(err)
    absPathServerKey, err := filepath.Abs("certs/server.key")
    handleError(err)

    clientCACert, err := ioutil.ReadFile(absPathServerCrt)
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
        Addr:      ":443",
        TLSConfig: tlsConfig,
    }

    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        HelloServer(w, r, httpServer)
    })

    fmt.Println("Running Server...")
    err = httpServer.ListenAndServeTLS(absPathServerCrt, absPathServerKey)

    if err != http.ErrServerClosed {
        handleError(err) 
    }

    fmt.Println("Server shut down successful.")
}
