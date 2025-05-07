package main

import (
        "bytes"
        "crypto/tls"
        "crypto/x509"
        "encoding/json"
        "fmt"
        "io/ioutil"
        "log"
        "net/http"
        "path/filepath"
)

func handleError(err error) {
        if err != nil {
                log.Fatal("Fatal:", err)
        }
}

func main() {
        // Paths to certificates and keys
        absPathClientCrt, err := filepath.Abs("certs/client.crt")
        handleError(err)
        absPathClientKey, err := filepath.Abs("certs/client.key")
        handleError(err)
        absPathServerCA, err := filepath.Abs("certs/server.crt")
        handleError(err)

        // Load client certificate and key
        cert, err := tls.LoadX509KeyPair(absPathClientCrt, absPathClientKey)
        handleError(err)

        // Load server CA certificate
        caCert, err := ioutil.ReadFile(absPathServerCA)
        handleError(err)

        // Append server CA certificate to the pool
        roots := x509.NewCertPool()
        if !roots.AppendCertsFromPEM(caCert) {
                log.Fatal("Failed to append server CA certificate")
        }

        // Configure TLS
        tlsConf := &tls.Config{
                Certificates:       []tls.Certificate{cert}, // Client certificate
                RootCAs:            roots,                   // Server CA
                InsecureSkipVerify: false,                   // Enforce verification
                MinVersion:         tls.VersionTLS12,
        }

        // Create HTTP client with TLS configuration
        tr := &http.Transport{TLSClientConfig: tlsConf}
        client := &http.Client{Transport: tr}

        // mTLS server
        serverIP := "192.168.1.4:443"
        data := map[string]string{
                "username":  "saranesh",
                "service":   "http",
                "client_ip": "192.168.1.7", // Example client IP
        }

        jsonData, err := json.Marshal(data)
        handleError(err)

        req, err := http.NewRequest("POST", "https://"+serverIP, bytes.NewBuffer(jsonData))
        handleError(err)
        req.Header.Set("Content-Type", "application/json")

        resp, err := client.Do(req)
        if err != nil {
                log.Fatal("Failed to send request to mTLS server:", err)
        }
        defer resp.Body.Close()

        body, err := ioutil.ReadAll(resp.Body)
        handleError(err)

        fmt.Println("Response from mTLS Server:", resp.Status)
        fmt.Println("Response Body from mTLS Server:", string(body))

}
