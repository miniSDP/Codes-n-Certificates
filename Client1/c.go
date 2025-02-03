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
        log.Fatal("Fatal", err)
    }
}

func main() {
    absPathClientCrt, err := filepath.Abs("certs/client.crt")
    handleError(err)
    absPathClientKey, err := filepath.Abs("certs/client.key")
    handleError(err)
    absPathServerCrt, err := filepath.Abs("certs/server.crt")
    handleError(err)

    cert, err := tls.LoadX509KeyPair(absPathClientCrt, absPathClientKey)
    if err != nil {
        log.Fatalln("Unable to load cert", err)
    }

    roots := x509.NewCertPool()

    fakeCA, err := ioutil.ReadFile(absPathServerCrt)
    if err != nil {
        log.Println(err)
        return
    }

    ok := roots.AppendCertsFromPEM([]byte(fakeCA))
    if !ok {
        panic("failed to parse root certificate")
    }

    tlsConf := &tls.Config{
        Certificates:       []tls.Certificate{cert},
        RootCAs:            roots,
        InsecureSkipVerify: false,
        MinVersion:         tls.VersionTLS12,
    }
    tr := &http.Transport{TLSClientConfig: tlsConf}
    client := &http.Client{Transport: tr}

    serverIP := "192.168.1.4"
    resp, err := client.Get("https://" + serverIP)
    if err != nil {
        log.Println(err)
        return
    }
    fmt.Println("Connected to Server:", resp.Status)

    defer resp.Body.Close()
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        log.Println(err)
        return
    }

    fmt.Println("Response from Server:", string(body))

    gatewayIP := "192.168.1.6"
    resp, err = client.Get("https://" + gatewayIP + ":8443")
    if err != nil {
        log.Println(err)
        return
    }
    fmt.Println("Connected to Gateway:", resp.Status)

    defer resp.Body.Close()
    body, err = ioutil.ReadAll(resp.Body)
    if err != nil {
        log.Println(err)
        return
    }

    fmt.Println("Response from Gateway:", string(body))
}
