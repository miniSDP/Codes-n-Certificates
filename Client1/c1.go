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
		log.Fatal("Fatal", err)
	}
}

// Load client certificate and send it with the request to the server and gateway
func main() {
	absPathClientCrt, err := filepath.Abs("certs/client.crt")
	handleError(err)
	absPathClientKey, err := filepath.Abs("certs/client.key")
	handleError(err)
	absPathServerCrt, err := filepath.Abs("certs/server.crt")
	handleError(err)

	// Load client certificate and key for mTLS
	cert, err := tls.LoadX509KeyPair(absPathClientCrt, absPathClientKey)
	handleError(err)

	// Load server's CA certificate for verifying the server
	roots := x509.NewCertPool()
	fakeCA, err := ioutil.ReadFile(absPathServerCrt)
	handleError(err)

	ok := roots.AppendCertsFromPEM([]byte(fakeCA))
	if !ok {
		log.Fatal("failed to parse root certificate")
	}

	// Configure TLS with the client certificate and server CA
	tlsConf := &tls.Config{
		Certificates:       []tls.Certificate{cert}, // Client certificate
		RootCAs:            roots,                   // Server certificate
		InsecureSkipVerify: false,                   // Enforce verification
		MinVersion:         tls.VersionTLS12,
	}
	tr := &http.Transport{TLSClientConfig: tlsConf}
	client := &http.Client{Transport: tr}

	// Prepare the JSON request body
	requestBody := map[string]string{
		"client_ip": "192.168.1.5", // Example client IP
	}

	body, err := json.Marshal(requestBody)
	if err != nil {
		log.Fatal("Error marshalling request body", err)
	}

	serverIP := "192.168.1.4"
	resp, err := client.Post("https://"+serverIP, "application/json", bytes.NewBuffer(body))
	if err != nil {
		log.Println("Error making the request:", err)
		return
	}
	defer resp.Body.Close()
	fmt.Println("Response from Server:", resp.Status)

	bodyResp, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("Error reading response body:", err)
		return
	}

	fmt.Println("Response Body from Server:", string(bodyResp))
	
	// Now, make a request to another HTTP service
	httpServiceURL := "http://192.168.1.6:8080/" // Replace with your HTTP service URL
	httpResp, err := client.Get(httpServiceURL)
	if err != nil {
		log.Printf("Error making the request to HTTP service: %v", err)
		return
	}
	defer httpResp.Body.Close()

	fmt.Println("Response from HTTP Service:", httpResp.Status)

	httpBodyResp, err := ioutil.ReadAll(httpResp.Body)
	if err != nil {
		log.Printf("Error reading response body from HTTP service: %v", err)
		return
	}

	fmt.Println("Response Body from HTTP Service:", string(httpBodyResp))
}

