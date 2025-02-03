sspackage main

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
	absPathClientCrt, err := filepath.Abs("certs/client.crt")
	handleError(err)
	absPathClientKey, err := filepath.Abs("certs/client.key")
	handleError(err)

	absPathServerCA, err := filepath.Abs("certs/server.crt")
	handleError(err)

	cert, err := tls.LoadX509KeyPair(absPathClientCrt, absPathClientKey)
	if err != nil {
		log.Fatalln("Unable to load client cert:", err)
	}

	caCert, err := ioutil.ReadFile(absPathServerCA)
	handleError(err)

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caCert) {
		log.Fatal("Failed to append server CA certificate")
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
		MinVersion:   tls.VersionTLS12,
	}

	tr := &http.Transport{TLSClientConfig: tlsConf}
	client := &http.Client{Transport: tr}

	serverIP := "192.168.1.4:443"

	data := map[string]string{
		"username": "saranesh",
		"service":  "service1",
	}
	jsonData, err := json.Marshal(data)
	handleError(err)

	req, err := http.NewRequest("POST", "https://"+serverIP, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatal("Failed to create request:", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("Failed to send request:", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	handleError(err)

	fmt.Println("Response status:", resp.Status)
	fmt.Println("Response body:", string(body))
}
