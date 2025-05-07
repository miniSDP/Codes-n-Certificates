package main

import (
        
        "log"
        "net/http"
)

func simpleHTTPService() {
        // Simple HTTP service that the client can connect to for testing
        http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
                w.WriteHeader(http.StatusOK)
                w.Write([]byte("Welcome to the Gateway's Awesome 0_0 !! HTTP Service"))
        })
        log.Fatal(http.ListenAndServe(":8080", nil))
}

func main() {
        // Start simple HTTP service in a separate goroutine
        go simpleHTTPService()
}
