package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"sync"
)

var (
	clients   = make(map[net.Conn]bool)
	broadcast = make(chan string)
	mutex     = &sync.Mutex{}
)

// Handle client connection
func handleClient(conn net.Conn) {
	defer conn.Close()
	clientAddr := conn.RemoteAddr().String()

	fmt.Printf("[INFO] Client connected: %s\n", clientAddr)

	mutex.Lock()
	clients[conn] = true
	mutex.Unlock()

	// Listen for messages from client
	go func() {
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			msg := fmt.Sprintf("\n [%s] %s\n", clientAddr, scanner.Text())
			fmt.Println(msg)
			
		}

		// Handle client disconnect
		mutex.Lock()
		delete(clients, conn)
		mutex.Unlock()
		fmt.Printf("[INFO] Client disconnected: %s\n", clientAddr)
	}()

	// Allow server to send messages
	serverInput := bufio.NewScanner(os.Stdin)
	for serverInput.Scan() {
		msg := fmt.Sprintf("[Server] %s", serverInput.Text())
		//fmt.Println(msg)

		mutex.Lock()
		for client := range clients {
			fmt.Fprintln(client, msg)
		}
		mutex.Unlock()
	}
}

// Broadcast messages to all clients
func broadcaster() {
	for msg := range broadcast {
		mutex.Lock()
		for client := range clients {
			fmt.Fprintln(client, msg)
		}
		mutex.Unlock()
	}
}

func main() {
	listenAddr := "192.168.1.6:9000"
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fmt.Println("[ERROR] Could not start server:", err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Println("[INFO] Server started on", listenAddr)
	go broadcaster()

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("[ERROR] Connection error:", err)
			continue
		}
		go handleClient(conn)
	}
}
