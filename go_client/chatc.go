package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
)

func main() {
	serverAddr := "192.168.1.6:9000"
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		fmt.Println("[ERROR] Connection failed:", err)
		return
	}
	defer conn.Close()

	fmt.Println("[INFO] Connected to chat server\n")

	// Receive messages from the server
	go func() {
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			fmt.Println("\n" + scanner.Text()+"\n") // Ensures new messages don't mix with user input
			                   // Prompt for user input after receiving a message
		}
	}()

	// Send messages to server
	input := bufio.NewScanner(os.Stdin)
	for {
		
		if input.Scan() {
			fmt.Fprintln(conn, input.Text())
		}
	}
}
