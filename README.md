# Software-Defined Perimeter (SDP) Project

This project implements a Software-Defined Perimeter (SDP), a modern security framework designed to enhance network security and access control based on the Zero Trust Architecture (ZTA). [cite: 25, 26, 57]

## Description

The SDP system operates on the principle of "never trust, always verify." [cite: 26] Access to network resources is granted only after strict identity verification and policy enforcement, regardless of whether the user or device is inside or outside the network. [cite: 27, 28] This approach dynamically defines the network perimeter based on user identity, device, and context, effectively hiding network resources from unauthorized users. [cite: 29, 30]

The system comprises three core components[cite: 58]:
* **Client**: Initiates access requests to the Controller via Single Packet Authorization (SPA) and establishes secure communication using mutual TLS (mTLS). [cite: 58, 59]
* **Controller**: The central authority that validates client credentials and permissions, and enforces access control policies. [cite: 59, 60]
* **Gateway**: Enforces dynamic firewall rules (using iptables) to allow or revoke client access and acts as a secure entry point to internal resources. [cite: 46, 61, 62]

## Key Features

* **Zero Trust Architecture**: No user or device is trusted by default. [cite: 26, 77]
* **Single Packet Authorization (SPA)**: Ensures only authorized clients can initiate access, preventing port scanning and network enumeration. [cite: 38, 39, 41]
* **Mutual TLS (mTLS)**: Provides secure, encrypted communication and mutual authentication between all components, preventing man-in-the-middle attacks. [cite: 42, 43, 44]
* **Dynamic Firewall Rules**: Enforces fine-grained access control by updating firewall rules in real-time based on client access details. [cite: 45, 46]
* **Reduced Attack Surface**: Hides internal network resources from unauthorized users until access is explicitly granted. [cite: 31, 37, 78]
* **Identity-Centric Security**: Access is granted based on authenticated and authorized users and devices. [cite: 36]

## Technologies Used

* **Programming Language**: Go (Golang) [cite: 92]
    * Key Libraries: `crypto/tls`, `net/http`, `encoding/json`, `os/exec` [cite: 94, 95, 96]
* **Cryptography**: X.509 Certificates (managed with OpenSSL) for mTLS. [cite: 97, 98]
* **Firewall Management**: iptables for dynamic firewall rule updates. [cite: 99]
* **SPA Implementation**: fwknop for Single Packet Authorization. [cite: 100]

## Project Setup

### Prerequisites

* Install Go: [https://golang.org/dl/](https://golang.org/dl/) [cite: 103]
* Install OpenSSL [cite: 104]
* Install iptables (Gateway, Server) [cite: 104]
* Install fwknop-client (Client) [cite: 104]
* Install fwknop-server (Server/Controller) [cite: 104]

### Setup Steps

1.  **Configure fwknop for Secure Access**[cite: 104]:
    * Generate SPA keys on the client using `fwknop --key-gen`. [cite: 104]
    * Configure the fwknop server (`/etc/fwknop/access.conf` and `/etc/fwknop/fwknopd.conf`) with the generated keys and appropriate network interface. [cite: 105]
    * Start the `fwknop-server` service. [cite: 105]
    * Configure firewall (iptables) to block relevant ports by default and allow only SPA-authorized connections. **Test SPA thoroughly before locking down ports.** [cite: 106, 107]

2.  **Generate Certificates**[cite: 107]:
    * Generate server certificates (`server.key`, `server.crt`) using OpenSSL. Store in `certs/` directory. [cite: 107]
    * Generate client certificates (`client.key`, `client.crt`) using OpenSSL. Store in `certs/` directory. [cite: 108]
    * Generate gateway certificates (`gateway.key`, `gateway.crt`) using OpenSSL. Store in `certs/` directory. (Assumed, as gateway also uses mTLS) [cite: 112]

3.  **Configure Components**[cite: 109]:
    * **Client (`client.go`)**: Update paths to client certificate and key. [cite: 109]
    * **Controller (`controller.go`)**: Update paths to server certificate and key. [cite: 110]
    * **Gateway (`gateway.go`)**: Update paths to gateway certificate and key. [cite: 111]
    * Update the user permissions and authorized services list in the controller's `permissions` folder as required. [cite: 112]

## How to Run

1.  **Start the Controller**:
    * Navigate to the `controller` directory.
    * Run `./fwknop_iptables.sh` (if applicable for initial setup or rules). [cite: 113]
    * Run `go run controller.go`. [cite: 113]

2.  **Start the Gateway**:
    * Run services on the gateway (e.g., chat and HTTP services) in separate terminals:
        * `go run chats.go` [cite: 113]
        * `go run http.go` [cite: 113]
    * Navigate to the `gateway` directory.
    * Run `go run gateway.go`. [cite: 113]

3.  **Initiate Access from the Client**:
    * Navigate to the `client` directory.
    * Run `./client.sh` (This script likely handles the SPA packet sending and then tries to connect). [cite: 113]

## Testing

The project underwent several testing phases[cite: 126, 127]:

* **Unit Testing**: Each component (Client, Controller, Gateway) was tested in isolation using Go's built-in testing framework. [cite: 128, 129]
* **Integration Testing**: Tested interactions between components to ensure end-to-end functionality. [cite: 132, 133]
* **Penetration Testing**: Simulated attacks (e.g., MITM, replay, brute force, port scanning) using tools like nmap, Wireshark, and fwknop to identify vulnerabilities. [cite: 137, 138, 139]

### Key Test Cases Included:
* Client Authentication with Controller via mTLS. [cite: 150]
* SPA Packet Validation by the Controller. [cite: 154]
* Dynamic Firewall Rule Updates by the Gateway. [cite: 159]
* Authorized Resource Access by the Client through the Gateway. [cite: 163]
* Resistance to MITM, Replay, Brute Force attacks, and Port Scanning. [cite: 169, 170, 171, 172, 173]

### Outcomes:
The system successfully authenticated clients, validated SPA packets, updated firewall rules dynamically, allowed authorized resource access, and resisted simulated attacks. [cite: 174, 176, 178, 180, 182]

## Future Upgrades Considered

* Automated Certificate Management (e.g., using Certbot, Hashicorp Vault). [cite: 188, 190]
* Multi-Factor Authentication (MFA) integration (e.g., Google Authenticator, Authy). [cite: 193, 195]
* Cloud Integration (AWS, Azure, GCP). [cite: 198, 200]
* Advanced Threat Detection using Machine Learning (e.g., TensorFlow, PyTorch). [cite: 203, 205]
* User Interface and Management Console (Web-based dashboard). [cite: 209, 211]
* IoT Support with lightweight clients and efficient cryptography. [cite: 214, 216]
* Scalability Enhancements (load balancing, distributed databases). [cite: 220, 222]
* Compliance and Auditing features (detailed logging, SIEM integration). [cite: 225, 227, 228]
