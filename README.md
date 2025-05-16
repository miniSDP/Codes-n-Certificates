# Software-Defined Perimeter (SDP) Project

This project implements a Software-Defined Perimeter (SDP), a modern security framework designed to enhance network security and access control based on the Zero Trust Architecture (ZTA). 

## Description

The SDP system operates on the principle of "never trust, always verify." Access to network resources is granted only after strict identity verification and policy enforcement, regardless of whether the user or device is inside or outside the network. This approach dynamically defines the network perimeter based on user identity, device, and context, effectively hiding network resources from unauthorized users.

The system comprises three core components:
* **Client**: Initiates access requests to the Controller via Single Packet Authorization (SPA) and establishes secure communication using mutual TLS (mTLS). 
* **Controller**: The central authority that validates client credentials and permissions, and enforces access control policies. 
* **Gateway**: Enforces dynamic firewall rules (using iptables) to allow or revoke client access and acts as a secure entry point to internal resources.

## Key Features

* **Zero Trust Architecture**: No user or device is trusted by default.
* **Single Packet Authorization (SPA)**: Ensures only authorized clients can initiate access, preventing port scanning and network enumeration. 
* **Mutual TLS (mTLS)**: Provides secure, encrypted communication and mutual authentication between all components, preventing man-in-the-middle attacks. 
* **Dynamic Firewall Rules**: Enforces fine-grained access control by updating firewall rules in real-time based on client access details. 
* **Reduced Attack Surface**: Hides internal network resources from unauthorized users until access is explicitly granted. 
* **Identity-Centric Security**: Access is granted based on authenticated and authorized users and devices.

## Technologies Used

* **Programming Language**: Go (Golang) 
    * Key Libraries: `crypto/tls`, `net/http`, `encoding/json`, `os/exec` 
* **Cryptography**: X.509 Certificates (managed with OpenSSL) for mTLS. 
* **Firewall Management**: iptables for dynamic firewall rule updates. 
* **SPA Implementation**: fwknop for Single Packet Authorization. 
## Project Setup

### Prerequisites

* Install Go: [https://golang.org/dl/](https://golang.org/dl/) 
* Install OpenSSL 
* Install iptables (Gateway, Server) 
* Install fwknop-client (Client) 
* Install fwknop-server (Server/Controller) 

### Setup Steps

1.  **Configure fwknop for Secure Access**
    * Generate SPA keys on the client using `fwknop --key-gen`. 
    * Configure the fwknop server (`/etc/fwknop/access.conf` and `/etc/fwknop/fwknopd.conf`) with the generated keys and appropriate network interface.
    * Start the `fwknop-server` service. 
    * Configure firewall (iptables) to block relevant ports by default and allow only SPA-authorized connections. **Test SPA thoroughly before locking down ports.** 

2.  **Generate Certificates**:
    * Generate server certificates (`server.key`, `server.crt`) using OpenSSL. Store in `certs/` directory. 
    * Generate client certificates (`client.key`, `client.crt`) using OpenSSL. Store in `certs/` directory. 
    * Generate gateway certificates (`gateway.key`, `gateway.crt`) using OpenSSL. Store in `certs/` directory. (Assumed, as gateway also uses mTLS)

3.  **Configure Components**
    * **Client (`client.go`)**: Update paths to client certificate and key. 
    * **Controller (`controller.go`)**: Update paths to server certificate and key.
    * **Gateway (`gateway.go`)**: Update paths to gateway certificate and key.
    * Update the user permissions and authorized services list in the controller's `permissions` folder as required. 

## How to Run

1.  **Start the Controller**:
    * Navigate to the `controller` directory.
    * Run `./fwknop_iptables.sh` (if applicable for initial setup or rules). 
    * Run `go run controller.go`. 

2.  **Start the Gateway**:
    * Run services on the gateway (e.g., chat and HTTP services) in separate terminals:
        * `go run chats.go` 
        * `go run http.go` 
    * Navigate to the `gateway` directory.
    * Run `go run gateway.go`. 

3.  **Initiate Access from the Client**:
    * Navigate to the `client` directory.
    * Run `./client.sh` (This script likely handles the SPA packet sending and then tries to connect). 

## Testing

The project underwent several testing phases:

* **Unit Testing**: Each component (Client, Controller, Gateway) was tested in isolation using Go's built-in testing framework. 
* **Integration Testing**: Tested interactions between components to ensure end-to-end functionality. 
* **Penetration Testing**: Simulated attacks (e.g., MITM, replay, brute force, port scanning) using tools like nmap, Wireshark, and fwknop to identify vulnerabilities. 

### Key Test Cases Included:
* Client Authentication with Controller via mTLS. 
* SPA Packet Validation by the Controller. 
* Dynamic Firewall Rule Updates by the Gateway.
* Authorized Resource Access by the Client through the Gateway.
* Resistance to MITM, Replay, Brute Force attacks, and Port Scanning. 

### Outcomes:
The system successfully authenticated clients, validated SPA packets, updated firewall rules dynamically, allowed authorized resource access, and resisted simulated attacks. 

## Future Upgrades Considered

* Automated Certificate Management (e.g., using Certbot, Hashicorp Vault). 
* Multi-Factor Authentication (MFA) integration (e.g., Google Authenticator, Authy). 
* Cloud Integration (AWS, Azure, GCP). 
* Advanced Threat Detection using Machine Learning (e.g., TensorFlow, PyTorch). 
* User Interface and Management Console (Web-based dashboard). 
* IoT Support with lightweight clients and efficient cryptography. 
* Scalability Enhancements (load balancing, distributed databases).
* Compliance and Auditing features (detailed logging, SIEM integration). 
