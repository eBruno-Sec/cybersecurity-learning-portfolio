# Ping Flood Lab Using Docker

**Network DoS Attack Simulation in Containerized Environment**  
*Erwin Bruno - 2025*  
*Secure Network Engineering (CYBR-508-02P)*

## Objective

This lab demonstrates how to simulate a ping flood DoS attack using Docker containers in an isolated network environment. Students will learn to monitor network traffic, analyze system resource consumption during attacks, and understand the impact of bandwidth limitations on attack effectiveness.

## Prerequisites

- Basic understanding of Docker and containerization
- Docker installed on your system (Linux, Mac, or Windows)
- Administrative privileges to run Docker commands
- Familiarity with Linux command line interface
- Understanding of ICMP protocol and network monitoring concepts

## Lab Setup

### Step 1: Create Docker Network
Create an isolated Docker network for the lab environment.

```bash
docker network create pingflood-net
```

Verify network creation:
```bash
docker network ls
```

### Step 2: Launch Target Container
Deploy the victim container with CPU limitations.

```bash
docker run -dit --name target --network pingflood-net --cpus="0.2" ubuntu /bin/bash
```

Verify container is running:
```bash
docker ps
```

### Step 3: Launch Attacker Container
Deploy the attacking container on the same network.

```bash
docker run -dit --name attacker --network pingflood-net ubuntu /bin/bash
```

Confirm both containers are active:
```bash
docker ps
```

## Attack Execution

### Step 4: Prepare Target for Monitoring
Access the target container and install monitoring tools.

```bash
docker exec -it target /bin/bash
```

Inside the target container, install required utilities:
```bash
apt update && apt install iputils-ping tcpdump htop iftop iprouge2 stress -y
```

Configure bandwidth limitation to simulate constrained network conditions:
```bash
tc qdisc add dev eth0 root tbf rate 1mbit burst 32kbit latency 400ms
```

Start system stress simulation:
```bash
stress --cpu 1 --io 1 --vm 1 --vm-bytes 64M --timeout 30s
```

### Step 5: Set Up Monitoring Windows
Open three additional terminal windows and connect each to the target container:

```bash
docker exec -it target /bin/bash
```

In the monitoring windows, run:

**Window 1 - Network Traffic Analysis:**
```bash
tcpdump -i eth0 icmp
```

**Window 2 - Bandwidth Monitoring:**
```bash
iftop
```

**Window 3 - System Resource Monitoring:**
```bash
htop
```

### Step 6: Execute Ping Flood Attack
In a new terminal window, access the attacker container:

```bash
docker exec -it attacker /bin/bash
```

Install ping utilities:
```bash
apt update && apt install iputils-ping -y
```

Launch the ping flood attack:
```bash
ping -f -s 1400 target
```

## Results and Observations

During the ping flood attack execution, comprehensive monitoring revealed significant system impact across multiple metrics.

### Key Findings

* **Network Traffic**: tcpdump displayed continuous ICMP Echo Request packets from attacker container, confirming active flood targeting
* **Bandwidth Utilization**: iftop showed sharp increase in eth0 traffic with sustained throughput reaching the imposed 1Mbit limit
* **System Resources**: htop revealed significant CPU utilization spikes due to stress process and ICMP traffic processing overhead
* **Host Impact**: Host machine CPU utilization climbed to 99-100%, demonstrating attack spillover effects
* **Performance Degradation**: Container remained mostly responsive but with noticeable performance degradation under load

### Real-World Implications

#### Organizations at Risk
* Small businesses with limited bandwidth infrastructure
* IoT device networks with constrained processing capabilities
* Legacy systems without proper DoS protection mechanisms
* Cloud environments with shared resource constraints

#### Business Impact
Even simple DoS attacks like ping floods can overwhelm systems when resources are constrained. In containerized environments with intentional resource limitations, systems become vulnerable to rapid resource exhaustion, leading to service degradation and potential downtime.

## Defense Strategies

### Technical Mitigations
* Implement rate limiting on ICMP traffic at network perimeter
* Configure proper firewall rules to filter excessive ping requests
* Deploy intrusion detection systems to identify flood patterns
* Set up traffic shaping policies to manage bandwidth allocation

### Infrastructure Solutions
* Utilize load balancers with DoS protection capabilities
* Implement network segmentation to isolate critical systems
* Deploy DDoS mitigation services at ISP or cloud provider level
* Configure monitoring alerts for abnormal traffic patterns

## Cleanup

Remove lab environment components:

```bash
docker stop target attacker
docker rm target attacker
docker network rm pingflood-net
```

## Educational Value

This lab demonstrates:
* How resource constraints amplify DoS attack effectiveness
* Network monitoring techniques using tcpdump and iftop
* System resource analysis during active attacks
* Container-based security testing methodologies
* Real-time attack observation and analysis skills

## Disclaimer

⚠️ **For Educational Purposes Only**

This lab is designed exclusively for educational purposes in controlled environments. Never conduct these attacks against unauthorized systems or networks. Always ensure compliance with applicable laws and regulations. Perform testing only in isolated environments that you own or have explicit permission to test.
