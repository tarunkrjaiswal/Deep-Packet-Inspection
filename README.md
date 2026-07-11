# Deep Packet Inspection (DPI) Engine & Dashboard

A professional, high-performance Deep Packet Inspection (DPI) Engine written in **Java** with a stunning, static-ready **React & Vite** dashboard for real-time traffic visualization.

---

## 📖 Overview

Deep Packet Inspection (DPI) is a technology used by ISPs and enterprise networks to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at Layer 3/4 headers (IP/Port), this DPI engine looks deep into the **Layer 7 Application payload** to identify and control traffic based on applications and domains.

### Key Capabilities:
- **Raw PCAP Parsing:** Manually dissects Ethernet, IPv4, TCP, and UDP protocols byte-by-byte without relying on external native PCAP libraries.
- **TLS SNI Extraction:** Intercepts TLS Client Hello handshakes to extract Server Name Indication (SNI) hostnames from encrypted HTTPS traffic.
- **HTTP/DNS Extraction:** Parses HTTP Host headers and unencrypted DNS query payloads.
- **Stateful Connection Tracking:** Uses a 5-Tuple (Src IP, Dst IP, Src Port, Dst Port, Protocol) hash to track active connections and their byte volumes.
- **Multi-threaded Architecture:** Implements a high-performance hash-based load balancer that queues traffic to multiple Fast Path worker threads.
- **Rule-Based Blocking:** Dynamically blocks traffic based on IPs, Domains, or Application Categories (e.g., YouTube, Discord).
- **Web Visualization:** Beautiful React dashboard to visualize traffic data, bandwidth usage, and blocked connections.

---

## 🏗️ System Architecture

### 1. Java DPI Engine (Backend)
The core engine (`java_version`) is designed for maximum throughput and concurrency:
1. **Reader Thread**: Ingests raw PCAP files and reads bytes into memory.
2. **Load Balancers (LB)**: Hashes the 5-Tuple of each packet to guarantee all packets from a single connection are routed to the exact same thread.
3. **Fast Path Processors (FP)**: Worker threads that consume packets from LB queues. They handle the heavy lifting: Layer 2-7 parsing, payload extraction, connection state management, and rule evaluation.
4. **JSON Exporter**: Aggregates statistics across all worker threads and exports a structured `report.json` for the frontend.

### 2. React Dashboard (Frontend)
A modern, glassmorphism-themed web application (`dashboard`) built with **React, Vite, TailwindCSS, and Recharts**.
- Designed to be **statically deployable** (e.g., to Vercel).
- Reads the generated `report.json` to display interactive Pie and Bar charts illustrating application breakdown, top domains, and dropped packet metrics.

---

## 🚀 Getting Started

### Prerequisites
- **Java 17+** and **Maven** (for the DPI Engine)
- **Node.js 18+** and **NPM** (for the Web Dashboard)

### 1. Build and Run the Java Engine

Navigate to the `java_version` directory and package the application using Maven:

```bash
cd java_version
mvn clean compile assembly:single
```

Execute the engine against a PCAP file. You can apply blocking rules and specify the JSON output path to point directly to the dashboard's source directory:

```bash
java -jar target/packet-analyzer-1.0-SNAPSHOT-jar-with-dependencies.jar \
  dpi ../mixed_traffic.pcap output.pcap \
  --block-app YOUTUBE \
  --block-domain discord.com \
  --json ../dashboard/src/report.json
```

**Arguments:**
- `dpi`: Command mode
- `../mixed_traffic.pcap`: Input PCAP file to analyze
- `output.pcap`: Output PCAP file (will exclude blocked packets)
- `--block-app <APP>`: Block a specific application (e.g., YOUTUBE, DISCORD)
- `--block-domain <DOMAIN>`: Block a specific domain substring
- `--block-ip <IP>`: Block a specific IP address
- `--json <FILE>`: Export statistics to a JSON file

### 2. Launch the Web Dashboard

Navigate to the `dashboard` directory and start the Vite development server:

```bash
cd dashboard
npm install
npm run dev
```

Open `http://localhost:5173` in your browser. 

> **Pro Tip:** While the dashboard is running locally, whenever you execute the Java engine and overwrite the `report.json` file, Vite's Hot Module Replacement (HMR) will **instantly and automatically refresh** the web dashboard with your new traffic data!

---

## 🧠 Technical Deep Dive: SNI Extraction

Even though HTTPS traffic is encrypted, the very first packet sent by the client (the TLS Client Hello) is transmitted in **plaintext**. 

This engine intercepts this packet, traverses the TLS record header, skips the session IDs and cipher suites, and scans the extensions payload for the `0x0000` (Server Name Indication) extension to extract the target domain (e.g., `www.youtube.com`). This allows the engine to accurately identify and block HTTPS applications without breaking end-to-end encryption.

---
