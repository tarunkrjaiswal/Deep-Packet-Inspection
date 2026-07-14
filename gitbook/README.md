# Deep Packet Inspection (DPI) Engine

A professional, high-performance Deep Packet Inspection (DPI) Engine written in **Java** with a stunning, static-ready **React & Vite** dashboard for real-time traffic visualization.

## 📖 Overview

Deep Packet Inspection (DPI) is a technology used by ISPs and enterprise networks to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at Layer 3/4 headers (IP/Port), this DPI engine looks deep into the **Layer 7 Application payload** to identify and control traffic based on applications and domains.

### Key Capabilities

* **Raw PCAP Parsing:** Manually dissects Ethernet, IPv4, TCP, and UDP protocols byte-by-byte without relying on external native PCAP libraries.
* **TLS SNI Extraction:** Intercepts TLS Client Hello handshakes to extract Server Name Indication (SNI) hostnames from encrypted HTTPS traffic.
* **HTTP/DNS Extraction:** Parses HTTP Host headers and unencrypted DNS query payloads.
* **Stateful Connection Tracking:** Uses a 5-Tuple (Src IP, Dst IP, Src Port, Dst Port, Protocol) hash to track active connections and their byte volumes.
* **Multi-threaded Architecture:** Implements a high-performance hash-based load balancer that queues traffic to multiple Fast Path worker threads.
* **Rule-Based Blocking:** Dynamically blocks traffic based on IPs, Domains, or Application Categories (e.g., YouTube, Discord).
* **Web Visualization:** Beautiful React dashboard to visualize traffic data, bandwidth usage, and blocked connections.
