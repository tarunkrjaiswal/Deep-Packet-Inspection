# System Architecture

## 1. Java DPI Engine (Backend)
The core engine (`java_version`) is designed for maximum throughput and concurrency:

1. **Reader Thread**: Ingests raw PCAP files and reads bytes into memory.
2. **Load Balancers (LB)**: Hashes the 5-Tuple of each packet to guarantee all packets from a single connection are routed to the exact same thread.
3. **Fast Path Processors (FP)**: Worker threads that consume packets from LB queues. They handle the heavy lifting: Layer 2-7 parsing, payload extraction, connection state management, and rule evaluation.
4. **JSON Exporter**: Aggregates statistics across all worker threads and exports a structured `report.json` for the frontend.

## 2. React Dashboard (Frontend)
A modern, glassmorphism-themed web application (`dashboard`) built with **React, Vite, TailwindCSS, and Recharts**.

* Designed to be **statically deployable** (e.g., to Vercel).
* Reads the generated `report.json` to display interactive Pie and Bar charts illustrating application breakdown, top domains, and dropped packet metrics.
