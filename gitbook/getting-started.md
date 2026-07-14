# Getting Started

## Prerequisites
* **Java 17+** and **Maven** (for the DPI Engine)
* **Node.js 18+** and **NPM** (for the Web Dashboard)

## 1. Build and Run the Java Engine

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
* `dpi`: Command mode
* `../mixed_traffic.pcap`: Input PCAP file to analyze
* `output.pcap`: Output PCAP file (will exclude blocked packets)
* `--block-app <APP>`: Block a specific application (e.g., YOUTUBE, DISCORD)
* `--block-domain <DOMAIN>`: Block a specific domain substring
* `--block-ip <IP>`: Block a specific IP address
* `--json <FILE>`: Export statistics to a JSON file

## 2. Launch the Web Dashboard

Navigate to the `dashboard` directory and start the Vite development server:

```bash
cd dashboard
npm install
npm run dev
```

Open `http://localhost:5173` in your browser. 

> **Pro Tip:** While the dashboard is running locally, whenever you execute the Java engine and overwrite the `report.json` file, Vite's Hot Module Replacement (HMR) will **instantly and automatically refresh** the web dashboard with your new traffic data!
