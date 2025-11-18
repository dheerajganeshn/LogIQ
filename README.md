# LogIQ 🧠📊  
**Enterprise Log Intelligence for DevOps, SRE, and Backend Engineers**

LogIQ is a lightweight, PowerShell-based log analyzer that turns raw logs into **actionable insights**.

It is designed to work with:

- ✅ POS / Retail logs (e.g., 7POS / SCO)
- ✅ Application logs
- ✅ Datadog export logs (JSON)
- ✅ ELK / Splunk JSON logs
- ✅ API performance logs
- ✅ Windows / Linux server logs
- ✅ Kubernetes / Docker logs (when piped to files)

---

## ✨ Features

- 🔎 Detects **errors**, **timeouts**, and **service failures**
- ⏱ Extracts **slow API calls** and computes **P50 / P90 / P99 latencies**
- 🧩 Groups similar errors for **pattern discovery**
- 🔗 Maps logs by **Correlation IDs** (trace-style debugging)
- 🧮 Generates **summarized metrics**
- 🧾 Outputs:
  - **JSON report** (`logiq-report.json`)
  - **Styled HTML dashboard** (`logiq-report.html`)
- 📡 Supports **real-time tail mode** for on-the-fly analysis

---

## 🚀 Getting Started

### 1. Requirements

- PowerShell 7+ (cross-platform)  
  - Windows: pre-installed or via [Microsoft Store]  
  - macOS: `brew install --cask powershell`  
  - Linux: use official Microsoft packages (`pwsh`)

### 2. Clone the repository

```bash
git clone https://github.com/<your-username>/LogIQ.git
cd LogIQ

### 3. Usage

Analyze a single log file:
pwsh ./LogIQ.ps1 -LogPath ./logs/app.log -HtmlReport -JsonReport

Analyze all .log files in a directory:
pwsh ./LogIQ.ps1 -LogPath ./logs -HtmlReport

Real-time tail mode (live):
pwsh ./LogIQ.ps1 -LogPath ./logs/app.log -Tail

📌 Why LogIQ Is Important for Organizations
Modern organizations generate millions of log lines each day across distributed systems,
microservices, POS terminals, Kubernetes clusters, and cloud-native applications.
Manually analyzing this volume of logs is slow, inconsistent, and reactive.

LogIQ provides immediate value to engineering teams by:

### 🔥 1. Accelerating Incident Response
• Detects errors, timeouts, service failures, and slow API calls automatically.  
• Helps SREs identify root causes faster without opening massive ELK or Datadog dashboards.  
• Reduces Mean Time To Detect (MTTD) and Mean Time To Resolve (MTTR).

### 🎯 2. Improving System Reliability
• Identifies unhealthy services, broken dependencies, and failing endpoints.  
• Highlights recurring error patterns and correlation IDs that indicate systemic failures.  
• Surfaces high-latency calls before they become customer-impacting issues.

### 🧭 3. Empowering Developers with Actionable Insights
• Converts messy logs into structured, readable dashboards.  
• Helps developers understand production issues without relying on Ops teams.  
• Makes it easy to reproduce and debug failures locally.

### 📊 4. Reducing Observability Tooling Costs
• Datadog, Splunk, and ELK ingest costs grow rapidly with log volume.  
• LogIQ lets teams export logs and analyze them offline — saving ingestion cost.  
• Lightweight alternative for analyzing logs during testing and pre-production.

### 🚀 5. Works Anywhere — Cloud, On-Prem, or POS Devices
• Fully portable PowerShell-based tooling.  
• Runs on Windows, macOS, and Linux.  
• Ideal for retail/enterprise environments with distributed edge devices (POS, IoT).

### 🛡 6. Helps Build a Culture of Proactive Monitoring
• Encourages teams to look at latency percentiles, service health, and recurring errors.  
• Makes log reviews part of CI pipelines or automated nightly checks.  
• Reduces firefighting by preventing issues instead of reacting to them.

---

LogIQ turns raw unstructured logs into a **single source of truth** for incident analysis, 
reliability engineering, debugging, and service health monitoring — all without requiring 
expensive observability platforms or complex infrastructure.