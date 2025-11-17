# LogIQ – Enterprise Log Intelligence Analyzer

LogIQ is a PowerShell-based tool that transforms raw application logs 
into actionable insights for engineering, DevOps, and retail operations teams.

## Features
- Detect service failures
- Identify timeout patterns
- Highlight slow APIs (>300ms)
- Extract correlation IDs and build flow trace maps
- Capture device health and startup errors
- Identify transaction anomalies
- Generate JSON or HTML reports

## Usage
## Sample Logs

A synthetic example log file is included under `examples/sample.log`.
This file contains safe, non‑production log lines that demonstrate how LogIQ parses:
- service startup
- API calls and latency
- timeouts
- errors and exceptions
- correlation IDs
- transactions

You may place additional synthetic logs inside the `examples/` folder.

### Run analysis
.\logiq.ps1 -LogPath ".\examples"
### Generate JSON report
.\logiq.ps1 -LogPath ".\examples" -JsonReport

### Generate HTML report
.\logiq.ps1 -LogPath ".\examples" -HtmlReport