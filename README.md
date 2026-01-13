# Windows Service & Process Monitoring Agent

![Project Badge](https://img.shields.io/badge/status-active-brightgreen) ![Python 3.7+](https://img.shields.io/badge/python-3.7%2B-blue) ![License](https://img.shields.io/badge/license-MIT-green)

## Overview

A comprehensive **Windows Service & Process Monitoring Agent** designed for detecting malicious processes, unauthorized services, suspicious parent-child process relationships, and potential privilege escalation techniques. Built for SOC analysts, incident responders, and threat detection professionals.

## Key Features

✅ **Process Tree Analysis** - Detect anomalous parent-child relationships (e.g., cmd.exe spawned from winword.exe)  
✅ **Service Auditing** - Monitor startup services for unauthorized or newly added entries  
✅ **Whitelist/Blacklist Detection** - Identify unknown, unsigned, or high-risk processes  
✅ **Real-time Monitoring** - Continuous process and service surveillance  
✅ **Alert System** - Behavior-based and rule-driven alerts  
✅ **Comprehensive Reporting** - Timestamped logs and detection reports  
✅ **Kali Linux Compatible** - Penetration testing and security scanning scripts included  

## Project Structure

```
Windows-Service-Process-Monitoring-Agent/
├── README.md
├── requirements.txt
├── src/
│   ├── monitor_agent.py          # Main monitoring agent
│   ├── process_monitor.py        # Process enumeration & analysis
│   ├── service_audit.py          # Windows service auditing
│   ├── anomaly_detector.py       # Detection rules & alerts
│   ├── whitelist_manager.py      # Whitelist/blacklist logic
│   └── reporter.py               # Reporting & logging
├── config/
│   ├── detection_rules.yaml      # Detection rules configuration
│   ├── whitelist.json            # Whitelisted processes
│   └── blacklist.json            # Blacklisted processes
├── kali_linux/
│   ├── process_scanner.sh        # Linux-based scanning
│   └── threat_analyzer.py        # Linux-compatible threat analysis
├── logs/
│   └── monitoring_logs.csv       # Event logs
├── reports/
│   └── detection_report.json     # Final detection report
└── docs/
    ├── INSTALLATION.md           # Setup guide
    ├── USAGE.md                  # Usage examples
    └── ARCHITECTURE.md           # Technical architecture
```

## Installation

### Prerequisites
- Python 3.7+
- Windows 10/11 or Windows Server 2016+
- Administrator privileges

### Setup

```bash
# Clone repository
git clone https://github.com/gauravmalhotra3300-hub/Windows-Service-Process-Monitoring-Agent.git
cd Windows-Service-Process-Monitoring-Agent

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

```bash
# Run monitoring agent
python src/monitor_agent.py

# Run process tree analysis
python src/process_monitor.py --analyze

# Audit startup services
python src/service_audit.py --audit

# Generate detection report
python src/reporter.py --generate
```

## Core Modules

### 1. Process Monitor (`process_monitor.py`)
- Enumerates active processes
- Builds parent-child process trees
- Detects suspicious process chains

### 2. Service Audit (`service_audit.py`)
- Lists all Windows startup services
- Identifies unauthorized service entries
- Detects service permission misconfigurations

### 3. Anomaly Detector (`anomaly_detector.py`)
- Rule-based detection engine
- Behavior-based anomaly scoring
- Real-time alert generation

### 4. Whitelist Manager (`whitelist_manager.py`)
- Maintain approved process list
- Filter legitimate processes
- Reduce false positives

### 5. Reporter (`reporter.py`)
- Generate timestamped logs
- Export JSON/CSV reports
- Create threat summary

## Detection Examples

### Suspicious Process Chain
```
Suspicious parent-child detected:
  cmd.exe spawned from: winword.exe
  Status: ALERT - Possible document-based malware
```

### Unauthorized Service
```
New startup service detected:
  Service: MalwareServiceX
  Path: C:\Windows\Temp\malware.exe
  Status: ALERT - High risk
```

### Process from Temp Directory
```
Unauthorized process running:
  Process: unknown.exe
  Path: C:\Users\AppData\Local\Temp
  Status: ALERT - Suspicious location
```

## Kali Linux Integration

For penetration testing and security assessments, use the Kali Linux toolkit:

```bash
# Run Linux-based process scanner
cd kali_linux
bash process_scanner.sh

# Analyze threats using Python
python threat_analyzer.py --scan
```

## Configuration

Edit `config/detection_rules.yaml` to customize detection rules:

```yaml
detection_rules:
  suspicious_parent_child:
    - source: winword.exe
      target: cmd.exe
      severity: HIGH
    - source: excel.exe
      target: powershell.exe
      severity: HIGH
```

## Output Examples

### Monitoring Logs
```csv
timestamp,pid,ppid,process_name,status,severity,description
2025-01-13 19:30:45,1234,5678,cmd.exe,ALERT,HIGH,cmd spawned from winword.exe
```

### Detection Report
```json
{
  "timestamp": "2025-01-13T19:35:20",
  "total_processes": 256,
  "suspicious_processes": 3,
  "alerts": [
    {
      "type": "suspicious_parent_child",
      "severity": "HIGH",
      "source_process": "winword.exe",
      "target_process": "cmd.exe"
    }
  ]
}
```

## Security Considerations

⚠️ This tool requires **Administrator/Root privileges**  
⚠️ Use in authorized environments only  
⚠️ Follow applicable laws and regulations  
⚠️ Test in isolated lab environments first  

## License

MIT License - See LICENSE file for details

## Contributing

Contributions welcome! Please fork and submit pull requests.

## Support

For issues, feature requests, or documentation updates, open an issue on GitHub.

## Author

**Gaurav Malhotra** - Cybersecurity & Threat Detection Specialist

---

**Last Updated:** January 2025
