# 🛡️ Automated SOC Alert Triage & Incident Reporting System


A **Master's-level cybersecurity project** that automates alert triage, threat intelligence enrichment, and executive incident report generation for Security Operations Centers (SOCs).

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Workflow](#workflow)
- [Sample Output](#sample-output)
- [Database Schema](#database-schema)
- [Security & Best Practices](#security--best-practices)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## 🎯 Overview

This project demonstrates **end-to-end SOC automation** by:

1. **Ingesting** raw security alerts from Wazuh SIEM
2. **Parsing** alert metadata (source IPs, rule IDs, severity levels, timestamps)
3. **Enriching** threat data via AbuseIPDB API (reputation scores, geographic location, ISP details)
4. **Triaging** alerts using automated rule evaluation (filtering noise, prioritizing threats)
5. **Persisting** triaged records in a structured SQLite database
6. **Generating** professional executive incident reports in PDF format

This is a **portfolio-ready project** that showcases Python automation, API integration, SQL database design, and cybersecurity fundamentals at a Master's level.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    SIEM Alert Ingestion                         │
│                   (Wazuh JSON Logs / API)                       │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│               Artifact Parser & Extraction                       │
│          (Alert ID, Rule ID, Severity, Source IP, TS)          │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│          Threat Intelligence Enrichment (AbuseIPDB API)         │
│    (Reputation Score, Country, ISP, Abuse Confidence %)        │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│            Automated Triage & Rule Evaluation                    │
│      (Filter Noise, Categorize Risk, Assign Priority)           │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│        Data Persistence (SQLite Triage Database)                │
│                    (soc_alerts.db)                              │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│      Executive PDF Report Generation (FPDF2)                    │
│               (SOC_Incident_Report.pdf)                         │
└─────────────────────────────────────────────────────────────────┘
```

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **🔍 Alert Ingestion** | Parse JSON alerts from Wazuh SIEM logs and API endpoints |
| **🌐 Threat Intel Enrichment** | Query AbuseIPDB for reputation scores, geolocation, ISP data |
| **⚙️ Automated Triage** | Rule-based filtering to prioritize critical threats vs. noise |
| **💾 Data Persistence** | Structured SQLite database for audit trails and compliance |
| **📊 PDF Report Generation** | Professional executive incident reports with FPDF2 |
| **🔐 Secure Config** | `.env`-based API key management (no hardcoded secrets) |
| **📝 Logging** | Comprehensive debug and audit logs for troubleshooting |
| **🧪 Modular Design** | Clean separation of concerns (parsing, enrichment, triage, reporting) |

---

## 🛠️ Tech Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Language** | Python 3.8+ | Core automation logic |
| **SIEM** | Wazuh 4.14.8 | Alert ingestion & log source |
| **Threat Intel** | AbuseIPDB API | IP reputation enrichment |
| **Database** | SQLite 3 | Alert storage & querying |
| **HTTP Client** | `requests` | API communication |
| **Config** | `python-dotenv` | Environment variable management |
| **PDF** | `fpdf2` | Executive report generation |
| **Version Control** | Git & GitHub | Portfolio & collaboration |

---

## 📁 Project Structure

```
soc-incident-triage/
│
├── 📄 main.py                      # Core automation execution engine
│   ├─ Orchestrates alert ingestion pipeline
│   ├─ Coordinates threat intelligence queries
│   └─ Triggers triage logic and report generation
│
├── 📄 fetch_alerts.py              # Log parser & threat intel fetcher
│   ├─ Parses Wazuh JSON logs
│   ├─ Extracts alert metadata (IPs, rule IDs, severity)
│   └─ Queries AbuseIPDB API for enrichment data
│
├── 📄 database.py                  # SQLite persistence interface
│   ├─ Creates/manages triage database schema
│   ├─ Inserts triaged alert records
│   └─ Queries historical alerts for reporting
│
├── 📄 generate_report.py           # PDF report generator (FPDF2)
│   ├─ Compiles triaged data from database
│   ├─ Formats executive summary sections
│   └─ Exports to SOC_Incident_Report.pdf
│
├── 📄 requirements.txt             # Python dependencies
│   ├─ requests
│   ├─ python-dotenv
│   └─ fpdf2
│
├── 📄 .env                         # Environment variables (Git-ignored)
│   └─ ABUSEIPDB_API_KEY=your_key_here
│
├── 📄 .gitignore                   # Security exclusion file
│   ├─ .env (API keys)
│   ├─ *.db (databases)
│   ├─ __pycache__/
│   └─ *.pdf (reports with data)
│
├── 📄 README.md                    # This file
│
└── 📁 logs/                        # (Optional) Audit logs directory
    └─ triage_audit.log
```

---

## 📋 Prerequisites

Before you begin, ensure you have:

- ✅ **Python 3.8 or higher** installed
- ✅ **pip** (Python package manager)
- ✅ **Wazuh 4.14+ SIEM** running locally or accessible via API
- ✅ **AbuseIPDB API key** (free account at [abuseipdb.com](https://www.abuseipdb.com/))
- ✅ **Git** for version control
- ✅ **Text editor** or IDE (VS Code, PyCharm, Vim, etc.)

### Check Python Version
```bash
python --version
# Output should be Python 3.8.0 or higher
```

---

## 🚀 Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/soc-incident-triage.git
cd soc-incident-triage
```

### Step 2: Create a Python Virtual Environment

```bash
# On Windows
python -m venv venv
venv\Scripts\activate

# On macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

**Expected Output:**
```
Successfully installed requests fpdf2 python-dotenv
```

### Step 4: Verify Installation

```bash
python -c "import requests, fpdf, dotenv; print('All dependencies installed!')"
```

---

## ⚙️ Configuration

### Create `.env` File

Create a `.env` file in the project root directory:

```bash
touch .env
```

### Add API Key

Edit `.env` and add your AbuseIPDB API key:

```plaintext
# AbuseIPDB Configuration
ABUSEIPDB_API_KEY=your_api_key_here
ABUSEIPDB_BASE_URL=https://api.abuseipdb.com/api/v2/check

# Wazuh Configuration (optional, if querying API)
WAZUH_MANAGER_IP=192.168.56.101
WAZUH_MANAGER_PORT=55000
WAZUH_API_USER=admin
WAZUH_API_PASSWORD=admin
```

### Get Your AbuseIPDB API Key

1. Visit [abuseipdb.com/register](https://www.abuseipdb.com/register)
2. Sign up for a **free account**
3. Log in and navigate to **Account Settings → API**
4. Copy your **API Key**
5. Paste it into `.env` as shown above

> ⚠️ **Security**: Never commit `.env` to Git. It's listed in `.gitignore` by default.

---

## 🎬 Usage

### Run the Full Triage Pipeline

```bash
python main.py
```

**Expected Output:**
```
[*] Starting SOC Alert Triage Engine...
[*] Step 1: Fetching alerts from Wazuh...
[+] Loaded 42 alerts from /var/ossec/logs/alerts.json
[*] Step 2: Parsing alert metadata...
[+] Extracted 42 alert records (IPs, rule IDs, severity levels)
[*] Step 3: Querying AbuseIPDB for threat intelligence...
[+] Enriched 42 alerts with reputation scores
[*] Step 4: Executing triage logic...
[+] Classified 5 HIGH-RISK alerts | 12 MEDIUM | 25 LOW
[*] Step 5: Storing triaged data in SQLite...
[+] Inserted 42 records into soc_alerts.db
[+] Triage pipeline completed successfully!
```

### Generate Executive PDF Report

```bash
python generate_report.py
```

**Expected Output:**
```
[*] Generating executive incident report...
[+] Queried soc_alerts.db for triaged records...
[+] Compiled report for 42 incidents
[+] Report generated: SOC_Incident_Report.pdf
```

---

## 📊 Workflow

### Full End-to-End Process

```
1. ALERT INGESTION
   └─ main.py → fetch_alerts.py
      └─ Reads Wazuh JSON logs from /var/ossec/logs/alerts/alerts.json
      └─ Extracts: Alert ID, Rule ID, Severity, Source IP, Timestamp

2. THREAT INTELLIGENCE ENRICHMENT
   └─ fetch_alerts.py → AbuseIPDB API
      └─ Queries: Reputation Score, Country, ISP, Abuse Confidence %

3. AUTOMATED TRIAGE
   └─ main.py (triage_logic)
      └─ Filters: Internal IPs (noise), Low-severity alerts
      └─ Prioritizes: External IPs + High Severity + Recent

4. DATA PERSISTENCE
   └─ database.py → SQLite (soc_alerts.db)
      └─ Stores: Alert records with enrichment data + triage status

5. REPORT GENERATION
   └─ generate_report.py → PDF (SOC_Incident_Report.pdf)
      └─ Compiles: Executive summary, incidents table, recommendations
```

---

## 📤 Sample Output

### Console Output (main.py)
```
[*] Step 4: Summary of Triage Database Records:

  • Alert ID: 1791220670.102034
    Agent: lab-agent-VMware-Virtual-Platform
    Status: NEW
    Timestamp: 2026-10-05T17:17:50.289+0000
    Rule ID / Level: 5712 (Level 10)
    Description: sshd: brute force trying to get access to the system. Non existent user.
    Source IP: 185.220.101.5
    Abuse Score: 100%
    Location / ISP: DE - Artikel10 e.V.
    Triage Status: HIGH-RISK

───────────────────────────────────────────────────────────

  • Alert ID: 1791220670.102035
    Agent: lab-agent-VMware-Virtual-Platform
    Status: NEW
    Timestamp: 2026-10-05T17:18:15.412+0000
    Rule ID / Level: 5712 (Level 10)
    Description: sshd: brute force trying to get access to the system.
    Source IP: 192.168.1.100
    Abuse Score: 0%
    Location / ISP: INTERNAL - Lab Network
    Triage Status: LOW-RISK (Internal)
```

### PDF Report (SOC_Incident_Report.pdf)
```
╔═══════════════════════════════════════════════════════════╗
║        SOC INCIDENT TRIAGE & RESPONSE REPORT             ║
║                   Generated: 2026-10-05                  ║
╚═══════════════════════════════════════════════════════════╝

EXECUTIVE SUMMARY
─────────────────
Total Alerts Processed:        42
High-Risk Incidents:           5
Medium-Risk Incidents:         12
Low-Risk Incidents:            25
Report Generated By:           Automated Triage Engine v1.0

CRITICAL INCIDENTS
──────────────────
[1] SSH Brute Force (185.220.101.5 - Tor Exit Node, DE)
    Severity: CRITICAL | Confidence: 100% | Attempts: 47
    Recommendation: Block IP, review auth logs, enable MFA

[2] SQL Injection Probe (203.0.113.45 - Unknown ISP)
    Severity: HIGH | Confidence: 87% | Pattern: SQLi signatures detected
    Recommendation: WAF rule deployment, log forensics required

... (additional incidents)
```

---

## 🗄️ Database Schema

### Table: `triaged_alerts`

```sql
CREATE TABLE triaged_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT UNIQUE NOT NULL,
    agent_id TEXT,
    rule_id INTEGER,
    severity_level INTEGER,
    source_ip TEXT,
    timestamp DATETIME,
    description TEXT,
    abuse_score INTEGER,
    location TEXT,
    isp TEXT,
    triage_status TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Example Query
```sql
-- Fetch all HIGH-RISK alerts from the last 24 hours
SELECT alert_id, source_ip, severity_level, abuse_score 
FROM triaged_alerts 
WHERE triage_status = 'HIGH-RISK' 
  AND timestamp > datetime('now', '-1 day')
ORDER BY severity_level DESC;
```

---

## 🔐 Security & Best Practices

### ✅ What This Project Does Right

- **No Hardcoded Secrets**: API keys stored in `.env` (Git-ignored)
- **HTTPS Only**: All API calls use secure TLS connections
- **Rate Limiting**: Respects AbuseIPDB API rate limits (15 requests/day free tier)
- **Input Validation**: Sanitizes alert data before database insertion
- **Audit Logging**: Tracks all enrichment queries and triage decisions
- **Least Privilege**: SQLite database with minimal required permissions

### ⚠️ Production Considerations

**For production SOC deployment:**

1. **Upgrade Database**: Replace SQLite with PostgreSQL/MySQL for multi-user access
2. **API Key Rotation**: Implement automated key rotation (monthly)
3. **HTTPS Certificates**: Use proper SSL/TLS certs (not self-signed)
4. **Backup Strategy**: Daily automated database backups to secure storage
5. **Monitoring**: Set up alerts for API quota exhaustion, database errors
6. **Access Control**: Implement RBAC for report access
7. **Compliance**: Ensure PII/sensitive data is redacted from reports

---

## 🐛 Troubleshooting

### Issue: `ModuleNotFoundError: No module named 'requests'`

**Solution:**
```bash
pip install -r requirements.txt
```

### Issue: `AbuseIPDB API Key Invalid`

**Solution:**
1. Verify `.env` file exists in project root
2. Check API key is correctly copied (no extra spaces)
3. Test API key directly:
   ```bash
   python -c "from fetch_alerts import query_abuseipdb; print(query_abuseipdb('8.8.8.8'))"
   ```

### Issue: `Wazuh Logs Not Found`

**Solution:**
1. Verify Wazuh VM is running: `https://192.168.56.101`
2. Check log path: `/var/ossec/logs/alerts/alerts.json` exists
3. Verify file permissions: `ls -la /var/ossec/logs/alerts/`

### Issue: `SQLite Database Locked`

**Solution:**
```bash
# Close all connections and restart
rm -f soc_alerts.db
python main.py  # Will recreate DB
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. **Fork** this repository
2. **Create a feature branch**: `git checkout -b feature/your-feature`
3. **Commit changes**: `git commit -m "Add your feature"`
4. **Push to branch**: `git push origin feature/your-feature`
5. **Open a Pull Request** with a clear description

### Code Style
- Follow **PEP 8** conventions
- Add docstrings to all functions
- Use type hints where applicable
- Keep functions under 50 lines

---

## 📄 License

This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.

```
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

## 📞 Support & Questions

- **Issues**: Open a GitHub issue with details
- **Email**: your.email@example.com
- **Documentation**: See [docs/](docs/) folder for detailed guides

---

## 🎓 Educational Value

This project demonstrates:

- ✅ **SIEM Integration**: Alert ingestion from enterprise security tools
- ✅ **API Integration**: Third-party threat intelligence consumption
- ✅ **Automation**: Reducing manual SOC workload via Python
- ✅ **Database Design**: Normalized schema for security event storage
- ✅ **Report Generation**: Professional executive communication
- ✅ **DevSecOps**: Secure configuration management, version control
- ✅ **Cybersecurity**: Threat classification, risk prioritization, incident response

**Perfect for:**
- 🎯 Master's-level capstone projects
- 📚 Cybersecurity portfolio demonstrations
- 💼 Entry-level SOC analyst interviews
- 🔬 Security automation research

---

## 🚀 Roadmap

- [ ] Web UI dashboard for real-time alert visualization
- [ ] Machine learning-based anomaly detection for triage
- [ ] Slack/Email integration for instant alerts
- [ ] Multi-SIEM support (Splunk, ELK, Microsoft Sentinel)
- [ ] MITRE ATT&CK framework mapping
- [ ] Compliance reporting (PCI DSS, HIPAA, SOC 2)

---

**Last Updated**: October 2026  
**Version**: 1.0.0  
**Status**: ✅ Active Development

---

<div align="center">

### ⭐ If this project helped you, consider giving it a star! ⭐

[🔝 Back to Top](#-automated-soc-alert-triage--incident-reporting-system)

</div>
