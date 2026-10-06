# Automated SOC Incident Triage Pipeline

An automated Security Operations Center (SOC) incident triage and enrichment engine built with Python, SQLite, and FPDF2. The pipeline ingests high-severity security alerts captured by Wazuh SIEM, enriches host and network artifacts using external Threat Intelligence APIs (AbuseIPDB), evaluates risk scores, and generates executive-ready PDF incident reports.

---

## Technical Architecture & Pipeline Flow

```text
[ SIEM Alert Ingestion ] ---> [ Artifact Parser ] ---> [ Threat Intel API Query ]
      (Wazuh Logs)               (IP / Metadata)          (AbuseIPDB Enrichment)
                                                                   |
                                                                   v
[ Executive PDF Report ] <--- [ Local Database Store ] <--- [ Triage Engine ]
 (FPDF2 Generator)             (SQLite Triage DB)          (Rule Evaluation)
Ingestion & Parsing: Extracts alert metadata (Alert ID, Rule ID, Severity Level, Source IP, Timestamp).

Threat Intelligence Enrichment: Queries AbuseIPDB API to determine domain reputation, country of origin, ISP details, and abuse confidence scores.

Automated Triage Logic: Filters low-severity internal noise and categorizes high-risk external threats (e.g., active SSH brute-force attempts from anonymized exit nodes).

Data Persistence: Stores triaged records and metadata in a structured SQLite database (soc_alerts.db).

Report Generation: Generates standardized executive incident reports in PDF format (SOC_Incident_Report.pdf).

Tech Stack
Language: Python 3.x

Database: SQLite 3

Libraries: requests (HTTP API communication), python-dotenv (Secure environment key management), fpdf2 (PDF report compilation)

SIEM / Threat Intel Integration: Wazuh JSON Logs, AbuseIPDB API

Project Structure
Plaintext
soc-incident-triage/
├── main.py                 # Core automation execution engine
├── generate_report.py      # PDF report generator using FPDF2
├── fetch_alerts.py         # Log parser and threat intel fetcher
├── database.py             # SQLite persistence interface
├── requirements.txt        # Python dependencies
├── .env                    # Environment variables & API keys (Git-ignored)
├── .gitignore              # Security exclusion file
└── README.md               # Project documentation
Quick Start & Setup
1. Prerequisites
Ensure Python 3.8+ is installed on your environment.

2. Clone Repository & Install Dependencies
Bash
git clone [https://github.com/YOUR_USERNAME/soc-incident-triage.git](https://github.com/YOUR_USERNAME/soc-incident-triage.git)
cd soc-incident-triage
pip install -r requirements.txt
3. Environment Configuration
Create a .env file in the root directory and add your AbuseIPDB API key:

Code snippet
ABUSEIPDB_API_KEY=your_api_key_here
4. Run Triage Engine
Execute the main script to ingest raw SIEM events, query threat intelligence, and record triaged alerts:

Bash
python main.py
5. Generate PDF Incident Report
Compile all triaged database records into an executive PDF report:

Bash
python generate_report.py
Sample Output
Plaintext
[*] Step 4: Summary of Triage Database Records:
  • Alert ID: 1791220670.102034 | Agent: lab-agent-VMware-Virtual-Platform | Status: NEW
    Timestamp: 2026-10-05T17:17:50.289+0000
    Rule ID / Level: 5712 (Level 10)
    Description: sshd: brute force trying to get access to the system. Non existent user.
    Source IP: 185.220.101.5
    Abuse Score: 100%
    Location / ISP: DE - Artikel10 e.V.
-------------------------------------------------------
License & Security
This repository is developed for educational and portfolio demonstration purposes. No live API credentials, private infrastructure details, or production database files are committed to this repository.