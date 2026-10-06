import os
import json
import sqlite3
from fetch_alerts import enrich_and_save, ALERTS_LOG_PATH
from database import init_db, save_alerts_to_db, get_unresolved_alerts
from generate_report import generate_pdf_report

def run_pipeline():
    print("=" * 60)
    print(" [  AUTOMATED SOC ALERT TRIAGE & INCIDENT PIPELINE  ]")
    print("=" * 60)

    # Step 1: Initialize Database
    print("\n[*] Step 1: Initializing SQLite Database...")
    init_db()

    # Step 2: Fetch and Enrich Telemetry from Wazuh Logs
    print("\n[*] Step 2: Fetching Wazuh telemetry & querying Threat Intelligence...")
    enrich_and_save()

    # Step 3: Load Enriched Telemetry into SQLite
    enriched_file = "enriched_alerts.json"
    if os.path.exists(enriched_file):
        print(f"\n[*] Step 3: Persisting enriched alerts into SQLite database...")
        with open(enriched_file, "r") as f:
            enriched_alerts = json.load(f)
        save_alerts_to_db(enriched_alerts)
    else:
        print("[-] Error: 'enriched_alerts.json' not found. Aborting pipeline.")
        return

    # Step 4: Display Unresolved High-Severity Alerts in CLI
    print("\n[*] Step 4: Summary of Triage Database Records:")
    alerts = get_unresolved_alerts()
    for alert in alerts:
        # DB tuple structure mapping
        alert_id, timestamp, agent, rule_id, desc, level, src_ip, score, country, isp, status = alert[:11]
        print(f"  • Alert ID: {alert_id} | Agent: {agent} | Status: {status}")
        print(f"    Timestamp: {timestamp}")
        print(f"    Rule ID / Level: {rule_id} (Level {level})")
        print(f"    Description: {desc}")
        print(f"    Source IP: {src_ip}")
        print(f"    Abuse Score: {score}")
        print(f"    Location / ISP: {country} - {isp}")
        print("-" * 55)

    # Step 5: Generate PDF Incident Report
    print("\n[*] Step 5: Generating PDF Incident Summary Report...")
    generate_pdf_report()
    print("\n[+] Pipeline execution completed successfully!")
    print("=" * 60)

if __name__ == "__main__":
    run_pipeline()