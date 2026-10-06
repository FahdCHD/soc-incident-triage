import sqlite3
import json
import os

DB_NAME = "soc_alerts.db"

def init_db():
    """Creates the SQLite database tables if they do not already exist."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id TEXT UNIQUE,
        timestamp TEXT,
        agent_name TEXT,
        rule_id TEXT,
        rule_description TEXT,
        rule_level INTEGER,
        source_ip TEXT,
        abuse_score TEXT,
        country TEXT,
        isp TEXT,
        total_reports INTEGER,
        triage_status TEXT DEFAULT 'NEW',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()
    print(f"[+] Database '{DB_NAME}' initialized successfully.")

def insert_enriched_alerts(json_file="enriched_alerts.json"):
    """Reads enriched_alerts.json and inserts new records into SQLite."""
    if not os.path.exists(json_file):
        print(f"[-] File '{json_file}' not found.")
        return

    with open(json_file, "r") as f:
        alerts = json.load(f)

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    inserted_count = 0
    skipped_count = 0

    for alert in alerts:
        threat_intel = alert.get("threat_intel", {}).get("abuseipdb", {})
        
        try:
            rule_level = int(alert.get("rule_level")) if alert.get("rule_level") != "N/A" else 0
        except (ValueError, TypeError):
            rule_level = 0

        # Strict score cleaning: Strips any pre-existing % symbols completely
        raw_score = threat_intel.get("abuse_score")
        if raw_score is None or str(raw_score) == "N/A":
            raw_score = threat_intel.get("abuseConfidenceScore", "N/A")

        if raw_score is not None and str(raw_score) != "N/A":
            clean_score = str(raw_score).replace("%", "").strip()
            score_str = f"{clean_score}%"
        else:
            score_str = "N/A"

        record = (
            str(alert.get("alert_id")),
            str(alert.get("timestamp")),
            str(alert.get("agent_name")),
            str(alert.get("rule_id")),
            str(alert.get("rule_description")),
            rule_level,
            str(alert.get("source_ip")),
            score_str,
            str(threat_intel.get("country", "N/A")),
            str(threat_intel.get("isp", "N/A")),
            threat_intel.get("total_reports", 0),
            "NEW"
        )

        try:
            cursor.execute("""
            INSERT INTO alerts (
                alert_id, timestamp, agent_name, rule_id, rule_description,
                rule_level, source_ip, abuse_score, country, isp, total_reports, triage_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, record)
            inserted_count += 1
        except sqlite3.IntegrityError:
            skipped_count += 1

    conn.commit()
    conn.close()
    print(f"[+] DB Sync Complete: {inserted_count} new alerts inserted, {skipped_count} duplicate alerts skipped.")

def get_unresolved_alerts():
    """Fetches all alerts with NEW status for CLI reporting."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
    SELECT alert_id, timestamp, agent_name, rule_id, rule_description, 
           rule_level, source_ip, abuse_score, country, isp, triage_status 
    FROM alerts 
    WHERE triage_status = 'NEW'
    ORDER BY id DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return rows

def save_alerts_to_db(alerts_data=None):
    """Wrapper function to align with pipeline main script naming."""
    insert_enriched_alerts()

if __name__ == "__main__":
    init_db()
    insert_enriched_alerts()