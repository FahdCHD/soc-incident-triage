import os
import json
import ipaddress
import requests
from dotenv import load_dotenv

load_dotenv()

ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ALERTS_LOG_PATH = "alerts.json"


def is_internal_ip(ip):
    """
    Returns True if the IP is missing, invalid, or not publicly routable.
    Uses Python's built-in 'ipaddress' module, which correctly covers:
      - RFC 1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
      - Loopback (127.0.0.0/8, ::1)
      - Link-local (169.254.0.0/16, fe80::/10)
      - IPv6 private ranges (fc00::/7)
    """
    if not ip or ip == "N/A":
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        # Not a valid IP string, so never send it to the external API
        return True
    return addr.is_private or addr.is_loopback or addr.is_link_local


def check_abuseipdb(ip):
    """Enriches public IP addresses with AbuseIPDB threat intelligence."""
    # Skip internal/non-routable IPs to save API quota and avoid pointless lookups
    if is_internal_ip(ip):
        return {
            "status": "Internal / RFC1918 Address",
            "abuse_score": "0%",
            "country": "Local Lab",
            "isp": "Internal Network"
        }

    if not ABUSE_API_KEY or ABUSE_API_KEY == "your_abuseipdb_api_key_here":
        return {
            "status": "API Key Not Configured",
            "abuse_score": "N/A",
            "country": "N/A",
            "isp": "N/A"
        }

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": ABUSE_API_KEY
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90"
    }

    try:
        res = requests.get(url, headers=headers, params=params, timeout=5)
        if res.status_code == 200:
            data = res.json()["data"]
            score = data.get("abuseConfidenceScore", 0)
            return {
                "status": "Success",
                "abuse_score": f"{score}%",
                "country": data.get("countryCode", "N/A"),
                "isp": data.get("isp", "N/A"),
                "total_reports": data.get("totalReports", 0)
            }
    except Exception as e:
        return {"error": str(e), "abuse_score": "N/A", "country": "N/A", "isp": "N/A"}

    return {"status": "Lookup Failed", "abuse_score": "N/A", "country": "N/A", "isp": "N/A"}


def fetch_live_wazuh_alerts(min_level=5):
    live_alerts = []
    if not os.path.exists(ALERTS_LOG_PATH):
        print(f"[-] Log file not found at '{ALERTS_LOG_PATH}'.")
        return live_alerts

    try:
        with open(ALERTS_LOG_PATH, "r") as f:
            for line in f:
                if not line.strip():
                    continue
                alert = json.loads(line.strip())
                rule_level = alert.get("rule", {}).get("level", 0)

                if rule_level >= min_level:
                    src_ip = alert.get("data", {}).get("srcip") or alert.get("srcip", "N/A")
                    extracted_alert = {
                        "alert_id": alert.get("id"),
                        "timestamp": alert.get("timestamp"),
                        "agent_name": alert.get("agent", {}).get("name", "wazuh-server"),
                        "rule_id": str(alert.get("rule", {}).get("id")),
                        "rule_description": alert.get("rule", {}).get("description"),
                        "rule_level": rule_level,
                        "source_ip": src_ip
                    }
                    live_alerts.append(extracted_alert)
    except Exception as e:
        print(f"[-] Error parsing Wazuh log file: {e}")

    return live_alerts


def enrich_and_save():
    print(f"[*] Reading live Wazuh alerts from {ALERTS_LOG_PATH}...")
    alerts = fetch_live_wazuh_alerts(min_level=5)
    print(f"[+] Extracted {len(alerts)} alerts matching threshold.")

    enriched_list = []
    for alert in alerts:
        src_ip = alert.get("source_ip", "N/A")
        intel_data = check_abuseipdb(src_ip)

        record = {
            "alert_id": alert.get("alert_id"),
            "timestamp": alert.get("timestamp"),
            "agent_name": alert.get("agent_name"),
            "rule_id": alert.get("rule_id"),
            "rule_description": alert.get("rule_description"),
            "rule_level": alert.get("rule_level"),
            "source_ip": src_ip,
            "threat_intel": {
                "abuseipdb": intel_data
            }
        }
        enriched_list.append(record)

    output_file = "enriched_alerts.json"
    with open(output_file, "w") as f:
        json.dump(enriched_list, f, indent=4)

    print(f"[+] Successfully saved {len(enriched_list)} enriched alerts to '{output_file}'.")


if __name__ == "__main__":
    enrich_and_save()