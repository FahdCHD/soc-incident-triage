import sqlite3
import datetime
from fpdf import FPDF

DB_NAME = "soc_alerts.db"

class SOCReport(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 16)
        self.set_text_color(20, 35, 60)
        self.cell(0, 10, "SOC Automated Incident Triage Report", border=False, new_x="LMARGIN", new_y="NEXT", align="C")
        self.set_font("Helvetica", "I", 10)
        self.set_text_color(100, 100, 100)
        self.cell(0, 6, f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", border=False, new_x="LMARGIN", new_y="NEXT", align="C")
        self.ln(5)
        self.set_draw_color(200, 200, 200)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()} | Confidential - Internal SOC Use Only", align="C")

def generate_pdf_report():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT alert_id, timestamp, agent_name, rule_id, rule_description, rule_level, source_ip, abuse_score, country, isp, triage_status
        FROM alerts
        ORDER BY id DESC
    """)
    alerts = cursor.fetchall()
    conn.close()

    if not alerts:
        print("[-] No alerts found in database to generate report.")
        return

    pdf = SOCReport()
    pdf.add_page()
    pdf.set_font("Helvetica", size=10)

    # Executive Summary Section
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(20, 35, 60)
    pdf.cell(0, 8, "Executive Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", size=10)
    pdf.set_text_color(50, 50, 50)
    pdf.multi_cell(0, 6, f"This report contains automated triage details for {len(alerts)} ingested security event(s) captured by Wazuh SIEM and enriched with Threat Intelligence.")
    pdf.ln(5)

    # Incident Details Section
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(20, 35, 60)
    pdf.cell(0, 8, "Incident Details & Threat Intelligence", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    for alert in alerts:
        (alert_id, timestamp, agent_name, rule_id, rule_description, 
         rule_level, source_ip, abuse_score, country, isp, triage_status) = alert

        # Clean score: Strip existing % symbols completely to avoid double percent signs
        clean_score = str(abuse_score).replace("%", "").strip() if abuse_score and str(abuse_score) != "N/A" else "N/A"
        formatted_score = f"{clean_score}%" if clean_score != "N/A" else "N/A"

        # Alert Box Header
        pdf.set_fill_color(240, 243, 246)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(20, 35, 60)
        pdf.cell(0, 7, f"Alert ID: {alert_id} | Agent: {agent_name} | Status: {triage_status}", fill=True, new_x="LMARGIN", new_y="NEXT")

        # Table Key-Value Details
        pdf.set_font("Helvetica", size=9)
        pdf.set_text_color(50, 50, 50)
        
        details = [
            ("Timestamp:", str(timestamp)),
            ("Rule ID / Level:", f"{rule_id} (Level {rule_level})"),
            ("Description:", str(rule_description)),
            ("Source IP:", str(source_ip)),
            ("Abuse Score:", formatted_score),
            ("Location / ISP:", f"{country} - {isp}" if country != "N/A" else "Internal Network")
        ]

        for key, val in details:
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(40, 6, key, border=0)
            pdf.set_font("Helvetica", size=9)
            pdf.cell(0, 6, val, border=0, new_x="LMARGIN", new_y="NEXT")

        pdf.ln(4)

    output_filename = "SOC_Incident_Report.pdf"
    pdf.output(output_filename)
    print(f"[+] PDF Incident Report generated successfully: '{output_filename}'")

if __name__ == "__main__":
    generate_pdf_report()