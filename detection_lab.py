import re
from collections import Counter
import os

# 1. Simulate a live server authentication log file (Normal traffic + an active Brute-Force attack)
SIMULATED_LOGS = """
2026-10-08 10:00:01 INFO - User 'dmarx' logged in successfully from IP 192.168.1.15
2026-10-08 10:01:12 WARN - Failed password for invalid user 'root' from IP 203.0.113.5
2026-10-08 10:01:14 WARN - Failed password for invalid user 'root' from IP 203.0.113.5
2026-10-08 10:01:15 WARN - Failed password for invalid user 'root' from IP 203.0.113.5
2026-10-08 10:01:17 WARN - Failed password for invalid user 'root' from IP 203.0.113.5
2026-10-08 10:01:19 WARN - Failed password for invalid user 'root' from IP 203.0.113.5
2026-10-08 10:02:45 INFO - User 'jsmith' logged in successfully from IP 192.168.1.22
2026-10-08 10:03:02 WARN - Failed password for user 'admin' from IP 192.168.1.99
"""

def run_security_analysis():
    print("[*] Launching Incident Detection Engine...")
    
    # 2. Use Regular Expressions (Regex) to extract offending IPs from failed attempts
    failed_ip_pattern = r"Failed password.*from IP (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    all_failed_ips = re.findall(failed_ip_pattern, SIMULATED_LOGS)
    
    # Count how many times each IP failed
    ip_tracker = Counter(all_failed_ips)
    
    # 3. Define threshold for an alert (e.g., more than 3 failed attempts)
    THRESHOLD = 3
    
    for ip, count in ip_tracker.items():
        if count >= THRESHOLD:
            print(f"\n[⚠️ CRITICAL ALERT] Brute-force signature detected from IP: {ip}!")
            print(f"Total Failed Attempts: {count}. Generating Incident Report...")
            
            # 4. Automate the generation of a professional Incident Report file
            generate_incident_report(ip, count)

def generate_incident_report(attacker_ip, total_failures):
    report_filename = "incident_report.txt"
    report_content = f"""==================================================
SEC-OPS INCIDENT RESPONSE COMPLIANCE REPORT
==================================================
Incident Date/Time: 2026-10-08 10:05:00 UTC
Severity Level: HIGH
Threat Type: Active Brute-Force Password Guessing
Source IP Address: {attacker_ip}
Total Malicious Events: {total_failures} Failed Authentications
Target Identifiers: Infrastructure Root Access Account

RECOMMENDED ACTIONS FOR IAM / NETWORK ENGINEERS:
1. Immediately commit a firewall block rule for source IP {attacker_ip}.
2. Enforce explicit Multi-Factor Authentication (MFA) tokens across target assets.
3. Review IAM access policies to ensure 'root' cannot log in directly over SSH.
==================================================
Report generated automatically by Security-SIEM-Automation Script.
"""
    with open(report_filename, "w") as report_file:
        report_file.write(report_content)
    
    print(f"[✔] Success! Incident report saved locally to '{report_filename}'.")

if __name__ == "__main__":
    run_security_analysis()
