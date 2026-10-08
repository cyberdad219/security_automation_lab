# Automated Incident Detection & Response Lab
By Tyler Huppe

## Project Overview
This project is a localized Security Information and Event Management (SIEM) simulation built in Python. It parses live authentication log streams, evaluates events against security thresholds, identifies active brute-force password-guessing attacks, and automates compliance incident reports for security engineers.

## Cyber Security Concepts Demonstrated
* **Log Analysis & Telemetry Monitoring:** Parsing system events for malicious indicators.
* **Signature-Based Detection:** Utilizing Regular Expressions (Regex) to isolate malicious strings (IP addresses).
* **Incident Response Automation:** Programmatically generating standardized documentation during an active breach.

## Lab Architecture
1. **Telemetry Ingestion:** Simulates an authentication stream (`auth.log`) containing mixed normal traffic and a high-velocity login failure attack vector.
2. **Analysis Engine:** Evaluates failed connection rates per source IP using a strict event threshold (3 failures).
3. **Automated Mitigation:** Executes a script loop to auto-generate a high-severity `incident_report.txt` containing recommended firewall block rules.

## Tools and Technologies Used
* **Development Workbench:** Visual Studio Code (VS Code)
* **Language Engine:** Python 3.x (Built-in `re` and `collections` libraries)
* **Version Control:** Git & GitHub

## How to Run the Lab Local Environment
1. Clone this repository to your local machine:
   ```bash
   git clone https://github.com
   ```
2. Navigate into the project folder and execute the automated script:
   ```bash
   python detection_lab.py
   ```
3. Open the newly generated `incident_report.txt` file to view the automated incident response output.
