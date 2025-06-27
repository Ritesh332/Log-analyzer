# Log File Analyzer for Intrusion Detection

This Python tool analyzes Apache and SSH log files to detect signs of malicious activity like brute-force attacks and known blacklisted IPs. It also visualizes the most active IPs and exports detected incidents for review.

---

## Features

- Parse Apache and SSH logs using regex
- Detect brute-force login attempts from repeated failed SSH logins
- Flag connections from blacklisted IPs
- Visualize top 10 IPs by number of requests
- Export a CSV report of all suspicious activity

---

## How It Works

### 1. **Log Parsing**
- **Apache Logs**: The tool extracts IP address, request time, method, URL, and status code.
- **SSH Logs**: It captures failed login attempts with timestamp, username, and source IP.

```apache
203.0.113.1 - - [10/Jun/2025:13:55:37 +0000] "GET /admin HTTP/1.1" 404 209
```
```ssh
Jun 10 14:32:24 localhost sshd[1235]: Failed password for root from 192.168.1.100 port 22 ssh2
```
### 2. **Threat Detection**
Brute-force attacks: If an IP appears with more than 2 failed SSH logins, it’s flagged.

Blacklisted IPs: Apache log IPs are compared against a file of known malicious IPs (ip_blacklist.txt).

DoS/Scanning detection can be added (see future work).

### 3. **Visualization**
A bar chart is generated showing the top 10 IP addresses accessing the server (based on Apache logs).

The image is saved to visualizations/access_patterns.png.

### 4. **Exporting Alerts**
All suspicious log entries (from SSH and Apache) are combined.

Each entry includes:

IP address

Timestamp

Type of threat (brute_force or blacklist)

Exported to reports/incidents.csv.

## Folder Structure
```perl
log-analyzer/
├── analyzer.py               # Main script
├── utils.py                  # Helper functions
├── data/
│   ├── apache.log            # Sample Apache log
│   └── auth.log              # Sample SSH log
├── blacklist/
│   └── ip_blacklist.txt      # List of known bad IPs
├── reports/
│   └── incidents.csv         # (Auto) Suspicious activity report
├── visualizations/
│   └── access_patterns.png   # (Auto) Bar chart of IPs
├── README.md
```
## Run Instructions
### 1. Install Dependencies
```bash
pip install pandas matplotlib
```
### 2. Run the Analyzer
```bash
python analyzer.py
```
### 3. View Results
reports/incidents.csv → All detected threats

visualizations/access_patterns.png → Graph of top IPs

## Future Improvements
Detect DoS (high request frequency from a single IP)

Detect port scanning (many different URLs/IPs accessed)

Real-time log monitoring

Web dashboard using Flask

## License
>This project is for educational and research use only.

---
