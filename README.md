# CodeAlpha_NetworkIDS

# Network Intrusion Detection System — CodeAlpha Task 4

## Description
A Python-based Network Intrusion Detection System (IDS) built
with Scapy that monitors live network traffic in real time and
detects 3 types of attack patterns with colored terminal alerts
and automatic file logging.

## Detection Rules
| Rule | Attack Type         | Threshold          | Severity | Color   |
|------|---------------------|--------------------|----------|---------|
| 1    | Port Scan           | 3 ports / 5 sec    | HIGH     | Yellow  |
| 2    | ICMP Flood          | 5 packets / 5 sec  | HIGH     | Red     |
| 3    | HTTP Brute Force    | 2 attempts / 5 sec | CRITICAL | Magenta |

## Files
- ids.py            — main IDS engine with real-time detection
- trigger_alerts.py — test script to simulate all 3 attack types
- rules.md          — detailed detection rules documentation
- ids_alerts.log    — sample alert output with timestamps
- README.md         — project documentation

## Tools Used
- Python 3
- Scapy (packet capture and analysis)
- Colorama (colored terminal output)
- Threading (sliding window counter reset)

## How to Run

### Step 1 - Install dependencies
pip install scapy colorama

### Step 2 - Run IDS as Administrator
Open Command Prompt as Administrator then run:
python ids.py

### Step 3 - Test the IDS
Open a second Command Prompt and run:
python trigger_alerts.py

### Step 4 - View saved alerts
type ids_alerts.log

##  Alert Output
[2026-05-25 01:13:34] ALERT | SSH BRUTE FORCE DETECTED | Source: 192.168.1.10 | Made 5 attempts to SSH port 22
[2026-05-25 01:13:35] ALERT | SSH BRUTE FORCE DETECTED | Source: 192.168.1.10 | Made 5 attempts to SSH port 22
[2026-05-25 01:28:32] ALERT | SSH BRUTE FORCE DETECTED | Source: 192.168.1.10 | Made 5 attempts to SSH port 22
[2026-05-25 01:51:56] ALERT | HTTP BRUTE FORCE DETECTED | Source: 192.168.1.10 | Made 2 rapid connections to port 80
[2026-05-25 01:51:56] ALERT | HTTP BRUTE FORCE DETECTED | Source: 192.168.1.10 | Made 2 rapid connections to port 80


## Internship
CodeAlpha Cybersecurity Internship
Task 4 — Network Intrusion Detection System
