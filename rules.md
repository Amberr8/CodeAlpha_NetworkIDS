# IDS Detection Rules — CodeAlpha Task 4

## Rule 1: Port Scan Detection
- Trigger: One IP hits 3 or more unique ports within 5 seconds
- Severity: HIGH
- Alert Color: Yellow
- Action: Log alert with source IP and number of ports scanned
- Reasoning: Normal traffic does not hit many different ports rapidly.
  This pattern indicates reconnaissance activity.

## Rule 2: ICMP Flood Detection
- Trigger: One IP sends 5 or more ICMP packets within 5 seconds
- Severity: HIGH
- Alert Color: Red
- Action: Log alert with source IP and packet count
- Reasoning: ICMP floods are commonly used in DoS and DDoS attacks
  to overwhelm a target with ping requests.

## Rule 3: HTTP Brute Force Detection
- Trigger: One IP makes 2 or more rapid connections to port 80 in 5 seconds
- Severity: CRITICAL
- Alert Color: Magenta
- Action: Log alert with source IP and connection count
- Reasoning: Repeated rapid connections to port 80 indicate automated
  brute force or scraping attacks against a web server.

## Response Mechanism
- All alerts are printed to terminal with colored output
- Every alert is saved to ids_alerts.log with full timestamp
- Counters auto-reset every 5 seconds using sliding window
- IDS runs continuously until manually stopped with Ctrl+C

## Sliding Window Logic
- Every 5 seconds all counters reset automatically
- This prevents false positives from slow legitimate traffic
- Only rapid repeated behavior within the 5 second window triggers alerts
