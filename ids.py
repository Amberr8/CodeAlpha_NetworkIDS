from scapy.all import sniff, IP, TCP, UDP, ICMP
from colorama import Fore, Style, init
from collections import defaultdict
from datetime import datetime
import threading

init(autoreset=True)

#  Thresholds (lowered for easy testing) 
PORT_SCAN_THRESHOLD   = 3   # unique ports from one IP in 5 sec
ICMP_FLOOD_THRESHOLD  = 5   # ICMP packets from one IP in 5 sec
BRUTE_FORCE_THRESHOLD = 2   # connections to port 80 in 5 sec

#  Yreal network interface 
MY_INTERFACE = "\\Device\\NPF_{49515971-D3DE-46EE-A9A5-E1DF9DE02BE5}"

#  Counters and trackers 
port_scan_tracker   = defaultdict(set)
icmp_flood_tracker  = defaultdict(int)
brute_force_tracker = defaultdict(int)
alert_log_file = "ids_alerts.log"

#  Log alert to file and terminal 
def log_alert(alert_type, src_ip, detail):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = f"[{timestamp}] ALERT | {alert_type} | Source: {src_ip} | {detail}"

    if "PORT SCAN" in alert_type:
        print(Fore.YELLOW + "⚠  " + message)
    elif "ICMP FLOOD" in alert_type:
        print(Fore.RED + "🚨 " + message)
    elif "BRUTE FORCE" in alert_type:
        print(Fore.MAGENTA + "🔑 " + message)
    else:
        print(Fore.CYAN + "ℹ  " + message)

    with open(alert_log_file, "a") as f:
        f.write(message + "\n")

# Reset counters 
def reset_counters():
    global port_scan_tracker, icmp_flood_tracker, brute_force_tracker
    port_scan_tracker   = defaultdict(set)
    icmp_flood_tracker  = defaultdict(int)
    brute_force_tracker = defaultdict(int)
    threading.Timer(5.0, reset_counters).start()

#  Packet analysis 
def analyze_packet(packet):
    if not IP in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # Rule 1: Port Scan Detection
    if TCP in packet:
        dst_port = packet[TCP].dport
        port_scan_tracker[src_ip].add(dst_port)

        if len(port_scan_tracker[src_ip]) >= PORT_SCAN_THRESHOLD:
            log_alert(
                "PORT SCAN DETECTED",
                src_ip,
                f"Scanned {len(port_scan_tracker[src_ip])} ports -> Target: {dst_ip}"
            )
            port_scan_tracker[src_ip] = set()

    # Rule 2: ICMP Flood Detection
    if ICMP in packet:
        icmp_flood_tracker[src_ip] += 1

        if icmp_flood_tracker[src_ip] >= ICMP_FLOOD_THRESHOLD:
            log_alert(
                "ICMP FLOOD DETECTED",
                src_ip,
                f"Sent {icmp_flood_tracker[src_ip]} ICMP packets -> Target: {dst_ip}"
            )
            icmp_flood_tracker[src_ip] = 0

    # Rule 3: HTTP Brute Force Detection (port 80)
    if TCP in packet and packet[TCP].dport == 80:
        brute_force_tracker[src_ip] += 1

        if brute_force_tracker[src_ip] >= BRUTE_FORCE_THRESHOLD:
            log_alert(
                "HTTP BRUTE FORCE DETECTED",
                src_ip,
                f"Made {brute_force_tracker[src_ip]} rapid connections to port 80"
            )
            brute_force_tracker[src_ip] = 0

    # Print every packet
    proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" if ICMP in packet else "OTHER"
    print(Fore.WHITE + Style.DIM + f"  [PACKET] {src_ip} -> {dst_ip}  |  {proto}")
#  Start IDS 
print(Fore.GREEN + "=" * 55)
print(Fore.GREEN + "   Python Network IDS — CodeAlpha Task 4")
print(Fore.GREEN + "   Monitoring: Port Scans | ICMP Flood | HTTP Brute Force")
print(Fore.GREEN + "   Interface: " + MY_INTERFACE)
print(Fore.GREEN + "   Alerts saved to: ids_alerts.log")
print(Fore.GREEN + "   Press Ctrl+C to stop")
print(Fore.GREEN + "=" * 55)

reset_counters()
sniff(prn=analyze_packet, store=0, iface=MY_INTERFACE)