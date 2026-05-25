from scapy.all import IP, TCP, ICMP, send

target = "192.168.1.10"
MY_INTERFACE = "\\Device\\NPF_{49515971-D3DE-46EE-A9A5-E1DF9DE02BE5}"

print("Sending ICMP flood...")
for i in range(10):
    send(IP(dst=target)/ICMP(), iface=MY_INTERFACE, verbose=0)

print("Sending Port Scan...")
for port in [21, 22, 23, 80, 443, 8080]:
    send(IP(dst=target)/TCP(dport=port, flags="S"), iface=MY_INTERFACE, verbose=0)

print("Sending HTTP Brute Force...")
for i in range(5):
    send(IP(dst=target)/TCP(dport=80, flags="S"), iface=MY_INTERFACE, verbose=0)

print("All done! Check IDS terminal for alerts.")