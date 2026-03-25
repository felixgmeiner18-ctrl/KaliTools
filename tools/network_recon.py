#!/usr/bin/env python3
"""
Network Recon - Erkennt alle Geräte im lokalen Netzwerk.
Kombiniert ARP-Scan, Reverse-DNS und OS-Fingerprinting.
"""

import sys
import os
import time
import argparse
import subprocess
import re
import socket
import concurrent.futures
from collections import defaultdict

try:
    from scapy.all import ARP, Ether, srp, conf, get_if_addr
    conf.verb = 0
except ImportError:
    print("[!] Scapy nicht installiert: pip install scapy")
    sys.exit(1)


# OUI Vendor-Lookup (gängige Hersteller)
OUI_DB = {
    "00:50:56": "VMware", "00:0c:29": "VMware", "00:1c:42": "Parallels",
    "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
    "3c:22:fb": "Apple", "a4:83:e7": "Apple", "f0:18:98": "Apple",
    "00:1a:8a": "Samsung", "5c:0a:5b": "Samsung",
    "3c:97:0e": "Intel", "68:05:ca": "Intel",
    "00:1a:a1": "Cisco", "58:ac:78": "Cisco",
    "50:c7:bf": "TP-Link", "c0:25:e9": "TP-Link",
    "b0:be:76": "TP-Link", "ec:08:6b": "TP-Link",
    "00:1e:58": "D-Link", "28:10:7b": "D-Link",
    "a4:77:33": "Google", "3c:5a:b4": "Google",
    "28:18:78": "Microsoft", "7c:1e:52": "Microsoft",
    "44:65:0d": "Amazon", "fc:65:de": "Amazon",
    "b4:f1:da": "HP", "00:21:5a": "HP",
    "ac:1f:6b": "Super Micro", "00:25:90": "Super Micro",
    "d8:cb:8a": "Micro-Star", "00:01:29": "DFI",
    "f8:75:a4": "FRITZ!Box", "c8:0e:14": "AVM",
    "2c:4d:54": "AVM", "b0:f2:08": "AVM",
}


def get_local_network():
    """Ermittelt das lokale Netzwerk automatisch."""
    result = subprocess.run(["ip", "route"], capture_output=True, text=True)
    for line in result.stdout.split("\n"):
        match = re.match(r"(\d+\.\d+\.\d+\.\d+/\d+)\s+dev\s+(\S+)\s+.*src\s+(\S+)", line)
        if match and "link" not in line.split("dev")[0]:
            return match.group(1), match.group(2), match.group(3)

    # Fallback: Default-Route Interface
    for line in result.stdout.split("\n"):
        if line.startswith("default"):
            parts = line.split()
            if "dev" in parts:
                iface = parts[parts.index("dev") + 1]
                ip = get_if_addr(iface)
                return f"{ip}/24", iface, ip
    return None, None, None


def arp_scan(network, interface, timeout=3):
    """Scannt das Netzwerk per ARP."""
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
    result = srp(pkt, iface=interface, timeout=timeout, verbose=0)[0]

    hosts = []
    for sent, received in result:
        hosts.append({
            "ip": received[ARP].psrc,
            "mac": received[Ether].src.lower(),
        })
    return hosts


def lookup_vendor(mac):
    """Schlägt den Hersteller anhand der MAC-Adresse nach."""
    prefix = mac[:8].lower()
    return OUI_DB.get(prefix, "Unknown")


def reverse_dns(ip):
    """Reverse-DNS-Lookup."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror):
        return ""


def check_common_ports(ip, timeout=1):
    """Prüft schnell gängige Ports."""
    open_ports = []
    ports = {
        22: "SSH", 80: "HTTP", 443: "HTTPS", 21: "FTP",
        23: "Telnet", 445: "SMB", 3389: "RDP", 8080: "HTTP-Proxy",
        53: "DNS", 139: "NetBIOS", 5900: "VNC", 3306: "MySQL",
        631: "CUPS", 9100: "Printer", 554: "RTSP", 1883: "MQTT",
    }
    for port, service in ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append((port, service))
            sock.close()
        except Exception:
            pass
    return open_ports


def os_fingerprint(ip, open_ports):
    """Einfaches OS-Fingerprinting basierend auf offenen Ports und TTL."""
    try:
        from scapy.all import sr1, IP, ICMP
        pkt = sr1(IP(dst=ip) / ICMP(), timeout=2, verbose=0)
        if pkt:
            ttl = pkt.ttl
            if ttl <= 64:
                os_guess = "Linux/Unix"
            elif ttl <= 128:
                os_guess = "Windows"
            else:
                os_guess = "Network Device"
        else:
            os_guess = "Unknown"
    except Exception:
        os_guess = "Unknown"

    # Port-basierte Verfeinerung
    port_nums = [p[0] for p in open_ports]
    if 3389 in port_nums and 445 in port_nums:
        os_guess = "Windows"
    elif 22 in port_nums and 3389 not in port_nums:
        if os_guess != "Windows":
            os_guess = "Linux/Unix"
    elif 631 in port_nums:
        os_guess += " (Printer/CUPS)"
    elif 554 in port_nums:
        os_guess = "IP Camera / Media Device"
    elif 1883 in port_nums:
        os_guess += " (IoT/MQTT)"

    return os_guess


def run(args=None):
    parser = argparse.ArgumentParser(description="Network Recon - LAN Host Discovery")
    parser.add_argument("-n", "--network", help="Netzwerk (z.B. 192.168.1.0/24)")
    parser.add_argument("-i", "--interface", help="Netzwerkinterface")
    parser.add_argument("--no-ports", action="store_true", help="Port-Scan überspringen")
    parser.add_argument("--no-os", action="store_true", help="OS-Fingerprinting überspringen")
    parser.add_argument("-o", "--output", help="Ergebnisse in Datei speichern")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Threads (Standard: 20)")

    args = parser.parse_args(args)

    if os.geteuid() != 0:
        print("[!] Root-Rechte erforderlich!")
        sys.exit(1)

    # Netzwerk ermitteln
    network, interface, local_ip = get_local_network()
    if args.network:
        network = args.network
    if args.interface:
        interface = args.interface

    if not network:
        print("[!] Netzwerk konnte nicht ermittelt werden. Bitte mit -n angeben.")
        sys.exit(1)

    print(f"\n{'═' * 70}")
    print(f"  Network Recon")
    print(f"  Netzwerk: {network} | Interface: {interface} | Eigene IP: {local_ip}")
    print(f"{'═' * 70}\n")

    # ARP-Scan
    print("[*] Starte ARP-Scan...")
    hosts = arp_scan(network, interface)
    print(f"[+] {len(hosts)} Hosts gefunden\n")

    if not hosts:
        print("[!] Keine Hosts gefunden.")
        return

    # Für jeden Host Details sammeln
    print("[*] Sammle Details...\n")

    for host in hosts:
        host["vendor"] = lookup_vendor(host["mac"])
        host["hostname"] = reverse_dns(host["ip"])
        host["ports"] = []
        host["os"] = "Unknown"

    # Port-Scans parallel
    if not args.no_ports:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(check_common_ports, h["ip"]): h for h in hosts}
            for future in concurrent.futures.as_completed(futures):
                host = futures[future]
                host["ports"] = future.result()

    # OS-Fingerprinting
    if not args.no_os:
        for host in hosts:
            host["os"] = os_fingerprint(host["ip"], host["ports"])

    # Sortiert nach IP
    hosts.sort(key=lambda h: [int(p) for p in h["ip"].split(".")])

    # Ausgabe
    for h in hosts:
        marker = " ← DU" if h["ip"] == local_ip else ""
        print(f"  ┌─ {h['ip']}{marker}")
        print(f"  │  MAC:      {h['mac']} ({h['vendor']})")
        if h["hostname"]:
            print(f"  │  Hostname: {h['hostname']}")
        if h["os"] != "Unknown":
            print(f"  │  OS:       {h['os']}")
        if h["ports"]:
            ports_str = ", ".join(f"{p}/{s}" for p, s in h["ports"])
            print(f"  │  Ports:    {ports_str}")
        print(f"  └{'─' * 50}")

    print(f"\n[+] {len(hosts)} Hosts im Netzwerk gefunden.")

    if args.output:
        with open(args.output, "w") as f:
            for h in hosts:
                ports = ",".join(f"{p}" for p, s in h["ports"])
                f.write(f"{h['ip']}\t{h['mac']}\t{h['vendor']}\t{h['hostname']}\t{h['os']}\t{ports}\n")
        print(f"[+] Gespeichert: {args.output}")


if __name__ == "__main__":
    run()
