#!/usr/bin/env python3
"""
Port Scanner - Multithreaded TCP/UDP port scanner with service detection.
Uses raw sockets for SYN scanning (requires root) and connect() for standard scans.
"""

import socket
import struct
import sys
import time
import argparse
import ipaddress
import concurrent.futures
from collections import defaultdict

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt", 27017: "MongoDB",
}


def grab_banner(ip, port, timeout=3):
    """Versucht einen Banner vom Service zu lesen."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # HTTP-Probe senden falls Port typisch für HTTP
        if port in (80, 8080, 8443, 8888, 443):
            sock.send(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
        else:
            sock.send(b"\r\n")

        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        return banner[:100] if banner else ""
    except Exception:
        return ""


def tcp_connect_scan(ip, port, timeout=1.5):
    """Standard TCP Connect Scan."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def syn_scan_port(ip, port, timeout=1.5):
    """SYN Scan mit Scapy (erfordert root)."""
    try:
        from scapy.all import sr1, IP, TCP, conf
        conf.verb = 0
        pkt = IP(dst=ip) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp and resp.haslayer(TCP):
            if resp[TCP].flags == 0x12:  # SYN-ACK
                # RST senden um Verbindung zu schließen
                from scapy.all import send
                rst = IP(dst=ip) / TCP(dport=port, flags="R")
                send(rst, verbose=0)
                return True
            elif resp[TCP].flags == 0x14:  # RST-ACK
                return False
        return False
    except Exception:
        return False


def udp_scan_port(ip, port, timeout=3):
    """UDP Scan - sendet leeres Paket und wartet auf ICMP unreachable."""
    try:
        from scapy.all import sr1, IP, UDP, ICMP, conf
        conf.verb = 0
        pkt = IP(dst=ip) / UDP(dport=port)
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp is None:
            return "open|filtered"
        elif resp.haslayer(ICMP):
            icmp_type = resp[ICMP].type
            icmp_code = resp[ICMP].code
            if icmp_type == 3 and icmp_code == 3:
                return "closed"
            elif icmp_type == 3 and icmp_code in (1, 2, 9, 10, 13):
                return "filtered"
        elif resp.haslayer(UDP):
            return "open"
        return "open|filtered"
    except Exception:
        return "error"


def resolve_target(target):
    """Löst Hostnamen auf und gibt IP-Adressen zurück."""
    try:
        # Prüfe ob es ein Netzwerk ist (CIDR)
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            return [str(ip) for ip in network.hosts()]
        # Einzelne IP oder Hostname
        ip = socket.gethostbyname(target)
        return [ip]
    except (socket.gaierror, ValueError) as e:
        print(f"[!] Kann '{target}' nicht auflösen: {e}")
        return []


def scan_target(ip, ports, scan_type="connect", threads=100, timeout=1.5, banner=False):
    """Scannt ein Ziel auf offene Ports."""
    open_ports = []

    if scan_type == "syn":
        scan_func = lambda p: syn_scan_port(ip, p, timeout)
    elif scan_type == "udp":
        scan_func = lambda p: udp_scan_port(ip, p, timeout)
    else:
        scan_func = lambda p: tcp_connect_scan(ip, p, timeout)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        if scan_type == "udp":
            # UDP braucht sequentiellen Scan wegen ICMP rate limiting
            futures = {}
            for port in ports:
                future = executor.submit(scan_func, port)
                futures[future] = port

            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                result = future.result()
                if result in ("open", "open|filtered"):
                    service = COMMON_PORTS.get(port, "unknown")
                    banner_text = ""
                    open_ports.append((port, service, result, banner_text))
        else:
            futures = {executor.submit(scan_func, p): p for p in ports}

            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                if future.result():
                    service = COMMON_PORTS.get(port, "unknown")
                    banner_text = ""
                    if banner:
                        banner_text = grab_banner(ip, port)
                    open_ports.append((port, service, "open", banner_text))

    open_ports.sort(key=lambda x: x[0])
    return open_ports


def parse_ports(port_str):
    """Parst Port-Angaben wie '80,443,1000-2000'."""
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def run(args=None):
    parser = argparse.ArgumentParser(description="Port Scanner - Multithreaded TCP/UDP Scanner")
    parser.add_argument("target", help="Ziel-IP, Hostname oder CIDR (z.B. 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Ports: 80,443 oder 1-1024 oder 1-65535 (Standard: 1-1024)")
    parser.add_argument("--top-ports", type=int, help="Scanne die N häufigsten Ports")
    parser.add_argument("-sS", "--syn", action="store_true", help="SYN Scan (erfordert root)")
    parser.add_argument("-sU", "--udp", action="store_true", help="UDP Scan (erfordert root)")
    parser.add_argument("-t", "--threads", type=int, default=200, help="Anzahl Threads (Standard: 200)")
    parser.add_argument("--timeout", type=float, default=1.5, help="Timeout in Sekunden (Standard: 1.5)")
    parser.add_argument("-b", "--banner", action="store_true", help="Banner Grabbing aktivieren")
    parser.add_argument("-o", "--output", help="Ergebnisse in Datei speichern")

    args = parser.parse_args(args)

    if args.top_ports:
        sorted_ports = sorted(COMMON_PORTS.keys())
        ports = sorted_ports[:args.top_ports]
    else:
        ports = parse_ports(args.ports)

    scan_type = "syn" if args.syn else ("udp" if args.udp else "connect")

    targets = resolve_target(args.target)
    if not targets:
        return

    print(f"\n{'═' * 60}")
    print(f"  Port Scanner")
    print(f"  Ziel: {args.target} ({len(targets)} Host(s))")
    print(f"  Ports: {len(ports)} | Typ: {scan_type.upper()} | Threads: {args.threads}")
    print(f"{'═' * 60}\n")

    all_results = {}
    start_time = time.time()

    for ip in targets:
        print(f"[*] Scanne {ip}...")
        results = scan_target(ip, ports, scan_type, args.threads, args.timeout, args.banner)
        all_results[ip] = results

        if results:
            print(f"\n  {'PORT':<10} {'STATUS':<16} {'SERVICE':<15} {'BANNER'}")
            print(f"  {'─' * 10} {'─' * 16} {'─' * 15} {'─' * 30}")
            for port, service, status, banner_text in results:
                proto = "udp" if args.udp else "tcp"
                print(f"  {port}/{proto:<7} {status:<16} {service:<15} {banner_text}")
            print()
        else:
            print(f"  Keine offenen Ports gefunden.\n")

    elapsed = time.time() - start_time
    total_open = sum(len(r) for r in all_results.values())
    print(f"[+] Scan abgeschlossen in {elapsed:.1f}s | {total_open} offene Port(s)")

    if args.output:
        with open(args.output, "w") as f:
            for ip, results in all_results.items():
                for port, service, status, banner_text in results:
                    f.write(f"{ip}:{port}\t{status}\t{service}\t{banner_text}\n")
        print(f"[+] Ergebnisse gespeichert: {args.output}")


if __name__ == "__main__":
    run()
