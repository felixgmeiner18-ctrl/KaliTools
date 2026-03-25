#!/usr/bin/env python3
"""
Network Sniffer - Paketanalyse und Credential-Sniffing im eigenen Netzwerk.
Nutzt Scapy für Echtzeit-Paketanalyse mit Filter-Optionen.
"""

import sys
import os
import time
import argparse
import signal
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import (
        sniff, Ether, IP, TCP, UDP, DNS, DNSQR, ARP, ICMP,
        Raw, conf, get_if_list
    )
    conf.verb = 0
except ImportError:
    print("[!] Scapy nicht installiert: pip install scapy")
    sys.exit(1)


class PacketSniffer:
    def __init__(self, interface=None, output_file=None, verbose=False, filter_proto=None):
        self.interface = interface
        self.output_file = output_file
        self.verbose = verbose
        self.filter_proto = filter_proto
        self.packet_count = 0
        self.stats = defaultdict(int)
        self.dns_queries = []
        self.credentials = []
        self.start_time = None
        self.log_handle = None

    def start(self):
        self.start_time = time.time()
        if self.output_file:
            self.log_handle = open(self.output_file, "w")

        bpf = self._build_bpf_filter()

        print(f"[*] Starte Sniffer auf {self.interface or 'allen Interfaces'}...")
        if bpf:
            print(f"    BPF Filter: {bpf}")
        print(f"    Drücke Ctrl+C zum Stoppen.\n")
        print(f"  {'Zeit':<12} {'Quelle':<22} {'Ziel':<22} {'Proto':<8} {'Info'}")
        print(f"  {'─' * 12} {'─' * 22} {'─' * 22} {'─' * 8} {'─' * 40}")

        try:
            sniff(
                iface=self.interface,
                filter=bpf,
                prn=self._process_packet,
                store=0
            )
        except KeyboardInterrupt:
            pass
        finally:
            self._print_summary()
            if self.log_handle:
                self.log_handle.close()

    def _build_bpf_filter(self):
        filters = {
            "tcp": "tcp",
            "udp": "udp",
            "icmp": "icmp",
            "dns": "udp port 53",
            "http": "tcp port 80 or tcp port 8080",
            "https": "tcp port 443",
            "arp": "arp",
            "ssh": "tcp port 22",
            "ftp": "tcp port 21",
        }
        if self.filter_proto:
            return filters.get(self.filter_proto, self.filter_proto)
        return None

    def _process_packet(self, pkt):
        self.packet_count += 1
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:12]

        if pkt.haslayer(ARP):
            self._handle_arp(pkt, timestamp)
        elif pkt.haslayer(IP):
            ip = pkt[IP]
            src = f"{ip.src}:{pkt[TCP].sport}" if pkt.haslayer(TCP) else \
                  f"{ip.src}:{pkt[UDP].sport}" if pkt.haslayer(UDP) else ip.src
            dst = f"{ip.dst}:{pkt[TCP].dport}" if pkt.haslayer(TCP) else \
                  f"{ip.dst}:{pkt[UDP].dport}" if pkt.haslayer(UDP) else ip.dst

            if pkt.haslayer(TCP):
                self.stats["TCP"] += 1
                self._handle_tcp(pkt, timestamp, src, dst)
            elif pkt.haslayer(UDP):
                self.stats["UDP"] += 1
                self._handle_udp(pkt, timestamp, src, dst)
            elif pkt.haslayer(ICMP):
                self.stats["ICMP"] += 1
                icmp = pkt[ICMP]
                info = f"ICMP type={icmp.type} code={icmp.code}"
                self._log(timestamp, ip.src, ip.dst, "ICMP", info)

    def _handle_arp(self, pkt, timestamp):
        self.stats["ARP"] += 1
        arp = pkt[ARP]
        if arp.op == 1:
            info = f"Who has {arp.pdst}? Tell {arp.psrc}"
        else:
            info = f"{arp.psrc} is at {arp.hwsrc}"
        self._log(timestamp, arp.psrc, arp.pdst, "ARP", info)

    def _handle_tcp(self, pkt, timestamp, src, dst):
        tcp = pkt[TCP]
        flags = tcp.sprintf("%TCP.flags%")

        # HTTP-Traffic analysieren
        if pkt.haslayer(Raw) and tcp.dport in (80, 8080):
            payload = pkt[Raw].load.decode("utf-8", errors="ignore")

            # HTTP-Request
            if payload.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ")):
                first_line = payload.split("\r\n")[0]
                host = ""
                for line in payload.split("\r\n"):
                    if line.lower().startswith("host:"):
                        host = line.split(":", 1)[1].strip()
                        break
                info = f"{first_line[:60]} (Host: {host})"
                self._log(timestamp, src, dst, "HTTP", info)

                # Credential-Suche in POST-Daten
                if "POST" in first_line:
                    self._check_credentials(payload, src, dst)
                return

            # HTTP-Response
            if payload.startswith("HTTP/"):
                first_line = payload.split("\r\n")[0]
                self._log(timestamp, src, dst, "HTTP", first_line[:70])
                return

        # FTP-Credentials
        if pkt.haslayer(Raw) and tcp.dport == 21:
            payload = pkt[Raw].load.decode("utf-8", errors="ignore").strip()
            if payload.upper().startswith(("USER ", "PASS ")):
                self._log(timestamp, src, dst, "FTP", f"⚠ {payload}")
                self.credentials.append(("FTP", src, dst, payload))
                return

        # Telnet
        if pkt.haslayer(Raw) and tcp.dport == 23:
            payload = pkt[Raw].load.decode("utf-8", errors="ignore").strip()
            if payload and len(payload) < 50:
                self._log(timestamp, src, dst, "TELNET", payload[:60])
                return

        # Standard TCP
        if self.verbose:
            info = f"[{flags}] seq={tcp.seq} ack={tcp.ack} len={len(pkt)}"
            self._log(timestamp, src, dst, "TCP", info)

    def _handle_udp(self, pkt, timestamp, src, dst):
        # DNS
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            dns = pkt[DNS]
            query = dns[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
            qtype = dns[DNSQR].sprintf("%DNSQR.qtype%")
            self.dns_queries.append(query)
            self.stats["DNS"] += 1
            self._log(timestamp, src, dst, "DNS", f"Query: {query} ({qtype})")
            return

        # Standard UDP
        if self.verbose:
            info = f"len={len(pkt)}"
            self._log(timestamp, src, dst, "UDP", info)

    def _check_credentials(self, payload, src, dst):
        """Sucht nach Klartext-Credentials in HTTP POST-Daten."""
        keywords = ["user", "login", "email", "pass", "pwd", "token", "auth"]
        body_start = payload.find("\r\n\r\n")
        if body_start > 0:
            body = payload[body_start + 4:]
            lower_body = body.lower()
            for kw in keywords:
                if kw in lower_body:
                    self.credentials.append(("HTTP-POST", src, dst, body[:200]))
                    self._log("", src, dst, "CRED", f"⚠ Mögliche Credentials in POST: {body[:80]}")
                    break

    def _log(self, timestamp, src, dst, proto, info):
        line = f"  {timestamp:<12} {str(src):<22} {str(dst):<22} {proto:<8} {info}"
        print(line)
        if self.log_handle:
            self.log_handle.write(line + "\n")

    def _print_summary(self):
        elapsed = time.time() - self.start_time
        print(f"\n{'═' * 60}")
        print(f"  Zusammenfassung ({elapsed:.1f}s)")
        print(f"  Pakete gesamt: {self.packet_count}")
        print(f"  Protokolle: {dict(self.stats)}")

        if self.dns_queries:
            unique_dns = list(dict.fromkeys(self.dns_queries))[:20]
            print(f"\n  DNS-Abfragen ({len(self.dns_queries)} gesamt, Top 20):")
            for q in unique_dns:
                print(f"    - {q}")

        if self.credentials:
            print(f"\n  ⚠ Gefundene Klartext-Credentials ({len(self.credentials)}):")
            for proto, src, dst, data in self.credentials:
                print(f"    [{proto}] {src} -> {dst}: {data[:80]}")

        print(f"{'═' * 60}")


def run(args=None):
    parser = argparse.ArgumentParser(description="Network Sniffer - Paketanalyse")
    parser.add_argument("-i", "--interface", help="Netzwerkinterface")
    parser.add_argument("-p", "--protocol",
                        choices=["tcp", "udp", "icmp", "dns", "http", "https", "arp", "ssh", "ftp"],
                        help="Nur bestimmtes Protokoll sniffern")
    parser.add_argument("-o", "--output", help="Log in Datei speichern")
    parser.add_argument("-v", "--verbose", action="store_true", help="Alle Pakete anzeigen")
    parser.add_argument("-l", "--list", action="store_true", help="Interfaces auflisten")

    args = parser.parse_args(args)

    if args.list:
        interfaces = get_if_list()
        print("\nVerfügbare Interfaces:")
        for iface in interfaces:
            print(f"  - {iface}")
        return

    if os.geteuid() != 0:
        print("[!] Root-Rechte erforderlich!")
        sys.exit(1)

    print(f"\n{'═' * 60}")
    print(f"  Network Sniffer")
    print(f"{'═' * 60}\n")

    sniffer = PacketSniffer(
        interface=args.interface,
        output_file=args.output,
        verbose=args.verbose,
        filter_proto=args.protocol,
    )
    sniffer.start()


if __name__ == "__main__":
    run()
