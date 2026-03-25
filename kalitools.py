#!/usr/bin/env python3
"""
KaliTools - Zentrale Verwaltung für Penetration Testing Tools.
Interaktives Menü mit direktem Zugriff auf alle integrierten Tools.
"""

import sys
import os
import subprocess
import importlib
import argparse
from pathlib import Path

# Projektverzeichnis zum Path hinzufügen
PROJECT_DIR = Path(__file__).parent
sys.path.insert(0, str(PROJECT_DIR))

TOOLS = {
    "1": {
        "name": "Port Scanner",
        "desc": "Multithreaded TCP/UDP Port-Scan mit Banner Grabbing",
        "module": "tools.port_scanner",
        "root": False,
        "usage": "kalitools.py scan <ziel> [-p 1-1024] [-sS] [-b]",
    },
    "2": {
        "name": "Network Recon",
        "desc": "LAN Host Discovery mit ARP-Scan, OS-Fingerprinting",
        "module": "tools.network_recon",
        "root": True,
        "usage": "kalitools.py recon [-n 192.168.1.0/24]",
    },
    "3": {
        "name": "ARP Spoofer",
        "desc": "Man-in-the-Middle via ARP Cache Poisoning",
        "module": "tools.arp_spoofer",
        "root": True,
        "usage": "kalitools.py arpspoof -t <ziel-ip> [-g <gateway>]",
    },
    "4": {
        "name": "Network Sniffer",
        "desc": "Echtzeit Paketanalyse mit Credential-Erkennung",
        "module": "tools.network_sniffer",
        "root": True,
        "usage": "kalitools.py sniff [-i wlan0] [-p http]",
    },
    "5": {
        "name": "WiFi Cracker",
        "desc": "WPA2-PSK Handshake Capture & Cracking",
        "module": None,  # Standalone script
        "script": "wifi_cracker.py",
        "root": True,
        "usage": "kalitools.py wifi",
    },
    "6": {
        "name": "SSH Brute Force",
        "desc": "SSH-Login Brute Force mit Wortlisten",
        "module": "tools.ssh_bruteforce",
        "root": False,
        "usage": "kalitools.py sshbrute <ziel> [-u root] [-w wordlist]",
    },
    "7": {
        "name": "Subdomain Enum",
        "desc": "Subdomain-Enumeration via DNS & crt.sh",
        "module": "tools.subdomain_enum",
        "root": False,
        "usage": "kalitools.py subenum <domain> [-w wordlist]",
    },
    "8": {
        "name": "MAC Changer",
        "desc": "MAC-Adresse ändern mit Vendor-Spoofing",
        "module": "tools.mac_changer",
        "root": True,
        "usage": "kalitools.py macchange [-i wlan0] [-r] [-v apple]",
    },
    "9": {
        "name": "Payload Generator",
        "desc": "Reverse/Bind Shell Payloads in allen Sprachen",
        "module": "tools.payload_generator",
        "root": False,
        "usage": "kalitools.py payload [-l LHOST] [-p 4444] [-t python]",
    },
}

# Subcommand-Mapping
SUBCOMMANDS = {
    "scan": "1",
    "recon": "2",
    "arpspoof": "3",
    "sniff": "4",
    "wifi": "5",
    "sshbrute": "6",
    "subenum": "7",
    "macchange": "8",
    "payload": "9",
}

BANNER = r"""
 ╔═══════════════════════════════════════════════════════╗
 ║                                                       ║
 ║   ██╗  ██╗ █████╗ ██╗     ██╗████████╗ ██████╗  ██╗  ║
 ║   ██║ ██╔╝██╔══██╗██║     ██║╚══██╔══╝██╔═══██╗██║   ║
 ║   █████╔╝ ███████║██║     ██║   ██║   ██║   ██║██║   ║
 ║   ██╔═██╗ ██╔══██║██║     ██║   ██║   ██║   ██║██║   ║
 ║   ██║  ██╗██║  ██║███████╗██║   ██║   ╚██████╔╝███████╗ ║
 ║   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝   ╚═╝    ╚═════╝ ╚══════╝ ║
 ║                                                       ║
 ║   Home Lab Penetration Testing Toolkit                ║
 ║   NUR auf eigenen Systemen verwenden!                 ║
 ╚═══════════════════════════════════════════════════════╝
"""


def print_menu():
    """Zeigt das Hauptmenü an."""
    print(BANNER)

    is_root = os.geteuid() == 0
    root_status = "ROOT" if is_root else "USER (einige Tools benötigen root)"

    print(f"  Status: {root_status}\n")
    print(f"  {'Nr':<4} {'Tool':<22} {'Root':<6} {'Beschreibung'}")
    print(f"  {'─' * 4} {'─' * 22} {'─' * 6} {'─' * 45}")

    for key, tool in TOOLS.items():
        root_marker = "*" if tool["root"] else " "
        print(f"  {key:<4} {tool['name']:<22} {root_marker:<6} {tool['desc']}")

    print(f"\n  {'─' * 78}")
    print(f"  h) Hilfe & Nutzung    u) System-Update    q) Beenden")
    print()


def print_help():
    """Zeigt erweiterte Hilfe."""
    print(f"\n  Direkte Nutzung per Subcommand:")
    print(f"  {'─' * 55}")
    for subcmd, key in SUBCOMMANDS.items():
        tool = TOOLS[key]
        print(f"  {tool['usage']}")
    print(f"\n  Beispiele:")
    print(f"  sudo python3 kalitools.py scan 192.168.1.1 -p 1-65535")
    print(f"  sudo python3 kalitools.py recon")
    print(f"  python3 kalitools.py payload -t python -l 10.0.0.1")
    print(f"  sudo python3 kalitools.py sniff -p dns")
    print()


def check_system():
    """Prüft System-Abhängigkeiten."""
    print("\n  System-Check:")
    print(f"  {'─' * 40}")

    checks = {
        "Python 3": ("python3", "--version"),
        "Scapy": ("python3", "-c", "import scapy; print(scapy.VERSION)"),
        "Paramiko": ("python3", "-c", "import paramiko; print(paramiko.__version__)"),
        "Requests": ("python3", "-c", "import requests; print(requests.__version__)"),
        "dnspython": ("python3", "-c", "import dns; print('OK')"),
        "aircrack-ng": ("which", "aircrack-ng"),
        "hashcat": ("which", "hashcat"),
        "nmap": ("which", "nmap"),
        "crunch": ("which", "crunch"),
        "hcxtools": ("which", "hcxpcapngtool"),
    }

    for name, cmd in checks.items():
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                ver = result.stdout.strip().split("\n")[0][:30]
                print(f"  [+] {name:<15} {ver}")
            else:
                print(f"  [-] {name:<15} NICHT INSTALLIERT")
        except Exception:
            print(f"  [-] {name:<15} FEHLER")

    print()


def run_tool(tool_key, extra_args=None):
    """Startet ein Tool."""
    tool = TOOLS[tool_key]

    if tool["root"] and os.geteuid() != 0:
        print(f"\n[!] '{tool['name']}' benötigt Root-Rechte!")
        print(f"    Starte mit: sudo python3 kalitools.py")
        return

    if tool["module"] is None:
        # Standalone Script ausführen
        script = PROJECT_DIR / tool["script"]
        cmd = [sys.executable, str(script)]
        if extra_args:
            cmd.extend(extra_args)
        subprocess.run(cmd)
    else:
        try:
            module = importlib.import_module(tool["module"])
            module.run(extra_args)
        except KeyboardInterrupt:
            print("\n[*] Abgebrochen.")
        except Exception as e:
            print(f"\n[!] Fehler: {e}")


def interactive_mode():
    """Interaktives Menü."""
    while True:
        print_menu()
        try:
            choice = input("  [?] Auswahl: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\n\n  Bye!\n")
            break

        if choice == "q":
            print("\n  Bye!\n")
            break
        elif choice == "h":
            print_help()
            input("  [Enter] Zurück zum Menü...")
        elif choice == "u":
            check_system()
            input("  [Enter] Zurück zum Menü...")
        elif choice in TOOLS:
            print()
            run_tool(choice)
            print()
            input("  [Enter] Zurück zum Menü...")
        else:
            print(f"\n  [!] Ungültige Auswahl: '{choice}'\n")


def main():
    # Prüfe ob ein Subcommand verwendet wird
    if len(sys.argv) > 1:
        subcmd = sys.argv[1]

        # Direkte Subcommands
        if subcmd in SUBCOMMANDS:
            tool_key = SUBCOMMANDS[subcmd]
            extra_args = sys.argv[2:] if len(sys.argv) > 2 else None
            run_tool(tool_key, extra_args)
            return

        # --help / -h
        if subcmd in ("--help", "-h"):
            print(BANNER)
            print_help()
            return

        # --check
        if subcmd in ("--check", "check"):
            check_system()
            return

        # list
        if subcmd == "list":
            print(f"\n  Verfügbare Tools:")
            print(f"  {'─' * 55}")
            for subcmd_name, key in SUBCOMMANDS.items():
                tool = TOOLS[key]
                root = "(root)" if tool["root"] else ""
                print(f"  {subcmd_name:<12} {tool['name']:<22} {root}")
            print()
            return

        print(f"[!] Unbekannter Befehl: '{subcmd}'")
        print(f"    Verfügbar: {', '.join(SUBCOMMANDS.keys())}")
        print(f"    Oder starte ohne Argumente für das interaktive Menü.")
        return

    interactive_mode()


if __name__ == "__main__":
    main()
