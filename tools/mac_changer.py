#!/usr/bin/env python3
"""
MAC Changer - Ändert die MAC-Adresse eines Netzwerkinterfaces.
Unterstützt zufällige MACs, Vendor-Spoofing und benutzerdefinierte Adressen.
"""

import subprocess
import sys
import os
import re
import random
import argparse

# Bekannte Vendor-Prefixes für realistisches Spoofing
VENDORS = {
    "apple":     ["00:1C:B3", "A4:83:E7", "3C:22:FB", "F0:18:98"],
    "samsung":   ["00:1A:8A", "5C:0A:5B", "AC:5F:3E", "C0:BD:D1"],
    "intel":     ["00:1B:21", "00:1E:64", "3C:97:0E", "68:05:CA"],
    "cisco":     ["00:1A:A1", "00:1B:0D", "00:26:0B", "58:AC:78"],
    "google":    ["3C:5A:B4", "54:60:09", "F4:F5:D8", "A4:77:33"],
    "microsoft": ["00:50:F2", "28:18:78", "7C:1E:52", "DC:B4:C4"],
    "tp-link":   ["00:27:19", "50:C7:BF", "C0:25:E9", "EC:08:6B"],
    "random":    [],
}


def get_current_mac(interface):
    """Liest die aktuelle MAC-Adresse."""
    try:
        result = subprocess.run(["ip", "link", "show", interface],
                                capture_output=True, text=True)
        match = re.search(r"link/ether ([0-9a-f:]{17})", result.stdout)
        return match.group(1) if match else None
    except Exception:
        return None


def get_interfaces():
    """Listet verfügbare Netzwerkinterfaces."""
    result = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True)
    interfaces = []
    for line in result.stdout.strip().split("\n"):
        match = re.match(r"\d+:\s+(\S+):", line)
        if match and match.group(1) != "lo":
            name = match.group(1)
            mac = get_current_mac(name)
            interfaces.append((name, mac))
    return interfaces


def generate_random_mac(vendor=None):
    """Generiert eine zufällige MAC-Adresse."""
    if vendor and vendor in VENDORS and VENDORS[vendor]:
        prefix = random.choice(VENDORS[vendor])
        suffix = ":".join(f"{random.randint(0, 255):02x}" for _ in range(3))
        return f"{prefix}:{suffix}"
    else:
        # Erstes Byte: unicast (bit 0 = 0), locally administered (bit 1 = 1)
        first_byte = random.randint(0, 255) & 0xFE | 0x02
        rest = [random.randint(0, 255) for _ in range(5)]
        return ":".join(f"{b:02x}" for b in [first_byte] + rest)


def validate_mac(mac):
    """Prüft ob MAC-Adresse gültig ist."""
    return bool(re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", mac))


def change_mac(interface, new_mac):
    """Ändert die MAC-Adresse."""
    old_mac = get_current_mac(interface)

    print(f"[*] Interface: {interface}")
    print(f"    Aktuelle MAC: {old_mac}")
    print(f"    Neue MAC:     {new_mac}")

    # Interface down
    result = subprocess.run(["ip", "link", "set", "dev", interface, "down"],
                            capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[!] Fehler beim Deaktivieren: {result.stderr.strip()}")
        return False

    # MAC ändern
    result = subprocess.run(["ip", "link", "set", "dev", interface, "address", new_mac],
                            capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[!] Fehler beim Ändern: {result.stderr.strip()}")
        subprocess.run(["ip", "link", "set", "dev", interface, "up"], capture_output=True)
        return False

    # Interface up
    subprocess.run(["ip", "link", "set", "dev", interface, "up"], capture_output=True)

    # Verifizieren
    current = get_current_mac(interface)
    if current and current.lower() == new_mac.lower():
        print(f"\n[+] MAC erfolgreich geändert!")
        return True
    else:
        print(f"[!] MAC-Änderung fehlgeschlagen. Aktuelle MAC: {current}")
        return False


def restore_mac(interface):
    """Stellt die Original-MAC über ethtool wieder her."""
    result = subprocess.run(["ethtool", "-P", interface], capture_output=True, text=True)
    match = re.search(r"([0-9a-f:]{17})", result.stdout)
    if match:
        original = match.group(1)
        print(f"[*] Stelle Original-MAC wieder her: {original}")
        return change_mac(interface, original)
    else:
        print("[!] Konnte Original-MAC nicht ermitteln.")
        return False


def run(args=None):
    parser = argparse.ArgumentParser(description="MAC Changer - Netzwerk-Interface MAC ändern")
    parser.add_argument("-i", "--interface", help="Netzwerkinterface")
    parser.add_argument("-m", "--mac", help="Neue MAC-Adresse (z.B. 00:11:22:33:44:55)")
    parser.add_argument("-r", "--random", action="store_true", help="Zufällige MAC generieren")
    parser.add_argument("-v", "--vendor", choices=list(VENDORS.keys()),
                        help="Vendor-Prefix verwenden (z.B. apple, samsung)")
    parser.add_argument("--restore", action="store_true", help="Original-MAC wiederherstellen")
    parser.add_argument("-l", "--list", action="store_true", help="Interfaces auflisten")

    args = parser.parse_args(args)

    if os.geteuid() != 0:
        print("[!] Root-Rechte erforderlich!")
        sys.exit(1)

    if args.list:
        interfaces = get_interfaces()
        print(f"\n  {'Interface':<15} {'MAC-Adresse'}")
        print(f"  {'─' * 15} {'─' * 20}")
        for name, mac in interfaces:
            print(f"  {name:<15} {mac or 'N/A'}")
        return

    if not args.interface:
        interfaces = get_interfaces()
        print("\n[?] Verfügbare Interfaces:")
        for i, (name, mac) in enumerate(interfaces):
            print(f"    {i + 1}) {name} ({mac})")
        try:
            choice = int(input("\n[?] Interface wählen: ")) - 1
            args.interface = interfaces[choice][0]
        except (ValueError, IndexError, KeyboardInterrupt):
            print("[!] Ungültige Auswahl.")
            sys.exit(1)

    print(f"\n{'═' * 50}")
    print(f"  MAC Changer")
    print(f"{'═' * 50}\n")

    if args.restore:
        restore_mac(args.interface)
    elif args.mac:
        if not validate_mac(args.mac):
            print("[!] Ungültige MAC-Adresse.")
            sys.exit(1)
        change_mac(args.interface, args.mac)
    elif args.random or args.vendor:
        new_mac = generate_random_mac(args.vendor)
        change_mac(args.interface, new_mac)
    else:
        new_mac = generate_random_mac()
        change_mac(args.interface, new_mac)


if __name__ == "__main__":
    run()
