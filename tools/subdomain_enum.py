#!/usr/bin/env python3
"""
Subdomain Enumerator - Findet Subdomains über DNS-Bruteforce und öffentliche Quellen.
Kombiniert DNS-Auflösung mit crt.sh Certificate Transparency Logs.
"""

import sys
import argparse
import socket
import time
import json
import concurrent.futures
from pathlib import Path

try:
    import dns.resolver
    import dns.exception
except ImportError:
    print("[!] dnspython nicht installiert: pip install dnspython")
    sys.exit(1)

try:
    import requests
except ImportError:
    requests = None

BUILTIN_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "blog", "admin", "portal", "dev", "staging", "test", "api",
    "app", "cdn", "cloud", "cpanel", "dashboard", "db", "demo", "dns", "docs",
    "email", "git", "gitlab", "grafana", "help", "imap", "jenkins", "jira",
    "ldap", "login", "manage", "media", "monitor", "mx", "mysql", "news",
    "old", "owa", "panel", "pop3", "proxy", "rdp", "remote", "secure",
    "server", "shop", "ssh", "ssl", "status", "store", "support", "svn",
    "sync", "syslog", "vpn", "web", "webdisk", "wiki", "www2", "crm",
    "erp", "exchange", "files", "forum", "gateway", "host", "hub", "intranet",
    "m", "mobile", "mx1", "mx2", "office", "pma", "prod", "production",
    "relay", "s3", "search", "sip", "staging", "static", "storage", "tools",
    "tracker", "vault", "voip", "ww", "autodiscover", "autoconfig",
]


def resolve_subdomain(subdomain, domain, nameserver=None):
    """Versucht einen Subdomain-DNS-Lookup."""
    fqdn = f"{subdomain}.{domain}"
    resolver = dns.resolver.Resolver()
    if nameserver:
        resolver.nameservers = [nameserver]
    resolver.timeout = 3
    resolver.lifetime = 3

    results = []
    try:
        answers = resolver.resolve(fqdn, "A")
        for rdata in answers:
            results.append(("A", str(rdata)))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout,
            dns.resolver.NoNameservers, Exception):
        pass

    try:
        answers = resolver.resolve(fqdn, "CNAME")
        for rdata in answers:
            results.append(("CNAME", str(rdata.target).rstrip(".")))
    except Exception:
        pass

    return fqdn, results


def query_crtsh(domain):
    """Fragt crt.sh Certificate Transparency Logs ab."""
    if not requests:
        print("[!] requests-Modul fehlt, überspringe crt.sh")
        return set()

    print("[*] Frage crt.sh ab...")
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15,
            headers={"User-Agent": "KaliTools-SubdomainEnum/1.0"}
        )
        if resp.status_code != 200:
            print(f"[!] crt.sh HTTP {resp.status_code}")
            return set()

        data = resp.json()
        subdomains = set()
        for entry in data:
            name = entry.get("name_value", "")
            for line in name.split("\n"):
                line = line.strip().lower()
                if line.endswith(f".{domain}") and "*" not in line:
                    subdomains.add(line)
        print(f"    {len(subdomains)} Subdomains aus crt.sh")
        return subdomains

    except Exception as e:
        print(f"[!] crt.sh Fehler: {e}")
        return set()


def bruteforce_subdomains(domain, wordlist, threads=50, nameserver=None):
    """DNS-Bruteforce mit Wortliste."""
    found = {}

    print(f"[*] DNS-Bruteforce mit {len(wordlist)} Einträgen ({threads} Threads)...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(resolve_subdomain, word, domain, nameserver): word
            for word in wordlist
        }

        done = 0
        total = len(futures)
        for future in concurrent.futures.as_completed(futures):
            done += 1
            if done % 100 == 0:
                print(f"\r    Fortschritt: {done}/{total}", end="", flush=True)

            fqdn, results = future.result()
            if results:
                found[fqdn] = results

    print(f"\r    Bruteforce abgeschlossen: {len(found)} gefunden     ")
    return found


def load_wordlist(path):
    """Lädt eine Wortliste aus einer Datei."""
    words = []
    with open(path, "r", errors="ignore") as f:
        for line in f:
            word = line.strip().lower()
            if word and not word.startswith("#"):
                words.append(word)
    return words


def run(args=None):
    parser = argparse.ArgumentParser(description="Subdomain Enumerator")
    parser.add_argument("domain", help="Ziel-Domain (z.B. example.com)")
    parser.add_argument("-w", "--wordlist", help="Pfad zur Subdomain-Wortliste")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Threads (Standard: 50)")
    parser.add_argument("--no-crtsh", action="store_true", help="crt.sh nicht abfragen")
    parser.add_argument("-n", "--nameserver", help="DNS-Server (z.B. 8.8.8.8)")
    parser.add_argument("-o", "--output", help="Ergebnisse in Datei speichern")
    parser.add_argument("--resolve-all", action="store_true",
                        help="Auch crt.sh-Ergebnisse per DNS auflösen")

    args = parser.parse_args(args)
    domain = args.domain.lower().strip(".")

    print(f"\n{'═' * 60}")
    print(f"  Subdomain Enumerator")
    print(f"  Ziel: {domain}")
    print(f"{'═' * 60}\n")

    all_found = {}

    # Wortliste laden
    if args.wordlist:
        wordlist = load_wordlist(args.wordlist)
    else:
        wordlist = BUILTIN_WORDLIST
        # Prüfe auf seclists
        seclists_path = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        if Path(seclists_path).exists():
            print(f"[*] Verwende SecLists: {seclists_path}")
            wordlist = load_wordlist(seclists_path)

    # DNS-Bruteforce
    bf_results = bruteforce_subdomains(domain, wordlist, args.threads, args.nameserver)
    all_found.update(bf_results)

    # crt.sh
    if not args.no_crtsh:
        crtsh_subdomains = query_crtsh(domain)

        if args.resolve_all and crtsh_subdomains:
            # Auch crt.sh Ergebnisse auflösen
            extra_words = []
            for sub in crtsh_subdomains:
                if sub.endswith(f".{domain}"):
                    word = sub[: -(len(domain) + 1)]
                    if word and word not in wordlist:
                        extra_words.append(word)

            if extra_words:
                print(f"[*] Löse {len(extra_words)} zusätzliche crt.sh-Subdomains auf...")
                extra_results = bruteforce_subdomains(domain, extra_words, args.threads, args.nameserver)
                all_found.update(extra_results)
        else:
            # crt.sh-Ergebnisse ohne DNS-Auflösung hinzufügen
            for sub in crtsh_subdomains:
                if sub not in all_found:
                    all_found[sub] = [("CRTSH", "unresolved")]

    # Ergebnisse anzeigen
    print(f"\n[+] {len(all_found)} Subdomains gefunden:\n")
    print(f"  {'Subdomain':<45} {'Typ':<8} {'Wert'}")
    print(f"  {'─' * 45} {'─' * 8} {'─' * 30}")

    for fqdn in sorted(all_found.keys()):
        records = all_found[fqdn]
        for rtype, rvalue in records:
            print(f"  {fqdn:<45} {rtype:<8} {rvalue}")

    # Speichern
    if args.output:
        with open(args.output, "w") as f:
            for fqdn in sorted(all_found.keys()):
                records = all_found[fqdn]
                for rtype, rvalue in records:
                    f.write(f"{fqdn}\t{rtype}\t{rvalue}\n")
        print(f"\n[+] Gespeichert: {args.output}")


if __name__ == "__main__":
    run()
