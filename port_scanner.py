# ============================================================
#  Port Scanner
#  Author : Sadam
#  Purpose: Scan one or more targets for open TCP ports
#  Usage  : python port_scanner.py
# ============================================================
 
import socket
from datetime import datetime
 
try:
    from IPy import IP
    IPY_AVAILABLE = True
except ImportError:
    IPY_AVAILABLE = False
 
 
# ── Helpers ──────────────────────────────────────────────────
 
def resolve_target(target):
    """
    Accept either a raw IP address or a hostname.
    Returns the IP address as a string, or exits on failure.
 
    IPy validates IP addresses (e.g. '192.168.1.1').
    gethostbyname resolves hostnames (e.g. 'scanme.nmap.org').
    """
    if IPY_AVAILABLE:
        try:
            IP(target)        # Valid IP — use as-is
            return target
        except ValueError:
            pass              # Not an IP — fall through to DNS lookup
 
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"  [!] Could not resolve '{target}'. Skipping.")
        return None
 
 
def get_service(port):
    """Return the well-known service name for a port, or 'unknown'."""
    try:
        return socket.getservbyport(port)
    except OSError:
        return "unknown"
 
 
# ── Core scanner ─────────────────────────────────────────────
 
def scan_port(ip, port):
    """
    Try to open a TCP connection to ip:port.
    Returns True if open, False if closed or filtered.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        sock.connect((ip, port))
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False
    finally:
        sock.close()    # Always close — prevents resource leaks
 
 
def scan(target, start_port=1, end_port=1024):
    """
    Scan a range of ports on a single target.
    Prints each open port as it is found, with a summary at the end.
    """
    ip = resolve_target(target)
    if ip is None:
        return
 
    open_ports = []
    start_time = datetime.now()
 
    print("\n" + "─" * 50)
    print(f"  Target  : {target}  ({ip})")
    print(f"  Ports   : {start_port}–{end_port}")
    print(f"  Started : {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("─" * 50)
 
    for port in range(start_port, end_port + 1):
        if scan_port(ip, port):
            service = get_service(port)
            print(f"  [+] Port {port:<6} open   ({service})")
            open_ports.append(port)
 
    duration = (datetime.now() - start_time).seconds
    print("─" * 50)
    print(f"  Done. {len(open_ports)} open port(s) found in {duration}s.")
    print("─" * 50)
 
 
# ── Entry point ───────────────────────────────────────────────
 
if __name__ == "__main__":
    print("=" * 50)
    print("         Simple Port Scanner")
    print("=" * 50)
 
    raw = input("\n  Target(s) — comma-separate for multiple:\n  > ").strip()
    start = int(input("  Start port [default 1]:    ").strip() or 1)
    end   = int(input("  End port   [default 1024]: ").strip() or 1024)
 
    targets = [t.strip() for t in raw.split(",") if t.strip()]
 
    for target in targets:
        scan(target, start, end)
 
    print("\n  All scans complete.")
 