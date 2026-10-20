"""
Network IP/MAC scanner with history (tkinter + sqlite3).

- Ping-sweeps a subnet, then reads the OS ARP table to get IP -> MAC pairs.
- Resolves device hostnames (reverse DNS, plus NetBIOS on Windows).
- Looks up the vendor from the official IEEE OUI registry (downloadable and
  updatable from inside the app, cached in the local database).
- Every scan is stored with its date/time.
- If the MAC of an IP changes, a new history record is created.
- No third-party packages required.
"""

import concurrent.futures
import csv
import io
import ipaddress
import json
import os
import platform
import queue
import random
import re
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import tkinter as tk
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from tkinter import messagebox, ttk


def get_app_dir():
    """Folder of the running program: next to the .exe when frozen
    (PyInstaller / Nuitka), next to this script otherwise."""
    if getattr(sys, "frozen", False):  # PyInstaller: __file__ would be a temp folder
        return os.path.dirname(os.path.abspath(sys.executable))
    if "__compiled__" in globals():  # Nuitka
        return os.path.dirname(os.path.abspath(sys.argv[0]))
    return os.path.dirname(os.path.abspath(__file__))


def get_db_path():
    """Database next to the program. If that folder is not writable
    (e.g. C:\\Program Files), fall back to the user's profile folder."""
    folder = get_app_dir()
    try:
        probe = os.path.join(folder, ".write_test")
        with open(probe, "w") as fh:
            fh.write("ok")
        os.remove(probe)
    except OSError:
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        folder = os.path.join(base, "NetworkScanner")
        os.makedirs(folder, exist_ok=True)
    return os.path.join(folder, "network_history.db")


DB_PATH = get_db_path()
IS_WIN = platform.system() == "Windows"
NO_WINDOW = subprocess.CREATE_NO_WINDOW if IS_WIN else 0
MAX_HOSTS = 1024
PING_WORKERS = 100
NAME_WORKERS = 64
NAME_TIMEOUT = 25  # seconds, total, for hostname resolution
OUI_MAX_AGE_DAYS = 30
ALL_ADAPTERS = "All adapters"
CIDR_RE = re.compile(r"\d+\.\d+\.\d+\.\d+/\d+")

# Official IEEE registries: MA-L (24 bit), MA-M (28 bit), MA-S (36 bit)
OUI_URLS = [
    ("MA-L", "https://standards-oui.ieee.org/oui/oui.csv", True),
    ("MA-M", "https://standards-oui.ieee.org/oui28/mam.csv", False),
    ("MA-S", "https://standards-oui.ieee.org/oui36/oui36.csv", False),
]

ARP_WIN = re.compile(
    r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+(\w+)"
)
ARP_NIX = re.compile(
    r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})"
)


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------
class Database:
    def __init__(self, path):
        self.conn = sqlite3.connect(path)
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time TEXT NOT NULL,
                network TEXT NOT NULL,
                host_count INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scan_results (
                scan_id INTEGER NOT NULL,
                ip TEXT NOT NULL,
                mac TEXT NOT NULL,
                hostname TEXT DEFAULT '',
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
            CREATE TABLE IF NOT EXISTS mac_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                mac TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                hostname TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS oui (
                prefix TEXT PRIMARY KEY,
                bits INTEGER NOT NULL,
                org TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_hist_ip ON mac_history(ip);
            CREATE INDEX IF NOT EXISTS idx_res_scan ON scan_results(scan_id);
            """)
        self._migrate("scan_results", "hostname")
        self._migrate("mac_history", "hostname")
        self.conn.commit()

    def _migrate(self, table, column):
        cols = [r[1] for r in self.conn.execute(f"PRAGMA table_info({table})")]
        if column not in cols:
            self.conn.execute(
                f"ALTER TABLE {table} ADD COLUMN {column} TEXT DEFAULT ''"
            )

    # ---- vendor (OUI) ----
    def oui_info(self):
        count = self.conn.execute("SELECT COUNT(*) FROM oui").fetchone()[0]
        row = self.conn.execute(
            "SELECT value FROM meta WHERE key='oui_updated'"
        ).fetchone()
        return count, (row[0] if row else None)

    def replace_oui(self, rows):
        """rows: list of (prefix, bits, org). Replaces the whole table."""
        cur = self.conn.cursor()
        cur.execute("DELETE FROM oui")
        cur.executemany(
            "INSERT OR REPLACE INTO oui (prefix, bits, org) VALUES (?, ?, ?)", rows
        )
        cur.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('oui_updated', ?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),),
        )
        self.conn.commit()

    def vendor_for(self, mac):
        raw = mac.replace(":", "").upper()
        if len(raw) != 12:
            return ""
        # Locally administered bit set -> randomized/private MAC, no vendor exists
        if int(raw[:2], 16) & 0x02:
            return "Private (randomized MAC)"
        row = self.conn.execute(
            "SELECT org FROM oui WHERE prefix IN (?, ?, ?) ORDER BY bits DESC LIMIT 1",
            (raw[:9], raw[:7], raw[:6]),
        ).fetchone()
        if row:
            return row[0]
        return "Unknown" if self.oui_info()[0] else "(vendor DB not loaded)"

    # ---- scans ----
    def save_scan(self, network, devices):
        """devices: dict ip -> (mac, hostname). Returns the scan_time string used."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO scans (scan_time, network, host_count) VALUES (?, ?, ?)",
            (now, network, len(devices)),
        )
        scan_id = cur.lastrowid
        for ip, (mac, host) in devices.items():
            cur.execute(
                "INSERT INTO scan_results (scan_id, ip, mac, hostname) VALUES (?, ?, ?, ?)",
                (scan_id, ip, mac, host),
            )
            cur.execute(
                "SELECT id, mac, hostname FROM mac_history WHERE ip = ? ORDER BY id DESC LIMIT 1",
                (ip,),
            )
            last = cur.fetchone()
            if last is None or last[1] != mac:
                cur.execute(
                    "INSERT INTO mac_history (ip, mac, first_seen, last_seen, hostname) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (ip, mac, now, now, host),
                )
            else:
                cur.execute(
                    "UPDATE mac_history SET last_seen = ?, hostname = ? WHERE id = ?",
                    (now, host or last[2] or "", last[0]),
                )
        self.conn.commit()
        return now

    def latest_scan(self):
        row = self.conn.execute(
            "SELECT id, scan_time FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return None, []
        scan_id, scan_time = row
        rows = self.conn.execute(
            """
            SELECT r.ip,
                   COALESCE(NULLIF(r.hostname, ''),
                            (SELECT h.hostname FROM mac_history h
                              WHERE h.ip = r.ip AND h.mac = r.mac
                              ORDER BY h.id DESC LIMIT 1), ''),
                   r.mac,
                   (SELECT first_seen FROM mac_history h
                     WHERE h.ip = r.ip AND h.mac = r.mac ORDER BY h.id DESC LIMIT 1),
                   (SELECT COUNT(*) FROM mac_history h WHERE h.ip = r.ip)
            FROM scan_results r WHERE r.scan_id = ?
            """,
            (scan_id,),
        ).fetchall()
        result = []
        for ip, host, mac, since, known in rows:
            status = ""
            if since == scan_time:
                status = "MAC CHANGED" if known > 1 else "NEW"
            result.append(
                (ip, host or "", mac, self.vendor_for(mac), since, known, status)
            )
        result.sort(key=lambda r: ipaddress.ip_address(r[0]))
        return scan_time, result

    def known_ips(self):
        ips = [r[0] for r in self.conn.execute("SELECT DISTINCT ip FROM mac_history")]
        return sorted(ips, key=ipaddress.ip_address)

    def history(self, ip=None, only_changed=False):
        sql = "SELECT ip, hostname, mac, first_seen, last_seen FROM mac_history"
        where, params = [], []
        if ip:
            where.append("ip = ?")
            params.append(ip)
        if only_changed:
            where.append(
                "ip IN (SELECT ip FROM mac_history GROUP BY ip HAVING COUNT(*) > 1)"
            )
        if where:
            sql += " WHERE " + " AND ".join(where)
        rows = self.conn.execute(sql, params).fetchall()
        rows.sort(key=lambda r: (ipaddress.ip_address(r[0]), r[3]))
        return [
            (ip_, host or "", mac, self.vendor_for(mac), first, last)
            for ip_, host, mac, first, last in rows
        ]

    def scans(self):
        return self.conn.execute(
            "SELECT id, scan_time, network, host_count FROM scans ORDER BY id DESC"
        ).fetchall()


# --------------------------------------------------------------------------
# Vendor DB download (IEEE)
# --------------------------------------------------------------------------
def download_oui():
    """Download IEEE registries. Returns (rows, warnings). Raises if MA-L fails."""
    rows, warnings = {}, []
    for label, url, required in OUI_URLS:
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0 (network-scanner)"}
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                text = resp.read().decode("utf-8", errors="replace")
            reader = csv.reader(io.StringIO(text))
            next(reader, None)  # header
            for rec in reader:
                if len(rec) < 3:
                    continue
                prefix = rec[1].strip().upper()
                if not re.fullmatch(r"[0-9A-F]{6}|[0-9A-F]{7}|[0-9A-F]{9}", prefix):
                    continue
                rows[prefix] = (prefix, len(prefix) * 4, rec[2].strip())
        except Exception as exc:  # noqa: BLE001
            if required:
                raise RuntimeError(f"Could not download {label} list: {exc}") from exc
            warnings.append(f"{label}: {exc}")
    return list(rows.values()), warnings


# --------------------------------------------------------------------------
# Scanner
# --------------------------------------------------------------------------
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # no packet is actually sent
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def _raw_adapters():
    """Returns a list of (ip, prefix, name, mac) for all IPv4 addresses of this PC."""
    raw = []
    if IS_WIN:
        # PowerShell property names are always English, even on localized Windows
        ps = (
            "Get-NetIPAddress -AddressFamily IPv4 | ForEach-Object { "
            "$a = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue; "
            "[pscustomobject]@{IP=[string]$_.IPAddress; Prefix=[int]$_.PrefixLength; "
            "Name=[string]$_.InterfaceAlias; Mac=[string]$a.MacAddress; "
            "Status=[string]$a.Status} } | ConvertTo-Json"
        )
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=25,
            creationflags=NO_WINDOW,
        ).stdout
        data = json.loads(out) if out.strip() else []
        if isinstance(data, dict):
            data = [data]
        for d in data:
            if d.get("Status") not in ("", "Up", None):
                continue  # disconnected adapter
            raw.append((d["IP"], d["Prefix"], d.get("Name") or "", d.get("Mac") or ""))
    else:
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout
        for m in re.finditer(
            r"^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", out, re.MULTILINE
        ):
            name, ip, prefix = m.groups()
            try:
                with open(f"/sys/class/net/{name}/address") as fh:
                    mac = fh.read().strip()
            except OSError:
                mac = ""
            raw.append((ip, int(prefix), name, mac))
    return raw


def get_adapters():
    """Network adapters with their subnets, derived from the adapters' own IP + mask.
    Returns a list of dicts: ip, net (IPv4Network), name, mac, note."""
    try:
        raw = _raw_adapters()
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired):
        raw = []

    result, seen = [], set()
    for ip, prefix, name, mac in raw:
        try:
            addr = ipaddress.ip_address(ip)
            net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        except ValueError:
            continue
        if addr.is_loopback or addr.is_link_local or net.prefixlen >= 31:
            continue
        note = ""
        if net.num_addresses > MAX_HOSTS:  # e.g. a /16: scan only the /24 around the IP
            note = f"  [/{prefix} limited to /24]"
            net = ipaddress.ip_network(f"{ip}/24", strict=False)
        if (ip, str(net)) in seen:
            continue
        seen.add((ip, str(net)))
        result.append(
            {
                "ip": ip,
                "net": net,
                "name": name or "adapter",
                "mac": normalize_mac(mac) if mac else "",
                "note": note,
            }
        )

    if not result:  # fallback: interface that holds the default route, assume /24
        ip = get_local_ip()
        if ip:
            node = uuid.getnode()
            mac = (
                ""
                if (node >> 40) & 1
                else normalize_mac(
                    "-".join(f"{(node >> s) & 0xFF:02x}" for s in range(40, -1, -8))
                )
            )
            result.append(
                {
                    "ip": ip,
                    "net": ipaddress.ip_network(f"{ip}/24", strict=False),
                    "name": "auto-detected",
                    "mac": mac,
                    "note": "  [assumed /24]",
                }
            )
    return result


def adapter_label(a):
    return f"{a['net']} - {a['name']} ({a['ip']}){a['note']}"


def pick_targets(text, adapters):
    """Turn the combobox text into [(network, adapter_or_None), ...]. Raises ValueError."""
    text = text.strip()
    if text == ALL_ADAPTERS:
        targets, seen = [], set()
        for a in adapters:
            if a["net"] not in seen:
                seen.add(a["net"])
                targets.append((a["net"], a))
        if not targets:
            raise ValueError("No network adapters detected. Type a network manually.")
        return targets

    m = CIDR_RE.search(text)
    try:
        net = ipaddress.ip_network(m.group(0) if m else text, strict=False)
    except ValueError:
        raise ValueError("Invalid network. Example: 192.168.1.0/24") from None
    if net.num_addresses > MAX_HOSTS:
        raise ValueError(f"Network too large (max {MAX_HOSTS} addresses).")
    adapter = next((a for a in adapters if a["net"] == net), None) or next(
        (a for a in adapters if ipaddress.ip_address(a["ip"]) in net), None
    )
    return [(net, adapter)]


def normalize_mac(mac):
    parts = re.split(r"[-:]", mac)
    return ":".join(p.zfill(2) for p in parts).upper()


def ping(ip):
    if IS_WIN:
        cmd = ["ping", "-n", "1", "-w", "700", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    try:
        subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=NO_WINDOW,
        )
    except OSError:
        pass


def read_arp_table():
    cmd = ["arp", "-a"] if IS_WIN else ["arp", "-an"]
    out = subprocess.run(
        cmd, capture_output=True, text=True, creationflags=NO_WINDOW
    ).stdout
    pairs = {}
    if IS_WIN:
        for ip, mac, kind in ARP_WIN.findall(out):
            if kind.lower() == "dynamic":
                pairs[ip] = normalize_mac(mac)
    else:
        for ip, mac in ARP_NIX.findall(out):
            pairs[ip] = normalize_mac(mac)
    return pairs


def _dns_name(data, off):
    """Parse a (possibly compressed) DNS/NetBIOS name. Returns (name, next_offset)."""
    labels, end, hops = [], None, 0
    while True:
        length = data[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0 == 0xC0:
            if end is None:
                end = off + 2
            off = ((length & 0x3F) << 8) | data[off + 1]
            hops += 1
            if hops > 20:
                raise ValueError("compression loop")
            continue
        off += 1
        labels.append(data[off : off + length].decode("utf-8", "replace"))
        off += length
    return ".".join(labels), (end if end is not None else off)


def _clean_name(name):
    name = name.strip().rstrip(".")
    if name.lower().endswith(".local"):
        name = name[:-6]
    return name


def _parse_ptr_response(data):
    _id, _flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    off = 12
    for _ in range(qd):
        _, off = _dns_name(data, off)
        off += 4
    for _ in range(an):
        _, off = _dns_name(data, off)
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[off : off + 10])
        off += 10
        if rtype == 12:  # PTR
            name, _ = _dns_name(data, off)
            return _clean_name(name)
        off += rdlen
    return ""


def _udp_query(packet, server, port, parser, timeout=1.5, tries=2):
    """Send one UDP packet, retry only on timeout. Returns parser(response) or ''."""
    for _ in range(tries):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (server, port))
            data, _addr = sock.recvfrom(2048)
            return parser(data)
        except socket.timeout:
            continue
        except (OSError, ValueError, IndexError, struct.error):
            return ""
        finally:
            sock.close()
    return ""


def query_ptr(ip, server, port, recursion=False):
    """Reverse (PTR) lookup of `ip` asking `server:port`.
    port 53 = normal DNS (e.g. the router), 5353 = mDNS, 5355 = LLMNR."""
    labels = ip.split(".")[::-1] + ["in-addr", "arpa"]
    qname = b"".join(bytes([len(p)]) + p.encode() for p in labels) + b"\x00"
    header = struct.pack(
        ">HHHHHH", random.randint(0, 0xFFFF), 0x0100 if recursion else 0, 1, 0, 0, 0
    )
    packet = header + qname + struct.pack(">HH", 12, 1)
    return _udp_query(packet, server, port, _parse_ptr_response)


def _parse_nbstat_response(data):
    _, off = _dns_name(data, 12)
    off += 10  # type, class, ttl, rdlength
    count = data[off]
    off += 1
    for _ in range(count):
        name = data[off : off + 15].decode("ascii", "replace").strip()
        suffix = data[off + 15]
        flags = struct.unpack(">H", data[off + 16 : off + 18])[0]
        off += 18
        if suffix == 0x00 and not flags & 0x8000:  # unique workstation name
            return name
    return ""


def query_netbios(ip, port=137):
    """NetBIOS node status query (what nbtstat -A does), sent directly over UDP."""
    encoded = b"".join(
        bytes([0x41 + (b >> 4), 0x41 + (b & 0x0F)]) for b in b"*" + b"\x00" * 15
    )
    header = struct.pack(">HHHHHH", random.randint(0, 0xFFFF), 0, 1, 0, 0, 0)
    packet = header + b"\x20" + encoded + b"\x00" + struct.pack(">HH", 0x0021, 1)
    return _udp_query(packet, ip, port, _parse_nbstat_response)


def query_system_dns(ip):
    try:
        name = socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""
    name = _clean_name(name)
    return "" if name == ip else name


def get_gateway(local_ip):
    """Default gateway (usually the router, which knows DHCP client names)."""
    try:
        if IS_WIN:
            out = subprocess.run(
                ["route", "print", "-4", "0.0.0.0"],
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=NO_WINDOW,
            ).stdout
            rows = re.findall(
                r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)",
                out,
                re.MULTILINE,
            )
            for gw, iface in rows:
                if iface == local_ip:
                    return gw
            return rows[0][0] if rows else None
        out = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def resolve_names(ips, gateway=None):
    """Try several methods in parallel for every IP and pick the best name.
    Priority: NetBIOS, mDNS, router DNS, system DNS, LLMNR."""
    methods = [
        ("netbios", query_netbios),
        ("mdns", lambda ip: query_ptr(ip, ip, 5353)),
    ]
    if gateway:
        methods.append(("gwdns", lambda ip: query_ptr(ip, gateway, 53, recursion=True)))
    methods.append(("dns", query_system_dns))
    methods.append(("llmnr", lambda ip: query_ptr(ip, ip, 5355)))

    ex = ThreadPoolExecutor(max_workers=NAME_WORKERS)
    futs = {}
    for ip in ips:
        for label, func in methods:
            futs[ex.submit(func, ip)] = (ip, label)
    done, _ = concurrent.futures.wait(futs, timeout=NAME_TIMEOUT)
    found = {}
    for f in done:
        ip, label = futs[f]
        try:
            name = f.result()
        except Exception:  # noqa: BLE001
            name = ""
        if name:
            found.setdefault(ip, {})[label] = name
    ex.shutdown(wait=False, cancel_futures=True)

    order = [label for label, _ in methods]
    names = {}
    for ip in ips:
        per_ip = found.get(ip, {})
        names[ip] = next((per_ip[l] for l in order if l in per_ip), "")
    return names


def scan_network(network, progress_cb, local_ip=None, local_mac=None):
    """Returns dict ip -> (mac, hostname). progress_cb(phase, i, total).
    local_ip/local_mac: this PC's own address on that network (not in its ARP table)."""
    hosts = [str(h) for h in network.hosts()]
    total = len(hosts)
    with ThreadPoolExecutor(max_workers=PING_WORKERS) as ex:
        for i, _ in enumerate(ex.map(ping, hosts), start=1):
            progress_cb("Pinging", i, total)

    found = {}
    for ip, mac in read_arp_table().items():
        if mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
            continue
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr in network and addr not in (
            network.network_address,
            network.broadcast_address,
        ):
            found[ip] = mac

    # The local machine does not appear in its own ARP table
    if local_ip and ipaddress.ip_address(local_ip) not in network:
        local_ip = None
    if local_ip and local_mac:
        found.setdefault(local_ip, local_mac)

    gateway = get_gateway(local_ip) if local_ip else None
    if gateway and ipaddress.ip_address(gateway) not in network:
        gateway = None

    progress_cb("Resolving names", 0, 0)
    names = resolve_names([ip for ip in found if ip != local_ip], gateway)
    if local_ip and local_ip in found:
        names[local_ip] = socket.gethostname()
    return {ip: (mac, names.get(ip, "")) for ip, mac in found.items()}


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network IP / MAC Scanner")
        self.geometry("1050x600")
        self.db = Database(DB_PATH)
        self.q = queue.Queue()
        self.scanning = False
        self.updating_oui = False
        self.detecting = False
        self.adapters = []

        self._build_top()
        self._build_tabs()
        self.refresh_all()
        self.refresh_oui_label()
        self.load_adapters()
        self.after(500, self.check_oui_on_start)

    # ---- layout ----
    def _build_top(self):
        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")
        ttk.Label(top, text="Network:").pack(side="left")
        self.net_var = tk.StringVar(value="")
        self.net_combo = ttk.Combobox(top, textvariable=self.net_var, width=52)
        self.net_combo.pack(side="left", padx=6)
        self.refresh_btn = ttk.Button(
            top, text="Refresh adapters", command=self.load_adapters
        )
        self.refresh_btn.pack(side="left", padx=(0, 6))
        self.scan_btn = ttk.Button(top, text="Scan", command=self.start_scan)
        self.scan_btn.pack(side="left")
        self.progress = ttk.Progressbar(top, length=160, mode="determinate")
        self.progress.pack(side="left", padx=10)
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(top, textvariable=self.status_var).pack(side="left")

        bottom = ttk.Frame(self, padding=(8, 0, 8, 4))
        bottom.pack(fill="x")
        self.oui_btn = ttk.Button(
            bottom, text="Update vendor DB (IEEE)", command=self.start_oui_update
        )
        self.oui_btn.pack(side="left")
        self.oui_var = tk.StringVar()
        ttk.Label(bottom, textvariable=self.oui_var).pack(side="left", padx=10)

    def _tree(self, parent, columns, widths):
        frame = ttk.Frame(parent)
        tree = ttk.Treeview(frame, columns=columns, show="headings")
        for col, w in zip(columns, widths):
            tree.heading(col, text=col)
            tree.column(col, width=w, anchor="w")
        sb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        return frame, tree

    def _build_tabs(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.nb = nb

        # Tab 1: latest scan
        t1 = ttk.Frame(nb, padding=6)
        nb.add(t1, text="Latest scan")
        self.latest_label = tk.StringVar(value="No scan yet")
        ttk.Label(t1, textvariable=self.latest_label).pack(anchor="w")
        ttk.Label(
            t1, text="Double-click a row to see the MAC history of that IP."
        ).pack(anchor="w")
        frame, self.latest_tree = self._tree(
            t1,
            (
                "IP",
                "Hostname",
                "MAC",
                "Vendor",
                "Current MAC since",
                "Known MACs",
                "Status",
            ),
            (110, 160, 135, 220, 140, 80, 100),
        )
        frame.pack(fill="both", expand=True, pady=4)
        self.latest_tree.tag_configure("changed", background="#ffd6d6")
        self.latest_tree.tag_configure("new", background="#d6f5d6")
        self.latest_tree.bind("<Double-1>", self.on_latest_double_click)

        # Tab 2: history
        t2 = ttk.Frame(nb, padding=6)
        nb.add(t2, text="IP / MAC history")
        bar = ttk.Frame(t2)
        bar.pack(fill="x")
        ttk.Label(bar, text="IP:").pack(side="left")
        self.ip_var = tk.StringVar(value="All")
        self.ip_combo = ttk.Combobox(
            bar, textvariable=self.ip_var, width=18, state="readonly"
        )
        self.ip_combo.pack(side="left", padx=6)
        self.ip_combo.bind("<<ComboboxSelected>>", lambda e: self.refresh_history())
        self.changed_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            bar,
            text="Only IPs whose MAC changed",
            variable=self.changed_var,
            command=self.refresh_history,
        ).pack(side="left", padx=10)
        frame, self.hist_tree = self._tree(
            t2,
            ("IP", "Hostname", "MAC", "Vendor", "First seen", "Last seen"),
            (110, 160, 135, 220, 150, 150),
        )
        frame.pack(fill="both", expand=True, pady=4)

        # Tab 3: scans
        t3 = ttk.Frame(nb, padding=6)
        nb.add(t3, text="Scan log")
        frame, self.scans_tree = self._tree(
            t3, ("ID", "Scan time", "Network", "Hosts found"), (60, 180, 160, 100)
        )
        frame.pack(fill="both", expand=True)

    # ---- refresh views ----
    def refresh_all(self):
        self.refresh_latest()
        self.refresh_history()
        self.refresh_scans()

    def refresh_latest(self):
        self.latest_tree.delete(*self.latest_tree.get_children())
        scan_time, rows = self.db.latest_scan()
        if scan_time is None:
            self.latest_label.set("No scan yet")
            return
        self.latest_label.set(f"Last scan: {scan_time}  |  {len(rows)} devices")
        for row in rows:
            status = row[-1]
            tag = ()
            if status == "MAC CHANGED":
                tag = ("changed",)
            elif status == "NEW":
                tag = ("new",)
            self.latest_tree.insert("", "end", values=row, tags=tag)

    def refresh_history(self):
        ips = self.db.known_ips()
        self.ip_combo["values"] = ["All"] + ips
        if self.ip_var.get() not in ["All"] + ips:
            self.ip_var.set("All")
        ip = None if self.ip_var.get() == "All" else self.ip_var.get()
        self.hist_tree.delete(*self.hist_tree.get_children())
        for row in self.db.history(ip, self.changed_var.get()):
            self.hist_tree.insert("", "end", values=row)

    def refresh_scans(self):
        self.scans_tree.delete(*self.scans_tree.get_children())
        for row in self.db.scans():
            self.scans_tree.insert("", "end", values=row)

    def refresh_oui_label(self):
        count, updated = self.db.oui_info()
        if not count:
            self.oui_var.set("Vendor DB: not loaded")
            return
        text = f"Vendor DB: {count:,} entries, updated {updated[:10]}"
        try:
            age = (
                datetime.now() - datetime.strptime(updated, "%Y-%m-%d %H:%M:%S")
            ).days
            if age > OUI_MAX_AGE_DAYS:
                text += f"  (older than {OUI_MAX_AGE_DAYS} days - consider updating)"
        except ValueError:
            pass
        self.oui_var.set(text)

    def on_latest_double_click(self, _event):
        sel = self.latest_tree.selection()
        if not sel:
            return
        ip = self.latest_tree.item(sel[0], "values")[0]
        self.ip_var.set(ip)
        self.refresh_history()
        self.nb.select(1)

    # ---- vendor DB update ----
    def check_oui_on_start(self):
        count, _ = self.db.oui_info()
        if count == 0 and messagebox.askyesno(
            "Vendor database",
            "The vendor (OUI) database is not loaded yet.\n"
            "Download it now from the IEEE registry?",
        ):
            self.start_oui_update()

    def start_oui_update(self):
        if self.updating_oui:
            return
        self.updating_oui = True
        self.oui_btn.config(state="disabled")
        self.oui_var.set("Downloading vendor DB from IEEE...")

        def worker():
            try:
                rows, warnings = download_oui()
                self.q.put(("oui_done", rows, warnings))
            except Exception as exc:  # noqa: BLE001
                self.q.put(("oui_error", str(exc)))

        threading.Thread(target=worker, daemon=True).start()
        self.after(100, self.poll_queue)

    # ---- adapters ----
    def load_adapters(self):
        if self.detecting:
            return
        self.detecting = True
        self.refresh_btn.config(state="disabled")
        self.status_var.set("Detecting network adapters...")

        def worker():
            self.q.put(("adapters", get_adapters()))

        threading.Thread(target=worker, daemon=True).start()
        self.after(100, self.poll_queue)

    def apply_adapters(self, adapters):
        self.adapters = adapters
        labels = [adapter_label(a) for a in adapters]
        if len(adapters) > 1:
            labels.append(ALL_ADAPTERS)
        self.net_combo["values"] = labels
        if (
            not self.net_var.get().strip()
        ):  # first detection: pick the default-route adapter
            default = next(
                (a for a in adapters if a["ip"] == get_local_ip()),
                adapters[0] if adapters else None,
            )
            self.net_var.set(adapter_label(default) if default else "192.168.1.0/24")
        self.detecting = False
        self.refresh_btn.config(state="normal")
        if not self.scanning:
            self.status_var.set(f"Ready - {len(adapters)} adapter network(s) detected")

    # ---- scanning ----
    def start_scan(self):
        if self.scanning:
            return
        try:
            targets = pick_targets(self.net_var.get(), self.adapters)
        except ValueError as exc:
            messagebox.showerror("Error", str(exc))
            return

        self.scanning = True
        self.scan_btn.config(state="disabled")
        self.progress["value"] = 0
        self.status_var.set("Scanning...")
        self.current_network = ", ".join(str(net) for net, _ in targets)

        def worker():
            try:
                merged = {}
                for k, (net, adapter) in enumerate(targets, start=1):
                    tag = (
                        f"[{k}/{len(targets)}] {net}" if len(targets) > 1 else str(net)
                    )
                    merged.update(
                        scan_network(
                            net,
                            lambda ph, i, t, tag=tag: self.q.put(
                                ("progress", f"{tag} {ph}", i, t)
                            ),
                            adapter["ip"] if adapter else None,
                            adapter["mac"] if adapter else None,
                        )
                    )
                self.q.put(("done", merged))
            except Exception as exc:  # noqa: BLE001
                self.q.put(("error", str(exc)))

        threading.Thread(target=worker, daemon=True).start()
        self.after(100, self.poll_queue)

    def poll_queue(self):
        try:
            while True:
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == "progress":
                    _, phase, i, total = msg
                    if total:
                        self.progress["maximum"] = total
                        self.progress["value"] = i
                        self.status_var.set(f"{phase} {i}/{total}")
                    else:
                        self.progress.config(value=self.progress["maximum"])
                        self.status_var.set(f"{phase}...")
                elif kind == "adapters":
                    self.apply_adapters(msg[1])
                elif kind == "done":
                    self.finish_scan(msg[1])
                elif kind == "error":
                    self.scanning = False
                    self.scan_btn.config(state="normal")
                    self.status_var.set("Error")
                    messagebox.showerror("Scan error", msg[1])
                elif kind == "oui_done":
                    self.db.replace_oui(msg[1])
                    self.updating_oui = False
                    self.oui_btn.config(state="normal")
                    self.refresh_oui_label()
                    self.refresh_all()
                    if msg[2]:
                        messagebox.showwarning(
                            "Vendor database",
                            "Updated, but some optional lists failed:\n"
                            + "\n".join(msg[2]),
                        )
                elif kind == "oui_error":
                    self.updating_oui = False
                    self.oui_btn.config(state="normal")
                    self.refresh_oui_label()
                    messagebox.showerror("Vendor database", msg[1])
        except queue.Empty:
            pass
        if self.scanning or self.updating_oui or self.detecting:
            self.after(100, self.poll_queue)

    def finish_scan(self, devices):
        self.db.save_scan(self.current_network, devices)
        self.scanning = False
        self.scan_btn.config(state="normal")
        self.status_var.set(f"Done - {len(devices)} devices found")
        self.refresh_all()


if __name__ == "__main__":
    App().mainloop()
