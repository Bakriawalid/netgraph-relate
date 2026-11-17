#!/usr/bin/env python3
"""
NetGraph — a local network topology & device analyzer on Relate (single-file mode).

Discovers the devices on your LAN (gateway, ARP neighbours, optional sweeps),
probes common TCP ports, and stores everything as a property graph in ONE file
(`network.rl`) using Relate, the embedded openCypher graph database by Neo4j.
You can then ask the graph questions: paths between devices, who exposes a port,
risky services, what appeared since the last scan, or any Cypher you like.

Graph model
-----------
  (:Device:Router|:Server|:Host {ip, mac, hostname, role, is_self, first_seen, last_seen})
  (:Port     {id: "tcp/22", number, protocol, service})
  (:Network  {cidr})
  (:External {name: "Internet"})
  (:Scan     {id, started, finished, mode, devices, open_ports})

  (Device)-[:CONNECTS_TO {medium, last_seen}]->(Router | External)
  (Device)-[:EXPOSES_PORT {state, last_seen}]->(Port)
  (Device)-[:MEMBER_OF]->(Network)
  (Scan)-[:OBSERVED]->(Device)

Only scan networks you own or are authorised to test.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import errno
import ipaddress
import json
import os
import platform
import re
import socket
import struct
import subprocess
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

try:
    import relate
except ImportError:  # pragma: no cover
    sys.exit("Relate is not installed. Run:  pip install relate-db")

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
DEFAULT_DB = "network.rl"  # the .rl extension is what selects Relate's single-file mode

COMMON_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    139: "netbios",
    143: "imap",
    443: "https",
    445: "smb",
    554: "rtsp",
    631: "ipp",
    1883: "mqtt",
    3306: "mysql",
    3389: "rdp",
    5000: "upnp/http-alt",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    7687: "bolt",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    9100: "jetdirect",
    9200: "elasticsearch",
    27017: "mongodb",
    62078: "iphone-sync",
}
# Ports that make a non-gateway device count as a "Server".
SERVER_PORTS = {
    21,
    22,
    25,
    53,
    80,
    110,
    143,
    443,
    1883,
    3306,
    5432,
    6379,
    7687,
    8000,
    8080,
    8443,
    9200,
    27017,
}
# Services that are risky when reachable on a LAN.
RISKY_PORTS = {
    21: "cleartext FTP",
    23: "cleartext Telnet",
    445: "SMB file sharing",
    3389: "remote desktop",
    5900: "VNC remote desktop",
    6379: "Redis (often unauthenticated)",
    9200: "Elasticsearch (often unauthenticated)",
    27017: "MongoDB (often unauthenticated)",
    1883: "MQTT (often unauthenticated)",
}
ROLES = ("Router", "Server", "Host")  # whitelisted: labels cannot be query parameters
SWEEP_PORTS = (80, 443, 22, 445, 139, 62078)


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
# Discovery (stdlib only; scapy is optional)
# --------------------------------------------------------------------------- #
@dataclass
class Device:
    ip: str
    mac: str | None = None
    hostname: str | None = None
    role: str = "Host"
    is_self: bool = False
    ports: dict[int, str] = field(default_factory=dict)


def local_ip() -> str:
    """IP of the interface holding the default route (no packet is actually sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def default_gateway() -> str | None:
    # Linux: /proc/net/route (gateway is little-endian hex)
    try:
        with open("/proc/net/route") as fh:
            for line in fh.readlines()[1:]:
                f = line.split()
                if len(f) > 2 and f[1] == "00000000" and int(f[3], 16) & 2:
                    return socket.inet_ntoa(struct.pack("<L", int(f[2], 16)))
    except OSError:
        pass
    # macOS / BSD / Linux fallbacks
    for cmd in (
        ["ip", "route", "show", "default"],
        ["route", "-n", "get", "default"],
        ["netstat", "-rn"],
        ["ipconfig"],
    ):
        out = _run(cmd)
        m = (
            re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
            or re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", out)
            or re.search(
                r"^(?:default|0\.0\.0\.0)\s+(?:0\.0\.0\.0\s+)?(\d+\.\d+\.\d+\.\d+)",
                out,
                re.M,
            )
            or re.search(r"Default Gateway[ .]*:\s*(\d+\.\d+\.\d+\.\d+)", out)
        )
        if m:
            return m.group(1)
    return None


_MAC_RE = re.compile(r"([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})")
_IP_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)")


def _norm_mac(mac: str) -> str:
    return ":".join(p.zfill(2) for p in re.split(r"[:-]", mac.lower()))


def arp_table() -> dict[str, str]:
    """ip -> mac from the OS neighbour cache."""
    table: dict[str, str] = {}
    try:
        with open("/proc/net/arp") as fh:
            for line in fh.readlines()[1:]:
                f = line.split()
                if len(f) >= 4 and f[2] != "0x0" and f[3] != "00:00:00:00:00:00":
                    table[f[0]] = _norm_mac(f[3])
        return table
    except OSError:
        pass
    for line in _run(["arp", "-a"]).splitlines():
        ip, mac = _IP_RE.search(line), _MAC_RE.search(line)
        if ip and mac and not mac.group(1).lower().startswith("ff"):
            table[ip.group(1)] = _norm_mac(mac.group(1))
    return table


def tcp_probe(ip: str, port: int, timeout: float) -> str:
    """'open', 'closed' (host answered with RST => alive) or 'filtered'."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            rc = s.connect_ex((ip, port))
        except OSError:
            return "filtered"
    if rc == 0:
        return "open"
    if rc in (errno.ECONNREFUSED, 10061):  # 10061 = WSAECONNREFUSED
        return "closed"
    return "filtered"


def tcp_sweep(net: ipaddress.IPv4Network, timeout: float, workers: int) -> set[str]:
    """Find live hosts by TCP-connecting to a few ports (no root needed)."""
    hosts = [str(h) for h in net.hosts()]
    if len(hosts) > 1024:
        print(f"  ! {net} has {len(hosts)} hosts; sweeping only the first 1024")
        hosts = hosts[:1024]
    alive: set[str] = set()

    def check(ip: str) -> str | None:
        for p in SWEEP_PORTS:
            if tcp_probe(ip, p, timeout) in ("open", "closed"):
                return ip
        return None

    with cf.ThreadPoolExecutor(workers) as pool:
        alive.update(ip for ip in pool.map(check, hosts) if ip)
    return alive


def scapy_arp_sweep(net: ipaddress.IPv4Network) -> dict[str, str]:
    """Layer-2 ARP sweep. Needs scapy and root/admin rights."""
    try:
        from scapy.all import ARP, Ether, conf, srp  # type: ignore
    except ImportError:
        print("  ! scapy not installed (pip install scapy); skipping ARP sweep")
        return {}
    conf.verb = 0
    try:
        answered, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net)), timeout=2
        )
    except (PermissionError, OSError) as exc:
        print(f"  ! ARP sweep needs root/admin ({exc}); skipping")
        return {}
    return {rcv.psrc: _norm_mac(rcv.hwsrc) for _, rcv in answered}


def reverse_dns(ips: list[str], timeout: float = 2.0) -> dict[str, str]:
    def lookup(ip: str) -> str | None:
        try:
            return socket.gethostbyaddr(ip)[0]
        except OSError:
            return None

    out: dict[str, str] = {}
    pool = cf.ThreadPoolExecutor(32)
    futures = {pool.submit(lookup, ip): ip for ip in ips}
    try:
        for fut in cf.as_completed(futures, timeout=timeout):
            if fut.result():
                out[futures[fut]] = fut.result()
    except cf.TimeoutError:
        pass
    pool.shutdown(wait=False)
    return out


def port_scan(
    ips: list[str], ports: list[int], timeout: float, workers: int
) -> dict[str, list[int]]:
    jobs = [(ip, p) for ip in ips for p in ports]
    found: dict[str, list[int]] = {ip: [] for ip in ips}
    with cf.ThreadPoolExecutor(workers) as pool:
        for (ip, p), state in zip(
            jobs, pool.map(lambda j: tcp_probe(j[0], j[1], timeout), jobs)
        ):
            if state == "open":
                found[ip].append(p)
    return found


def classify(dev: Device, gateway: str | None) -> str:
    if dev.ip == gateway:
        return "Router"
    if set(dev.ports) & SERVER_PORTS:
        return "Server"
    return "Host"


def discover(args) -> tuple[str, str | None, list[Device]]:
    me = local_ip()
    gw = default_gateway()
    net = ipaddress.ip_network(args.cidr or f"{me}/24", strict=False)
    print(f"• this machine {me}  gateway {gw or '?'}  network {net}")

    neighbours = arp_table()
    if args.arp:
        print("• ARP sweep (scapy)…")
        neighbours.update(scapy_arp_sweep(net))
    live = set()
    if args.sweep:
        print(f"• TCP sweep of {net}…")
        live = tcp_sweep(net, args.timeout, args.workers)
        neighbours.update(arp_table())  # the sweep refreshed the OS ARP cache

    ips = (
        {ip for ip in set(neighbours) | live if ipaddress.ip_address(ip) in net}
        | {me}
        | ({gw} if gw else set())
    )
    devices = {
        ip: Device(ip=ip, mac=neighbours.get(ip), is_self=(ip == me)) for ip in ips
    }
    devices[me].hostname = socket.gethostname()

    print(f"• {len(devices)} device(s); probing {len(args.ports)} TCP ports each…")
    for ip, open_ports in port_scan(
        sorted(devices), args.ports, args.timeout, args.workers
    ).items():
        devices[ip].ports = {
            p: COMMON_PORTS.get(p, _service_name(p)) for p in open_ports
        }
    for ip, name in reverse_dns(
        [ip for ip in devices if not devices[ip].hostname]
    ).items():
        devices[ip].hostname = name
    for d in devices.values():
        d.role = classify(d, gw)
    return (
        str(net),
        gw,
        sorted(devices.values(), key=lambda d: ipaddress.ip_address(d.ip)),
    )


def _service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def demo_topology() -> tuple[str, str, list[Device]]:
    """A realistic small-office network so the project can be demoed anywhere."""
    D = Device
    devs = [
        D(
            "192.168.1.1",
            "a0:63:91:00:00:01",
            "gateway.lan",
            ports={53: "dns", 80: "http", 443: "https"},
        ),
        D(
            "192.168.1.10",
            "00:11:32:aa:bb:10",
            "nas.lan",
            ports={22: "ssh", 80: "http", 445: "smb", 5000: "upnp/http-alt"},
        ),
        D(
            "192.168.1.20",
            "52:54:00:12:34:20",
            "db.lan",
            ports={22: "ssh", 5432: "postgresql", 6379: "redis"},
        ),
        D(
            "192.168.1.21",
            "52:54:00:12:34:21",
            "web.lan",
            ports={22: "ssh", 80: "http", 443: "https", 8080: "http-proxy"},
        ),
        D("192.168.1.30", "3c:22:fb:00:00:30", "laptop-alice", is_self=True),
        D(
            "192.168.1.31",
            "f0:18:98:00:00:31",
            "iphone-bob",
            ports={62078: "iphone-sync"},
        ),
        D(
            "192.168.1.40",
            "00:1b:a9:00:00:40",
            "printer.lan",
            ports={80: "http", 631: "ipp", 9100: "jetdirect"},
        ),
        D(
            "192.168.1.50",
            "b8:27:eb:00:00:50",
            "camera-lobby",
            ports={23: "telnet", 554: "rtsp"},
        ),
        D(
            "192.168.1.60",
            "00:15:5d:00:00:60",
            "win-desktop",
            ports={139: "netbios", 445: "smb", 3389: "rdp"},
        ),
        D(
            "192.168.1.2",
            "c4:ad:34:00:00:02",
            "lab-router",
            ports={22: "ssh", 80: "http"},
        ),
        D(
            "10.0.0.5",
            "dc:a6:32:00:00:05",
            "lab-pi",
            ports={22: "ssh", 1883: "mqtt", 5900: "vnc"},
        ),
        D(
            "10.0.0.6",
            "dc:a6:32:00:00:06",
            "lab-gpu",
            ports={22: "ssh", 8000: "http-alt", 27017: "mongodb"},
        ),
    ]
    for d in devs:
        d.role = (
            "Router" if d.ip in ("192.168.1.1", "192.168.1.2") else classify(d, None)
        )
    return "192.168.1.0/24", "192.168.1.1", devs


# --------------------------------------------------------------------------- #
# Graph store (Relate)
# --------------------------------------------------------------------------- #
class NetGraph:
    def __init__(self, path: str = DEFAULT_DB, read_only: bool = False):
        if not path.endswith(".rl") and path != ":memory:":
            print(
                f"  ! '{path}' has no .rl extension, so Relate will create a DIRECTORY store, "
                "not a single file",
                file=sys.stderr,
            )
        self.db_path = path
        self.conn = relate.connect(path, read_only=read_only)
        if not read_only:
            self._schema()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def q(self, cypher: str, params: dict | None = None) -> list:
        return self.conn.execute(cypher, params or {}).fetchall()

    def _schema(self) -> None:
        for stmt in (
            "CREATE CONSTRAINT device_ip IF NOT EXISTS FOR (d:Device) REQUIRE d.ip IS UNIQUE",
            "CREATE CONSTRAINT port_id IF NOT EXISTS FOR (p:Port) REQUIRE p.id IS UNIQUE",
            "CREATE CONSTRAINT network_cidr IF NOT EXISTS FOR (n:Network) REQUIRE n.cidr IS UNIQUE",
        ):
            self.conn.execute(stmt)

    # -- ingestion --------------------------------------------------------- #
    def ingest(
        self,
        cidr: str,
        gateway: str | None,
        devices: list[Device],
        mode: str,
        uplinks: dict[str, str] | None = None,
    ) -> dict:
        """Write one scan atomically. `uplinks` maps device ip -> router ip it hangs off."""
        ts, scan_id = now(), uuid.uuid4().hex[:12]
        uplinks = uplinks or {}
        rows = [
            {
                "ip": d.ip,
                "mac": d.mac,
                "hostname": d.hostname,
                "role": d.role,
                "is_self": d.is_self,
            }
            for d in devices
        ]
        port_rows = [
            {"ip": d.ip, "number": p, "service": s, "id": f"tcp/{p}"}
            for d in devices
            for p, s in sorted(d.ports.items())
        ]

        self.conn.autocommit = False
        try:
            self.conn.execute("MERGE (n:Network {cidr: $cidr})", {"cidr": cidr})
            self.conn.execute("MERGE (:External {name: 'Internet'})")
            self.conn.execute(
                "CREATE (:Scan {id: $id, started: $ts, mode: $mode})",
                {"id": scan_id, "ts": ts, "mode": mode},
            )
            self.conn.execute(
                """
                UNWIND $rows AS r
                MERGE (d:Device {ip: r.ip})
                  ON CREATE SET d.first_seen = $ts
                SET d.mac = coalesce(r.mac, d.mac),
                    d.hostname = coalesce(r.hostname, d.hostname),
                    d.role = r.role, d.is_self = r.is_self, d.last_seen = $ts
                WITH d
                MATCH (n:Network {cidr: $cidr}), (s:Scan {id: $scan})
                MERGE (d)-[:MEMBER_OF]->(n)
                CREATE (s)-[:OBSERVED]->(d)
                """,
                {"rows": rows, "ts": ts, "cidr": cidr, "scan": scan_id},
            )
            # Role labels (labels can't be parameters, so whitelist + format).
            for role in ROLES:
                others = ":".join(r for r in ROLES if r != role)
                self.conn.execute(
                    f"MATCH (d:Device) WHERE d.ip IN $ips REMOVE d:{others} SET d:{role}",
                    {"ips": [d.ip for d in devices if d.role == role]},
                )
            # Ports: refresh this scan's view of each device.
            self.conn.execute(
                "MATCH (d:Device)-[e:EXPOSES_PORT]->() WHERE d.ip IN $ips DELETE e",
                {"ips": [d.ip for d in devices]},
            )
            self.conn.execute(
                """
                UNWIND $rows AS r
                MATCH (d:Device {ip: r.ip})
                MERGE (p:Port {id: r.id})
                  ON CREATE SET p.number = r.number, p.protocol = 'tcp'
                SET p.service = r.service
                MERGE (d)-[e:EXPOSES_PORT]->(p)
                SET e.state = 'open', e.last_seen = $ts
                """,
                {"rows": port_rows, "ts": ts},
            )
            # Topology: every non-router device -> its router; routers -> upstream / Internet.
            links = []
            for d in devices:
                up = uplinks.get(d.ip, gateway)
                if d.ip != gateway and up and up != d.ip:
                    links.append({"src": d.ip, "dst": up})
            self.conn.execute(
                """
                UNWIND $links AS l
                MATCH (a:Device {ip: l.src}), (b:Device {ip: l.dst})
                MERGE (a)-[c:CONNECTS_TO]->(b)
                SET c.medium = 'lan', c.last_seen = $ts
                """,
                {"links": links, "ts": ts},
            )
            if gateway:
                self.conn.execute(
                    """
                    MATCH (g:Device {ip: $gw}), (i:External {name: 'Internet'})
                    MERGE (g)-[c:CONNECTS_TO]->(i) SET c.medium = 'wan', c.last_seen = $ts
                    """,
                    {"gw": gateway, "ts": ts},
                )
            self.conn.execute(
                "MATCH (s:Scan {id: $id}) SET s.finished = $ts, s.devices = $n, s.open_ports = $p",
                {"id": scan_id, "ts": now(), "n": len(devices), "p": len(port_rows)},
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        finally:
            self.conn.autocommit = True
        return {"scan": scan_id, "devices": len(devices), "open_ports": len(port_rows)}

    def reset(self) -> None:
        self.conn.execute("MATCH (n) DETACH DELETE n")

    # -- questions --------------------------------------------------------- #
    def stats(self) -> list:
        return (
            self.q("""
            MATCH (n) UNWIND labels(n) AS label
            RETURN label, count(*) AS nodes ORDER BY nodes DESC""")
            + self.q(
                """
            MATCH ()-[r]->() RETURN type(r) AS label, count(*) AS nodes ORDER BY nodes DESC"""
            )
        )

    def devices(self, role: str | None = None) -> list:
        return self.q(
            """
            MATCH (d:Device) WHERE $role IS NULL OR d.role = $role
            OPTIONAL MATCH (d)-[:EXPOSES_PORT]->(p:Port)
            WITH d, p ORDER BY p.number
            RETURN d.ip AS ip, d.role AS role, d.hostname AS hostname, d.mac AS mac,
                   collect(p.number) AS open_ports, d.last_seen AS last_seen
            ORDER BY role, ip""",
            {"role": role},
        )

    def ports(self, ip: str | None = None) -> list:
        return self.q(
            """
            MATCH (d:Device)-[e:EXPOSES_PORT]->(p:Port)
            WHERE $ip IS NULL OR d.ip = $ip
            RETURN d.ip AS ip, d.hostname AS hostname, p.number AS port,
                   p.service AS service, e.last_seen AS last_seen
            ORDER BY ip, port""",
            {"ip": ip},
        )

    def exposing(self, port_or_service: str) -> list:
        key = port_or_service
        return self.q(
            """
            MATCH (d:Device)-[:EXPOSES_PORT]->(p:Port)
            WHERE toString(p.number) = $key OR toLower(p.service) = toLower($key)
            RETURN p.number AS port, p.service AS service, d.ip AS ip,
                   d.hostname AS hostname, d.role AS role
            ORDER BY ip""",
            {"key": key},
        )

    def path(self, src: str, dst: str) -> list:
        return self.q(
            """
            MATCH (a {ip: $src}), (b)
            WHERE b.ip = $dst OR b.name = $dst
            MATCH p = shortestPath((a)-[:CONNECTS_TO*..10]-(b))
            RETURN length(p) AS hops,
                   [n IN nodes(p) | coalesce(n.hostname, n.ip, n.name)] AS route,
                   [n IN nodes(p) | coalesce(n.ip, n.name)] AS addresses""",
            {"src": src, "dst": dst},
        )

    def neighbors(self, ip: str, depth: int = 2) -> list:
        depth = max(1, min(int(depth), 6))  # bounds can't be parameters
        return self.q(
            f"""
            MATCH (a:Device {{ip: $ip}})-[:CONNECTS_TO*1..{depth}]-(n:Device)
            WHERE n <> a
            WITH DISTINCT n
            OPTIONAL MATCH (n)-[:EXPOSES_PORT]->(p:Port)
            WITH n, p ORDER BY p.number
            RETURN n.ip AS ip, n.role AS role, n.hostname AS hostname,
                   collect(p.service) AS services ORDER BY ip""",
            {"ip": ip},
        )

    def risky(self) -> list:
        rows = [{"port": p, "why": why} for p, why in RISKY_PORTS.items()]
        return self.q(
            """
            UNWIND $rows AS r
            MATCH (d:Device)-[:EXPOSES_PORT]->(p:Port {number: r.port})
            OPTIONAL MATCH path = shortestPath((d)-[:CONNECTS_TO*..10]-(:External))
            RETURN d.ip AS ip, d.hostname AS hostname, p.number AS port, r.why AS risk,
                   CASE WHEN path IS NULL THEN null ELSE length(path) END AS hops_to_internet
            ORDER BY hops_to_internet, ip""",
            {"rows": rows},
        )

    def new_devices(self) -> list:
        return self.q("""
            MATCH (s:Scan) WITH s ORDER BY s.started DESC LIMIT 1
            MATCH (s)-[:OBSERVED]->(d:Device) WHERE d.first_seen >= s.started
            RETURN d.ip AS ip, d.role AS role, d.hostname AS hostname, d.mac AS mac
            ORDER BY ip""")

    def gone_devices(self) -> list:
        return self.q("""
            MATCH (s:Scan) WITH s ORDER BY s.started DESC LIMIT 1
            MATCH (d:Device) WHERE NOT (s)-[:OBSERVED]->(d)
            RETURN d.ip AS ip, d.role AS role, d.hostname AS hostname, d.last_seen AS last_seen
            ORDER BY ip""")

    def scans(self) -> list:
        return self.q(
            """
            MATCH (s:Scan) RETURN s.id AS id, s.mode AS mode, s.started AS started,
                   s.devices AS devices, s.open_ports AS open_ports ORDER BY started DESC"""
        )


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def _cell(v) -> str:
    if v is None:
        return "-"
    if isinstance(v, list):
        return ", ".join(_cell(x) for x in v) or "-"
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, (dict, str, int, float)):
        return json.dumps(v, default=str) if isinstance(v, dict) else str(v)
    return str(v)


def show(rows: list, as_json: bool = False, title: str | None = None) -> None:
    if as_json:
        print(
            json.dumps(
                [r.to_dict() if hasattr(r, "to_dict") else r for r in rows],
                indent=2,
                default=str,
            )
        )
        return
    if title:
        print(f"\n{title}")
    if not rows:
        print("  (no results)")
        return
    keys = list(rows[0].keys())
    table = [[_cell(r[k]) for k in keys] for r in rows]
    widths = [
        min(max(len(k), *(len(row[i]) for row in table)), 60)
        for i, k in enumerate(keys)
    ]
    print("  " + "  ".join(k.upper().ljust(w) for k, w in zip(keys, widths)))
    print("  " + "  ".join("─" * w for w in widths))
    for row in table:
        print("  " + "  ".join(c[:w].ljust(w) for c, w in zip(row, widths)))
    print(f"  ({len(rows)} row{'s' if len(rows) != 1 else ''})")


def parse_params(pairs: list[str]) -> dict:
    params = {}
    for pair in pairs or []:
        k, _, v = pair.partition("=")
        try:
            params[k] = json.loads(v)
        except json.JSONDecodeError:
            params[k] = v
    return params


def parse_ports(spec: str) -> list[int]:
    if spec == "common":
        return sorted(COMMON_PORTS)
    ports: set[int] = set()
    for part in spec.split(","):
        a, _, b = part.partition("-")
        ports.update(range(int(a), int(b or a) + 1))
    return sorted(p for p in ports if 0 < p < 65536)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="netgraph",
        description=__doc__.split("\n\n")[1],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "--db",
        default=os.environ.get("NETGRAPH_DB", DEFAULT_DB),
        help=f"single-file Relate store (default: {DEFAULT_DB})",
    )
    ap.add_argument("--json", action="store_true", help="print results as JSON")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser(
        "scan", help="discover the local network and store it in the graph"
    )
    s.add_argument("--cidr", help="network to analyse (default: <your-ip>/24)")
    s.add_argument(
        "--ports",
        type=parse_ports,
        default=sorted(COMMON_PORTS),
        help="'common' (default), or e.g. '22,80,443,8000-8100'",
    )
    s.add_argument(
        "--sweep", action="store_true", help="TCP sweep the subnet to find quiet hosts"
    )
    s.add_argument(
        "--arp", action="store_true", help="ARP sweep with scapy (needs root)"
    )
    s.add_argument(
        "--timeout", type=float, default=0.4, help="per-probe timeout in seconds"
    )
    s.add_argument("--workers", type=int, default=128, help="parallel probes")

    sub.add_parser("demo", help="load a sample office network (no scanning)")
    sub.add_parser("stats", help="node and relationship counts")
    d = sub.add_parser("devices", help="list devices")
    d.add_argument("--role", choices=ROLES)
    p = sub.add_parser("ports", help="open ports, optionally for one device")
    p.add_argument("ip", nargs="?")
    e = sub.add_parser("exposed", help="devices exposing a port number or service name")
    e.add_argument("port", help="e.g. 22 or ssh")
    pa = sub.add_parser("path", help="shortest network path between two devices")
    pa.add_argument("src")
    pa.add_argument("dst", help="an IP, or 'Internet'")
    n = sub.add_parser("neighbors", help="assets connected to a device")
    n.add_argument("ip")
    n.add_argument("--depth", type=int, default=2)
    sub.add_parser(
        "risky", help="risky services and how close they sit to the Internet"
    )
    sub.add_parser("new", help="devices first seen in the latest scan")
    sub.add_parser("gone", help="devices missing from the latest scan")
    sub.add_parser("scans", help="scan history")
    c = sub.add_parser("cypher", help="run any Cypher query")
    c.add_argument("query")
    c.add_argument(
        "-p",
        "--param",
        action="append",
        metavar="KEY=VALUE",
        help="query parameter (value parsed as JSON when possible)",
    )
    sub.add_parser("reset", help="delete everything in the graph")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    writes = args.cmd in ("scan", "demo", "reset", "cypher")
    if not writes and not os.path.exists(args.db):
        print(
            f"No graph at {args.db}. Run `python main.py scan` or `python main.py demo` first."
        )
        return 1

    try:
        with NetGraph(args.db, read_only=not writes) as g:
            if args.cmd == "scan":
                print(f"NetGraph scan on {platform.node()} → {args.db}")
                cidr, gw, devices = discover(args)
                res = g.ingest(cidr, gw, devices, mode="live")
                print(
                    f"✓ scan {res['scan']}: {res['devices']} devices, {res['open_ports']} open ports"
                )
                show(g.devices(), args.json, "Devices")
            elif args.cmd == "demo":
                cidr, gw, devices = demo_topology()
                lab = {"10.0.0.5": "192.168.1.2", "10.0.0.6": "192.168.1.2"}
                res = g.ingest(cidr, gw, devices, mode="demo", uplinks=lab)
                print(
                    f"✓ demo network loaded into {args.db}: "
                    f"{res['devices']} devices, {res['open_ports']} open ports"
                )
                show(g.devices(), args.json, "Devices")
            elif args.cmd == "stats":
                show(
                    g.stats(),
                    args.json,
                    f"Graph in {args.db} ({os.path.getsize(args.db):,} bytes)",
                )
            elif args.cmd == "devices":
                show(g.devices(args.role), args.json, "Devices")
            elif args.cmd == "ports":
                show(g.ports(args.ip), args.json, "Open ports")
            elif args.cmd == "exposed":
                show(g.exposing(args.port), args.json, f"Devices exposing {args.port}")
            elif args.cmd == "path":
                rows = g.path(args.src, args.dst)
                if rows and not args.json:
                    print(f"\n{args.src} → {args.dst}: {rows[0]['hops']} hop(s)")
                    print("  " + "  ──▶  ".join(rows[0]["route"]))
                else:
                    show(rows, args.json, "Path")
            elif args.cmd == "neighbors":
                show(
                    g.neighbors(args.ip, args.depth),
                    args.json,
                    f"Assets within {args.depth} hop(s) of {args.ip}",
                )
            elif args.cmd == "risky":
                show(g.risky(), args.json, "Risky exposed services")
            elif args.cmd == "new":
                show(g.new_devices(), args.json, "New in latest scan")
            elif args.cmd == "gone":
                show(g.gone_devices(), args.json, "Missing from latest scan")
            elif args.cmd == "scans":
                show(g.scans(), args.json, "Scan history")
            elif args.cmd == "cypher":
                show(g.q(args.query, parse_params(args.param)), args.json)
            elif args.cmd == "reset":
                g.reset()
                print(f"✓ cleared {args.db}")
    except relate.RelateError as exc:
        print(
            f"Relate error [{getattr(exc, 'neo4j_code', None)}]: {exc}", file=sys.stderr
        )
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
