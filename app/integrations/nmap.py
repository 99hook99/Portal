"""
NMAP integration – runs nmap and parses XML output for open services/ports.

Configuration (from .env):
  NMAP_TARGETS  – comma-separated targets, e.g. 192.168.1.0/24,10.0.0.0/8
  NMAP_ARGS     – default: -sV -sC --open -T4

Requires nmap to be installed: apt install nmap
"""
import asyncio
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Optional

from app.integrations.base import BaseIntegration, VulnFinding

RISKY_PORTS = {
    21:   ("FTP Service Detected",            "medium"),
    23:   ("Telnet Service Exposed",           "high"),
    25:   ("SMTP Relay Open",                  "medium"),
    53:   ("DNS Service Exposed",              "low"),
    80:   ("HTTP (Unencrypted) Service",       "low"),
    135:  ("RPC Endpoint Mapper Exposed",      "high"),
    139:  ("NetBIOS Session Service Exposed",  "high"),
    445:  ("SMB Service Exposed",              "high"),
    1433: ("MSSQL Service Exposed",            "high"),
    1521: ("Oracle DB Service Exposed",        "high"),
    3306: ("MySQL Service Exposed",            "medium"),
    3389: ("Remote Desktop Protocol Exposed",  "high"),
    5432: ("PostgreSQL Service Exposed",       "medium"),
    5900: ("VNC Service Exposed",              "high"),
    6379: ("Redis Service Exposed (No Auth)",  "high"),
    8080: ("HTTP Proxy/Alt Port Exposed",      "low"),
    27017:("MongoDB Service Exposed",          "high"),
}


class NmapIntegration(BaseIntegration):
    def __init__(self, targets: Optional[str], args: str = "-sV --open -T4"):
        self.targets = targets or ""
        self.args = args

    async def test_connection(self) -> bool:
        try:
            result = subprocess.run(["nmap", "--version"], capture_output=True, timeout=10)
            return result.returncode == 0
        except Exception:
            return False

    async def fetch_vulnerabilities(self) -> list[VulnFinding]:
        findings: list[VulnFinding] = []
        targets = [t.strip() for t in self.targets.split(",") if t.strip()]

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            out_file = tmp.name

        cmd = ["nmap"] + self.args.split() + ["-oX", out_file] + targets
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()

        tree = ET.parse(out_file)
        root = tree.getroot()

        for host in root.findall("host"):
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue

            ip = None
            hostname = None
            for addr in host.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    ip = addr.get("addr")
            hn_el = host.find("hostnames/hostname")
            if hn_el is not None:
                hostname = hn_el.get("name")

            for port_el in host.findall("ports/port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                portnum = int(port_el.get("portid", 0))
                proto = port_el.get("protocol", "tcp")
                service_el = port_el.find("service")
                service_name = service_el.get("name", "unknown") if service_el is not None else "unknown"
                product = service_el.get("product", "") if service_el is not None else ""
                version = service_el.get("version", "") if service_el is not None else ""

                if portnum in RISKY_PORTS:
                    title, severity = RISKY_PORTS[portnum]
                    description = f"Port {portnum}/{proto} ({service_name}) is open."
                    if product:
                        description += f" Service: {product} {version}".strip()
                else:
                    title = f"Open Port {portnum}/{proto} ({service_name})"
                    severity = "info"
                    description = f"Port {portnum}/{proto} is open. Service: {service_name} {product} {version}".strip()

                findings.append(VulnFinding(
                    title=title,
                    severity=severity,
                    source="nmap",
                    asset_ip=ip,
                    asset_hostname=hostname,
                    description=description,
                    port=portnum,
                    protocol=proto,
                ))

        return findings
