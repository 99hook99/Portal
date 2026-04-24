"""Demo data seeder – runs once when the database is empty."""
from datetime import datetime, timedelta
import random
from sqlalchemy.orm import Session
from app.models import Asset, Vulnerability, CVERecord, Scanner, ScanJob


ASSETS = [
    ("web-prod-01", "10.10.1.11", "Windows Server 2022", "server", "high"),
    ("web-prod-02", "10.10.1.12", "Windows Server 2022", "server", "high"),
    ("web-prod-03", "10.10.1.13", "Ubuntu 22.04 LTS",    "server", "high"),
    ("app-prod-01", "10.10.2.21", "Windows Server 2019", "server", "critical"),
    ("app-prod-02", "10.10.2.22", "Windows Server 2019", "server", "critical"),
    ("app-prod-03", "10.10.2.23", "Red Hat 8.6",         "server", "critical"),
    ("db-prod-01",  "10.10.3.31", "Windows Server 2019", "server", "critical"),
    ("db-prod-02",  "10.10.3.32", "Ubuntu 20.04 LTS",    "server", "critical"),
    ("db-prod-03",  "10.10.3.33", "Oracle Linux 8",      "server", "critical"),
    ("dc-prod-01",  "10.10.4.41", "Windows Server 2022", "server", "critical"),
    ("dc-prod-02",  "10.10.4.42", "Windows Server 2022", "server", "critical"),
    ("esxi-01",     "10.10.5.51", "VMware ESXi 7.0",     "server", "critical"),
    ("esxi-02",     "10.10.5.52", "VMware ESXi 7.0",     "server", "high"),
    ("fw-edge-01",  "10.10.0.1",  "Cisco ASA 9.18",      "network", "critical"),
    ("sw-core-01",  "10.10.0.10", "Cisco IOS 15.2",      "network", "high"),
    ("sw-core-02",  "10.10.0.11", "Cisco IOS 15.2",      "network", "high"),
    ("rtr-wan-01",  "10.10.0.20", "Cisco IOS-XE 17.6",   "network", "high"),
    ("ws-dev-01",   "10.20.1.101","Windows 11 22H2",      "workstation", "medium"),
    ("ws-dev-02",   "10.20.1.102","Windows 11 22H2",      "workstation", "medium"),
    ("ws-dev-03",   "10.20.1.103","Windows 10 22H2",      "workstation", "low"),
    ("ws-dev-04",   "10.20.1.104","Windows 11 23H2",      "workstation", "medium"),
    ("ws-dev-05",   "10.20.1.105","macOS 14 Sonoma",      "workstation", "low"),
    ("ws-ops-01",   "10.20.2.101","Windows 11 22H2",      "workstation", "medium"),
    ("ws-ops-02",   "10.20.2.102","Windows 10 21H2",      "workstation", "medium"),
    ("backup-01",   "10.10.6.61", "Windows Server 2019",  "server", "high"),
    ("mon-01",      "10.10.6.62", "Ubuntu 22.04 LTS",     "server", "medium"),
    ("proxy-01",    "10.10.1.20", "Ubuntu 22.04 LTS",     "server", "high"),
    ("mail-01",     "10.10.1.30", "Windows Server 2019",  "server", "critical"),
]

VULNS = [
    # title, severity, cvss, cve_ids, plugin_id, description, solution
    (
        "Apache Log4j Remote Code Execution (Log4Shell)",
        "critical", 10.0, "CVE-2021-44228",
        "155999",
        "A critical RCE vulnerability in Apache Log4j 2.x allows unauthenticated remote code execution via JNDI lookup in log messages.",
        "Update Apache Log4j to version 2.17.1 or later. If patching is not immediately possible, set the JVM flag -Dlog4j2.formatMsgNoLookups=true.",
    ),
    (
        "Windows Print Spooler Remote Code Execution (PrintNightmare)",
        "critical", 8.8, "CVE-2021-34527",
        "151264",
        "A remote code execution vulnerability exists when the Windows Print Spooler service improperly performs privileged file operations.",
        "Apply Microsoft security update KB5004945. Consider disabling the Print Spooler service on Domain Controllers and systems that do not require printing.",
    ),
    (
        "Microsoft Exchange ProxyLogon RCE",
        "critical", 9.8, "CVE-2021-26855",
        "147193",
        "A server-side request forgery vulnerability in Exchange Server allows an attacker to bypass authentication and execute arbitrary code.",
        "Apply the cumulative update released by Microsoft in March 2021. Restrict untrusted connections to Exchange server port 443.",
    ),
    (
        "Zerologon – Netlogon Privilege Escalation",
        "critical", 10.0, "CVE-2020-1472",
        "140862",
        "A privilege escalation vulnerability exists in the Netlogon Remote Protocol (MS-NRPC). An attacker can spoof a domain controller identity and gain domain admin privileges.",
        "Apply August 2020 Patch Tuesday updates. Enable enforcement mode in the Netlogon registry setting.",
    ),
    (
        "Microsoft Outlook NTLM Credential Leak (CVE-2023-23397)",
        "critical", 9.8, "CVE-2023-23397",
        "172954",
        "An attacker can exploit Outlook's handling of calendar reminder sounds to force NTLM authentication to an attacker-controlled server, leaking Net-NTLMv2 hashes.",
        "Apply Microsoft March 2023 cumulative update. Block outbound TCP 445 from workstations to external IPs.",
    ),
    (
        "HTTP/2 Rapid Reset – DoS (CVE-2023-44487)",
        "high", 7.5, "CVE-2023-44487",
        "182533",
        "Attackers can send a stream of HTTP/2 HEADERS followed immediately by RST_STREAM frames to exhaust server resources.",
        "Update web servers (nginx, Apache, IIS) to patched versions. Implement rate limiting on HTTP/2 connections.",
    ),
    (
        "Spring Cloud Function RCE (SpringShell)",
        "critical", 9.8, "CVE-2022-22963",
        "160288",
        "A routing functionality flaw in Spring Cloud Function allows remote code execution via specially crafted Spring Expression Language (SpEL) expressions.",
        "Upgrade Spring Cloud Function to 3.1.7 or 3.2.3. Apply spring.cloud.function.definition property restriction.",
    ),
    (
        "Microsoft Support Diagnostic Tool RCE (Follina)",
        "critical", 7.8, "CVE-2022-30190",
        "162098",
        "A vulnerability in MSDT allows code execution when opening a specially crafted Office document, even without macros enabled.",
        "Apply Microsoft June 2022 cumulative update. Disable MSDT URL protocol via registry if patching is not immediately possible.",
    ),
    (
        "F5 BIG-IP iControl REST Authentication Bypass",
        "critical", 9.8, "CVE-2022-1388",
        "160597",
        "Undisclosed requests to the iControl REST API may bypass authentication, allowing unauthenticated attackers to execute arbitrary commands.",
        "Upgrade to BIG-IP 17.0.0, 16.1.2.2, 15.1.5.1, 14.1.4.6, or 13.1.5 or later.",
    ),
    (
        "Cisco IOS XE Web UI Privilege Escalation (CVE-2023-20198)",
        "critical", 10.0, "CVE-2023-20198",
        "183619",
        "A vulnerability in the web UI of Cisco IOS XE allows an unauthenticated remote attacker to create a privileged account.",
        "Apply Cisco Security Advisory cisco-sa-iosxe-webui-privesc-j22SaA4z. Disable HTTP Server feature if not required.",
    ),
    (
        "TLS 1.0 / 1.1 Protocol Enabled",
        "medium", 5.3, None,
        "104743",
        "The remote host supports TLS 1.0 and/or TLS 1.1, which are deprecated protocols with known weaknesses including POODLE and BEAST.",
        "Disable TLS 1.0 and 1.1 on all affected services. Enforce TLS 1.2 (minimum) or TLS 1.3.",
    ),
    (
        "SSL Certificate Expired",
        "high", 7.5, None,
        "15901",
        "The SSL certificate on this host has expired. Clients may receive security warnings and encrypted communication may be disrupted.",
        "Renew the SSL certificate immediately and deploy the updated certificate.",
    ),
    (
        "SMB Signing Not Required",
        "medium", 5.3, None,
        "57608",
        "The remote SMB server does not enforce message signing. This can allow man-in-the-middle attacks to be carried out against the SMB server.",
        "Enable and enforce SMB signing via Group Policy: Microsoft network server: Digitally sign communications (always).",
    ),
    (
        "Remote Desktop Protocol (RDP) Exposed to Internet",
        "high", 7.2, None,
        "18405",
        "Remote Desktop Protocol (port 3389/tcp) is directly reachable from the internet. This dramatically increases the attack surface for brute-force and exploitation attacks.",
        "Restrict RDP access through VPN or firewall rules. Enable Network Level Authentication (NLA). Implement account lockout policies.",
    ),
    (
        "OpenSSH Terrapin Attack (CVE-2023-48795)",
        "medium", 5.9, "CVE-2023-48795",
        "187862",
        "A vulnerability in the SSH Binary Packet Protocol allows a MITM attacker to downgrade connection security, potentially enabling authentication bypass.",
        "Upgrade OpenSSH to version 9.6 or later. Disable affected algorithms: chacha20-poly1305@openssh.com and CBC-mode ciphers with ETM.",
    ),
    (
        "Apache HTTP Server mod_proxy SSRF (CVE-2021-40438)",
        "critical", 9.0, "CVE-2021-40438",
        "153609",
        "A crafted request URI-path can cause mod_proxy to forward the request to an arbitrary origin server and expose sensitive data.",
        "Upgrade Apache HTTP Server to version 2.4.49 or later. Restrict mod_proxy with appropriate ProxyRequests Off directives.",
    ),
    (
        "Default SNMP Community String (public/private)",
        "high", 7.5, None,
        "10264",
        "The remote device uses the default SNMP community strings 'public' and/or 'private', which allows an attacker to read or modify device configuration.",
        "Change SNMP community strings to complex, unique values. Consider upgrading to SNMPv3 with authentication and encryption.",
    ),
    (
        "Windows BlueKeep RDP Pre-Auth RCE (CVE-2019-0708)",
        "critical", 9.8, "CVE-2019-0708",
        "125313",
        "A critical vulnerability in Remote Desktop Services allows unauthenticated remote code execution. The exploit is wormable and can spread between unpatched systems.",
        "Apply Microsoft security patch (KB4499175 or equivalent for your OS version). Disable RDP if not required. Enable NLA.",
    ),
    (
        "VMware ESXi OpenSLP RCE (ESXiArgs)",
        "critical", 9.8, "CVE-2021-21974",
        "155592",
        "A heap overflow vulnerability in OpenSLP, as used by VMware ESXi, allows an attacker on the same network segment to execute arbitrary code.",
        "Apply VMware Security Advisory VMSA-2021-0002. Disable the SLP service on ESXi hosts if not required.",
    ),
    (
        "Windows LDAP Remote Code Execution (CVE-2022-26919)",
        "high", 8.1, "CVE-2022-26919",
        "159943",
        "A race condition in the Windows LDAP client implementation allows a remote attacker to execute arbitrary code when processing malformed LDAP responses.",
        "Apply April 2022 Windows cumulative update. Restrict LDAP traffic using firewall rules where possible.",
    ),
    (
        "PHP-FPM Remote Code Execution (CVE-2019-11043)",
        "critical", 9.8, "CVE-2019-11043",
        "130244",
        "A buffer underflow in PHP-FPM, when combined with certain nginx configurations, allows unauthenticated remote code execution.",
        "Upgrade PHP to 7.1.33, 7.2.24, or 7.3.11 or later. Review nginx configuration to avoid affected PATH_INFO patterns.",
    ),
    (
        "SSH Weak Algorithms Supported (MD5/96-bit MAC)",
        "low", 2.6, None,
        "70658",
        "The remote SSH server supports weak message authentication algorithms (MD5 and/or 96-bit MACs). These algorithms have known cryptographic weaknesses.",
        "Disable weak MAC algorithms in sshd_config: MACs hmac-sha2-256,hmac-sha2-512",
    ),
    (
        "Microsoft Windows Unquoted Service Path Privilege Escalation",
        "medium", 4.4, None,
        "63155",
        "One or more Windows services have unquoted paths containing spaces. A local attacker can exploit this to run arbitrary code with elevated privileges.",
        "Enclose service executable paths in double quotes in the registry: HKLM\\SYSTEM\\CurrentControlSet\\Services.",
    ),
]

CVES = [
    ("CVE-2021-44228", "critical", 10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
     "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
     "2021-12-10"),
    ("CVE-2021-34527", "critical", 8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
     "Windows Print Spooler Remote Code Execution Vulnerability.",
     "2021-07-01"),
    ("CVE-2021-26855", "critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "Microsoft Exchange Server Remote Code Execution Vulnerability (ProxyLogon).",
     "2021-03-02"),
    ("CVE-2020-1472", "critical", 10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
     "Netlogon Elevation of Privilege Vulnerability (Zerologon).",
     "2020-08-11"),
    ("CVE-2023-23397", "critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "Microsoft Outlook Elevation of Privilege Vulnerability.",
     "2023-03-14"),
    ("CVE-2023-44487", "high", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
     "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly.",
     "2023-10-10"),
    ("CVE-2022-22963", "critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution.",
     "2022-04-01"),
    ("CVE-2022-30190", "critical", 7.8, "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
     "Microsoft Support Diagnostic Tool (MSDT) Remote Code Execution Vulnerability (Follina).",
     "2022-06-01"),
    ("CVE-2022-1388", "critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "On F5 BIG-IP 16.1.x, 15.1.x, 14.1.x, 13.1.x, and all 12.1.x and 11.6.x versions, undisclosed requests may bypass iControl REST authentication.",
     "2022-05-04"),
    ("CVE-2023-20198", "critical", 10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
     "A vulnerability in the web UI feature of Cisco IOS XE Software could allow an unauthenticated, remote attacker to create an account on an affected system with privilege level 15 access.",
     "2023-10-16"),
    ("CVE-2019-0708", "critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "A remote code execution vulnerability exists in Remote Desktop Services – formerly known as Terminal Services – when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests.",
     "2019-05-14"),
    ("CVE-2021-21974", "high", 8.8, "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "OpenSLP as used in VMware ESXi has a heap-overflow vulnerability. An attacker with access to port 427 on the same network segment as ESXi may be able to trigger the heap-overflow issue in OpenSLP service resulting in remote code execution.",
     "2021-02-24"),
    ("CVE-2023-48795", "medium", 5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
     "The SSH transport protocol with certain OpenSSH extensions, found in OpenSSH before 9.6 allows a MITM to downgrade security.",
     "2023-12-18"),
    ("CVE-2021-40438", "critical", 9.0, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
     "A crafted request uri-path can cause mod_proxy to forward the request to an origin server choosen by the remote user.",
     "2021-09-16"),
    ("CVE-2019-11043", "critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "In PHP versions 7.1.x below 7.1.33, 7.2.x below 7.2.24 and 7.3.x below 7.3.11 in certain configurations of FPM setup it is possible to cause FPM module to write past allocated buffers.",
     "2019-10-28"),
]

SCANNERS = [
    ("Nessus Professional", "nessus"),
    ("Microsoft Defender for Endpoint", "mde"),
    ("OpenVAS / Greenbone", "openvas"),
    ("NMAP Network Scanner", "nmap"),
    ("PAC Vulnerability Scanner", "pac"),
    ("Nuclei (ProjectDiscovery)", "nuclei"),
    ("AWS Security (Inspector + Config + SecHub)", "aws"),
]


def _days_ago(n: int) -> datetime:
    return datetime.utcnow() - timedelta(days=n)


def seed(db: Session) -> None:
    if db.query(Asset).count() > 0:
        return

    # ── Assets ──────────────────────────────────────────────────────────────
    asset_objs = []
    for hostname, ip, os_name, atype, crit in ASSETS:
        a = Asset(
            hostname=hostname,
            ip_address=ip,
            os=os_name,
            asset_type=atype,
            criticality=crit,
            source=random.choice(["nessus", "mde", "nmap"]),
            status="active",
            first_seen=_days_ago(random.randint(30, 180)),
            last_seen=_days_ago(random.randint(0, 5)),
        )
        db.add(a)
        asset_objs.append(a)

    db.flush()

    # ── Vulnerabilities ──────────────────────────────────────────────────────
    sources = ["nessus", "mde", "openvas", "nmap"]
    statuses = ["open"] * 7 + ["in_progress"] * 2 + ["accepted"] * 1

    for asset in asset_objs:
        n_vulns = {
            "critical": random.randint(4, 8),
            "high": random.randint(2, 5),
            "medium": random.randint(3, 8),
            "low": random.randint(1, 4),
        }
        if asset.criticality in ("critical", "high"):
            n_vulns["critical"] += 2
            n_vulns["high"] += 2

        for sev, count in n_vulns.items():
            pool = [v for v in VULNS if v[1] == sev]
            if not pool:
                continue
            chosen = random.choices(pool, k=count)
            for vuln in chosen:
                v = Vulnerability(
                    title=vuln[0],
                    severity=sev,
                    cvss_score=vuln[2],
                    cve_ids=vuln[3],
                    plugin_id=vuln[4],
                    description=vuln[5],
                    solution=vuln[6],
                    source=random.choice(sources),
                    status=random.choice(statuses),
                    asset_id=asset.id,
                    port=random.choice([80, 443, 445, 3389, 22, 8080, None]),
                    first_seen=_days_ago(random.randint(1, 60)),
                    last_seen=_days_ago(random.randint(0, 3)),
                )
                db.add(v)

    # ── CVE Records ──────────────────────────────────────────────────────────
    for cve_id, sev, cvss, vector, desc, pub in CVES:
        c = CVERecord(
            cve_id=cve_id,
            severity=sev,
            cvss_v3_score=cvss,
            cvss_v3_vector=vector,
            description=desc,
            published_date=datetime.strptime(pub, "%Y-%m-%d"),
        )
        db.add(c)

    # ── Scanners ─────────────────────────────────────────────────────────────
    scanner_objs = []
    for name, stype in SCANNERS:
        existing = db.query(Scanner).filter(Scanner.name == name).first()
        if existing:
            scanner_objs.append(existing)
            continue
        s = Scanner(
            name=name,
            scanner_type=stype,
            enabled=True,
            status="unconfigured",
            total_findings=random.randint(50, 300),
        )
        db.add(s)
        scanner_objs.append(s)

    db.flush()

    # ── Scan Jobs ────────────────────────────────────────────────────────────
    job_statuses = ["completed", "completed", "completed", "failed"]
    for scanner in scanner_objs:
        for i in range(random.randint(2, 5)):
            st = _days_ago(random.randint(1, 30))
            js = random.choice(job_statuses)
            j = ScanJob(
                scanner_id=scanner.id,
                status=js,
                started_at=st,
                completed_at=st + timedelta(minutes=random.randint(5, 120)),
                findings_count=random.randint(10, 150),
                error_message="Connection timeout" if js == "failed" else None,
            )
            db.add(j)

    db.commit()

    # ── Update asset risk scores ─────────────────────────────────────────────
    from sqlalchemy import func
    for asset in db.query(Asset).all():
        crits = db.query(func.count(Vulnerability.id)).filter(
            Vulnerability.asset_id == asset.id,
            Vulnerability.severity == "critical",
            Vulnerability.status != "remediated",
        ).scalar() or 0
        highs = db.query(func.count(Vulnerability.id)).filter(
            Vulnerability.asset_id == asset.id,
            Vulnerability.severity == "high",
            Vulnerability.status != "remediated",
        ).scalar() or 0
        asset.risk_score = min(100.0, crits * 10 + highs * 4)

    db.commit()
