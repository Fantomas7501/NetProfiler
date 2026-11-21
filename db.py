"""SQLite persistence layer, schema initialization, and seed data for NetProfiler."""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

DEFAULT_DB_PATH = str(Path(__file__).resolve().parent / "netprofiler.db")


def get_db_path() -> str:
    return os.environ.get("NETPROFILER_DB", DEFAULT_DB_PATH)


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(get_db_path(), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


DEFAULT_CONFIG: dict[str, str] = {
    "target_subnet": "192.168.10.0/24",
    "scan_interval_minutes": "60",
    "port_range": "top-1000",
    "nmap_flags": "-sV -O --version-intensity 5 -T4",
    "enable_os_detection": "true",
    "enable_script_scan": "true",
    "alert_on_new_port": "true",
    "alert_webhook_url": "",
    "session_ttl_hours": "24",
    "retention_days": "30",
    "organization_name": "Réseau Principal",
}


def init_db(seed_demo: bool = True) -> None:
    """Initialize all database tables, default config, default admin user, and optional demo scan data."""
    with get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                display_name TEXT NOT NULL DEFAULT '',
                email TEXT NOT NULL DEFAULT '',
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'viewer' CHECK(role IN ('admin', 'analyst', 'viewer')),
                is_active INTEGER NOT NULL DEFAULT 1,
                must_change_password INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                last_login_at TEXT
            );

            CREATE TABLE IF NOT EXISTS auth_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT NOT NULL UNIQUE,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                user_agent TEXT NOT NULL DEFAULT '',
                ip_address TEXT NOT NULL DEFAULT ''
            );

            CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth_sessions(user_id);

            CREATE TABLE IF NOT EXISTS app_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scan_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time TEXT NOT NULL,
                subnet TEXT NOT NULL,
                hosts_up INTEGER NOT NULL DEFAULT 0,
                duration_sec REAL NOT NULL DEFAULT 0,
                scanner_notes TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
                ip TEXT NOT NULL,
                mac TEXT NOT NULL DEFAULT 'Inconnu',
                hostname TEXT NOT NULL DEFAULT 'Inconnu',
                vendor TEXT NOT NULL DEFAULT 'Inconnu',
                os TEXT NOT NULL DEFAULT 'Inconnu',
                device_type TEXT NOT NULL DEFAULT 'unknown',
                latency_ms REAL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_devices_session_ip ON devices(session_id, ip);

            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL DEFAULT 'tcp',
                state TEXT NOT NULL DEFAULT 'open',
                service TEXT NOT NULL DEFAULT 'unknown',
                product TEXT NOT NULL DEFAULT '',
                version TEXT NOT NULL DEFAULT '',
                extrainfo TEXT NOT NULL DEFAULT '',
                cpe TEXT NOT NULL DEFAULT '',
                banner TEXT NOT NULL DEFAULT '',
                script_output TEXT NOT NULL DEFAULT '',
                risk_level TEXT NOT NULL DEFAULT 'low',
                is_new INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_ports_device ON ports(device_id);
            """
        )

        now_iso = datetime.now(timezone.utc).isoformat()
        for k, v in DEFAULT_CONFIG.items():
            conn.execute(
                "INSERT OR IGNORE INTO app_config (key, value, updated_at) VALUES (?, ?, ?)",
                (k, v, now_iso),
            )

        # Ensure at least one admin exists on first launch
        user_count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        if user_count == 0:
            from auth import hash_password

            admin_user = os.environ.get("NETPROFILER_ADMIN_USER", "admin")
            custom_pw = os.environ.get("NETPROFILER_ADMIN_PASSWORD")
            admin_pw = custom_pw if custom_pw else "NetProfiler!2026"
            must_change = 0 if custom_pw else 1
            conn.execute(
                """
                INSERT INTO users (username, display_name, email, password_hash, role, is_active, must_change_password, created_at)
                VALUES (?, ?, ?, ?, 'admin', 1, ?, ?)
                """,
                (
                    admin_user,
                    "Administrateur",
                    "admin@netprofiler.local",
                    hash_password(admin_pw),
                    must_change,
                    now_iso,
                ),
            )

        # Seed realistic network scan sessions if database has no scans yet
        if seed_demo:
            scan_count = conn.execute("SELECT COUNT(*) AS c FROM scan_sessions").fetchone()["c"]
            if scan_count == 0:
                _seed_demo_scans(conn)


def _seed_demo_scans(conn: sqlite3.Connection) -> None:
    """Populate 3 realistic historical scan sessions with deep port profiling metadata."""
    now = datetime.now(timezone.utc)
    t_old = (now - timedelta(hours=3)).isoformat()
    t_prev = (now - timedelta(hours=1)).isoformat()
    t_now = (now - timedelta(minutes=6)).isoformat()
    first_week = (now - timedelta(days=12)).isoformat()
    first_3d = (now - timedelta(days=3)).isoformat()

    base_assets: list[dict[str, Any]] = [
        {
            "ip": "192.168.10.1",
            "mac": "74:AC:B9:40:11:01",
            "hostname": "gw-core.lan",
            "vendor": "Ubiquiti Networks",
            "os": "UniFi OS 3.2 (Linux 5.15)",
            "device_type": "router",
            "latency_ms": 0.4,
            "first_seen": first_week,
            "ports": [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "service": "ssh",
                    "product": "Dropbear sshd",
                    "version": "2022.83",
                    "extrainfo": "protocol 2.0",
                    "cpe": "cpe:/a:matt_johnston:dropbear_ssh_server:2022.83",
                    "banner": "SSH-2.0-dropbear_2022.83",
                    "script_output": json.dumps({
                        "ssh-hostkey": "ED25519 SHA256:8xJ3mK...a91Q",
                        "ssh-auth-methods": "publickey, password",
                    }),
                    "risk_level": "medium",
                },
                {
                    "port": 53,
                    "protocol": "tcp",
                    "service": "domain",
                    "product": "dnsmasq",
                    "version": "2.89",
                    "extrainfo": "DNS forwarding",
                    "cpe": "cpe:/a:thekelleys:dnsmasq:2.89",
                    "banner": "dnsmasq-2.89",
                    "script_output": json.dumps({
                        "dns-nsid": "bind.version: dnsmasq-2.89",
                        "dns-recursion": "enabled (LAN only)",
                    }),
                    "risk_level": "low",
                },
                {
                    "port": 443,
                    "protocol": "tcp",
                    "service": "https",
                    "product": "nginx",
                    "version": "1.24.0",
                    "extrainfo": "UniFi Management UI",
                    "cpe": "cpe:/a:igor_sysoev:nginx:1.24.0",
                    "banner": "HTTP/1.1 200 OK | Server: nginx/1.24.0",
                    "script_output": json.dumps({
                        "http-title": "UniFi OS — Passerelle Principale",
                        "ssl-cert": "CN=gw-core.lan, Valid until 2027-06-15, TLSv1.3",
                    }),
                    "risk_level": "low",
                },
            ],
        },
        {
            "ip": "192.168.10.2",
            "mac": "00:1E:67:8A:22:02",
            "hostname": "sw-distrib-01.lan",
            "vendor": "Cisco Systems",
            "os": "Cisco IOS XE 17.9",
            "device_type": "switch",
            "latency_ms": 0.7,
            "first_seen": first_week,
            "ports": [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "service": "ssh",
                    "product": "Cisco SSH",
                    "version": "2.0",
                    "extrainfo": "protocol 2.0",
                    "cpe": "cpe:/o:cisco:ios_xe:17.9",
                    "banner": "SSH-2.0-Cisco-1.25",
                    "script_output": json.dumps({
                        "ssh2-enum-algos": "aes256-gcm, chacha20-poly1305",
                    }),
                    "risk_level": "low",
                },
                {
                    "port": 161,
                    "protocol": "udp",
                    "service": "snmp",
                    "product": "SNMPv3 server",
                    "version": "v3",
                    "extrainfo": "authPriv enabled",
                    "cpe": "cpe:/o:cisco:ios_xe:17.9",
                    "banner": "SNMPv3 EngineID 800000090300001E678A2202",
                    "script_output": json.dumps({
                        "snmp-info": "sysDescr: Cisco Catalyst C9200L-24P-4G",
                    }),
                    "risk_level": "low",
                },
            ],
        },
        {
            "ip": "192.168.10.10",
            "mac": "52:54:00:A1:10:10",
            "hostname": "srv-web-prod.lan",
            "vendor": "QEMU / KVM Virtual NIC",
            "os": "Ubuntu 24.04 LTS (Linux 6.8)",
            "device_type": "server",
            "latency_ms": 1.1,
            "first_seen": first_week,
            "ports": [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "9.6p1",
                    "extrainfo": "Ubuntu Linux; protocol 2.0",
                    "cpe": "cpe:/a:openbsd:openssh:9.6p1",
                    "banner": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
                    "script_output": json.dumps({
                        "ssh-hostkey": "ED25519 SHA256:k9Lm2p...4vRx",
                        "ssh-auth-methods": "publickey only",
                    }),
                    "risk_level": "low",
                },
                {
                    "port": 80,
                    "protocol": "tcp",
                    "service": "http",
                    "product": "nginx",
                    "version": "1.24.0",
                    "extrainfo": "Redirection HTTPS 301",
                    "cpe": "cpe:/a:igor_sysoev:nginx:1.24.0",
                    "banner": "HTTP/1.1 301 Moved Permanently | Location: https://srv-web-prod.lan/",
                    "script_output": json.dumps({
                        "http-server-header": "nginx/1.24.0 (Ubuntu)",
                        "http-headers": "Strict-Transport-Security: max-age=31536000",
                    }),
                    "risk_level": "low",
                },
                {
                    "port": 443,
                    "protocol": "tcp",
                    "service": "https",
                    "product": "nginx",
                    "version": "1.24.0",
                    "extrainfo": "Reverse proxy + HTTP/2",
                    "cpe": "cpe:/a:igor_sysoev:nginx:1.24.0",
                    "banner": "HTTP/2 200 | server: nginx/1.24.0",
                    "script_output": json.dumps({
                        "http-title": "Portail Interne — Production",
                        "ssl-cert": "CN=*.lan, Let's Encrypt Internal CA, TLS 1.3",
                        "ssl-enum-ciphers": "TLS_AES_256_GCM_SHA384 (A+)",
                    }),
                    "risk_level": "low",
                },
                {
                    "port": 8080,
                    "protocol": "tcp",
                    "service": "http-proxy",
                    "product": "Uvicorn / FastAPI",
                    "version": "0.30.6",
                    "extrainfo": "API Debug exposée sans TLS",
                    "cpe": "cpe:/a:uvicorn:uvicorn:0.30.6",
                    "banner": "HTTP/1.1 200 OK | server: uvicorn",
                    "script_output": json.dumps({
                        "http-title": "Internal API — Swagger UI",
                        "security-note": "Interface API en clair sur le LAN",
                    }),
                    "risk_level": "medium",
                    "only_in_latest": True,
                },
            ],
        },
        {
            "ip": "192.168.10.12",
            "mac": "52:54:00:A1:10:12",
            "hostname": "srv-db-01.lan",
            "vendor": "QEMU / KVM Virtual NIC",
            "os": "Debian 12 Bookworm (Linux 6.1)",
            "device_type": "database",
            "latency_ms": 1.3,
            "first_seen": first_week,
            "ports": [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "9.2p1",
                    "extrainfo": "Debian 2+deb12u3",
                    "cpe": "cpe:/a:openbsd:openssh:9.2p1",
                    "banner": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
                    "script_output": json.dumps({
                        "ssh-auth-methods": "publickey",
                    }),
                    "risk_level": "low",
                },
                {
                    "port": 5432,
                    "protocol": "tcp",
                    "service": "postgresql",
                    "product": "PostgreSQL DB",
                    "version": "16.4",
                    "extrainfo": "SSL requis, scram-sha-256",
                    "cpe": "cpe:/a:postgresql:postgresql:16.4",
                    "banner": "PostgreSQL 16.4 (Debian 16.4-1.pgdg120+1)",
                    "script_output": json.dumps({
                        "ssl-cert": "CN=srv-db-01.lan, TLSv1.3",
                        "pg-auth": "scram-sha-256 enforced",
                    }),
                    "risk_level": "medium",
                },
                {
                    "port": 6379,
                    "protocol": "tcp",
                    "service": "redis",
                    "product": "Redis key-value store",
                    "version": "7.2.5",
                    "extrainfo": "Exposé sur 0.0.0.0 — authentification ACL",
                    "cpe": "cpe:/a:redis:redis:7.2.5",
                    "banner": "-NOAUTH Authentication required.",
                    "script_output": json.dumps({
                        "redis-info": "Protected mode active; AUTH required",
                        "security-note": "Recommandation : restreindre Redis au VLAN applicatif",
                    }),
                    "risk_level": "high",
                    "only_in_latest": True,
                },
            ],
        },
        {
            "ip": "192.168.10.20",
            "mac": "00:11:32:D4:55:20",
            "hostname": "nas-vault.lan",
            "vendor": "Synology Incorporated",
            "os": "Synology DSM 7.2 (Linux 4.4)",
            "device_type": "storage",
            "latency_ms": 1.6,
            "first_seen": first_week,
            "ports": [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "8.2p1",
                    "extrainfo": "Synology DSM",
                    "cpe": "cpe:/a:openbsd:openssh:8.2p1",
                    "banner": "SSH-2.0-OpenSSH_8.2p1",
                    "script_output": json.dumps({"ssh-auth-methods": "publickey, password"}),
                    "risk_level": "low",
                },
                {
                    "port": 445,
                    "protocol": "tcp",
                    "service": "microsoft-ds",
                    "product": "Samba smbd",
                    "version": "4.15.13",
                    "extrainfo": "SMBv3.1.1 signing enabled",
                    "cpe": "cpe:/a:samba:samba:4.15.13",
                    "banner": "SMB 3.1.1 | Workgroup: CORP-LAN",
                    "script_output": json.dumps({
                        "smb2-security-mode": "Message signing enabled and required",
                        "smb-shares": "backups, media, engineering",
                    }),
                    "risk_level": "medium",
                },
                {
                    "port": 5001,
                    "protocol": "tcp",
                    "service": "https",
                    "product": "Synology DSM WebUI",
                    "version": "7.2.1",
                    "extrainfo": "Portail d'administration HTTPS",
                    "cpe": "cpe:/o:synology:diskstation_manager:7.2.1",
                    "banner": "HTTP/1.1 200 OK | Server: nginx",
                    "script_output": json.dumps({
                        "http-title": "nas-vault — Synology DiskStation",
                        "ssl-cert": "CN=nas-vault.lan",
                    }),
                    "risk_level": "low",
                },
            ],
        },
        {
            "ip": "192.168.10.25",
            "mac": "A8:A1:59:3B:77:25",
            "hostname": "pve-node-01.lan",
            "vendor": "ASRock / Intel Corp.",
            "os": "Proxmox VE 8.2 (Debian 12 / Linux 6.8)",
            "device_type": "server",
            "latency_ms": 0.9,
            "first_seen": first_week,
            "ports": [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "9.2p1",
                    "extrainfo": "Debian Linux",
                    "cpe": "cpe:/a:openbsd:openssh:9.2p1",
                    "banner": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
                    "script_output": json.dumps({"ssh-auth-methods": "publickey"}),
                    "risk_level": "low",
                },
                {
                    "port": 8006,
                    "protocol": "tcp",
                    "service": "https",
                    "product": "Proxmox Virtual Environment",
                    "version": "8.2.4",
                    "extrainfo": "pveproxy HTTPS API & Console",
                    "cpe": "cpe:/a:proxmox:virtual_environment:8.2.4",
                    "banner": "HTTP/1.1 200 OK | Server: pve-api-daemon/3.0",
                    "script_output": json.dumps({
                        "http-title": "pve-node-01 — Proxmox Virtual Environment",
                        "ssl-cert": "CN=pve-node-01.lan, Self-signed",
                    }),
                    "risk_level": "medium",
                },
            ],
        },
        {
            "ip": "192.168.10.30",
            "mac": "DC:A6:32:91:04:30",
            "hostname": "dns-pihole.lan",
            "vendor": "Raspberry Pi Trading Ltd",
            "os": "Raspberry Pi OS 12 (ARM64 Linux 6.6)",
            "device_type": "server",
            "latency_ms": 1.4,
            "first_seen": first_week,
            "ports": [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "9.2p1",
                    "extrainfo": "Raspbian",
                    "cpe": "cpe:/a:openbsd:openssh:9.2p1",
                    "banner": "SSH-2.0-OpenSSH_9.2p1 Raspbian-2+deb12u2",
                    "script_output": json.dumps({"ssh-auth-methods": "publickey"}),
                    "risk_level": "low",
                },
                {
                    "port": 53,
                    "protocol": "tcp",
                    "service": "domain",
                    "product": "Pi-hole FTL",
                    "version": "5.25.2",
                    "extrainfo": "DNS Sinkhole & Local Resolver",
                    "cpe": "cpe:/a:pi-hole:ftl:5.25.2",
                    "banner": "FTL-dnsmasq 5.25.2",
                    "script_output": json.dumps({"dns-recursion": "enabled"}),
                    "risk_level": "low",
                },
                {
                    "port": 80,
                    "protocol": "tcp",
                    "service": "http",
                    "product": "lighttpd",
                    "version": "1.4.69",
                    "extrainfo": "Interface admin Pi-hole",
                    "cpe": "cpe:/a:lighttpd:lighttpd:1.4.69",
                    "banner": "HTTP/1.1 200 OK | Server: lighttpd/1.4.69",
                    "script_output": json.dumps({"http-title": "Pi-hole Admin Console"}),
                    "risk_level": "low",
                },
            ],
        },
        {
            "ip": "192.168.10.50",
            "mac": "3C:7C:3F:19:C2:50",
            "hostname": "wkst-dev-01.lan",
            "vendor": "ASUSTek Computer Inc.",
            "os": "Windows 11 Pro 23H2",
            "device_type": "workstation",
            "latency_ms": 2.1,
            "first_seen": first_3d,
            "ports": [
                {
                    "port": 3389,
                    "protocol": "tcp",
                    "service": "ms-wbt-server",
                    "product": "Microsoft Terminal Services",
                    "version": "RDP 10.0",
                    "extrainfo": "NLA activé",
                    "cpe": "cpe:/o:microsoft:windows_11:23h2",
                    "banner": "RDP NLA / CredSSP",
                    "script_output": json.dumps({
                        "rdp-ntlm-info": "Target: WKST-DEV-01, OS Build 22631",
                        "security-note": "RDP exposé sur le LAN — limiter via pare-feu hôte",
                    }),
                    "risk_level": "medium",
                },
            ],
        },
        {
            "ip": "192.168.10.65",
            "mac": "F4:39:09:4E:81:65",
            "hostname": "macbook-ops.lan",
            "vendor": "Apple, Inc.",
            "os": "macOS 15 Sequoia",
            "device_type": "workstation",
            "latency_ms": 3.8,
            "first_seen": first_3d,
            "ports": [],
        },
        {
            "ip": "192.168.10.80",
            "mac": "10:E7:C6:22:09:80",
            "hostname": "prt-office-hp.lan",
            "vendor": "HP Inc.",
            "os": "HP FutureSmart Firmware 5.7",
            "device_type": "printer",
            "latency_ms": 2.9,
            "first_seen": first_week,
            "ports": [
                {
                    "port": 631,
                    "protocol": "tcp",
                    "service": "ipp",
                    "product": "HP LaserJet IPP",
                    "version": "2.0",
                    "extrainfo": "AirPrint / CUPS",
                    "cpe": "cpe:/h:hp:laserjet_pro_m404dn:-",
                    "banner": "HTTP/1.1 200 OK | Server: HP-ChaiSOE/1.0",
                    "script_output": json.dumps({"http-title": "HP LaserJet Pro M404dn"}),
                    "risk_level": "low",
                },
                {
                    "port": 9100,
                    "protocol": "tcp",
                    "service": "jetdirect",
                    "product": "HP JetDirect Raw Print",
                    "version": "",
                    "extrainfo": "Impression brute TCP sans authentification",
                    "cpe": "cpe:/h:hp:jetdirect:-",
                    "banner": "HP JetDirect Raw Socket",
                    "script_output": json.dumps({
                        "security-note": "Port 9100 ouvert sans auth — segmenter sur VLAN imprimantes",
                    }),
                    "risk_level": "medium",
                },
            ],
        },
        {
            "ip": "192.168.10.91",
            "mac": "AC:CC:8E:7F:14:91",
            "hostname": "cam-entree-01.lan",
            "vendor": "Axis Communications AB",
            "os": "AXIS OS 11.11 (Embedded Linux)",
            "device_type": "camera",
            "latency_ms": 4.2,
            "first_seen": first_week,
            "ports": [
                {
                    "port": 554,
                    "protocol": "tcp",
                    "service": "rtsp",
                    "product": "Axis RTSP Stream",
                    "version": "1.0",
                    "extrainfo": "Digest Auth requis",
                    "cpe": "cpe:/o:axis:axis_os:11.11",
                    "banner": "RTSP/1.0 401 Unauthorized | WWW-Authenticate: Digest",
                    "script_output": json.dumps({"rtsp-methods": "DESCRIBE, SETUP, PLAY, TEARDOWN"}),
                    "risk_level": "low",
                },
                {
                    "port": 23,
                    "protocol": "tcp",
                    "service": "telnet",
                    "product": "BusyBox telnetd",
                    "version": "1.35",
                    "extrainfo": "Protocole en clair détecté !",
                    "cpe": "cpe:/a:busybox:busybox:1.35",
                    "banner": "AXIS Maintenance Console login:",
                    "script_output": json.dumps({
                        "security-note": "CRITIQUE : Telnet actif en clair — désactiver immédiatement",
                    }),
                    "risk_level": "high",
                    "only_in_latest": True,
                },
            ],
        },
    ]

    sessions_spec = [
        (t_old, 9, 41.2, "Scan planifié automatique", False, False),
        (t_prev, 10, 44.8, "Scan planifié automatique", True, False),
        (t_now, 11, 47.5, "Scan complet avec profilage NSE", True, True),
    ]

    for scan_time, host_limit, duration, notes, include_macbook, include_latest_ports in sessions_spec:
        assets_slice = [
            a for a in base_assets
            if include_macbook or a["ip"] != "192.168.10.65"
        ][:host_limit]
        cur = conn.execute(
            """
            INSERT INTO scan_sessions (scan_time, subnet, hosts_up, duration_sec, scanner_notes)
            VALUES (?, ?, ?, ?, ?)
            """,
            (scan_time, "192.168.10.0/24", len(assets_slice), duration, notes),
        )
        session_id = cur.lastrowid

        for asset in assets_slice:
            dev_cur = conn.execute(
                """
                INSERT INTO devices (session_id, ip, mac, hostname, vendor, os, device_type, latency_ms, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    asset["ip"],
                    asset["mac"],
                    asset["hostname"],
                    asset["vendor"],
                    asset["os"],
                    asset["device_type"],
                    asset["latency_ms"],
                    asset["first_seen"],
                    scan_time,
                ),
            )
            device_id = dev_cur.lastrowid

            for p in asset["ports"]:
                if p.get("only_in_latest") and not include_latest_ports:
                    continue
                is_new = 1 if (p.get("only_in_latest") and include_latest_ports) else 0
                conn.execute(
                    """
                    INSERT INTO ports (
                        device_id, port, protocol, state, service, product, version,
                        extrainfo, cpe, banner, script_output, risk_level, is_new
                    )
                    VALUES (?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        device_id,
                        p["port"],
                        p["protocol"],
                        p["service"],
                        p["product"],
                        p["version"],
                        p["extrainfo"],
                        p["cpe"],
                        p["banner"],
                        p["script_output"],
                        p["risk_level"],
                        is_new,
                    ),
                )


def get_config_all() -> dict[str, str]:
    with get_conn() as conn:
        rows = conn.execute("SELECT key, value FROM app_config").fetchall()
    result = dict(DEFAULT_CONFIG)
    for r in rows:
        result[r["key"]] = r["value"]
    return result


def get_config_value(key: str, default: Optional[str] = None) -> Optional[str]:
    with get_conn() as conn:
        row = conn.execute("SELECT value FROM app_config WHERE key = ?", (key,)).fetchone()
    if row:
        return row["value"]
    return DEFAULT_CONFIG.get(key, default)


def update_config(updates: dict[str, Any]) -> dict[str, str]:
    allowed = set(DEFAULT_CONFIG.keys())
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        for k, v in updates.items():
            if k not in allowed:
                continue
            str_val = "true" if v is True else "false" if v is False else str(v)
            conn.execute(
                """
                INSERT INTO app_config (key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
                """,
                (k, str_val, now_iso),
            )
    return get_config_all()


def list_scan_sessions(limit: int = 50) -> list[dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, scan_time, subnet, hosts_up, duration_sec, scanner_notes
            FROM scan_sessions
            ORDER BY scan_time DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def _serialize_port(row: sqlite3.Row) -> dict[str, Any]:
    scripts_parsed: dict[str, Any] = {}
    raw_scripts = row["script_output"] or ""
    if raw_scripts:
        try:
            scripts_parsed = json.loads(raw_scripts)
        except json.JSONDecodeError:
            scripts_parsed = {"output": raw_scripts}
    return {
        "id": row["id"],
        "port": row["port"],
        "protocol": row["protocol"],
        "state": row["state"],
        "service": row["service"],
        "product": row["product"],
        "version": row["version"],
        "extrainfo": row["extrainfo"],
        "cpe": row["cpe"],
        "banner": row["banner"],
        "scripts": scripts_parsed,
        "risk_level": row["risk_level"],
        "is_new": bool(row["is_new"]),
    }


def get_scan_data(session_id: Optional[int] = None) -> dict[str, Any]:
    """Return scan session metadata, KPI stats, and devices with their exposed ports."""
    with get_conn() as conn:
        if session_id is None:
            session_row = conn.execute(
                "SELECT * FROM scan_sessions ORDER BY scan_time DESC, id DESC LIMIT 1"
            ).fetchone()
        else:
            session_row = conn.execute(
                "SELECT * FROM scan_sessions WHERE id = ?", (session_id,)
            ).fetchone()

        if not session_row:
            return {
                "session": None,
                "stats": {
                    "total_devices": 0,
                    "total_ports": 0,
                    "unique_services": 0,
                    "new_ports_count": 0,
                    "high_risk_ports": 0,
                },
                "devices": [],
            }

        device_rows = conn.execute(
            "SELECT * FROM devices WHERE session_id = ? ORDER BY ip ASC",
            (session_row["id"],),
        ).fetchall()

        # Sort numerically by IPv4 octets when possible
        def ip_sort_key(row: sqlite3.Row) -> tuple[int, ...]:
            try:
                return tuple(int(part) for part in row["ip"].split("."))
            except ValueError:
                return (999, 999, 999, 999)

        device_rows = sorted(device_rows, key=ip_sort_key)

        device_ids = [d["id"] for d in device_rows]
        ports_by_device: dict[int, list[dict[str, Any]]] = {did: [] for did in device_ids}

        if device_ids:
            placeholders = ",".join("?" for _ in device_ids)
            port_rows = conn.execute(
                f"SELECT * FROM ports WHERE device_id IN ({placeholders}) ORDER BY port ASC, protocol ASC",
                device_ids,
            ).fetchall()
            for pr in port_rows:
                ports_by_device[pr["device_id"]].append(_serialize_port(pr))

        devices_out: list[dict[str, Any]] = []
        total_ports = 0
        new_ports_count = 0
        high_risk_ports = 0
        services_set: set[str] = set()

        for d in device_rows:
            d_ports = ports_by_device[d["id"]]
            total_ports += len(d_ports)
            for p in d_ports:
                if p["service"]:
                    services_set.add(p["service"].lower())
                if p["is_new"]:
                    new_ports_count += 1
                if p["risk_level"] == "high":
                    high_risk_ports += 1

            devices_out.append(
                {
                    "id": d["id"],
                    "ip": d["ip"],
                    "mac": d["mac"],
                    "hostname": d["hostname"],
                    "vendor": d["vendor"],
                    "os": d["os"],
                    "device_type": d["device_type"],
                    "latency_ms": d["latency_ms"],
                    "first_seen": d["first_seen"],
                    "last_seen": d["last_seen"],
                    "ports": d_ports,
                }
            )

        return {
            "session": dict(session_row),
            "stats": {
                "total_devices": len(devices_out),
                "total_ports": total_ports,
                "unique_services": len(services_set),
                "new_ports_count": new_ports_count,
                "high_risk_ports": high_risk_ports,
            },
            "devices": devices_out,
        }


def get_asset_detail(ip: str, session_id: Optional[int] = None) -> Optional[dict[str, Any]]:
    """Return full profiling details for a single asset plus its historical timeline across scans."""
    with get_conn() as conn:
        if session_id is None:
            session_row = conn.execute(
                "SELECT * FROM scan_sessions ORDER BY scan_time DESC, id DESC LIMIT 1"
            ).fetchone()
        else:
            session_row = conn.execute(
                "SELECT * FROM scan_sessions WHERE id = ?", (session_id,)
            ).fetchone()

        if not session_row:
            return None

        dev_row = conn.execute(
            "SELECT * FROM devices WHERE session_id = ? AND ip = ?",
            (session_row["id"], ip),
        ).fetchone()
        if not dev_row:
            return None

        port_rows = conn.execute(
            "SELECT * FROM ports WHERE device_id = ? ORDER BY port ASC, protocol ASC",
            (dev_row["id"],),
        ).fetchall()
        ports = [_serialize_port(pr) for pr in port_rows]

        history_rows = conn.execute(
            """
            SELECT s.id AS session_id, s.scan_time, s.subnet,
                   COUNT(p.id) AS port_count,
                   SUM(CASE WHEN p.is_new = 1 THEN 1 ELSE 0 END) AS new_ports
            FROM devices d
            JOIN scan_sessions s ON s.id = d.session_id
            LEFT JOIN ports p ON p.device_id = d.id
            WHERE d.ip = ?
            GROUP BY s.id
            ORDER BY s.scan_time DESC, s.id DESC
            LIMIT 12
            """,
            (ip,),
        ).fetchall()

        return {
            "session": dict(session_row),
            "asset": {
                "id": dev_row["id"],
                "ip": dev_row["ip"],
                "mac": dev_row["mac"],
                "hostname": dev_row["hostname"],
                "vendor": dev_row["vendor"],
                "os": dev_row["os"],
                "device_type": dev_row["device_type"],
                "latency_ms": dev_row["latency_ms"],
                "first_seen": dev_row["first_seen"],
                "last_seen": dev_row["last_seen"],
                "ports": ports,
            },
            "history": [
                {
                    "session_id": hr["session_id"],
                    "scan_time": hr["scan_time"],
                    "subnet": hr["subnet"],
                    "port_count": hr["port_count"],
                    "new_ports": hr["new_ports"] or 0,
                }
                for hr in history_rows
            ],
        }


def trigger_simulated_scan() -> dict[str, Any]:
    """Duplicate the latest scan snapshot with a fresh timestamp to simulate a new scan run."""
    with get_conn() as conn:
        latest = conn.execute(
            "SELECT * FROM scan_sessions ORDER BY scan_time DESC, id DESC LIMIT 1"
        ).fetchone()
        now_iso = datetime.now(timezone.utc).isoformat()
        subnet = get_config_value("target_subnet", "192.168.10.0/24") or "192.168.10.0/24"

        if not latest:
            _seed_demo_scans(conn)
            latest = conn.execute(
                "SELECT * FROM scan_sessions ORDER BY scan_time DESC, id DESC LIMIT 1"
            ).fetchone()
            return dict(latest)

        devices = conn.execute(
            "SELECT * FROM devices WHERE session_id = ?", (latest["id"],)
        ).fetchall()

        cur = conn.execute(
            """
            INSERT INTO scan_sessions (scan_time, subnet, hosts_up, duration_sec, scanner_notes)
            VALUES (?, ?, ?, ?, ?)
            """,
            (now_iso, subnet, len(devices), 39.4, "Scan manuel déclenché depuis l'interface"),
        )
        new_session_id = cur.lastrowid

        for d in devices:
            d_cur = conn.execute(
                """
                INSERT INTO devices (session_id, ip, mac, hostname, vendor, os, device_type, latency_ms, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_session_id,
                    d["ip"],
                    d["mac"],
                    d["hostname"],
                    d["vendor"],
                    d["os"],
                    d["device_type"],
                    d["latency_ms"],
                    d["first_seen"],
                    now_iso,
                ),
            )
            new_dev_id = d_cur.lastrowid
            ports = conn.execute(
                "SELECT * FROM ports WHERE device_id = ?", (d["id"],)
            ).fetchall()
            for p in ports:
                conn.execute(
                    """
                    INSERT INTO ports (
                        device_id, port, protocol, state, service, product, version,
                        extrainfo, cpe, banner, script_output, risk_level, is_new
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                    """,
                    (
                        new_dev_id,
                        p["port"],
                        p["protocol"],
                        p["state"],
                        p["service"],
                        p["product"],
                        p["version"],
                        p["extrainfo"],
                        p["cpe"],
                        p["banner"],
                        p["script_output"],
                        p["risk_level"],
                    ),
                )

        row = conn.execute(
            "SELECT * FROM scan_sessions WHERE id = ?", (new_session_id,)
        ).fetchone()
        return dict(row)
