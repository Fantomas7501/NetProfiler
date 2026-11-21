"""SQLite persistence layer, schema initialization, multi-network support, and seed data for NetProfiler."""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import sqlite3
import subprocess
import xml.etree.ElementTree as ET
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


def normalize_cidr(cidr: str) -> str:
    """Validate and normalize an IPv4/IPv6 CIDR string (e.g. '192.168.55.10/24' -> '192.168.55.0/24')."""
    net = ipaddress.ip_network(cidr.strip(), strict=False)
    return str(net)


def init_db(seed_demo: bool = True) -> None:
    """Initialize all database tables, run safe migrations, seed default admin and optional multi-network demo data."""
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

            CREATE TABLE IF NOT EXISTS networks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                cidr TEXT NOT NULL UNIQUE,
                description TEXT NOT NULL DEFAULT '',
                scan_interval_minutes INTEGER NOT NULL DEFAULT 60,
                port_range TEXT NOT NULL DEFAULT 'top-1000',
                nmap_flags TEXT NOT NULL DEFAULT '-sV -O --version-intensity 5 -T4',
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scan_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                network_id INTEGER REFERENCES networks(id) ON DELETE SET NULL,
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

        # Safe migration for existing databases created prior to multi-network support
        cols = {row["name"] for row in conn.execute("PRAGMA table_info(scan_sessions)").fetchall()}
        if "network_id" not in cols:
            conn.execute("ALTER TABLE scan_sessions ADD COLUMN network_id INTEGER REFERENCES networks(id) ON DELETE SET NULL")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_sessions_network ON scan_sessions(network_id, scan_time DESC)")

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

        # Backfill networks from any pre-existing scan_sessions without network_id
        orphan_subnets = conn.execute(
            "SELECT DISTINCT subnet FROM scan_sessions WHERE network_id IS NULL AND subnet != ''"
        ).fetchall()
        for row in orphan_subnets:
            subnet = row["subnet"]
            net_row = conn.execute("SELECT id FROM networks WHERE cidr = ?", (subnet,)).fetchone()
            if not net_row:
                cur = conn.execute(
                    """
                    INSERT INTO networks (name, cidr, description, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (f"Réseau {subnet}", subnet, "Importé depuis l'historique existant", now_iso, now_iso),
                )
                net_id = cur.lastrowid
            else:
                net_id = net_row["id"]
            conn.execute(
                "UPDATE scan_sessions SET network_id = ? WHERE subnet = ? AND network_id IS NULL",
                (net_id, subnet),
            )

        # Seed realistic multi-network scan sessions if database has no scans and no networks yet
        if seed_demo:
            scan_count = conn.execute("SELECT COUNT(*) AS c FROM scan_sessions").fetchone()["c"]
            net_count = conn.execute("SELECT COUNT(*) AS c FROM networks").fetchone()["c"]
            if scan_count == 0 and net_count == 0:
                _seed_demo_networks_and_scans(conn)


def _insert_session_with_assets(
    conn: sqlite3.Connection,
    network_id: int,
    subnet: str,
    scan_time: str,
    duration_sec: float,
    notes: str,
    assets: list[dict[str, Any]],
    include_latest_ports: bool,
) -> int:
    cur = conn.execute(
        """
        INSERT INTO scan_sessions (network_id, scan_time, subnet, hosts_up, duration_sec, scanner_notes)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (network_id, scan_time, subnet, len(assets), duration_sec, notes),
    )
    session_id = cur.lastrowid

    for asset in assets:
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
    return session_id


def _seed_demo_networks_and_scans(conn: sqlite3.Connection) -> None:
    """Populate 3 realistic networks with historical scan sessions and deep port profiling metadata."""
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    t_old = (now - timedelta(hours=3)).isoformat()
    t_prev = (now - timedelta(hours=1)).isoformat()
    t_now = (now - timedelta(minutes=6)).isoformat()
    first_week = (now - timedelta(days=12)).isoformat()
    first_3d = (now - timedelta(days=3)).isoformat()

    # ------------------------------------------------------------------
    # Network 1: LAN Bureaux & Infrastructure (192.168.10.0/24)
    # ------------------------------------------------------------------
    net1_id = conn.execute(
        """
        INSERT INTO networks (name, cidr, description, scan_interval_minutes, port_range, nmap_flags, enabled, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
        """,
        (
            "LAN Bureaux & Infra",
            "192.168.10.0/24",
            "Réseau interne principal : passerelle, serveurs, NAS, postes de travail et périphériques.",
            60,
            "top-1000",
            "-sV -O --version-intensity 5 -T4",
            now_iso,
            now_iso,
        ),
    ).lastrowid

    lan_assets: list[dict[str, Any]] = [
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
                    "script_output": json.dumps({"ssh2-enum-algos": "aes256-gcm, chacha20-poly1305"}),
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
                    "script_output": json.dumps({"snmp-info": "sysDescr: Cisco Catalyst C9200L-24P-4G"}),
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
                    "script_output": json.dumps({"ssh-auth-methods": "publickey"}),
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

    _insert_session_with_assets(
        conn, net1_id, "192.168.10.0/24", t_old, 41.2, "Scan planifié automatique",
        [a for a in lan_assets if a["ip"] != "192.168.10.65"][:9], False,
    )
    _insert_session_with_assets(
        conn, net1_id, "192.168.10.0/24", t_prev, 44.8, "Scan planifié automatique",
        lan_assets[:10], False,
    )
    _insert_session_with_assets(
        conn, net1_id, "192.168.10.0/24", t_now, 47.5, "Scan complet avec profilage NSE",
        lan_assets, True,
    )

    # ------------------------------------------------------------------
    # Network 2: DMZ Serveurs Web (10.20.0.0/24)
    # ------------------------------------------------------------------
    net2_id = conn.execute(
        """
        INSERT INTO networks (name, cidr, description, scan_interval_minutes, port_range, nmap_flags, enabled, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
        """,
        (
            "DMZ Serveurs Web",
            "10.20.0.0/24",
            "Zone démilitarisée hébergeant le reverse proxy, le portail public, le relais SMTP et la supervision.",
            30,
            "top-1000",
            "-sV -sC -T4",
            now_iso,
            now_iso,
        ),
    ).lastrowid

    dmz_assets: list[dict[str, Any]] = [
        {
            "ip": "10.20.0.1",
            "mac": "00:0D:B9:55:20:01",
            "hostname": "fw-dmz.corp",
            "vendor": "OPNsense / PC Engines",
            "os": "FreeBSD 14.1 (OPNsense 24.7)",
            "device_type": "router",
            "latency_ms": 0.5,
            "first_seen": first_week,
            "ports": [
                {
                    "port": 443,
                    "protocol": "tcp",
                    "service": "https",
                    "product": "lighttpd",
                    "version": "1.4.76",
                    "extrainfo": "OPNsense Admin (VLAN Mgmt)",
                    "cpe": "cpe:/a:lighttpd:lighttpd:1.4.76",
                    "banner": "HTTP/1.1 200 OK | Server: OPNsense",
                    "script_output": json.dumps({"ssl-cert": "CN=fw-dmz.corp, TLSv1.3"}),
                    "risk_level": "low",
                },
            ],
        },
        {
            "ip": "10.20.0.10",
            "mac": "52:54:00:D2:20:10",
            "hostname": "edge-haproxy-01.dmz",
            "vendor": "QEMU / KVM Virtual NIC",
            "os": "Debian 12 Bookworm (Linux 6.1)",
            "device_type": "server",
            "latency_ms": 1.0,
            "first_seen": first_week,
            "ports": [
                {
                    "port": 80,
                    "protocol": "tcp",
                    "service": "http",
                    "product": "HAProxy",
                    "version": "2.8.10",
                    "extrainfo": "HTTP -> HTTPS redirect",
                    "cpe": "cpe:/a:haproxy:haproxy:2.8.10",
                    "banner": "HTTP/1.1 301 Moved Permanently",
                    "script_output": json.dumps({"http-headers": "HSTS enabled"}),
                    "risk_level": "low",
                },
                {
                    "port": 443,
                    "protocol": "tcp",
                    "service": "https",
                    "product": "HAProxy",
                    "version": "2.8.10",
                    "extrainfo": "TLS 1.3 Termination + WAF",
                    "cpe": "cpe:/a:haproxy:haproxy:2.8.10",
                    "banner": "HTTP/2 200 OK",
                    "script_output": json.dumps({"ssl-enum-ciphers": "TLSv1.3 (Grade A+)"}),
                    "risk_level": "low",
                },
                {
                    "port": 8404,
                    "protocol": "tcp",
                    "service": "http",
                    "product": "HAProxy Stats",
                    "version": "2.8.10",
                    "extrainfo": "Tableau de bord métriques Prometheus",
                    "cpe": "cpe:/a:haproxy:haproxy:2.8.10",
                    "banner": "HTTP/1.1 200 OK | HAProxy Statistics Report",
                    "script_output": json.dumps({
                        "security-note": "Page de stats HAProxy accessible sur la DMZ",
                    }),
                    "risk_level": "medium",
                    "only_in_latest": True,
                },
            ],
        },
        {
            "ip": "10.20.0.15",
            "mac": "52:54:00:D2:20:15",
            "hostname": "smtp-relay.dmz",
            "vendor": "QEMU / KVM Virtual NIC",
            "os": "Debian 12 Bookworm (Linux 6.1)",
            "device_type": "server",
            "latency_ms": 1.2,
            "first_seen": first_week,
            "ports": [
                {
                    "port": 25,
                    "protocol": "tcp",
                    "service": "smtp",
                    "product": "Postfix smtpd",
                    "version": "3.7.11",
                    "extrainfo": "STARTTLS requis",
                    "cpe": "cpe:/a:postfix:postfix:3.7.11",
                    "banner": "220 smtp-relay.dmz ESMTP Postfix (Debian/GNU)",
                    "script_output": json.dumps({"smtp-commands": "PIPELINING, SIZE, STARTTLS"}),
                    "risk_level": "low",
                },
                {
                    "port": 587,
                    "protocol": "tcp",
                    "service": "submission",
                    "product": "Postfix smtpd",
                    "version": "3.7.11",
                    "extrainfo": "Authenticated submission",
                    "cpe": "cpe:/a:postfix:postfix:3.7.11",
                    "banner": "220 smtp-relay.dmz ESMTP Postfix",
                    "script_output": json.dumps({"ssl-cert": "CN=smtp-relay.dmz, TLSv1.3"}),
                    "risk_level": "low",
                },
            ],
        },
        {
            "ip": "10.20.0.22",
            "mac": "52:54:00:D2:20:22",
            "hostname": "bastion-ssh.dmz",
            "vendor": "QEMU / KVM Virtual NIC",
            "os": "Ubuntu 24.04 LTS (Linux 6.8)",
            "device_type": "server",
            "latency_ms": 0.9,
            "first_seen": first_week,
            "ports": [
                {
                    "port": 2222,
                    "protocol": "tcp",
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "9.6p1",
                    "extrainfo": "MFA + clé ED25519 obligatoire",
                    "cpe": "cpe:/a:openbsd:openssh:9.6p1",
                    "banner": "SSH-2.0-OpenSSH_9.6p1",
                    "script_output": json.dumps({"ssh-auth-methods": "publickey, keyboard-interactive"}),
                    "risk_level": "low",
                },
            ],
        },
        {
            "ip": "10.20.0.30",
            "mac": "52:54:00:D2:20:30",
            "hostname": "obs-grafana.dmz",
            "vendor": "QEMU / KVM Virtual NIC",
            "os": "Ubuntu 24.04 LTS (Linux 6.8)",
            "device_type": "database",
            "latency_ms": 1.5,
            "first_seen": first_3d,
            "ports": [
                {
                    "port": 3000,
                    "protocol": "tcp",
                    "service": "https",
                    "product": "Grafana",
                    "version": "11.2.0",
                    "extrainfo": "Tableaux de bord supervision",
                    "cpe": "cpe:/a:grafana:grafana:11.2.0",
                    "banner": "HTTP/1.1 200 OK | Grafana v11.2.0",
                    "script_output": json.dumps({"http-title": "Grafana — Observabilité"}),
                    "risk_level": "low",
                },
                {
                    "port": 9090,
                    "protocol": "tcp",
                    "service": "http",
                    "product": "Prometheus",
                    "version": "2.54.1",
                    "extrainfo": "Interface métriques interne",
                    "cpe": "cpe:/a:prometheus:prometheus:2.54.1",
                    "banner": "HTTP/1.1 200 OK | Prometheus Time Series Collection",
                    "script_output": json.dumps({"http-title": "Prometheus Time Series"}),
                    "risk_level": "medium",
                },
            ],
        },
    ]

    _insert_session_with_assets(
        conn, net2_id, "10.20.0.0/24", t_prev, 18.4, "Scan DMZ planifié", dmz_assets, False
    )
    _insert_session_with_assets(
        conn, net2_id, "10.20.0.0/24", t_now, 20.1, "Scan DMZ complet NSE", dmz_assets, True
    )

    # ------------------------------------------------------------------
    # Network 3: VLAN IoT & Sécurité Physique (172.16.40.0/24)
    # ------------------------------------------------------------------
    net3_id = conn.execute(
        """
        INSERT INTO networks (name, cidr, description, scan_interval_minutes, port_range, nmap_flags, enabled, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
        """,
        (
            "VLAN IoT & Caméras",
            "172.16.40.0/24",
            "VLAN isolé dédié aux caméras de surveillance, contrôle d'accès et capteurs salle serveurs.",
            120,
            "top-100",
            "-sV -T4",
            now_iso,
            now_iso,
        ),
    ).lastrowid

    iot_assets: list[dict[str, Any]] = [
        {
            "ip": "172.16.40.1",
            "mac": "74:AC:B9:40:40:01",
            "hostname": "gw-iot.vlan40",
            "vendor": "Ubiquiti Networks",
            "os": "UniFi OS 3.2 (VLAN 40)",
            "device_type": "router",
            "latency_ms": 0.6,
            "first_seen": first_week,
            "ports": [
                {
                    "port": 53,
                    "protocol": "tcp",
                    "service": "domain",
                    "product": "dnsmasq",
                    "version": "2.89",
                    "extrainfo": "DNS restreint VLAN 40",
                    "cpe": "cpe:/a:thekelleys:dnsmasq:2.89",
                    "banner": "dnsmasq-2.89",
                    "script_output": json.dumps({"dns-recursion": "restricted"}),
                    "risk_level": "low",
                },
            ],
        },
        {
            "ip": "172.16.40.11",
            "mac": "AC:CC:8E:99:40:11",
            "hostname": "cam-parking-nord.iot",
            "vendor": "Axis Communications AB",
            "os": "AXIS OS 11.11",
            "device_type": "camera",
            "latency_ms": 3.4,
            "first_seen": first_week,
            "ports": [
                {
                    "port": 443,
                    "protocol": "tcp",
                    "service": "https",
                    "product": "Axis Embedded Web",
                    "version": "11.11",
                    "extrainfo": "TLS 1.2+",
                    "cpe": "cpe:/o:axis:axis_os:11.11",
                    "banner": "HTTP/1.1 200 OK | Axis",
                    "script_output": json.dumps({"http-title": "AXIS P3265-LVE"}),
                    "risk_level": "low",
                },
                {
                    "port": 554,
                    "protocol": "tcp",
                    "service": "rtsp",
                    "product": "Axis RTSP Stream",
                    "version": "1.0",
                    "extrainfo": "Flux H.265 chiffré",
                    "cpe": "cpe:/o:axis:axis_os:11.11",
                    "banner": "RTSP/1.0 401 Unauthorized",
                    "script_output": json.dumps({"rtsp-methods": "DESCRIBE, PLAY, TEARDOWN"}),
                    "risk_level": "low",
                },
            ],
        },
        {
            "ip": "172.16.40.20",
            "mac": "00:04:A3:12:40:20",
            "hostname": "sensor-rack-temp.iot",
            "vendor": "Microchip Technology Inc.",
            "os": "FreeRTOS Embedded",
            "device_type": "unknown",
            "latency_ms": 5.1,
            "first_seen": first_3d,
            "ports": [
                {
                    "port": 1883,
                    "protocol": "tcp",
                    "service": "mqtt",
                    "product": "Mosquitto / MQTT Sensor",
                    "version": "3.1.1",
                    "extrainfo": "MQTT sans TLS détecté",
                    "cpe": "cpe:/a:eclipse:mosquitto:2.0",
                    "banner": "MQTT CONNACK",
                    "script_output": json.dumps({
                        "security-note": "Flux MQTT en clair — migrer vers MQTTS (port 8883)",
                    }),
                    "risk_level": "high",
                    "only_in_latest": True,
                },
            ],
        },
        {
            "ip": "172.16.40.30",
            "mac": "00:17:88:71:40:30",
            "hostname": "badge-ctrl-01.iot",
            "vendor": "HID Global Corp.",
            "os": "Embedded Linux 5.4",
            "device_type": "switch",
            "latency_ms": 2.3,
            "first_seen": first_week,
            "ports": [
                {
                    "port": 443,
                    "protocol": "tcp",
                    "service": "https",
                    "product": "HID VertX Management",
                    "version": "4.2",
                    "extrainfo": "Contrôle d'accès badges",
                    "cpe": "cpe:/h:hid:vertx:-",
                    "banner": "HTTP/1.1 200 OK",
                    "script_output": json.dumps({"ssl-cert": "CN=badge-ctrl-01.iot"}),
                    "risk_level": "low",
                },
            ],
        },
    ]

    _insert_session_with_assets(
        conn, net3_id, "172.16.40.0/24", t_now, 14.6, "Scan VLAN IoT", iot_assets, True
    )


# ---------------------------------------------------------------------------
# Networks CRUD & Aggregated Stats
# ---------------------------------------------------------------------------

def list_networks() -> list[dict[str, Any]]:
    """List all configured networks along with persisted scan & asset counts."""
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT n.*,
                   (SELECT COUNT(*) FROM scan_sessions s WHERE s.network_id = n.id) AS scan_count,
                   (SELECT s.id FROM scan_sessions s WHERE s.network_id = n.id ORDER BY s.scan_time DESC, s.id DESC LIMIT 1) AS last_session_id,
                   (SELECT s.scan_time FROM scan_sessions s WHERE s.network_id = n.id ORDER BY s.scan_time DESC, s.id DESC LIMIT 1) AS last_scan_time,
                   (SELECT s.hosts_up FROM scan_sessions s WHERE s.network_id = n.id ORDER BY s.scan_time DESC, s.id DESC LIMIT 1) AS last_hosts_up
            FROM networks n
            ORDER BY n.id ASC
            """
        ).fetchall()

        results: list[dict[str, Any]] = []
        for r in rows:
            last_sid = r["last_session_id"]
            last_ports = 0
            last_new_ports = 0
            if last_sid is not None:
                p_row = conn.execute(
                    """
                    SELECT COUNT(p.id) AS total_p,
                           SUM(CASE WHEN p.is_new = 1 THEN 1 ELSE 0 END) AS new_p
                    FROM devices d
                    JOIN ports p ON p.device_id = d.id
                    WHERE d.session_id = ?
                    """,
                    (last_sid,),
                ).fetchone()
                last_ports = p_row["total_p"] or 0
                last_new_ports = p_row["new_p"] or 0

            results.append(
                {
                    "id": r["id"],
                    "name": r["name"],
                    "cidr": r["cidr"],
                    "description": r["description"],
                    "scan_interval_minutes": r["scan_interval_minutes"],
                    "port_range": r["port_range"],
                    "nmap_flags": r["nmap_flags"],
                    "enabled": bool(r["enabled"]),
                    "created_at": r["created_at"],
                    "updated_at": r["updated_at"],
                    "scan_count": r["scan_count"] or 0,
                    "last_session_id": last_sid,
                    "last_scan_time": r["last_scan_time"],
                    "last_hosts_up": r["last_hosts_up"] or 0,
                    "last_ports_count": last_ports,
                    "last_new_ports_count": last_new_ports,
                }
            )
        return results


def get_network(network_id: int) -> Optional[dict[str, Any]]:
    for net in list_networks():
        if net["id"] == network_id:
            return net
    return None


def create_network(
    name: str,
    cidr: str,
    description: str = "",
    scan_interval_minutes: int = 60,
    port_range: str = "top-1000",
    nmap_flags: str = "-sV -O --version-intensity 5 -T4",
    enabled: bool = True,
) -> dict[str, Any]:
    norm_cidr = normalize_cidr(cidr)
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO networks (
                name, cidr, description, scan_interval_minutes, port_range, nmap_flags, enabled, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                name.strip(),
                norm_cidr,
                description.strip(),
                scan_interval_minutes,
                port_range.strip() or "top-1000",
                nmap_flags.strip(),
                1 if enabled else 0,
                now_iso,
                now_iso,
            ),
        )
        new_id = cur.lastrowid
        # Re-link any historical sessions matching this CIDR that were previously unlinked
        conn.execute(
            "UPDATE scan_sessions SET network_id = ? WHERE subnet = ? AND network_id IS NULL",
            (new_id, norm_cidr),
        )
    return get_network(new_id)  # type: ignore[return-value]


def update_network(network_id: int, updates: dict[str, Any]) -> Optional[dict[str, Any]]:
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        existing = conn.execute("SELECT * FROM networks WHERE id = ?", (network_id,)).fetchone()
        if not existing:
            return None

        clauses: list[str] = ["updated_at = ?"]
        params: list[Any] = [now_iso]

        if "name" in updates and updates["name"] is not None:
            clauses.append("name = ?")
            params.append(updates["name"].strip())
        if "cidr" in updates and updates["cidr"] is not None:
            clauses.append("cidr = ?")
            params.append(normalize_cidr(updates["cidr"]))
        if "description" in updates and updates["description"] is not None:
            clauses.append("description = ?")
            params.append(updates["description"].strip())
        if "scan_interval_minutes" in updates and updates["scan_interval_minutes"] is not None:
            clauses.append("scan_interval_minutes = ?")
            params.append(int(updates["scan_interval_minutes"]))
        if "port_range" in updates and updates["port_range"] is not None:
            clauses.append("port_range = ?")
            params.append(updates["port_range"].strip())
        if "nmap_flags" in updates and updates["nmap_flags"] is not None:
            clauses.append("nmap_flags = ?")
            params.append(updates["nmap_flags"].strip())
        if "enabled" in updates and updates["enabled"] is not None:
            clauses.append("enabled = ?")
            params.append(1 if updates["enabled"] else 0)

        params.append(network_id)
        conn.execute(f"UPDATE networks SET {', '.join(clauses)} WHERE id = ?", params)

    return get_network(network_id)


def delete_network(network_id: int, purge_history: bool = False) -> bool:
    """Delete a configured network. By default preserves all historical scans and assets in SQLite."""
    with get_conn() as conn:
        existing = conn.execute("SELECT id FROM networks WHERE id = ?", (network_id,)).fetchone()
        if not existing:
            return False
        if purge_history:
            conn.execute("DELETE FROM scan_sessions WHERE network_id = ?", (network_id,))
        conn.execute("DELETE FROM networks WHERE id = ?", (network_id,))
    return True


# ---------------------------------------------------------------------------
# Configuration CRUD
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Scan Sessions & Asset Profiling Queries
# ---------------------------------------------------------------------------

def list_scan_sessions(network_id: Optional[int] = None, limit: int = 50) -> list[dict[str, Any]]:
    with get_conn() as conn:
        if network_id is not None:
            rows = conn.execute(
                """
                SELECT s.id, s.network_id, s.scan_time, s.subnet, s.hosts_up, s.duration_sec, s.scanner_notes,
                       n.name AS network_name
                FROM scan_sessions s
                LEFT JOIN networks n ON n.id = s.network_id
                WHERE s.network_id = ?
                ORDER BY s.scan_time DESC, s.id DESC
                LIMIT ?
                """,
                (network_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT s.id, s.network_id, s.scan_time, s.subnet, s.hosts_up, s.duration_sec, s.scanner_notes,
                       n.name AS network_name
                FROM scan_sessions s
                LEFT JOIN networks n ON n.id = s.network_id
                ORDER BY s.scan_time DESC, s.id DESC
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


def get_scan_data(
    session_id: Optional[int] = None,
    network_id: Optional[int] = None,
) -> dict[str, Any]:
    """Return scan session metadata, KPI stats, and devices with their exposed ports."""
    with get_conn() as conn:
        network_row = None
        if session_id is not None:
            session_row = conn.execute(
                """
                SELECT s.*, n.name AS network_name
                FROM scan_sessions s
                LEFT JOIN networks n ON n.id = s.network_id
                WHERE s.id = ?
                """,
                (session_id,),
            ).fetchone()
            if session_row and session_row["network_id"]:
                network_row = conn.execute(
                    "SELECT id, name, cidr, description, enabled FROM networks WHERE id = ?",
                    (session_row["network_id"],),
                ).fetchone()
        elif network_id is not None:
            network_row = conn.execute(
                "SELECT id, name, cidr, description, enabled FROM networks WHERE id = ?",
                (network_id,),
            ).fetchone()
            session_row = conn.execute(
                """
                SELECT s.*, n.name AS network_name
                FROM scan_sessions s
                LEFT JOIN networks n ON n.id = s.network_id
                WHERE s.network_id = ?
                ORDER BY s.scan_time DESC, s.id DESC
                LIMIT 1
                """,
                (network_id,),
            ).fetchone()
        else:
            session_row = conn.execute(
                """
                SELECT s.*, n.name AS network_name
                FROM scan_sessions s
                LEFT JOIN networks n ON n.id = s.network_id
                ORDER BY s.scan_time DESC, s.id DESC
                LIMIT 1
                """
            ).fetchone()
            if session_row and session_row["network_id"]:
                network_row = conn.execute(
                    "SELECT id, name, cidr, description, enabled FROM networks WHERE id = ?",
                    (session_row["network_id"],),
                ).fetchone()

        if not session_row:
            return {
                "network": dict(network_row) if network_row else None,
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
            "network": dict(network_row) if network_row else None,
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


def get_asset_detail(
    ip: str,
    session_id: Optional[int] = None,
    network_id: Optional[int] = None,
) -> Optional[dict[str, Any]]:
    """Return full profiling details for a single asset plus its historical timeline across scans."""
    with get_conn() as conn:
        if session_id is not None:
            session_row = conn.execute(
                "SELECT * FROM scan_sessions WHERE id = ?", (session_id,)
            ).fetchone()
        elif network_id is not None:
            session_row = conn.execute(
                "SELECT * FROM scan_sessions WHERE network_id = ? ORDER BY scan_time DESC, id DESC LIMIT 1",
                (network_id,),
            ).fetchone()
        else:
            session_row = conn.execute(
                """
                SELECT s.*
                FROM scan_sessions s
                JOIN devices d ON d.session_id = s.id
                WHERE d.ip = ?
                ORDER BY s.scan_time DESC, s.id DESC
                LIMIT 1
                """,
                (ip,),
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

        # Scope history to same network if known
        if session_row["network_id"] is not None:
            history_rows = conn.execute(
                """
                SELECT s.id AS session_id, s.scan_time, s.subnet,
                       COUNT(p.id) AS port_count,
                       SUM(CASE WHEN p.is_new = 1 THEN 1 ELSE 0 END) AS new_ports
                FROM devices d
                JOIN scan_sessions s ON s.id = d.session_id
                LEFT JOIN ports p ON p.device_id = d.id
                WHERE d.ip = ? AND s.network_id = ?
                GROUP BY s.id
                ORDER BY s.scan_time DESC, s.id DESC
                LIMIT 12
                """,
                (ip, session_row["network_id"]),
            ).fetchall()
        else:
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


def _infer_risk_from_port(port_num: int, service: str) -> str:
    if port_num in (21, 23, 69, 1883, 6379, 27017, 9200) or service in ("telnet", "ftp"):
        return "high"
    if port_num in (22, 445, 3306, 3389, 5432, 8080, 9100):
        return "medium"
    return "low"


def _run_real_nmap_scan(network: dict[str, Any]) -> Optional[tuple[list[dict[str, Any]], float]]:
    """Run real nmap XML scan if NETPROFILER_REAL_SCAN=true and nmap is installed."""
    if os.environ.get("NETPROFILER_REAL_SCAN", "false").lower() != "true":
        return None
    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        return None

    cmd = [nmap_bin, "-oX", "-", "-sV", "-T4"]
    pr = network.get("port_range", "top-1000")
    if pr == "top-100":
        cmd.extend(["--top-ports", "100"])
    elif pr == "1-65535":
        cmd.extend(["-p-"])
    else:
        cmd.extend(["--top-ports", "1000"])
    cmd.append(network["cidr"])

    started = datetime.now(timezone.utc)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
    elapsed = (datetime.now(timezone.utc) - started).total_seconds()
    if proc.returncode != 0 or not proc.stdout.strip().startswith("<"):
        return None

    root = ET.fromstring(proc.stdout)
    assets: list[dict[str, Any]] = []
    for host in root.findall("host"):
        status_el = host.find("status")
        if status_el is None or status_el.attrib.get("state") != "up":
            continue
        ip_addr = ""
        mac_addr = "Inconnu"
        vendor = "Inconnu"
        for addr in host.findall("address"):
            atype = addr.attrib.get("addrtype")
            if atype in ("ipv4", "ipv6"):
                ip_addr = addr.attrib.get("addr", "")
            elif atype == "mac":
                mac_addr = addr.attrib.get("addr", "Inconnu")
                vendor = addr.attrib.get("vendor", "Inconnu")
        if not ip_addr:
            continue

        hostname = ip_addr
        hn_el = host.find("hostnames/hostname")
        if hn_el is not None and hn_el.attrib.get("name"):
            hostname = hn_el.attrib["name"]

        os_name = "Inconnu"
        os_el = host.find("os/osmatch")
        if os_el is not None and os_el.attrib.get("name"):
            os_name = os_el.attrib["name"]

        latency_ms = None
        times_el = host.find("times")
        if times_el is not None and times_el.attrib.get("srtt"):
            try:
                latency_ms = round(int(times_el.attrib["srtt"]) / 1000.0, 2)
            except ValueError:
                pass

        ports_list: list[dict[str, Any]] = []
        for p_el in host.findall("ports/port"):
            st_el = p_el.find("state")
            if st_el is None or st_el.attrib.get("state") != "open":
                continue
            port_num = int(p_el.attrib["portid"])
            proto = p_el.attrib.get("protocol", "tcp")
            svc = p_el.find("service")
            svc_name = svc.attrib.get("name", "unknown") if svc is not None else "unknown"
            product = svc.attrib.get("product", "") if svc is not None else ""
            version = svc.attrib.get("version", "") if svc is not None else ""
            extrainfo = svc.attrib.get("extrainfo", "") if svc is not None else ""
            cpe_el = svc.find("cpe") if svc is not None else None
            cpe = cpe_el.text.strip() if (cpe_el is not None and cpe_el.text) else ""

            scripts_dict: dict[str, str] = {}
            for sc in p_el.findall("script"):
                sid = sc.attrib.get("id", "script")
                sout = sc.attrib.get("output", "").strip()
                if sout:
                    scripts_dict[sid] = sout

            ports_list.append(
                {
                    "port": port_num,
                    "protocol": proto,
                    "state": "open",
                    "service": svc_name,
                    "product": product,
                    "version": version,
                    "extrainfo": extrainfo,
                    "cpe": cpe,
                    "banner": " ".join(x for x in (product, version, extrainfo) if x),
                    "script_output": json.dumps(scripts_dict) if scripts_dict else "",
                    "risk_level": _infer_risk_from_port(port_num, svc_name),
                }
            )

        assets.append(
            {
                "ip": ip_addr,
                "mac": mac_addr,
                "hostname": hostname,
                "vendor": vendor,
                "os": os_name,
                "device_type": "unknown",
                "latency_ms": latency_ms,
                "ports": ports_list,
            }
        )
    return assets, round(elapsed, 2)


def trigger_network_scan(network_id: Optional[int] = None) -> dict[str, Any]:
    """Run (or snapshot) a scan for a specific configured network and persist results in SQLite."""
    with get_conn() as conn:
        if network_id is not None:
            net_row = conn.execute("SELECT * FROM networks WHERE id = ?", (network_id,)).fetchone()
        else:
            net_row = conn.execute(
                "SELECT * FROM networks WHERE enabled = 1 ORDER BY id ASC LIMIT 1"
            ).fetchone()
            if not net_row:
                net_row = conn.execute("SELECT * FROM networks ORDER BY id ASC LIMIT 1").fetchone()

        if not net_row:
            raise ValueError("Aucun réseau configuré à scanner.")

        net_dict = dict(net_row)
        now_iso = datetime.now(timezone.utc).isoformat()

        # Fetch previous scan for diffing first_seen and is_new ports
        prev_session = conn.execute(
            "SELECT * FROM scan_sessions WHERE network_id = ? ORDER BY scan_time DESC, id DESC LIMIT 1",
            (net_dict["id"],),
        ).fetchone()

        prev_ports_by_ip: dict[str, set[tuple[int, str]]] = {}
        prev_first_seen_by_ip: dict[str, str] = {}
        if prev_session:
            prev_devs = conn.execute(
                "SELECT * FROM devices WHERE session_id = ?", (prev_session["id"],)
            ).fetchall()
            for pd in prev_devs:
                prev_first_seen_by_ip[pd["ip"]] = pd["first_seen"]
                p_rows = conn.execute(
                    "SELECT port, protocol FROM ports WHERE device_id = ?", (pd["id"],)
                ).fetchall()
                prev_ports_by_ip[pd["ip"]] = {(pr["port"], pr["protocol"]) for pr in p_rows}

        # Attempt real nmap scan if explicitly enabled
        nmap_result = _run_real_nmap_scan(net_dict)
        if nmap_result is not None:
            scanned_assets, duration = nmap_result
            cur = conn.execute(
                """
                INSERT INTO scan_sessions (network_id, scan_time, subnet, hosts_up, duration_sec, scanner_notes)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (net_dict["id"], now_iso, net_dict["cidr"], len(scanned_assets), duration, "Scan Nmap réel"),
            )
            new_sid = cur.lastrowid
            for a in scanned_assets:
                first_seen = prev_first_seen_by_ip.get(a["ip"], now_iso)
                d_cur = conn.execute(
                    """
                    INSERT INTO devices (session_id, ip, mac, hostname, vendor, os, device_type, latency_ms, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        new_sid, a["ip"], a["mac"], a["hostname"], a["vendor"],
                        a["os"], a["device_type"], a["latency_ms"], first_seen, now_iso,
                    ),
                )
                dev_id = d_cur.lastrowid
                known_ports = prev_ports_by_ip.get(a["ip"], set())
                for p in a["ports"]:
                    is_new = 1 if (prev_session is not None and (p["port"], p["protocol"]) not in known_ports) else 0
                    conn.execute(
                        """
                        INSERT INTO ports (
                            device_id, port, protocol, state, service, product, version,
                            extrainfo, cpe, banner, script_output, risk_level, is_new
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            dev_id, p["port"], p["protocol"], p["state"], p["service"], p["product"],
                            p["version"], p["extrainfo"], p["cpe"], p["banner"], p["script_output"],
                            p["risk_level"], is_new,
                        ),
                    )
            row = conn.execute(
                """
                SELECT s.*, n.name AS network_name
                FROM scan_sessions s
                LEFT JOIN networks n ON n.id = s.network_id
                WHERE s.id = ?
                """,
                (new_sid,),
            ).fetchone()
            return dict(row)

        # Fallback snapshot mode when real Nmap scanning is not active
        if prev_session:
            prev_devs = conn.execute(
                "SELECT * FROM devices WHERE session_id = ?", (prev_session["id"],)
            ).fetchall()
            cur = conn.execute(
                """
                INSERT INTO scan_sessions (network_id, scan_time, subnet, hosts_up, duration_sec, scanner_notes)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (net_dict["id"], now_iso, net_dict["cidr"], len(prev_devs), 12.4, "Scan manuel déclenché depuis l'interface"),
            )
            new_sid = cur.lastrowid
            for d in prev_devs:
                d_cur = conn.execute(
                    """
                    INSERT INTO devices (session_id, ip, mac, hostname, vendor, os, device_type, latency_ms, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        new_sid, d["ip"], d["mac"], d["hostname"], d["vendor"],
                        d["os"], d["device_type"], d["latency_ms"], d["first_seen"], now_iso,
                    ),
                )
                new_dev_id = d_cur.lastrowid
                ports = conn.execute("SELECT * FROM ports WHERE device_id = ?", (d["id"],)).fetchall()
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
                            new_dev_id, p["port"], p["protocol"], p["state"], p["service"], p["product"],
                            p["version"], p["extrainfo"], p["cpe"], p["banner"], p["script_output"], p["risk_level"],
                        ),
                    )
        else:
            # Brand-new custom network with no Nmap enabled: record clean empty scan without fabricating hosts
            cur = conn.execute(
                """
                INSERT INTO scan_sessions (network_id, scan_time, subnet, hosts_up, duration_sec, scanner_notes)
                VALUES (?, ?, ?, 0, 1.0, ?)
                """,
                (
                    net_dict["id"],
                    now_iso,
                    net_dict["cidr"],
                    "Session initialisée — activez NETPROFILER_REAL_SCAN=true (avec nmap) pour la découverte réelle",
                ),
            )
            new_sid = cur.lastrowid

        row = conn.execute(
            """
            SELECT s.*, n.name AS network_name
            FROM scan_sessions s
            LEFT JOIN networks n ON n.id = s.network_id
            WHERE s.id = ?
            """,
            (new_sid,),
        ).fetchone()
        return dict(row)


def trigger_simulated_scan() -> dict[str, Any]:
    """Backward-compatible wrapper triggering a scan on the first enabled network."""
    return trigger_network_scan(network_id=None)
