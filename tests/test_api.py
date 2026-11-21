"""End-to-end API tests for NetProfiler authentication, RBAC, user management, scan profiling, and config."""

from __future__ import annotations

import http.cookiejar
import json
import os
import socket
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

import uvicorn


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class APIClient:
    """Minimal cookie-aware HTTP JSON client using Python stdlib."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def request(self, method: str, path: str, payload: dict | None = None) -> tuple[int, dict | list | str]:
        url = f"{self.base_url}{path}"
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=5) as resp:
                raw = resp.read().decode("utf-8")
                try:
                    return resp.status, json.loads(raw)
                except json.JSONDecodeError:
                    return resp.status, raw
        except urllib.error.HTTPError as err:
            raw = err.read().decode("utf-8")
            try:
                return err.code, json.loads(raw)
            except json.JSONDecodeError:
                return err.code, raw


class NetProfilerAPITestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmpdir = tempfile.TemporaryDirectory()
        cls._db_path = os.path.join(cls._tmpdir.name, "test_netprofiler.db")
        os.environ["NETPROFILER_DB"] = cls._db_path
        os.environ["NETPROFILER_ADMIN_USER"] = "admin"
        os.environ["NETPROFILER_ADMIN_PASSWORD"] = "TestAdmin!2026"

        import app as netprofiler_app
        import db

        db.init_db(seed_demo=True)

        cls.port = _find_free_port()
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        config = uvicorn.Config(
            netprofiler_app.app,
            host="127.0.0.1",
            port=cls.port,
            log_level="error",
        )
        cls.server = uvicorn.Server(config)
        cls.thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.thread.start()

        # Wait until server responds
        for _ in range(50):
            try:
                code, _ = APIClient(cls.base_url).request("GET", "/api/auth/status")
                if code == 200:
                    break
            except Exception:
                time.sleep(0.05)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.should_exit = True
        cls.thread.join(timeout=3)
        cls._tmpdir.cleanup()

    def test_01_unauthenticated_blocked(self) -> None:
        client = APIClient(self.base_url)
        code, body = client.request("GET", "/api/auth/status")
        self.assertEqual(code, 200)
        self.assertFalse(body["authenticated"])

        for endpoint in ("/api/sessions", "/api/data", "/api/users", "/api/config", "/api/assets/192.168.10.10"):
            code, _ = client.request("GET", endpoint)
            self.assertEqual(code, 401, f"{endpoint} should require authentication")

    def test_02_admin_login_and_scan_profiling(self) -> None:
        admin = APIClient(self.base_url)

        # Bad password
        code, _ = admin.request("POST", "/api/auth/login", {"username": "admin", "password": "wrongpassword"})
        self.assertEqual(code, 401)

        # Valid login
        code, body = admin.request("POST", "/api/auth/login", {"username": "admin", "password": "TestAdmin!2026"})
        self.assertEqual(code, 200)
        self.assertTrue(body["authenticated"])
        self.assertEqual(body["user"]["role"], "admin")

        # Networks & sessions match frontend contract
        code, networks = admin.request("GET", "/api/networks")
        self.assertEqual(code, 200)
        self.assertGreaterEqual(len(networks), 3)
        lan_net = next(n for n in networks if n["cidr"] == "192.168.10.0/24")

        code, sessions = admin.request("GET", f"/api/sessions?network_id={lan_net['id']}")
        self.assertEqual(code, 200)
        self.assertGreaterEqual(len(sessions), 3)

        code, scan_data = admin.request("GET", f"/api/data?session_id={sessions[0]['id']}")
        self.assertEqual(code, 200)
        self.assertIn("stats", scan_data)
        self.assertIn("devices", scan_data)
        self.assertGreaterEqual(len(scan_data["devices"]), 10)

        # Asset detail & deep port profiling
        code, asset_detail = admin.request("GET", "/api/assets/192.168.10.10")
        self.assertEqual(code, 200)
        self.assertEqual(asset_detail["asset"]["ip"], "192.168.10.10")
        self.assertGreaterEqual(len(asset_detail["asset"]["ports"]), 3)
        self.assertTrue(any(p.get("banner") and p.get("cpe") for p in asset_detail["asset"]["ports"]))
        self.assertGreaterEqual(len(asset_detail["history"]), 3)

    def test_03_user_management_and_rbac(self) -> None:
        admin = APIClient(self.base_url)
        code, login_body = admin.request("POST", "/api/auth/login", {"username": "admin", "password": "TestAdmin!2026"})
        self.assertEqual(code, 200)
        admin_id = login_body["user"]["id"]

        # Guardrail: cannot demote or disable last admin
        code, _ = admin.request("PUT", f"/api/users/{admin_id}", {"role": "viewer"})
        self.assertEqual(code, 400)
        code, _ = admin.request("DELETE", f"/api/users/{admin_id}")
        self.assertEqual(code, 400)

        # Create viewer user
        code, created = admin.request(
            "POST",
            "/api/users",
            {
                "username": "alice",
                "display_name": "Alice Martin",
                "email": "alice@lan.local",
                "password": "ViewerPass!123",
                "role": "viewer",
            },
        )
        self.assertEqual(code, 201)
        alice_id = created["id"]

        # Viewer login & RBAC verification
        viewer = APIClient(self.base_url)
        code, _ = viewer.request("POST", "/api/auth/login", {"username": "alice", "password": "ViewerPass!123"})
        self.assertEqual(code, 200)

        code, _ = viewer.request("GET", "/api/data")
        self.assertEqual(code, 200)
        code, _ = viewer.request("GET", "/api/users")
        self.assertEqual(code, 403)
        code, _ = viewer.request("PUT", "/api/config", {"target_subnet": "10.0.0.0/24"})
        self.assertEqual(code, 403)
        code, _ = viewer.request("POST", "/api/scan/trigger")
        self.assertEqual(code, 403)

        # Viewer changes own password
        code, _ = viewer.request(
            "POST",
            "/api/auth/change-password",
            {"current_password": "ViewerPass!123", "new_password": "NewViewerPass!456"},
        )
        self.assertEqual(code, 200)

        # Logout revokes session
        code, _ = viewer.request("POST", "/api/auth/logout")
        self.assertEqual(code, 200)
        code, _ = viewer.request("GET", "/api/data")
        self.assertEqual(code, 401)

        # Admin updates and deletes user
        code, updated = admin.request("PUT", f"/api/users/{alice_id}", {"role": "analyst", "is_active": False})
        self.assertEqual(code, 200)
        self.assertEqual(updated["role"], "analyst")
        self.assertFalse(updated["is_active"])

        code, _ = admin.request("DELETE", f"/api/users/{alice_id}")
        self.assertEqual(code, 200)

    def test_04_config_update_and_manual_scan(self) -> None:
        admin = APIClient(self.base_url)
        code, _ = admin.request("POST", "/api/auth/login", {"username": "admin", "password": "TestAdmin!2026"})
        self.assertEqual(code, 200)

        code, cfg = admin.request(
            "PUT",
            "/api/config",
            {"target_subnet": "10.20.0.0/24", "scan_interval_minutes": 30, "enable_os_detection": False},
        )
        self.assertEqual(code, 200)
        self.assertEqual(cfg["target_subnet"], "10.20.0.0/24")
        self.assertEqual(cfg["scan_interval_minutes"], "30")
        self.assertEqual(cfg["enable_os_detection"], "false")

        code, before = admin.request("GET", "/api/sessions")
        self.assertEqual(code, 200)
        code, trig = admin.request("POST", "/api/scan/trigger")
        self.assertEqual(code, 200)
        self.assertTrue(trig["ok"])
        code, after = admin.request("GET", "/api/sessions")
        self.assertEqual(len(after), len(before) + 1)

    def test_05_multi_network_management_and_persistence(self) -> None:
        admin = APIClient(self.base_url)
        code, _ = admin.request("POST", "/api/auth/login", {"username": "admin", "password": "TestAdmin!2026"})
        self.assertEqual(code, 200)

        # Verify distinct networks have their own isolated assets in DB
        code, networks = admin.request("GET", "/api/networks")
        self.assertEqual(code, 200)
        dmz = next(n for n in networks if n["cidr"] == "10.20.0.0/24")
        iot = next(n for n in networks if n["cidr"] == "172.16.40.0/24")

        code, dmz_data = admin.request("GET", f"/api/data?network_id={dmz['id']}")
        self.assertEqual(code, 200)
        self.assertEqual(dmz_data["session"]["subnet"], "10.20.0.0/24")
        self.assertTrue(all(d["ip"].startswith("10.20.0.") for d in dmz_data["devices"]))

        code, iot_data = admin.request("GET", f"/api/data?network_id={iot['id']}")
        self.assertEqual(code, 200)
        self.assertEqual(iot_data["session"]["subnet"], "172.16.40.0/24")
        self.assertTrue(all(d["ip"].startswith("172.16.40.") for d in iot_data["devices"]))

        # Invalid CIDR rejected
        code, _ = admin.request("POST", "/api/networks", {"name": "Bad Net", "cidr": "not-a-cidr"})
        self.assertEqual(code, 400)

        # Add a new network (normalizes host IP to network CIDR)
        code, created = admin.request(
            "POST",
            "/api/networks",
            {
                "name": "Serveurs Debian LAN55",
                "cidr": "192.168.55.115/24",
                "description": "Segment serveurs Debian",
                "scan_interval_minutes": 45,
                "port_range": "top-1000",
            },
        )
        self.assertEqual(code, 201)
        self.assertEqual(created["cidr"], "192.168.55.0/24")
        net_id = created["id"]

        # Duplicate CIDR rejected
        code, _ = admin.request("POST", "/api/networks", {"name": "Dup", "cidr": "192.168.55.0/24"})
        self.assertEqual(code, 409)

        # Update network metadata
        code, updated = admin.request(
            "PUT",
            f"/api/networks/{net_id}",
            {"name": "LAN Debian 55", "enabled": False, "scan_interval_minutes": 15},
        )
        self.assertEqual(code, 200)
        self.assertEqual(updated["name"], "LAN Debian 55")
        self.assertFalse(updated["enabled"])
        self.assertEqual(updated["scan_interval_minutes"], 15)

        # Trigger scan specifically for the new network
        code, scan_res = admin.request("POST", f"/api/networks/{net_id}/scan")
        self.assertEqual(code, 200)
        new_sid = scan_res["session"]["id"]
        self.assertEqual(scan_res["session"]["subnet"], "192.168.55.0/24")

        # Delete network while preserving historical scans in DB (default purge_history=false)
        code, del_res = admin.request("DELETE", f"/api/networks/{net_id}")
        self.assertEqual(code, 200)
        self.assertTrue(del_res["history_preserved"])

        # Preserved scan session is still readable in SQLite
        code, preserved = admin.request("GET", f"/api/data?session_id={new_sid}")
        self.assertEqual(code, 200)
        self.assertEqual(preserved["session"]["subnet"], "192.168.55.0/24")


if __name__ == "__main__":
    unittest.main()
