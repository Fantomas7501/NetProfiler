"""NetProfiler Web Application — FastAPI backend with password auth, RBAC, multi-network management, and profiling API."""

from __future__ import annotations

import re
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Optional

from fastapi import Body, Cookie, Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import auth
import db

STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{3,32}$")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    db.init_db(seed_demo=True)
    auth.cleanup_expired_sessions()
    yield


app = FastAPI(
    title="NetProfiler API",
    version="2.1.0",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Request Schemas
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=128)
    new_password: str = Field(..., min_length=8, max_length=128)
    revoke_other_sessions: bool = False


class CreateUserRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    display_name: str = Field(default="", max_length=80)
    email: str = Field(default="", max_length=120)
    password: str = Field(..., min_length=8, max_length=128)
    role: Literal["admin", "analyst", "viewer"] = "viewer"
    is_active: bool = True
    must_change_password: bool = False


class UpdateUserRequest(BaseModel):
    display_name: Optional[str] = Field(default=None, max_length=80)
    email: Optional[str] = Field(default=None, max_length=120)
    role: Optional[Literal["admin", "analyst", "viewer"]] = None
    is_active: Optional[bool] = None
    new_password: Optional[str] = Field(default=None, min_length=8, max_length=128)
    must_change_password: Optional[bool] = None


class CreateNetworkRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=80)
    cidr: str = Field(..., min_length=3, max_length=64)
    description: str = Field(default="", max_length=300)
    scan_interval_minutes: int = Field(default=60, ge=5, le=1440)
    port_range: str = Field(default="top-1000", max_length=64)
    nmap_flags: str = Field(default="-sV -O --version-intensity 5 -T4", max_length=160)
    enabled: bool = True


class UpdateNetworkRequest(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=80)
    cidr: Optional[str] = Field(default=None, min_length=3, max_length=64)
    description: Optional[str] = Field(default=None, max_length=300)
    scan_interval_minutes: Optional[int] = Field(default=None, ge=5, le=1440)
    port_range: Optional[str] = Field(default=None, max_length=64)
    nmap_flags: Optional[str] = Field(default=None, max_length=160)
    enabled: Optional[bool] = None


class TriggerScanRequest(BaseModel):
    network_id: Optional[int] = None


class ConfigUpdateRequest(BaseModel):
    target_subnet: Optional[str] = None
    scan_interval_minutes: Optional[int] = Field(default=None, ge=5, le=1440)
    port_range: Optional[str] = None
    nmap_flags: Optional[str] = None
    enable_os_detection: Optional[bool] = None
    enable_script_scan: Optional[bool] = None
    alert_on_new_port: Optional[bool] = None
    alert_webhook_url: Optional[str] = None
    session_ttl_hours: Optional[int] = Field(default=None, ge=1, le=720)
    retention_days: Optional[int] = Field(default=None, ge=1, le=365)
    organization_name: Optional[str] = Field(default=None, max_length=80)


def _public_user(user: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": user["id"],
        "username": user["username"],
        "display_name": user["display_name"],
        "email": user["email"],
        "role": user["role"],
        "is_active": bool(user["is_active"]),
        "must_change_password": bool(user["must_change_password"]),
        "created_at": user["created_at"],
        "last_login_at": user["last_login_at"],
    }


def _count_active_admins(conn) -> int:
    row = conn.execute(
        "SELECT COUNT(*) AS c FROM users WHERE role = 'admin' AND is_active = 1"
    ).fetchone()
    return int(row["c"])


# ---------------------------------------------------------------------------
# Authentication Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/auth/status")
def auth_status(
    session_token: Optional[str] = Cookie(default=None, alias=auth.SESSION_COOKIE_NAME),
) -> dict[str, Any]:
    if not session_token:
        return {"authenticated": False, "user": None}
    try:
        user = auth.get_current_user(session_token=session_token)
        return {"authenticated": True, "user": _public_user(user)}
    except HTTPException:
        return {"authenticated": False, "user": None}


@app.post("/api/auth/login")
def login(payload: LoginRequest, request: Request, response: Response) -> dict[str, Any]:
    client_ip = request.client.host if request.client else "unknown"
    username = payload.username.strip()

    auth.check_login_rate_limit(client_ip, username)

    with db.get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
            (username,),
        ).fetchone()

    if not row or not auth.verify_password(payload.password, row["password_hash"]):
        auth.record_failed_login(client_ip, username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identifiant ou mot de passe incorrect.",
        )

    if not row["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Ce compte est désactivé. Contactez un administrateur.",
        )

    auth.clear_failed_logins(client_ip, username)
    raw_token, expires_at = auth.create_session(row["id"], request)

    ttl_hours = auth.DEFAULT_SESSION_TTL_HOURS
    cfg_ttl = db.get_config_value("session_ttl_hours")
    if cfg_ttl:
        try:
            ttl_hours = max(1, min(720, int(cfg_ttl)))
        except ValueError:
            pass

    response.set_cookie(
        key=auth.SESSION_COOKIE_NAME,
        value=raw_token,
        httponly=True,
        samesite="lax",
        secure=auth.COOKIE_SECURE,
        max_age=ttl_hours * 3600,
        path="/",
    )

    user_dict = dict(row)
    user_dict["last_login_at"] = datetime.now(timezone.utc).isoformat()
    return {
        "authenticated": True,
        "expires_at": expires_at,
        "user": _public_user(user_dict),
    }


@app.post("/api/auth/logout")
def logout(
    response: Response,
    session_token: Optional[str] = Cookie(default=None, alias=auth.SESSION_COOKIE_NAME),
) -> dict[str, Any]:
    if session_token:
        auth.revoke_session(session_token)
    response.delete_cookie(key=auth.SESSION_COOKIE_NAME, path="/")
    return {"ok": True}


@app.get("/api/auth/me")
def get_me(user: dict[str, Any] = Depends(auth.get_current_user)) -> dict[str, Any]:
    with db.get_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, created_at, expires_at, user_agent, ip_address
            FROM auth_sessions
            WHERE user_id = ?
            ORDER BY created_at DESC
            """,
            (user["id"],),
        ).fetchall()

    sessions = [
        {
            "id": r["id"],
            "created_at": r["created_at"],
            "expires_at": r["expires_at"],
            "user_agent": r["user_agent"],
            "ip_address": r["ip_address"],
            "is_current": r["id"] == user["current_session_id"],
        }
        for r in rows
    ]
    return {"user": _public_user(user), "sessions": sessions}


@app.post("/api/auth/change-password")
def change_password(
    payload: ChangePasswordRequest,
    user: dict[str, Any] = Depends(auth.get_current_user),
) -> dict[str, Any]:
    pw_err = auth.validate_password_strength(payload.new_password)
    if pw_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=pw_err)

    with db.get_conn() as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE id = ?", (user["id"],)
        ).fetchone()
        if not row or not auth.verify_password(payload.current_password, row["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Le mot de passe actuel est incorrect.",
            )

        conn.execute(
            "UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?",
            (auth.hash_password(payload.new_password), user["id"]),
        )

    revoked = 0
    if payload.revoke_other_sessions:
        revoked = auth.revoke_all_user_sessions(
            user["id"], except_token_hash=user["current_token_hash"]
        )

    return {"ok": True, "revoked_other_sessions": revoked}


@app.delete("/api/auth/sessions/{session_id}")
def revoke_own_session(
    session_id: int,
    user: dict[str, Any] = Depends(auth.get_current_user),
) -> dict[str, Any]:
    if session_id == user["current_session_id"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Utilisez la déconnexion pour fermer la session active.",
        )
    with db.get_conn() as conn:
        cur = conn.execute(
            "DELETE FROM auth_sessions WHERE id = ? AND user_id = ?",
            (session_id, user["id"]),
        )
    if cur.rowcount == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session introuvable.")
    return {"ok": True}


# ---------------------------------------------------------------------------
# User Management Endpoints (Admin only)
# ---------------------------------------------------------------------------

@app.get("/api/users")
def list_users(_admin: dict[str, Any] = Depends(auth.require_admin)) -> list[dict[str, Any]]:
    with db.get_conn() as conn:
        rows = conn.execute(
            """
            SELECT u.id, u.username, u.display_name, u.email, u.role,
                   u.is_active, u.must_change_password, u.created_at, u.last_login_at,
                   (SELECT COUNT(*) FROM auth_sessions s WHERE s.user_id = u.id) AS active_sessions
            FROM users u
            ORDER BY u.id ASC
            """
        ).fetchall()
    return [
        {
            **_public_user(dict(r)),
            "active_sessions": r["active_sessions"],
        }
        for r in rows
    ]


@app.post("/api/users", status_code=status.HTTP_201_CREATED)
def create_user(
    payload: CreateUserRequest,
    _admin: dict[str, Any] = Depends(auth.require_admin),
) -> dict[str, Any]:
    username = payload.username.strip()
    if not USERNAME_RE.match(username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Le nom d'utilisateur doit contenir 3 à 32 caractères alphanumériques (._- autorisés).",
        )

    pw_err = auth.validate_password_strength(payload.password)
    if pw_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=pw_err)

    now_iso = datetime.now(timezone.utc).isoformat()
    with db.get_conn() as conn:
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ? COLLATE NOCASE", (username,)
        ).fetchone()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"L'utilisateur '{username}' existe déjà.",
            )

        cur = conn.execute(
            """
            INSERT INTO users (username, display_name, email, password_hash, role, is_active, must_change_password, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                username,
                payload.display_name.strip() or username,
                payload.email.strip(),
                auth.hash_password(payload.password),
                payload.role,
                1 if payload.is_active else 0,
                1 if payload.must_change_password else 0,
                now_iso,
            ),
        )
        row = conn.execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()

    return _public_user(dict(row))


@app.put("/api/users/{user_id}")
def update_user(
    user_id: int,
    payload: UpdateUserRequest,
    admin: dict[str, Any] = Depends(auth.require_admin),
) -> dict[str, Any]:
    with db.get_conn() as conn:
        target = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Utilisateur introuvable.")

        new_role = payload.role if payload.role is not None else target["role"]
        new_active = (1 if payload.is_active else 0) if payload.is_active is not None else target["is_active"]

        if target["role"] == "admin" and target["is_active"] == 1:
            if new_role != "admin" or new_active == 0:
                if _count_active_admins(conn) <= 1:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Impossible de rétrograder ou désactiver le dernier administrateur actif.",
                    )

        if user_id == admin["id"] and new_active == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Vous ne pouvez pas désactiver votre propre compte.",
            )

        updates: list[str] = []
        params: list[Any] = []

        if payload.display_name is not None:
            updates.append("display_name = ?")
            params.append(payload.display_name.strip())
        if payload.email is not None:
            updates.append("email = ?")
            params.append(payload.email.strip())
        if payload.role is not None:
            updates.append("role = ?")
            params.append(payload.role)
        if payload.is_active is not None:
            updates.append("is_active = ?")
            params.append(1 if payload.is_active else 0)
        if payload.must_change_password is not None:
            updates.append("must_change_password = ?")
            params.append(1 if payload.must_change_password else 0)
        if payload.new_password is not None:
            pw_err = auth.validate_password_strength(payload.new_password)
            if pw_err:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=pw_err)
            updates.append("password_hash = ?")
            params.append(auth.hash_password(payload.new_password))

        if updates:
            params.append(user_id)
            conn.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)

        if new_active == 0:
            conn.execute("DELETE FROM auth_sessions WHERE user_id = ?", (user_id,))

        updated = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    return _public_user(dict(updated))


@app.delete("/api/users/{user_id}")
def delete_user(
    user_id: int,
    admin: dict[str, Any] = Depends(auth.require_admin),
) -> dict[str, Any]:
    if user_id == admin["id"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Vous ne pouvez pas supprimer votre propre compte.",
        )

    with db.get_conn() as conn:
        target = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Utilisateur introuvable.")

        if target["role"] == "admin" and target["is_active"] == 1:
            if _count_active_admins(conn) <= 1:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Impossible de supprimer le dernier administrateur actif.",
                )

        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))

    return {"ok": True, "deleted_user_id": user_id}


# ---------------------------------------------------------------------------
# Networks Management Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/networks")
def api_list_networks(_user: dict[str, Any] = Depends(auth.get_current_user)) -> list[dict[str, Any]]:
    return db.list_networks()


@app.post("/api/networks", status_code=status.HTTP_201_CREATED)
def api_create_network(
    payload: CreateNetworkRequest,
    _admin: dict[str, Any] = Depends(auth.require_admin),
) -> dict[str, Any]:
    try:
        return db.create_network(
            name=payload.name,
            cidr=payload.cidr,
            description=payload.description,
            scan_interval_minutes=payload.scan_interval_minutes,
            port_range=payload.port_range,
            nmap_flags=payload.nmap_flags,
            enabled=payload.enabled,
        )
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Format CIDR invalide : '{payload.cidr}'. Exemple attendu : 192.168.55.0/24.",
        )
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Un réseau avec le sous-réseau '{payload.cidr}' existe déjà.",
        )


@app.put("/api/networks/{network_id}")
def api_update_network(
    network_id: int,
    payload: UpdateNetworkRequest,
    _admin: dict[str, Any] = Depends(auth.require_admin),
) -> dict[str, Any]:
    updates = {k: v for k, v in payload.model_dump().items() if v is not None}
    try:
        updated = db.update_network(network_id, updates)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Format CIDR invalide. Exemple attendu : 192.168.55.0/24.",
        )
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Ce sous-réseau CIDR est déjà configuré sur un autre réseau.",
        )
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Réseau introuvable.")
    return updated


@app.delete("/api/networks/{network_id}")
def api_delete_network(
    network_id: int,
    purge_history: bool = Query(default=False),
    _admin: dict[str, Any] = Depends(auth.require_admin),
) -> dict[str, Any]:
    deleted = db.delete_network(network_id, purge_history=purge_history)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Réseau introuvable.")
    return {"ok": True, "deleted_network_id": network_id, "history_preserved": not purge_history}


@app.post("/api/networks/{network_id}/scan")
def api_scan_network(
    network_id: int,
    user: dict[str, Any] = Depends(auth.get_current_user),
) -> dict[str, Any]:
    if user["role"] not in ("admin", "analyst"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Seuls les administrateurs et analystes peuvent déclencher un scan.",
        )
    if not db.get_network(network_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Réseau introuvable.")
    new_session = db.trigger_network_scan(network_id=network_id)
    return {"ok": True, "session": new_session}


# ---------------------------------------------------------------------------
# Network Scan & Asset Profiling Endpoints (Authenticated)
# ---------------------------------------------------------------------------

@app.get("/api/sessions")
def api_sessions(
    network_id: Optional[int] = Query(default=None),
    _user: dict[str, Any] = Depends(auth.get_current_user),
) -> list[dict[str, Any]]:
    return db.list_scan_sessions(network_id=network_id)


@app.get("/api/data")
def api_data(
    session_id: Optional[int] = Query(default=None),
    network_id: Optional[int] = Query(default=None),
    _user: dict[str, Any] = Depends(auth.get_current_user),
) -> dict[str, Any]:
    data = db.get_scan_data(session_id=session_id, network_id=network_id)
    if session_id is not None and data["session"] is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session de scan introuvable.")
    return data


@app.get("/api/assets/{ip}")
def api_asset_detail(
    ip: str,
    session_id: Optional[int] = Query(default=None),
    network_id: Optional[int] = Query(default=None),
    _user: dict[str, Any] = Depends(auth.get_current_user),
) -> dict[str, Any]:
    detail = db.get_asset_detail(ip=ip, session_id=session_id, network_id=network_id)
    if not detail:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Actif {ip} introuvable dans cette session.")
    return detail


@app.post("/api/scan/trigger")
def api_trigger_scan(
    payload: Optional[TriggerScanRequest] = Body(default=None),
    user: dict[str, Any] = Depends(auth.get_current_user),
) -> dict[str, Any]:
    if user["role"] not in ("admin", "analyst"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Seuls les administrateurs et analystes peuvent déclencher un scan.",
        )
    net_id = payload.network_id if payload else None
    try:
        new_session = db.trigger_network_scan(network_id=net_id)
    except ValueError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err))
    return {"ok": True, "session": new_session}


# ---------------------------------------------------------------------------
# Configuration Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/config")
def api_get_config(_user: dict[str, Any] = Depends(auth.get_current_user)) -> dict[str, str]:
    return db.get_config_all()


@app.put("/api/config")
def api_update_config(
    payload: ConfigUpdateRequest,
    _admin: dict[str, Any] = Depends(auth.require_admin),
) -> dict[str, str]:
    updates = {k: v for k, v in payload.model_dump().items() if v is not None}
    return db.update_config(updates)


# ---------------------------------------------------------------------------
# Static Frontend Routes
# ---------------------------------------------------------------------------

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
def serve_index() -> FileResponse:
    index_path = STATIC_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="Interface introuvable.")
    return FileResponse(index_path)
