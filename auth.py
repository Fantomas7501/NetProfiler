"""Authentication, password hashing, session management, and RBAC for NetProfiler."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import Cookie, Depends, HTTPException, Request, status

import db

SESSION_COOKIE_NAME = "netprofiler_session"
DEFAULT_SESSION_TTL_HOURS = int(os.environ.get("NETPROFILER_SESSION_TTL_HOURS", "24"))
COOKIE_SECURE = os.environ.get("NETPROFILER_COOKIE_SECURE", "false").lower() == "true"

# Simple in-memory sliding-window brute-force protection
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 300
_failed_attempts: dict[str, list[float]] = defaultdict(list)


def hash_password(password: str) -> str:
    """Hash a plaintext password using scrypt with a random 16-byte salt."""
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=32,
    )
    return f"scrypt$16384$8$1${salt.hex()}${derived.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a plaintext password against a stored scrypt hash in constant time."""
    try:
        parts = stored_hash.split("$")
        if len(parts) != 6 or parts[0] != "scrypt":
            return False
        n = int(parts[1])
        r = int(parts[2])
        p = int(parts[3])
        salt = bytes.fromhex(parts[4])
        expected = bytes.fromhex(parts[5])
        derived = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=len(expected),
        )
        return hmac.compare_digest(derived, expected)
    except Exception:
        return False


def validate_password_strength(password: str) -> Optional[str]:
    """Return an error message if password does not meet minimum policy, else None."""
    if len(password) < 8:
        return "Le mot de passe doit contenir au moins 8 caractères."
    if len(password) > 128:
        return "Le mot de passe ne doit pas dépasser 128 caractères."
    return None


def hash_session_token(raw_token: str) -> str:
    """Hash a raw session cookie token with SHA-256 before storing or looking up."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _rate_limit_key(client_ip: str, username: str) -> str:
    return f"{client_ip}:{username.strip().lower()}"


def check_login_rate_limit(client_ip: str, username: str) -> None:
    """Raise 429 if too many failed login attempts happened recently."""
    key = _rate_limit_key(client_ip, username)
    now = time.time()
    recent = [ts for ts in _failed_attempts[key] if now - ts < LOGIN_WINDOW_SECONDS]
    _failed_attempts[key] = recent
    if len(recent) >= MAX_LOGIN_ATTEMPTS:
        retry_after = int(LOGIN_WINDOW_SECONDS - (now - recent[0]))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Trop de tentatives échouées. Réessayez dans {max(1, retry_after)} secondes.",
        )


def record_failed_login(client_ip: str, username: str) -> None:
    key = _rate_limit_key(client_ip, username)
    _failed_attempts[key].append(time.time())


def clear_failed_logins(client_ip: str, username: str) -> None:
    key = _rate_limit_key(client_ip, username)
    _failed_attempts.pop(key, None)


def create_session(user_id: int, request: Request) -> tuple[str, str]:
    """Create a new persisted auth session and return (raw_token, expires_at_iso)."""
    raw_token = secrets.token_urlsafe(32)
    token_hash = hash_session_token(raw_token)

    ttl_hours = DEFAULT_SESSION_TTL_HOURS
    cfg_ttl = db.get_config_value("session_ttl_hours")
    if cfg_ttl:
        try:
            ttl_hours = max(1, min(720, int(cfg_ttl)))
        except ValueError:
            pass

    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(hours=ttl_hours)).isoformat()
    created_at = now.isoformat()
    user_agent = (request.headers.get("user-agent") or "")[:250]
    ip_address = request.client.host if request.client else "unknown"

    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT INTO auth_sessions (token_hash, user_id, created_at, expires_at, user_agent, ip_address)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (token_hash, user_id, created_at, expires_at, user_agent, ip_address),
        )
        conn.execute(
            "UPDATE users SET last_login_at = ? WHERE id = ?",
            (created_at, user_id),
        )
    return raw_token, expires_at


def revoke_session(raw_token: str) -> None:
    """Delete an auth session by its raw cookie token."""
    token_hash = hash_session_token(raw_token)
    with db.get_conn() as conn:
        conn.execute("DELETE FROM auth_sessions WHERE token_hash = ?", (token_hash,))


def revoke_all_user_sessions(user_id: int, except_token_hash: Optional[str] = None) -> int:
    """Revoke all sessions belonging to a user, optionally keeping the current session."""
    with db.get_conn() as conn:
        if except_token_hash:
            cur = conn.execute(
                "DELETE FROM auth_sessions WHERE user_id = ? AND token_hash != ?",
                (user_id, except_token_hash),
            )
        else:
            cur = conn.execute(
                "DELETE FROM auth_sessions WHERE user_id = ?",
                (user_id,),
            )
        return cur.rowcount


def cleanup_expired_sessions() -> None:
    now_iso = datetime.now(timezone.utc).isoformat()
    with db.get_conn() as conn:
        conn.execute("DELETE FROM auth_sessions WHERE expires_at < ?", (now_iso,))


def get_current_user(
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> dict[str, Any]:
    """FastAPI dependency returning the authenticated active user or raising 401."""
    if not session_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentification requise.",
        )

    token_hash = hash_session_token(session_token)
    now_iso = datetime.now(timezone.utc).isoformat()

    with db.get_conn() as conn:
        row = conn.execute(
            """
            SELECT u.id, u.username, u.display_name, u.email, u.role,
                   u.is_active, u.must_change_password, u.created_at, u.last_login_at,
                   s.id AS session_id, s.expires_at, s.token_hash
            FROM auth_sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ?
            """,
            (token_hash,),
        ).fetchone()

        if not row:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session invalide ou expirée.",
            )

        if row["expires_at"] < now_iso:
            conn.execute("DELETE FROM auth_sessions WHERE token_hash = ?", (token_hash,))
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expirée. Veuillez vous reconnecter.",
            )

        if not row["is_active"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Ce compte utilisateur a été désactivé.",
            )

        return {
            "id": row["id"],
            "username": row["username"],
            "display_name": row["display_name"],
            "email": row["email"],
            "role": row["role"],
            "is_active": bool(row["is_active"]),
            "must_change_password": bool(row["must_change_password"]),
            "created_at": row["created_at"],
            "last_login_at": row["last_login_at"],
            "current_session_id": row["session_id"],
            "current_token_hash": row["token_hash"],
        }


def require_admin(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    """FastAPI dependency enforcing administrator role."""
    if user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Accès réservé aux administrateurs.",
        )
    return user
