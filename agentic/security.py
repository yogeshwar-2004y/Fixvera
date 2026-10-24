import hashlib
import hmac
import ipaddress
import os
import secrets
import socket
import asyncio
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from aiohttp.abc import AbstractResolver
from fastapi import HTTPException, Request

from .db import connect, one


def now():
    return datetime.now(timezone.utc).isoformat()


def new_id():
    return secrets.token_urlsafe(16)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def password_hash(password):
    if len(password) < 12:
        raise HTTPException(422, "Password must have at least 12 characters")
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
    return f"{salt.hex()}:{derived.hex()}"


def password_valid(password, stored):
    try:
        salt, expected = stored.split(":")
        actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1)
        return hmac.compare_digest(actual, bytes.fromhex(expected))
    except (ValueError, TypeError):
        return False


def encryption():
    key = os.getenv("AGENTIC_ENCRYPTION_KEY")
    if not key:
        raise RuntimeError("AGENTIC_ENCRYPTION_KEY is required for WordPress connections")
    return Fernet(key.encode())


def encrypt(value):
    return encryption().encrypt(value.encode()).decode()


def decrypt(value):
    return encryption().decrypt(value.encode()).decode()


async def session_user(request: Request):
    token = request.cookies.get("agentic_session")
    if not token:
        raise HTTPException(401, "Sign in required")
    with connect() as db:
        record = one(db, "SELECT s.*,u.email FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id_hash=?", (digest(token),))
    if not record or record["expires_at"] < now():
        raise HTTPException(401, "Session expired")
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        csrf = request.headers.get("x-csrf-token", "")
        if not hmac.compare_digest(digest(csrf), record["csrf_hash"]):
            raise HTTPException(403, "CSRF token required")
        origin = request.headers.get("origin")
        expected_origin = os.getenv("AGENTIC_PUBLIC_ORIGIN") or str(request.base_url).rstrip("/")
        if origin and origin != expected_origin.rstrip("/"):
            raise HTTPException(403, "Invalid request origin")
    return {"id": record["user_id"], "email": record["email"], "csrf_hash": record["csrf_hash"]}


def session_expiry():
    return (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()


def normalized_site(raw):
    try:
        url = urlsplit(raw.strip())
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.port not in (None, 443):
            raise ValueError
        host = url.hostname.encode("idna").decode("ascii").lower()
        if host == "localhost" or "." not in host or host.endswith((".local", ".internal")):
            raise ValueError
        return f"https://{host}", host
    except (ValueError, UnicodeError):
        raise HTTPException(422, "Enter a public HTTPS website origin")


def assert_public_host(host):
    try:
        answers = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError:
        raise HTTPException(422, "Website DNS lookup failed")
    ips = {ipaddress.ip_address(item[4][0]) for item in answers}
    if not ips or any(not ip.is_global for ip in ips):
        raise HTTPException(422, "Website must resolve only to public IP addresses")


class PublicResolver(AbstractResolver):
    """Resolve once per connection and connect only to the vetted addresses."""

    async def resolve(self, host, port=0, family=socket.AF_INET):
        try:
            answers = await asyncio.get_running_loop().getaddrinfo(host, port, family=family, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise OSError("Website DNS lookup failed") from exc
        results = []
        for af, socktype, proto, canonname, address in answers:
            ip = ipaddress.ip_address(address[0])
            if not ip.is_global:
                raise OSError("Website resolved to a private or reserved IP")
            results.append({"hostname": host, "host": str(ip), "port": port,
                            "family": af, "proto": proto, "flags": 0})
        if not results:
            raise OSError("Website DNS lookup failed")
        return results

    async def close(self):
        pass


def safe_page_url(raw, hostname):
    try:
        value = urlsplit(raw)
        if value.scheme != "https" or value.hostname != hostname or value.port not in (None, 443) or value.username or value.password:
            return None
        return value._replace(fragment="").geturl()
    except ValueError:
        return None
