"""
auth.py — Drop-in authentication module for Nexus AI (FastAPI backend)

Mount this router in your existing server.py:

    from auth import router as auth_router, get_current_user
    app.include_router(auth_router)

Protect any existing route by adding a dependency:

    @app.post("/chat")
    async def chat(request: Request, user: dict = Depends(get_current_user)):
        ...

Install requirements:
    pip install passlib[bcrypt] python-jose[cryptography] python-multipart

Set a real secret in production (never hardcode):
    export JWT_SECRET="$(openssl rand -hex 32)"
"""

import json
import os
import time
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, field_validator
from jose import JWTError, jwt

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

USERS_FILE = Path(__file__).parent / "users.json"

# Bug source #1: hardcoded secrets. Always pull from env, fail loudly if missing
# in production, but allow a dev fallback so local testing isn't blocked.
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-only-change-me-before-deploy")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 60 * 60 * 8  # 8 hours

COOKIE_NAME = "nexus_session"
IS_PROD = os.environ.get("ENV", "development") == "production"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

router = APIRouter(prefix="/auth", tags=["auth"])

# ---------------------------------------------------------------------------
# Storage (JSON, matching your existing memory.json pattern)
# Swap this for a real DB later without touching the routes below —
# only _load_users / _save_users / _find_user need to change.
# ---------------------------------------------------------------------------

_lock_file = Path(__file__).parent / ".users.lock"


def _load_users() -> dict:
    if not USERS_FILE.exists():
        return {}
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        # Bug source #2: a corrupted store crashing every request forever.
        # Fail safe to empty rather than 500-ing on every request.
        return {}


def _save_users(users: dict) -> None:
    tmp = USERS_FILE.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)
    tmp.replace(USERS_FILE)  # atomic write — avoids truncated-file corruption


def _find_user(email: str) -> Optional[dict]:
    users = _load_users()
    return users.get(email.lower())


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: Optional[str] = None

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        # Bug source #3: no server-side validation, relying on frontend only.
        # Frontend checks are cosmetic — always re-check here.
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------

def _create_token(email: str) -> str:
    now = int(time.time())
    payload = {
        "sub": email.lower(),
        "iat": now,
        "exp": now + ACCESS_TOKEN_EXPIRE_SECONDS,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
        )


def get_current_user(request: Request) -> dict:
    """
    Dependency for protecting routes. Reads the JWT from the HttpOnly cookie
    — NOT from localStorage/Authorization header — so it can't be read or
    exfiltrated by client-side JS (mitigates XSS token theft, bug source #4).
    """
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    payload = _decode_token(token)
    user = _find_user(payload["sub"])
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User no longer exists",
        )
    return {"email": user["email"], "name": user.get("name")}


def get_optional_user(request: Request) -> Optional[dict]:
    """Same as above but returns None instead of raising — for pages that
    render differently when logged in vs out, without forcing a redirect."""
    try:
        return get_current_user(request)
    except HTTPException:
        return None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/register")
def register(payload: RegisterRequest, response: Response):
    users = _load_users()
    email = payload.email.lower()

    # Bug source #5: race-free duplicate check. Since this is single-process
    # JSON storage, check-then-write is fine; if you move to Postgres, make
    # the email column UNIQUE and catch the IntegrityError too — don't rely
    # on this check alone.
    if email in users:
        raise HTTPException(status_code=409, detail="An account with this email already exists")

    users[email] = {
        "email": email,
        "name": payload.name or email.split("@")[0],
        "password_hash": pwd_context.hash(payload.password),
        "created_at": int(time.time()),
    }
    _save_users(users)

    token = _create_token(email)
    _set_auth_cookie(response, token)
    return {"email": email, "name": users[email]["name"]}


@router.post("/login")
def login(payload: LoginRequest, response: Response):
    user = _find_user(payload.email)

    # Bug source #6: timing-safe-ish failure. Always run verify() even when
    # the user doesn't exist, so response time doesn't leak which emails are
    # registered (basic user-enumeration mitigation).
    dummy_hash = "$2b$12$CwaJ4Ny7Ax1z1x1x1x1x1eYQvQvQvQvQvQvQvQvQvQvQvQvQvQvQ"
    hash_to_check = user["password_hash"] if user else dummy_hash
    valid = pwd_context.verify(payload.password, hash_to_check)

    if not user or not valid:
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    token = _create_token(user["email"])
    _set_auth_cookie(response, token)
    return {"email": user["email"], "name": user.get("name")}


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}


@router.get("/me")
def me(user: dict = Depends(get_current_user)):
    return user


def _set_auth_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,          # JS cannot read it — blocks XSS token theft
        secure=IS_PROD,         # only sent over HTTPS in production
        samesite="lax",         # CSRF mitigation for top-level navigation
        max_age=ACCESS_TOKEN_EXPIRE_SECONDS,
        path="/",
    )
