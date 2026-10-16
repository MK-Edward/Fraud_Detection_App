import html
import hashlib
import hmac
import logging
import math
import os
import secrets
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Form, Request, HTTPException, status, Depends, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from app.database import init_db, get_db_connection

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("unique_bank")

# Configure a stable secret in your environment for deployments.
SECRET_KEY = os.getenv("BANK_SECRET_KEY", "dev-only-change-this-bank-secret-key")
SESSION_COOKIE = "unique_bank_auth_session"
SESSION_MAX_AGE = 3600
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
serializer = URLSafeTimedSerializer(SECRET_KEY, salt="unique-bank-session-salt")

COUNTY_COORDINATES = {
    "Mombasa": (-4.0435, 39.6682), "Kwale": (-4.1737, 39.4521),
    "Kilifi": (-3.5107, 39.9093), "Tana River": (-1.5236, 39.1056),
    "Lamu": (-2.2717, 40.9020), "Taita-Taveta": (-3.3161, 38.4850),
    "Garissa": (-0.4532, 39.6461), "Wajir": (1.7471, 40.0573),
    "Mandera": (3.9373, 41.8569), "Marsabit": (2.3284, 37.9899),
    "Isiolo": (0.3546, 37.5822), "Meru": (0.0463, 37.6559),
    "Tharaka-Nithi": (-0.2965, 37.7238), "Embu": (-0.5388, 37.4574),
    "Kitui": (-1.3667, 38.0106), "Machakos": (-1.5177, 37.2634),
    "Makueni": (-2.2559, 37.8937), "Nyandarua": (-0.1804, 36.5220),
    "Nyeri": (-0.4167, 36.9500), "Kirinyaga": (-0.6591, 37.3827),
    "Murang'a": (-0.7839, 37.0400), "Kiambu": (-1.1714, 36.8356),
    "Turkana": (3.1191, 35.5973), "West Pokot": (1.6210, 35.1108),
    "Samburu": (1.2150, 36.9541), "Trans Nzoia": (1.0567, 34.9507),
    "Uasin Gishu": (0.5143, 35.2698), "Elgeyo-Marakwet": (0.8000, 35.5000),
    "Nandi": (0.1836, 35.1269), "Baringo": (0.4667, 35.9667),
    "Laikipia": (0.3606, 36.7819), "Nakuru": (-0.3031, 36.0800),
    "Narok": (-1.0783, 35.8601), "Kajiado": (-2.0981, 36.7820),
    "Kericho": (-0.3676, 35.2831), "Bomet": (-0.7813, 35.3416),
    "Kakamega": (0.2827, 34.7519), "Vihiga": (0.0768, 34.7071),
    "Bungoma": (0.5635, 34.5606), "Busia": (0.4608, 34.1115),
    "Siaya": (0.0612, 34.2871), "Kisumu": (-0.0917, 34.7680),
    "Homa Bay": (-0.5273, 34.4571), "Migori": (-1.0634, 34.4731),
    "Kisii": (-0.6817, 34.7667), "Nyamira": (-0.5633, 34.9358),
    "Nairobi": (-1.2921, 36.8219),
}


def page(title: str, body: str) -> str:
    safe_title = html.escape(title)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{safe_title} — Unique Bank</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<style>body{{background:#f3f6fb;color:#172b4d}}.navbar{{background:#102a43}}
.card{{border:0;border-radius:16px}}.brand{{font-weight:800}}main{{max-width:1000px}}
</style></head><body>
<nav class="navbar navbar-dark mb-4 py-3"><div class="container">
<a class="navbar-brand brand" href="/">🛡️ Unique Bank</a>
<a class="btn btn-outline-light btn-sm" href="/auth/logout">Sign out</a>
</div></nav><main class="container pb-5">{body}</main>
<footer class="container text-center text-secondary py-3"><small>© 2026 Unique Bank — Demonstration system</small></footer>
</body></html>"""


def alert_redirect(message: str, destination: str = "/portal") -> HTMLResponse:
    # JSON string encoding safely escapes quotes and newlines for JavaScript.
    import json
    return HTMLResponse(
        f"<script>alert({json.dumps(message)});window.location.href={json.dumps(destination)};</script>"
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    # Optional manager provisioning. Set ADMIN_USERNAME and ADMIN_PASSWORD explicitly.
    admin_username = os.getenv("ADMIN_USERNAME")
    admin_password = os.getenv("ADMIN_PASSWORD")
    if admin_username and admin_password:
        conn = get_db_connection()
        try:
            existing = conn.execute(
                "SELECT id FROM users WHERE username = ?", (admin_username,)
            ).fetchone()
            if not existing:
                conn.execute(
                    """INSERT INTO users
