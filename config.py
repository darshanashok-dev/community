"""Application configuration for the Cybersecurity Awareness Platform."""

import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _as_int(value: str | None, default: int) -> int:
    if value is None:
        return default
    try:
        parsed = int(value)
        return parsed if parsed > 0 else default
    except ValueError:
        return default


class Config:
    """Base configuration with privacy-first defaults."""

    APP_NAME = "CyberShield Awareness"
    PROJECT_TITLE = (
        "Cybersecurity Awareness Platform for Phishing, "
        "Digital Arrest Scams, and Malicious Applications"
    )

    SECRET_KEY = os.environ.get("SECRET_KEY") or os.urandom(32).hex()
    DEBUG = _as_bool(os.environ.get("FLASK_DEBUG"), default=False)
    TESTING = False

    # Secure cookie defaults
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _as_bool(os.environ.get("SESSION_COOKIE_SECURE"), default=False)

    HOST = os.environ.get("FLASK_HOST", "127.0.0.1")
    PORT = _as_int(os.environ.get("FLASK_PORT"), default=5000)

    # Privacy, payload & rate-limit constraints
    MAX_CONTENT_LENGTH = 64 * 1024  # 64 KB cap on HTTP request payloads
    MAX_MESSAGE_LENGTH = _as_int(os.environ.get("MAX_MESSAGE_LENGTH"), default=5000)
    MAX_URL_LENGTH = _as_int(os.environ.get("MAX_URL_LENGTH"), default=2048)
    RATE_LIMIT_ENABLED = _as_bool(os.environ.get("RATE_LIMIT_ENABLED"), default=True)
    RATE_LIMIT_REQUESTS_PER_MINUTE = _as_int(
        os.environ.get("RATE_LIMIT_REQUESTS_PER_MINUTE"), default=60
    )

    # External integration settings
    SAFE_BROWSING_API_KEY = os.environ.get("SAFE_BROWSING_API_KEY", "").strip()
    EXTERNAL_API_TIMEOUT_SECONDS = _as_int(
        os.environ.get("EXTERNAL_API_TIMEOUT_SECONDS"), default=5
    )
    RDAP_BASE_URL = os.environ.get("RDAP_BASE_URL", "https://rdap.org/domain/").strip()

    # Static content paths
    DATABASE_DIR = BASE_DIR / "app" / "database"


class TestingConfig(Config):
    """Configuration used by automated tests."""

    TESTING = True
    DEBUG = False
    SECRET_KEY = "test-only-secret-key-not-for-production"
    RATE_LIMIT_ENABLED = False
