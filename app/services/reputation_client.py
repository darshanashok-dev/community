"""External URL reputation clients (opt-in only, privacy-reduced indicators).

Includes:
- Google Safe Browsing API v5 (`GET /v5/hashes:search` with 4-byte SHA-256 prefixes)
- ICANN RDAP registrable-domain lookup (`GET https://rdap.org/domain/<domain>`)
"""

from __future__ import annotations

import base64
import ipaddress
import socket
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit

import requests

SAFE_BROWSING_V5_ENDPOINT = "https://safebrowsing.googleapis.com/v5/hashes:search"
SAFE_BROWSING_ATTRIBUTION = (
    "Powered by Google Safe Browsing API v5 (4-byte SHA-256 hash-prefix lookup). "
    "Reliability and accuracy cannot be guaranteed; absence from Safe Browsing lists is not proof of safety."
)

_THREAT_TYPE_NAMES = {
    0: "THREAT_TYPE_UNSPECIFIED",
    1: "MALWARE",
    2: "SOCIAL_ENGINEERING",
    3: "UNWANTED_SOFTWARE",
    4: "POTENTIALLY_HARMFUL_APPLICATION",
}

_THREAT_ATTR_NAMES = {
    0: "THREAT_ATTRIBUTE_UNSPECIFIED",
    1: "CANARY",
    2: "FRAME_ONLY",
}


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while pos < len(buf):
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, pos
        shift += 7
        if shift > 63:
            raise ValueError("Malformed protobuf varint.")
    raise ValueError("Truncated protobuf varint.")


def _skip_field(buf: bytes, pos: int, wire_type: int) -> int:
    if wire_type == 0:
        _, pos = _read_varint(buf, pos)
        return pos
    if wire_type == 1:
        if pos + 8 > len(buf):
            raise ValueError("Truncated 64-bit protobuf field.")
        return pos + 8
    if wire_type == 2:
        length, pos = _read_varint(buf, pos)
        if pos + length > len(buf):
            raise ValueError("Truncated length-delimited protobuf field.")
        return pos + length
    if wire_type == 5:
        if pos + 4 > len(buf):
            raise ValueError("Truncated 32-bit protobuf field.")
        return pos + 4
    raise ValueError(f"Unsupported protobuf wire type: {wire_type}")


def _decode_full_hash_detail(buf: bytes) -> dict[str, Any]:
    pos = 0
    threat_type = "THREAT_TYPE_UNSPECIFIED"
    attributes: list[str] = []
    while pos < len(buf):
        tag, pos = _read_varint(buf, pos)
        field_num = tag >> 3
        wire_type = tag & 0x07
        if field_num == 1 and wire_type == 0:
            val, pos = _read_varint(buf, pos)
            threat_type = _THREAT_TYPE_NAMES.get(val, f"UNKNOWN_{val}")
        elif field_num == 2 and wire_type == 0:
            val, pos = _read_varint(buf, pos)
            attributes.append(_THREAT_ATTR_NAMES.get(val, f"ATTR_{val}"))
        elif field_num == 2 and wire_type == 2:
            length, pos = _read_varint(buf, pos)
            end = pos + length
            while pos < end:
                val, pos = _read_varint(buf, pos)
                attributes.append(_THREAT_ATTR_NAMES.get(val, f"ATTR_{val}"))
        else:
            pos = _skip_field(buf, pos, wire_type)
    return {"threatType": threat_type, "attributes": attributes}


def _decode_full_hash(buf: bytes) -> dict[str, Any]:
    pos = 0
    full_hash_bytes = b""
    details: list[dict[str, Any]] = []
    while pos < len(buf):
        tag, pos = _read_varint(buf, pos)
        field_num = tag >> 3
        wire_type = tag & 0x07
        if field_num == 1 and wire_type == 2:
            length, pos = _read_varint(buf, pos)
            if pos + length > len(buf):
                raise ValueError("Truncated full_hash bytes.")
            full_hash_bytes = buf[pos : pos + length]
            pos += length
        elif field_num == 2 and wire_type == 2:
            length, pos = _read_varint(buf, pos)
            if pos + length > len(buf):
                raise ValueError("Truncated full_hash_details message.")
            details.append(_decode_full_hash_detail(buf[pos : pos + length]))
            pos += length
        else:
            pos = _skip_field(buf, pos, wire_type)
    return {
        "fullHash": base64.b64encode(full_hash_bytes).decode("ascii"),
        "fullHashDetails": details,
    }


def _decode_duration(buf: bytes) -> str:
    pos = 0
    seconds = 0
    while pos < len(buf):
        tag, pos = _read_varint(buf, pos)
        field_num = tag >> 3
        wire_type = tag & 0x07
        if field_num == 1 and wire_type == 0:
            seconds, pos = _read_varint(buf, pos)
        else:
            pos = _skip_field(buf, pos, wire_type)
    return f"{seconds}s"


def decode_search_hashes_response(payload: bytes) -> dict[str, Any]:
    """Decode Safe Browsing v5 SearchHashesResponse from binary protobuf wire format."""
    pos = 0
    full_hashes: list[dict[str, Any]] = []
    cache_duration = "0s"
    while pos < len(payload):
        tag, pos = _read_varint(payload, pos)
        field_num = tag >> 3
        wire_type = tag & 0x07
        if field_num == 1 and wire_type == 2:
            length, pos = _read_varint(payload, pos)
            if pos + length > len(payload):
                raise ValueError("Truncated FullHash message.")
            full_hashes.append(_decode_full_hash(payload[pos : pos + length]))
            pos += length
        elif field_num == 2 and wire_type == 2:
            length, pos = _read_varint(payload, pos)
            if pos + length > len(payload):
                raise ValueError("Truncated cache_duration message.")
            cache_duration = _decode_duration(payload[pos : pos + length])
            pos += length
        else:
            pos = _skip_field(payload, pos, wire_type)
    return {"fullHashes": full_hashes, "cacheDuration": cache_duration}


def check_safe_browsing_v5(
    hash_prefixes_b64: list[str],
    candidate_full_hashes_b64: list[str],
    api_key: str,
    timeout_seconds: int = 5,
    http_get: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Query Google Safe Browsing API v5 hashes:search using 4-byte SHA-256 prefixes."""
    if not api_key:
        return {
            "status": "unavailable",
            "display_status": "Reputation information unavailable",
            "reason": "Google Safe Browsing API key is not configured on this server.",
            "matches": [],
            "attribution": None,
        }

    if not hash_prefixes_b64:
        return {
            "status": "skipped",
            "display_status": "Reputation check skipped",
            "reason": "No eligible privacy-reduced hash prefixes could be generated.",
            "matches": [],
            "attribution": None,
        }

    getter = http_get or requests.get
    params: list[tuple[str, str]] = [("key", api_key)]
    for prefix in hash_prefixes_b64[:30]:
        params.append(("hashPrefixes", prefix))

    try:
        response = getter(
            SAFE_BROWSING_V5_ENDPOINT,
            params=params,
            timeout=timeout_seconds,
            allow_redirects=False,
        )
    except requests.Timeout:
        return {
            "status": "unavailable",
            "display_status": "Reputation information unavailable",
            "reason": "Safe Browsing lookup timed out.",
            "matches": [],
            "attribution": None,
        }
    except requests.RequestException:
        return {
            "status": "unavailable",
            "display_status": "Reputation information unavailable",
            "reason": "Could not reach Google Safe Browsing service.",
            "matches": [],
            "attribution": None,
        }

    if response.status_code == 429:
        return {
            "status": "unavailable",
            "display_status": "Reputation information unavailable",
            "reason": "Safe Browsing API quota limit reached.",
            "matches": [],
            "attribution": None,
        }

    if response.status_code != 200:
        return {
            "status": "unavailable",
            "display_status": "Reputation information unavailable",
            "reason": f"Safe Browsing service returned HTTP {response.status_code}.",
            "matches": [],
            "attribution": None,
        }

    content_type = (response.headers.get("Content-Type") or "").lower()
    raw_content: bytes = response.content or b""
    try:
        if "json" in content_type or raw_content.lstrip().startswith(b"{"):
            decoded = response.json()
        else:
            decoded = decode_search_hashes_response(raw_content)
    except (ValueError, TypeError):
        return {
            "status": "unavailable",
            "display_status": "Reputation information unavailable",
            "reason": "Invalid response format received from Safe Browsing.",
            "matches": [],
            "attribution": None,
        }

    if not isinstance(decoded, dict):
        return {
            "status": "unavailable",
            "display_status": "Reputation information unavailable",
            "reason": "Unexpected Safe Browsing payload structure.",
            "matches": [],
            "attribution": None,
        }

    candidate_raw = {base64.b64decode(h) for h in candidate_full_hashes_b64}
    matched_threats: list[dict[str, Any]] = []

    for entry in decoded.get("fullHashes", []):
        if not isinstance(entry, dict) or not entry.get("fullHash"):
            continue
        try:
            returned_raw = base64.b64decode(entry["fullHash"])
        except Exception:
            continue
        if returned_raw in candidate_raw:
            for detail in entry.get("fullHashDetails", []):
                threat_type = detail.get("threatType", "THREAT_TYPE_UNSPECIFIED")
                if threat_type != "THREAT_TYPE_UNSPECIFIED":
                    matched_threats.append(
                        {
                            "threat_type": threat_type,
                            "attributes": detail.get("attributes", []),
                        }
                    )

    if matched_threats:
        return {
            "status": "matched",
            "display_status": "Threat match reported by Google Safe Browsing",
            "reason": "One or more privacy-reduced expressions matched an active Safe Browsing threat list.",
            "matches": matched_threats,
            "cache_duration": decoded.get("cacheDuration"),
            "attribution": SAFE_BROWSING_ATTRIBUTION,
        }

    return {
        "status": "not_listed",
        "display_status": "Not listed in Google Safe Browsing",
        "reason": (
            "No threat match was returned for the checked hash prefixes. "
            "Absence from this feed does not prove the URL is safe."
        ),
        "matches": [],
        "cache_duration": decoded.get("cacheDuration"),
        "attribution": SAFE_BROWSING_ATTRIBUTION,
    }


def _is_public_https_rdap_url(url: str) -> bool:
    parsed = urlsplit(url)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        return False
    host = parsed.hostname.lower()
    if host in {"localhost"} or host.endswith((".local", ".internal", ".invalid")):
        return False
    try:
        ip_obj = ipaddress.ip_address(host)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved)
    except ValueError:
        pass
    try:
        resolved = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        for item in resolved:
            ip_str = item[4][0]
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
                return False
    except OSError:
        # DNS failure will be handled cleanly by requests
        return True
    return True


def _extract_registrar_name(rdap_json: dict[str, Any]) -> str | None:
    for entity in rdap_json.get("entities", []):
        if not isinstance(entity, dict):
            continue
        roles = entity.get("roles", [])
        if "registrar" not in roles:
            continue
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) >= 2 and isinstance(vcard[1], list):
            for prop in vcard[1]:
                if isinstance(prop, list) and len(prop) >= 4 and prop[0] in {"fn", "org"}:
                    if isinstance(prop[3], str) and prop[3].strip():
                        return prop[3].strip()
    return None


def lookup_rdap_domain(
    registrable_domain: str | None,
    base_url: str = "https://rdap.org/domain/",
    timeout_seconds: int = 5,
    http_get: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Query ICANN RDAP using ONLY the registrable domain and return contextual metadata."""
    if not registrable_domain:
        return {
            "status": "skipped",
            "display_status": "RDAP lookup skipped",
            "reason": "RDAP requires a valid public registrable domain name.",
            "domain": None,
        }

    getter = http_get or requests.get
    clean_base = base_url if base_url.endswith("/") else f"{base_url}/"
    target_url = f"{clean_base}{registrable_domain}"

    try:
        response = None
        current_url = target_url
        for _ in range(3):
            if not _is_public_https_rdap_url(current_url):
                return {
                    "status": "unavailable",
                    "display_status": "Reputation information unavailable",
                    "reason": "RDAP target URL failed outbound safety validation.",
                    "domain": registrable_domain,
                }
            response = getter(
                current_url,
                headers={"Accept": "application/rdap+json, application/json"},
                timeout=timeout_seconds,
                allow_redirects=False,
            )
            if response.status_code in {301, 302, 303, 307, 308} and response.headers.get("Location"):
                current_url = urljoin(current_url, response.headers["Location"])
                continue
            break
    except requests.Timeout:
        return {
            "status": "unavailable",
            "display_status": "Reputation information unavailable",
            "reason": "RDAP lookup timed out.",
            "domain": registrable_domain,
        }
    except requests.RequestException:
        return {
            "status": "unavailable",
            "display_status": "Reputation information unavailable",
            "reason": "Could not reach RDAP domain registry service.",
            "domain": registrable_domain,
        }

    if response is None:
        return {
            "status": "unavailable",
            "display_status": "Reputation information unavailable",
            "reason": "RDAP lookup did not complete.",
            "domain": registrable_domain,
        }

    if response.status_code == 404:
        return {
            "status": "not_found",
            "display_status": "Domain not found in RDAP",
            "reason": "The RDAP registry returned 404 (not found or unregistered).",
            "domain": registrable_domain,
        }

    if response.status_code == 429:
        return {
            "status": "unavailable",
            "display_status": "Reputation information unavailable",
            "reason": "RDAP service rate limit exceeded.",
            "domain": registrable_domain,
        }

    if response.status_code != 200:
        return {
            "status": "unavailable",
            "display_status": "Reputation information unavailable",
            "reason": f"RDAP service returned HTTP {response.status_code}.",
            "domain": registrable_domain,
        }

    try:
        data = response.json()
    except (ValueError, TypeError):
        return {
            "status": "unavailable",
            "display_status": "Reputation information unavailable",
            "reason": "Invalid JSON returned by RDAP service.",
            "domain": registrable_domain,
        }

    if not isinstance(data, dict):
        return {
            "status": "unavailable",
            "display_status": "Reputation information unavailable",
            "reason": "Unexpected RDAP payload structure.",
            "domain": registrable_domain,
        }

    events_map: dict[str, str] = {}
    for ev in data.get("events", []):
        if isinstance(ev, dict) and ev.get("eventAction") and ev.get("eventDate"):
            events_map[str(ev["eventAction"])] = str(ev["eventDate"])

    reg_date_str = events_map.get("registration")
    age_days: int | None = None
    recently_registered = False
    if reg_date_str:
        try:
            reg_dt = datetime.fromisoformat(reg_date_str.replace("Z", "+00:00"))
            age_days = max(0, (datetime.now(timezone.utc) - reg_dt).days)
            recently_registered = age_days < 90
        except ValueError:
            age_days = None

    return {
        "status": "ok",
        "display_status": "Contextual domain registration data retrieved",
        "domain": data.get("ldhName") or registrable_domain,
        "registrar": _extract_registrar_name(data),
        "registration_date": reg_date_str,
        "last_changed": events_map.get("last changed"),
        "expiration_date": events_map.get("expiration"),
        "domain_statuses": data.get("status", [])[:6],
        "age_days": age_days,
        "recently_registered": recently_registered,
        "contextual_note": (
            "RDAP registration details are contextual domain metadata only, not a malware or safety verdict."
        ),
    }
