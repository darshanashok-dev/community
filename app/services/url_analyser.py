"""Text-only URL structural analyser and privacy-reduction pipeline.

Privacy & safety contract:
- Parses URLs strictly as text; never opens, fetches, or connects to submitted URLs.
- Never follows redirects or expands shortened links.
- Strips credentials, query parameters, fragments, and token-like path segments before
  preparing privacy-reduced Safe Browsing v5 hash prefixes or registrable-domain RDAP inputs.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import posixpath
import re
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import publicsuffix2

DEFAULT_URL_RULES_PATH = Path(__file__).resolve().parent.parent / "database" / "url_rules.json"
_PSL = publicsuffix2.PublicSuffixList(idna=True)
_NON_PUBLIC_TLDS = frozenset(
    {"localhost", "local", "internal", "invalid", "lan", "home", "arpa", "example", "test"}
)
_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)

_SHORTHAND_OR_RADIX_IP_RE = re.compile(
    r"^(?:0x[0-9a-f]+|0[0-7]+|\d+)(?:\.(?:0x[0-9a-f]+|0[0-7]+|\d+)){0,3}$",
    re.IGNORECASE,
)
_HEX_OR_UUID_SEGMENT_RE = re.compile(
    r"^(?:[0-9a-f]{16,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$",
    re.IGNORECASE,
)
_TOKEN_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_-]{18,}$")
_LONG_DIGITS_RE = re.compile(r"^\d{8,}$")


class UrlValidationError(ValueError):
    """Raised when submitted URL input fails validation."""


@lru_cache(maxsize=4)
def load_url_rules(rules_path: Path = DEFAULT_URL_RULES_PATH) -> dict[str, Any]:
    with rules_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ch_a in enumerate(a, start=1):
        curr = [i]
        for j, ch_b in enumerate(b, start=1):
            cost = 0 if ch_a == ch_b else 1
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


def _normalize_leet(value: str) -> str:
    return (
        value.replace("0", "o")
        .replace("1", "l")
        .replace("3", "e")
        .replace("4", "a")
        .replace("5", "s")
        .replace("7", "t")
        .replace("rn", "m")
        .replace("vv", "w")
    )


def _try_parse_ip_host(hostname: str) -> str | None:
    """Return canonical IP string if hostname is an IPv4/IPv6/hex/octal/shorthand IP."""
    stripped = hostname.strip("[]")
    try:
        return str(ipaddress.ip_address(stripped))
    except ValueError:
        pass

    if _SHORTHAND_OR_RADIX_IP_RE.match(stripped):
        parts = stripped.split(".")
        try:
            if len(parts) == 1:
                num = int(parts[0], 0)
                if 0 <= num <= 0xFFFFFFFF:
                    return str(ipaddress.IPv4Address(num))
            elif len(parts) in (2, 3, 4):
                nums = [int(p, 0) for p in parts]
                if len(nums) == 4 and all(0 <= n <= 255 for n in nums):
                    return ".".join(str(n) for n in nums)
                if len(nums) == 2 and 0 <= nums[0] <= 255 and 0 <= nums[1] <= 0xFFFFFF:
                    val = (nums[0] << 24) | nums[1]
                    return str(ipaddress.IPv4Address(val))
                if (
                    len(nums) == 3
                    and 0 <= nums[0] <= 255
                    and 0 <= nums[1] <= 255
                    and 0 <= nums[2] <= 0xFFFF
                ):
                    val = (nums[0] << 24) | (nums[1] << 16) | nums[2]
                    return str(ipaddress.IPv4Address(val))
        except ValueError:
            return None
    return None


def extract_registrable_domain(
    hostname: str,
    multi_part_tlds: set[str] | None = None,
) -> str | None:
    """Extract registrable domain (eTLD+1) offline using the Mozilla Public Suffix List.

    Returns None for IP addresses, malformed hosts, non-public local suffixes,
    or bare public suffixes (e.g., 'co.uk', 'com.mx', 'com').
    """
    del multi_part_tlds  # Retained only for backward signature compatibility.
    host = hostname.strip().strip(".").lower()
    if not host or "." not in host:
        return None
    if _try_parse_ip_host(host) is not None:
        return None

    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None

    labels = ascii_host.split(".")
    if len(labels) < 2 or any(not lbl or not _DNS_LABEL_RE.match(lbl) for lbl in labels):
        return None

    if labels[-1] in _NON_PUBLIC_TLDS:
        return None

    sld = _PSL.get_sld(ascii_host, strict=True)
    tld = _PSL.get_tld(ascii_host)
    if not sld or not tld or sld == tld:
        return None
    if "." not in sld:
        return None
    return sld


def _has_mixed_or_non_ascii_script(hostname: str) -> bool:
    return any(ord(ch) > 127 for ch in hostname)


def _strip_token_like_path_segments(path: str) -> tuple[str, bool]:
    """Strip token-like, email-like, or long numeric ID segments from a path.

    Returns (reduced_path, had_token_segments).
    """
    if not path or path == "/":
        return "/", False

    segments = [seg for seg in path.split("/") if seg]
    kept: list[str] = []
    stripped_any = False

    for seg in segments:
        decoded = unquote(seg)
        is_token = (
            "@" in decoded
            or bool(_HEX_OR_UUID_SEGMENT_RE.match(decoded))
            or bool(_TOKEN_SEGMENT_RE.match(decoded))
            or bool(_LONG_DIGITS_RE.match(decoded))
        )
        if is_token:
            stripped_any = True
            break
        kept.append(seg)

    if not kept:
        return "/", stripped_any
    trailing = "/" if (path.endswith("/") or stripped_any) else ""
    return "/" + "/".join(kept) + trailing, stripped_any


def _repeated_unquote(value: str, max_passes: int = 5) -> str:
    current = value
    for _ in range(max_passes):
        nxt = unquote(current)
        if nxt == current:
            break
        current = nxt
    return current


def _canonicalize_for_safe_browsing(scheme: str, host: str, port: int | None, path: str) -> str:
    """Canonicalize a privacy-reduced URL following Safe Browsing rules (no query/fragment/creds)."""
    clean_host = re.sub(r"\.+", ".", host.strip(".").lower())
    ip_norm = _try_parse_ip_host(clean_host)
    if ip_norm:
        clean_host = f"[{ip_norm}]" if ":" in ip_norm else ip_norm

    unescaped_path = _repeated_unquote(path or "/")
    unescaped_path = re.sub(r"[\t\r\n]", "", unescaped_path)
    normalized_path = posixpath.normpath(unescaped_path)
    if not normalized_path.startswith("/"):
        normalized_path = "/" + normalized_path
    if unescaped_path.endswith("/") and not normalized_path.endswith("/"):
        normalized_path += "/"
    normalized_path = re.sub(r"/{2,}", "/", normalized_path)

    # Percent-encode spaces and control chars cleanly
    safe_path = "".join(
        f"%{ord(ch):02X}" if ord(ch) <= 0x20 or ord(ch) >= 0x7F or ch == "#" or ch == "%"
        else ch
        for ch in normalized_path
    )

    netloc = clean_host
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{clean_host}:{port}"

    return f"{scheme}://{netloc}{safe_path}"


def generate_safe_browsing_expressions(canonical_url: str) -> list[str]:
    """Generate up to 30 Safe Browsing host-suffix / path-prefix expressions."""
    parsed = urlsplit(canonical_url)
    host = (parsed.hostname or "").lower()
    if not host:
        return []

    ip_norm = _try_parse_ip_host(host)
    if ip_norm:
        host_candidates = [ip_norm]
    else:
        labels = [lbl for lbl in host.split(".") if lbl]
        host_candidates = [host]
        # Up to 5 host suffixes: full host + up to 4 trailing suffix slices down to 2 labels
        for idx in range(1, len(labels) - 1):
            candidate = ".".join(labels[idx:])
            if candidate not in host_candidates:
                host_candidates.append(candidate)
            if len(host_candidates) >= 5:
                break

    path = parsed.path or "/"
    path_candidates = [path]
    if path != "/":
        parts = [p for p in path.split("/") if p]
        prefix = "/"
        if prefix not in path_candidates:
            path_candidates.append(prefix)
        for part in parts[:-1]:
            prefix = f"{prefix}{part}/"
            if prefix not in path_candidates:
                path_candidates.append(prefix)
            if len(path_candidates) >= 6:
                break
        if len(path_candidates) < 6 and "/" not in path_candidates:
            path_candidates.append("/")

    # Deduplicate and cap at 30 expressions
    expressions: list[str] = []
    for h in host_candidates[:5]:
        for p in path_candidates[:6]:
            expr = f"{h}{p}"
            if expr not in expressions:
                expressions.append(expr)
            if len(expressions) >= 30:
                return expressions
    return expressions


def prepare_privacy_reduced_indicators(
    raw_url: str,
    rules_path: Path = DEFAULT_URL_RULES_PATH,
) -> dict[str, Any]:
    """Strip sensitive components and prepare 4-byte SHA-256 prefixes + registrable domain."""
    rules = load_url_rules(rules_path)
    shorteners = set(rules["shorteners"])

    parsed = urlsplit(raw_url.strip())
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().strip(".")
    try:
        port = parsed.port
    except ValueError:
        port = None

    registrable_domain = extract_registrable_domain(host)
    is_shortener = host in shorteners or (registrable_domain in shorteners if registrable_domain else False)

    # Strip userinfo, query string, fragment, and token-like path segments
    reduced_path, had_tokens = _strip_token_like_path_segments(parsed.path or "/")

    # Skip Safe Browsing if host is missing, non-public/local, or is an unexpanded shortener
    is_private_or_local = False
    ip_norm = _try_parse_ip_host(host)
    if ip_norm:
        try:
            ip_obj = ipaddress.ip_address(ip_norm)
            is_private_or_local = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved
        except ValueError:
            is_private_or_local = True
    elif host in {"localhost"} or host.endswith((".local", ".internal", ".invalid", ".lan")):
        is_private_or_local = True

    if not host or is_private_or_local or is_shortener:
        skip_reason = (
            "Shortened URLs cannot be verified via external hash lookup without expanding the hidden destination."
            if is_shortener
            else "External reputation lookup skipped because the host is local, private, or cannot be safely reduced."
        )
        return {
            "safe_browsing_eligible": False,
            "skip_reason": skip_reason,
            "reduced_url_preview": None,
            "registrable_domain": registrable_domain if not is_private_or_local else None,
            "hash_prefixes_b64": [],
            "full_hashes": [],
            "stripped_sensitive_parts": bool(parsed.username or parsed.password or parsed.query or parsed.fragment or had_tokens),
        }

    canonical_reduced = _canonicalize_for_safe_browsing(scheme, host, port, reduced_path)
    expressions = generate_safe_browsing_expressions(canonical_reduced)
    full_hashes_bytes = [hashlib.sha256(expr.encode("utf-8")).digest() for expr in expressions]
    prefixes_b64: list[str] = []
    seen_prefixes: set[bytes] = set()
    for digest in full_hashes_bytes:
        prefix = digest[:4]
        if prefix not in seen_prefixes:
            seen_prefixes.add(prefix)
            prefixes_b64.append(base64.b64encode(prefix).decode("ascii"))

    return {
        "safe_browsing_eligible": bool(prefixes_b64),
        "skip_reason": None if prefixes_b64 else "Could not derive Safe Browsing hash expressions.",
        "reduced_url_preview": canonical_reduced,
        "registrable_domain": registrable_domain,
        "hash_prefixes_b64": prefixes_b64,
        "full_hashes": [base64.b64encode(d).decode("ascii") for d in full_hashes_bytes],
        "stripped_sensitive_parts": bool(
            parsed.username or parsed.password or parsed.query or parsed.fragment or had_tokens
        ),
    }


def _select_category(score: int, categories: list[dict[str, Any]]) -> dict[str, Any]:
    for cat in categories:
        if cat["min_score"] <= score <= cat["max_score"]:
            return cat
    return categories[-1]


def analyze_url_locally(
    raw_url: str | None,
    max_length: int = 2048,
    rules_path: Path = DEFAULT_URL_RULES_PATH,
) -> dict[str, Any]:
    """Inspect a submitted HTTP/HTTPS URL strictly as text without visiting it."""
    if raw_url is None or not isinstance(raw_url, str):
        raise UrlValidationError("Please enter a URL to inspect.")

    trimmed = raw_url.strip()
    if not trimmed:
        raise UrlValidationError("URL input cannot be empty.")

    if len(trimmed) > max_length:
        raise UrlValidationError(
            f"URL exceeds the maximum allowed length of {max_length} characters."
        )

    if any(ch.isspace() for ch in trimmed):
        raise UrlValidationError("URL cannot contain spaces or line breaks.")

    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", trimmed) and not trimmed.lower().startswith(
        ("http://", "https://")
    ):
        raise UrlValidationError(
            "Only http:// and https:// URLs are supported for text inspection."
        )

    if "://" not in trimmed:
        raise UrlValidationError(
            "Please submit a complete HTTP or HTTPS URL (for example, https://example.com)."
        )

    try:
        parsed = urlsplit(trimmed)
    except ValueError as exc:
        raise UrlValidationError("The submitted URL structure could not be parsed.") from exc

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise UrlValidationError(
            "Only http:// and https:// URLs are supported for text inspection."
        )

    if not parsed.hostname:
        raise UrlValidationError("The submitted URL does not contain a valid hostname.")

    try:
        port = parsed.port
    except ValueError as exc:
        raise UrlValidationError("The submitted URL contains an invalid port number.") from exc

    rules = load_url_rules(rules_path)
    weights = rules["weights"]
    shorteners = set(rules["shorteners"])
    brands = list(rules["protected_brands"])
    official_domains = set(rules["official_domains"])
    path_keywords = set(rules["suspicious_path_keywords"])
    risky_tlds = set(rules["risky_tlds"])

    host = parsed.hostname.lower().strip(".")
    registrable_domain = extract_registrable_domain(host)
    indicators: list[dict[str, Any]] = []

    # 1. IP-based host check (dotted decimal, hex, octal, shorthand, IPv6)
    ip_host = _try_parse_ip_host(host)
    if ip_host is not None:
        indicators.append(
            {
                "id": "ip_host",
                "title": "IP Address Used Instead of Domain Name",
                "contribution": int(weights["ip_host"]),
                "why_it_matters": (
                    f"The host resolves structurally to IP address '{ip_host}' instead of a registered domain name, "
                    "a common tactic to hide phishing hosts."
                ),
            }
        )

    # 2. Embedded credentials / '@' userinfo trick
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        indicators.append(
            {
                "id": "userinfo_at_trick",
                "title": "Embedded Credentials or '@' Host Obfuscation",
                "contribution": int(weights["non_http_scheme_or_userinfo"]),
                "why_it_matters": (
                    "Text before '@' in a web address is treated as login credentials while the browser actually visits "
                    "the domain after '@', often used to disguise a fake link."
                ),
            }
        )

    # 3. Punycode / IDN homograph check
    if "xn--" in host or _has_mixed_or_non_ascii_script(host):
        indicators.append(
            {
                "id": "punycode_homograph",
                "title": "Punycode or Non-ASCII Look-Alike Domain Characters",
                "contribution": int(weights["punycode_or_homograph"]),
                "why_it_matters": (
                    "Internationalized ('xn--') or non-ASCII domain characters can visually imitate familiar Latin letters "
                    "in homograph phishing attacks."
                ),
            }
        )

    # 4. Shortener detection
    is_shortener = host in shorteners or (
        registrable_domain in shorteners if registrable_domain else False
    )
    if is_shortener:
        indicators.append(
            {
                "id": "shortener_unverified",
                "title": "URL Shortener — Destination Not Verified",
                "contribution": int(weights["shortener_unverified"]),
                "why_it_matters": (
                    "Shortened links conceal the real destination domain. This platform never expands shorteners automatically, "
                    "so the final destination remains unverified."
                ),
            }
        )

    # 5. Subdomain, brand-in-subdomain, and look-alike domain checks
    labels = host.split(".")
    if ip_host is None and registrable_domain is None:
        if any(not lbl or not _DNS_LABEL_RE.match(lbl) for lbl in labels) or (
            "." in host and labels[-1] not in _NON_PUBLIC_TLDS
        ):
            indicators.append(
                {
                    "id": "invalid_or_public_suffix_host",
                    "title": "Malformed Hostname or Bare Public Suffix",
                    "contribution": int(weights["invalid_or_public_suffix_host"]),
                    "why_it_matters": (
                        "The URL hostname is either syntactically irregular or resolves only to a bare public suffix "
                        "rather than a valid registrable domain."
                    ),
                }
            )
    if ip_host is None and registrable_domain:
        is_official = host in official_domains or registrable_domain in official_domains
        subdomain_part = host[: -len(registrable_domain)].rstrip(".")
        subdomain_labels = [lbl for lbl in subdomain_part.split(".") if lbl]

        if len(subdomain_labels) >= 3:
            indicators.append(
                {
                    "id": "excessive_subdomains",
                    "title": "Unusually Deep Subdomain Nesting",
                    "contribution": int(weights["excessive_subdomains"]),
                    "why_it_matters": (
                        f"The host contains {len(subdomain_labels)} subdomain levels before '{registrable_domain}', "
                        "which can push the real domain out of view on mobile screens."
                    ),
                }
            )

        if not is_official and subdomain_part:
            matched_brand = next(
                (b for b in brands if len(b) >= 3 and re.search(rf"(^|[-.]){re.escape(b)}($|[-.])", subdomain_part)),
                None,
            )
            if matched_brand:
                indicators.append(
                    {
                        "id": "brand_in_subdomain",
                        "title": "Recognised Brand Name Placed in Subdomain",
                        "contribution": int(weights["brand_in_subdomain"]),
                        "why_it_matters": (
                            f"The brand-like term '{matched_brand}' appears in a subdomain, while the actual controlling "
                            f"registrable domain is '{registrable_domain}'."
                        ),
                    }
                )

        # Look-alike check on the registrable label itself (including leet-speak & hyphenated parts)
        reg_label = registrable_domain.split(".")[0]
        if not is_official:
            normalized_reg = _normalize_leet(reg_label)
            norm_parts = [p for p in normalized_reg.split("-") if p]
            lookalike_hit = None
            for brand in brands:
                if len(brand) < 4:
                    continue
                if brand in normalized_reg and reg_label != brand:
                    lookalike_hit = brand
                    break
                if _levenshtein(normalized_reg, brand) == 1 and reg_label != brand:
                    lookalike_hit = brand
                    break
                if any(_levenshtein(part, brand) == 1 and part != brand for part in norm_parts):
                    lookalike_hit = brand
                    break
            if lookalike_hit:
                indicators.append(
                    {
                        "id": "lookalike_domain",
                        "title": "Potential Brand Look-Alike Domain",
                        "contribution": int(weights["lookalike_domain"]),
                        "why_it_matters": (
                            f"The registrable domain '{registrable_domain}' resembles or embeds '{lookalike_hit}' "
                            "and is not in the known official reference list."
                        ),
                    }
                )

        # Risky TLD check
        tld = labels[-1] if labels else ""
        if tld in risky_tlds:
            indicators.append(
                {
                    "id": "risky_tld",
                    "title": f"High-Abuse Top-Level Domain (.{tld})",
                    "contribution": int(weights["risky_tld"]),
                    "why_it_matters": (
                        f"Low-cost or frequently abused top-level domains such as '.{tld}' are commonly used in short-lived phishing campaigns."
                    ),
                }
            )

    # 6. Suspicious path / query keywords & APK hints
    lower_path_query = f"{parsed.path} {parsed.query}".lower()
    tokens_in_path = set(re.findall(r"[a-z0-9]+", lower_path_query))
    matched_path_kw = sorted(tokens_in_path & path_keywords)
    if lower_path_query.endswith(".apk") or ".apk" in lower_path_query:
        indicators.append(
            {
                "id": "apk_download_hint",
                "title": "Direct Android Package (.apk) Link Reference",
                "contribution": int(weights["apk_download_hint"]),
                "why_it_matters": (
                    "Links pointing directly to '.apk' files outside official app stores are frequently used to distribute malicious Android apps."
                ),
            }
        )
    elif matched_path_kw:
        indicators.append(
            {
                "id": "suspicious_path_keywords",
                "title": "Sensitive Action Keywords in URL Path or Parameters",
                "contribution": int(weights["suspicious_path_keywords"]),
                "why_it_matters": (
                    f"The URL path/query uses action keywords ({', '.join(matched_path_kw[:4])}) often seen in credential or KYC phishing pages."
                ),
            }
        )

    # 7. Obfuscated encoding / double encoding / backslashes
    percent_count = len(re.findall(r"%[0-9a-fA-F]{2}", trimmed))
    if "%25" in trimmed or percent_count >= 5 or "\\" in trimmed or "//" in (parsed.path or ""):
        indicators.append(
            {
                "id": "obfuscated_encoding",
                "title": "Obfuscated URL Encoding or Path Structure",
                "contribution": int(weights["obfuscated_encoding"]),
                "why_it_matters": (
                    "Repeated percent-encoding, double-encoded '%25' sequences, or extra slashes can hide deceptive URL paths."
                ),
            }
        )

    # 8. Non-standard port
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        indicators.append(
            {
                "id": "non_standard_port",
                "title": f"Non-Standard Network Port (:{port})",
                "contribution": int(weights["non_standard_port"]),
                "why_it_matters": (
                    "Legitimate public banking, delivery, and government portals rarely serve user links on non-standard port numbers."
                ),
            }
        )

    # 9. Unusual URL length
    if len(trimmed) > 95:
        indicators.append(
            {
                "id": "unusual_length",
                "title": f"Unusually Long URL ({len(trimmed)} characters)",
                "contribution": int(weights["unusual_length"]),
                "why_it_matters": (
                    "Long URLs packed with parameters or nested paths are often used to obscure the true domain on mobile screens."
                ),
            }
        )

    # 10. Plain HTTP with sensitive keywords
    if scheme == "http" and (matched_path_kw or any(i["id"] == "lookalike_domain" for i in indicators)):
        indicators.append(
            {
                "id": "plain_http_sensitive",
                "title": "Unencrypted HTTP Link with Sensitive Action Cues",
                "contribution": int(weights["plain_http_with_sensitive_path"]),
                "why_it_matters": (
                    "Using unencrypted 'http://' for account verification, login, or payment pages is unsafe and abnormal for legitimate services."
                ),
            }
        )

    raw_score = sum(item["contribution"] for item in indicators)
    min_score = int(rules["score_bounds"]["min"])
    max_score = int(rules["score_bounds"]["max"])
    final_score = max(min_score, min(max_score, raw_score))
    category = _select_category(final_score, rules["categories"])

    privacy_prep = prepare_privacy_reduced_indicators(trimmed, rules_path=rules_path)

    recommended_actions = [
        "Never click an unfamiliar link directly from SMS, WhatsApp, or email—open the organisation's official app or type its known address manually.",
    ]
    if is_shortener:
        recommended_actions.append(
            "Because shortened links hide the real website until opened, do not visit this link unless you verified it with the sender via a separate channel."
        )
    if final_score >= 31:
        recommended_actions.append(
            "Do not enter OTPs, passwords, banking details, or download APK files from this address."
        )
    else:
        recommended_actions.append(
            "Treat 'No known red flags' as advisory only: a clean-looking domain can still host fraudulent content."
        )

    return {
        "scheme": scheme,
        "hostname": host,
        "registrable_domain": registrable_domain,
        "is_shortener": is_shortener,
        "destination_status": "Destination not verified (shortened URL not expanded)" if is_shortener else "Inspected as text only (never visited)",
        "url_length": len(trimmed),
        "score": final_score,
        "category": {
            "id": category["id"],
            "label": category["label"],
            "badge_kind": category["badge_kind"],
            "summary": category["summary"],
        },
        "matched_indicators": indicators,
        "privacy_reduction": {
            "safe_browsing_eligible": privacy_prep["safe_browsing_eligible"],
            "skip_reason": privacy_prep["skip_reason"],
            "reduced_url_preview": privacy_prep["reduced_url_preview"],
            "registrable_domain": privacy_prep["registrable_domain"],
            "hash_prefix_count": len(privacy_prep["hash_prefixes_b64"]),
            "stripped_sensitive_parts": privacy_prep["stripped_sensitive_parts"],
        },
        "_safe_browsing_payload": {
            "hash_prefixes_b64": privacy_prep["hash_prefixes_b64"],
            "full_hashes": privacy_prep["full_hashes"],
        },
        "recommended_actions": recommended_actions,
        "advisory_note": (
            "Advisory local inspection only: this URL was never visited, opened, or fetched. "
            "No score guarantees a link is safe."
        ),
        "rules_version": rules["version"],
    }
