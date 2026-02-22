"""
PhishGuard — URL Feature Extractor
Extracts 30+ heuristic features from a URL for the ML model.
Uses only Python stdlib — no external packages required for this module.
"""

import re
import math
import socket
import urllib.parse
from datetime import datetime, timezone
from typing import Any

# ─── Known high-abuse TLDs (from ICANN / Spamhaus abuse reports) ─────────────
HIGH_RISK_TLDS = {
    "tk", "ml", "ga", "cf", "gq",
    "xyz", "top", "icu", "buzz", "click",
    "pw", "date", "download", "racing",
    "win", "loan", "party", "stream",
    "review", "country", "science",
    "work", "trade", "link", "online",
    "site", "website", "live", "shop",
}

# ─── Suspicious keywords ──────────────────────────────────────────────────────
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "confirm", "bank", "paypal", "apple", "amazon", "google",
    "microsoft", "ebay", "netflix", "password", "credential",
    "billing", "invoice", "suspended", "urgent", "alert",
    "webscr", "validate", "auth", "recover",
]

# ─── Brand-to-official-domain mapping ────────────────────────────────────────
BRAND_DOMAINS = {
    "paypal": "paypal", "apple": "apple", "google": "google",
    "microsoft": "microsoft", "amazon": "amazon", "ebay": "ebay",
    "netflix": "netflix", "facebook": "facebook", "instagram": "instagram",
    "twitter": "twitter", "chase": "chase", "wellsfargo": "wellsfargo",
    "bankofamerica": "bankofamerica",
}

MULTI_TLDS = {"co.uk", "co.nz", "co.jp", "com.au", "com.br", "org.uk", "net.au"}


def _parse_domain_parts(hostname: str):
    """Split hostname into (subdomain, domain, tld) without external libs."""
    parts = hostname.lower().split(".")
    if len(parts) == 1:
        return "", hostname, ""
    if len(parts) == 2:
        return "", parts[0], parts[1]
    possible_multi = f"{parts[-2]}.{parts[-1]}"
    if possible_multi in MULTI_TLDS:
        tld = possible_multi
        domain = parts[-3] if len(parts) >= 3 else ""
        subdomain = ".".join(parts[:-3]) if len(parts) > 3 else ""
    else:
        tld = parts[-1]
        domain = parts[-2]
        subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
    return subdomain, domain, tld


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)


def extract_features(url: str) -> tuple:
    """
    Extract feature vector from a URL.
    Returns (features_dict, metadata_dict).
    """
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    subdomain, domain, tld = _parse_domain_parts(hostname)
    url_lower = url.lower()

    has_https = scheme == "https"
    url_length = len(url)
    path_length = len(path)
    num_dots = url.count(".")
    num_hyphens = domain.count("-") + subdomain.count("-")
    num_digits_in_domain = sum(c.isdigit() for c in domain)
    num_slashes = path.count("/")
    num_query_params = len(urllib.parse.parse_qs(query))
    has_ip_address = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname))
    has_at_symbol = "@" in url
    has_double_slash = "//" in path
    has_hex_encoding = bool(re.search(r"%[0-9a-fA-F]{2}", url))
    subdomain_parts = [s for s in subdomain.split(".") if s] if subdomain else []
    num_subdomains = len(subdomain_parts)
    subdomain_count = num_subdomains
    domain_length = len(domain)
    url_entropy = round(shannon_entropy(url), 4)
    tld_is_high_risk = tld in HIGH_RISK_TLDS

    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    suspicious_keyword_count = len(matched_keywords)

    brand_impersonation = False
    for brand, brand_domain in BRAND_DOMAINS.items():
        if brand in url_lower and domain != brand_domain:
            brand_impersonation = True
            break

    # WHOIS (optional)
    domain_age_days = -1
    domain_created_str = "Unknown"
    registered_domain = f"{domain}.{tld}" if domain and tld else hostname
    try:
        import whois
        w = whois.whois(registered_domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            domain_age_days = (datetime.now(timezone.utc) - creation_date).days
            domain_created_str = creation_date.strftime("%Y-%m-%d")
    except Exception:
        pass

    # DNS
    dns_resolves = False
    try:
        socket.setdefaulttimeout(3)
        socket.gethostbyname(hostname)
        dns_resolves = True
    except Exception:
        pass

    has_non_standard_port = bool(parsed.port and parsed.port not in (80, 443))

    features = {
        "url_length": url_length,
        "path_length": path_length,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_digits_in_domain": num_digits_in_domain,
        "num_slashes": num_slashes,
        "num_query_params": num_query_params,
        "num_subdomains": num_subdomains,
        "subdomain_count": subdomain_count,
        "domain_length": domain_length,
        "url_entropy": url_entropy,
        "suspicious_keyword_count": suspicious_keyword_count,
        "domain_age_days": domain_age_days,
        "has_https": int(has_https),
        "has_ip_address": int(has_ip_address),
        "has_at_symbol": int(has_at_symbol),
        "has_double_slash": int(has_double_slash),
        "has_hex_encoding": int(has_hex_encoding),
        "tld_is_high_risk": int(tld_is_high_risk),
        "brand_impersonation": int(brand_impersonation),
        "dns_resolves": int(dns_resolves),
        "has_non_standard_port": int(has_non_standard_port),
    }

    meta = {
        "protocol": scheme,
        "hostname": hostname,
        "tld": tld,
        "domain": domain,
        "subdomain": subdomain,
        "suspicious_keywords": matched_keywords,
        "domain_created": domain_created_str,
    }

    return features, meta


FEATURE_COLUMNS = [
    "url_length", "path_length", "num_dots", "num_hyphens",
    "num_digits_in_domain", "num_slashes", "num_query_params",
    "num_subdomains", "domain_length", "url_entropy",
    "suspicious_keyword_count", "domain_age_days",
    "has_https", "has_ip_address", "has_at_symbol",
    "has_double_slash", "has_hex_encoding", "tld_is_high_risk",
    "brand_impersonation", "dns_resolves", "has_non_standard_port",
    "subdomain_count",
]
