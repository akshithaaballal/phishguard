"""
PhishGuard — Rule-Based Risk Scorer
Generates a transparent, explainable risk score broken down by category.
Used alongside the ML model to produce the API response.
"""

from typing import Any


def compute_risk_breakdown(features: dict, meta: dict) -> dict:
    """
    Compute a risk score (0-100) broken down by 4 categories:
      - URL Structure   (max 40)
      - Domain Intel    (max 35)
      - Content Analysis(max 15)
      - Behavioral      (max 10)

    Returns a dict with individual scores and a list of flags.
    """
    f = features

    # ── 1. URL Structure (max 40) ──────────────────────────────────────────
    url_score = 0
    flags = []

    if not f["has_https"]:
        url_score += 8
        flags.append({
            "severity": "red",
            "title": "No HTTPS",
            "description": "The URL uses unencrypted HTTP. Phishing pages frequently avoid HTTPS.",
            "feature": "has_https",
        })

    if f["url_length"] > 100:
        pts = min(10, (f["url_length"] - 100) // 20 * 3 + 3)
        url_score += pts
        flags.append({
            "severity": "red",
            "title": "Excessively Long URL",
            "description": f"URL is {f['url_length']} characters. Attackers pad URLs to confuse users.",
            "feature": "url_length",
        })
    elif f["url_length"] > 75:
        url_score += 3
        flags.append({
            "severity": "yellow",
            "title": "Moderately Long URL",
            "description": f"URL length ({f['url_length']} chars) is above average.",
            "feature": "url_length",
        })

    if f["has_ip_address"]:
        url_score += 10
        flags.append({
            "severity": "red",
            "title": "IP Address Used Instead of Domain",
            "description": "IP-based URLs are a strong phishing indicator — legitimate services use domain names.",
            "feature": "has_ip_address",
        })

    if f["num_hyphens"] >= 3:
        url_score += 5
        flags.append({
            "severity": "yellow",
            "title": "Excessive Hyphens in Domain",
            "description": f"Domain contains {f['num_hyphens']} hyphens — common in impersonation attacks.",
            "feature": "num_hyphens",
        })
    elif f["num_hyphens"] >= 1:
        url_score += 2

    if f["has_at_symbol"]:
        url_score += 7
        flags.append({
            "severity": "red",
            "title": "@ Symbol in URL",
            "description": "The @ symbol causes browsers to ignore everything before it — classic redirect trick.",
            "feature": "has_at_symbol",
        })

    if f["has_double_slash"]:
        url_score += 4
        flags.append({
            "severity": "yellow",
            "title": "Double Slash in Path",
            "description": "Double slashes in paths can be used to obscure redirect targets.",
            "feature": "has_double_slash",
        })

    if f["has_hex_encoding"]:
        url_score += 4
        flags.append({
            "severity": "yellow",
            "title": "Hex / Percent Encoding Detected",
            "description": "Percent-encoded characters can be used to bypass URL filters.",
            "feature": "has_hex_encoding",
        })

    if f["num_subdomains"] >= 3:
        url_score += 6
        flags.append({
            "severity": "red",
            "title": "Excessive Subdomains",
            "description": f"{f['num_subdomains']} subdomain levels detected. Phishers use deep subdomains to appear legitimate (e.g. paypal.com.evil.tk).",
            "feature": "num_subdomains",
        })
    elif f["num_subdomains"] == 2:
        url_score += 3

    if f["has_non_standard_port"]:
        url_score += 5
        flags.append({
            "severity": "yellow",
            "title": "Non-Standard Port",
            "description": "Legitimate websites rarely use non-standard ports. This may indicate a malicious server.",
            "feature": "has_non_standard_port",
        })

    url_score = min(url_score, 40)

    # ── 2. Domain Intelligence (max 35) ───────────────────────────────────
    domain_score = 0

    if f["tld_is_high_risk"]:
        domain_score += 12
        flags.append({
            "severity": "red",
            "title": "High-Abuse TLD",
            "description": f".{meta.get('tld', '?')} is among the top TLDs for phishing abuse (Spamhaus / ICANN data).",
            "feature": "tld_is_high_risk",
        })

    if f["brand_impersonation"]:
        domain_score += 15
        flags.append({
            "severity": "red",
            "title": "Brand Impersonation",
            "description": "A well-known brand name appears in the URL but the domain does not match the official brand domain.",
            "feature": "brand_impersonation",
        })

    age = f["domain_age_days"]
    if age == -1:
        domain_score += 5
        flags.append({
            "severity": "yellow",
            "title": "WHOIS Unavailable",
            "description": "Domain age could not be determined. Privacy-protected or newly created domains are common in phishing campaigns.",
            "feature": "domain_age_days",
        })
    elif age < 7:
        domain_score += 12
        flags.append({
            "severity": "red",
            "title": "Brand-New Domain (< 7 days)",
            "description": f"Domain created {age} day(s) ago. Phishing domains are often registered days before an attack.",
            "feature": "domain_age_days",
        })
    elif age < 30:
        domain_score += 8
        flags.append({
            "severity": "red",
            "title": "Very New Domain (< 30 days)",
            "description": f"Domain is only {age} days old. Most legitimate sites have domains older than a year.",
            "feature": "domain_age_days",
        })
    elif age < 180:
        domain_score += 3
        flags.append({
            "severity": "yellow",
            "title": "Relatively New Domain",
            "description": f"Domain is {age} days old ({age // 30} months). Established services typically have older domains.",
            "feature": "domain_age_days",
        })
    else:
        flags.append({
            "severity": "green",
            "title": "Established Domain",
            "description": f"Domain has been registered for {age} days — a positive indicator.",
            "feature": "domain_age_days",
        })

    domain_score = min(domain_score, 35)

    # ── 3. Content Analysis (max 15) ──────────────────────────────────────
    content_score = 0

    kw_count = f["suspicious_keyword_count"]
    if kw_count >= 3:
        content_score += 10
        flags.append({
            "severity": "red",
            "title": "Multiple Credential-Themed Keywords",
            "description": f"{kw_count} suspicious keywords detected (e.g. {', '.join(meta.get('suspicious_keywords', [])[:3])}). This strongly suggests a credential-harvesting page.",
            "feature": "suspicious_keyword_count",
        })
    elif kw_count == 2:
        content_score += 6
        flags.append({
            "severity": "yellow",
            "title": "Suspicious Keywords",
            "description": f"Keywords found: {', '.join(meta.get('suspicious_keywords', []))}.",
            "feature": "suspicious_keyword_count",
        })
    elif kw_count == 1:
        content_score += 3
        flags.append({
            "severity": "yellow",
            "title": "One Suspicious Keyword",
            "description": f"Keyword found: {', '.join(meta.get('suspicious_keywords', []))}.",
            "feature": "suspicious_keyword_count",
        })

    if f["url_entropy"] > 5.0:
        content_score += 5
        flags.append({
            "severity": "yellow",
            "title": "High URL Entropy",
            "description": f"Entropy of {f['url_entropy']:.2f} bits. Randomly generated or encoded paths suggest automation.",
            "feature": "url_entropy",
        })

    content_score = min(content_score, 15)

    # ── 4. Behavioral (max 10) ────────────────────────────────────────────
    behavioral_score = 0

    if not f["dns_resolves"]:
        behavioral_score += 5
        flags.append({
            "severity": "yellow",
            "title": "DNS Does Not Resolve",
            "description": "The domain could not be resolved via DNS. May be a sinkhole, inactive phishing domain, or typo.",
            "feature": "dns_resolves",
        })

    if f["has_https"]:
        flags.append({
            "severity": "green",
            "title": "HTTPS Enabled",
            "description": "Connection is encrypted. Note: phishing sites can also use HTTPS via free certificates.",
            "feature": "has_https",
        })

    behavioral_score = min(behavioral_score, 10)

    total = url_score + domain_score + content_score + behavioral_score

    return {
        "url_score": url_score,
        "domain_score": domain_score,
        "content_score": content_score,
        "behavioral_score": behavioral_score,
        "total": total,
        "flags": flags,
    }
