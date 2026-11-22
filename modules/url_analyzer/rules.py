import ipaddress
import re
from urllib.parse import urlparse, unquote

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "rebrand.ly", "cutt.ly", "tiny.cc", "goo.gl", "rotf.lol"
}

SUSPICIOUS_KEYWORDS = [
    "verify", "secure", "login", "update", "account",
    "banking", "signin", "wallet", "password", "credential",
    "confirm", "support", "security", "recovery", "auth"
]

def check_url_001_scheme(parsed_url):
    """URL-001: Non-HTTPS scheme (HTTP instead of HTTPS)"""
    scheme = parsed_url.scheme.lower()
    if scheme == "http":
        return {
            "rule_id": "URL-001",
            "title": "Non-HTTPS Scheme",
            "explanation": "Scheme is unencrypted HTTP rather than HTTPS. Data transmitted over HTTP can be intercepted in transit.",
            "caution": "HTTPS alone does not guarantee a site is safe; modern phishing sites often obtain free SSL certificates.",
            "points": 5
        }
    return None

def check_url_002_ip_host(hostname):
    """URL-002: IP-literal host"""
    if not hostname:
        return None
    cleaned_host = hostname.split(":")[0].strip("[]")
    is_ip = False
    try:
        ipaddress.ip_address(cleaned_host)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        return {
            "rule_id": "URL-002",
            "title": "IP-Literal Hostname",
            "explanation": f"Hostname '{hostname}' is a raw IP address instead of a registered domain name. Attackers use this to evade domain reputation filters.",
            "caution": "Some legitimate internal network devices and development servers use raw IP addresses.",
            "points": 20
        }
    return None

def check_url_003_suspicious_terms(hostname, path, query):
    """URL-003: Suspicious terms in host or path (+5 each, capped at +15)"""
    target_text = f"{hostname} {path} {query}".lower()
    matched = [term for term in SUSPICIOUS_KEYWORDS if term in target_text]
    if matched:
        points = min(len(matched) * 5, 15)
        return {
            "rule_id": "URL-003",
            "title": "Suspicious Security Keywords",
            "explanation": f"URL contains authentication/security keywords frequently abused in phishing lures: {', '.join(matched[:4])}.",
            "caution": "These keywords are common in legitimate authentication flows; context is essential.",
            "points": points
        }
    return None

def check_url_004_length(raw_url, threshold=75):
    """URL-004: Excessive URL length"""
    if len(raw_url) > threshold:
        return {
            "rule_id": "URL-004",
            "title": "Excessive URL Length",
            "explanation": f"URL length ({len(raw_url)} characters) exceeds standard threshold ({threshold}). Attackers often lengthen URLs to push misleading domains off-screen.",
            "caution": "Legitimate tracking, search query and OAuth redirection URLs can be lengthy.",
            "points": 10
        }
    return None

def check_url_005_subdomain_depth(hostname, max_depth=3):
    """URL-005: Unusual subdomain depth"""
    if not hostname:
        return None
    labels = hostname.split(".")
    # E.g. sub.portal.verify.example.com has 5 labels -> 4 dots
    if len(labels) > max_depth + 1:
        return {
            "rule_id": "URL-005",
            "title": "Unusual Subdomain Depth",
            "explanation": f"Hostname contains {len(labels)} domain levels ({len(labels)-1} dots). Attackers frequently prepend deceptive subdomains to mimic reputable brands.",
            "caution": "Large organizations and content delivery networks sometimes employ multi-tier subdomains.",
            "points": 10
        }
    return None

def check_url_006_obfuscation(raw_url):
    """URL-006: Encoded/obfuscated patterns"""
    percent_count = raw_url.count("%")
    has_at_symbol = "@" in raw_url
    if percent_count >= 3 or has_at_symbol:
        indicators = []
        if percent_count >= 3:
            indicators.append(f"{percent_count} percent-encoded characters")
        if has_at_symbol:
            indicators.append("userinfo '@' symbol used to mask actual host")
        return {
            "rule_id": "URL-006",
            "title": "Encoded or Obfuscated Pattern",
            "explanation": f"Detected URL obfuscation indicators: {', '.join(indicators)}.",
            "caution": "Percent encoding is standard in URL parameter encoding.",
            "points": 10
        }
    return None

def check_url_007_shortener(hostname):
    """URL-007: URL shortener"""
    if not hostname:
        return None
    host_lower = hostname.lower().split(":")[0]
    if host_lower in KNOWN_SHORTENERS:
        return {
            "rule_id": "URL-007",
            "title": "Known URL Shortening Service",
            "explanation": f"Host '{host_lower}' matches a public link-shortening service that obscures the true destination URL.",
            "caution": "URL shorteners are used legitimately across social media and marketing campaigns.",
            "points": 10
        }
    return None

def check_url_008_unicode_homograph(hostname):
    """URL-008: Unicode/homograph indicator (Punycode xn-- or non-ASCII)"""
    if not hostname:
        return None
    host_lower = hostname.lower()
    has_punycode = "xn--" in host_lower
    has_non_ascii = any(ord(c) > 127 for c in host_lower)
    if has_punycode or has_non_ascii:
        return {
            "rule_id": "URL-008",
            "title": "Unicode / Homograph Indicator",
            "explanation": "Hostname contains Punycode ('xn--') or internationalized non-ASCII characters, which can visually mimic legitimate alphabetic domain names.",
            "caution": "Legitimate multilingual domain names (IDNs) also utilize Punycode.",
            "points": 15
        }
    return None

def evaluate_all_rules(raw_url, parsed_url, config):
    hostname = parsed_url.hostname or ""
    path = parsed_url.path or ""
    query = parsed_url.query or ""

    findings = []
    
    # URL-001: HTTP
    r1 = check_url_001_scheme(parsed_url)
    if r1: findings.append(r1)

    # URL-002: IP Host
    r2 = check_url_002_ip_host(hostname)
    if r2: findings.append(r2)

    # URL-003: Suspicious Terms
    r3 = check_url_003_suspicious_terms(hostname, path, query)
    if r3: findings.append(r3)

    # URL-004: Excessive Length
    threshold = getattr(config, "MAX_URL_LENGTH_THRESHOLD", 75)
    r4 = check_url_004_length(raw_url, threshold)
    if r4: findings.append(r4)

    # URL-005: Subdomain Depth
    max_depth = getattr(config, "MAX_SUBDOMAIN_DEPTH", 3)
    r5 = check_url_005_subdomain_depth(hostname, max_depth)
    if r5: findings.append(r5)

    # URL-006: Obfuscation
    r6 = check_url_006_obfuscation(raw_url)
    if r6: findings.append(r6)

    # URL-007: Shortener
    r7 = check_url_007_shortener(hostname)
    if r7: findings.append(r7)

    # URL-008: Homograph/Unicode
    r8 = check_url_008_unicode_homograph(hostname)
    if r8: findings.append(r8)

    return findings
