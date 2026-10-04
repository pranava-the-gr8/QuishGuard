from urllib.parse import urlparse
import ipaddress
import re


def analyze_static_indicators(url: str) -> dict:
    parsed = urlparse(url)

    indicators = []
    score = 0

    domain = parsed.hostname or ""
    full_url = url.lower()

    # 1. IP address instead of domain
    try:
        ipaddress.ip_address(domain)
        indicators.append("URL uses an IP address instead of a domain name")
        score += 25
    except ValueError:
        pass

    # 2. @ symbol
    if "@" in url:
        indicators.append("URL contains an @ symbol, which can hide the real destination")
        score += 20

    # 3. Very long URL
    if len(url) > 150:
        indicators.append("URL is unusually long")
        score += 10

    # 4. Too many subdomains
    domain_parts = domain.split(".")
    if len(domain_parts) > 4:
        indicators.append("URL contains an unusually large number of subdomains")
        score += 10

    # 5. Suspicious keywords
    suspicious_keywords = [
        "login",
        "verify",
        "verification",
        "password",
        "account",
        "secure",
        "update",
        "confirm",
        "banking",
        "signin"
    ]

    found_keywords = [
        keyword for keyword in suspicious_keywords
        if keyword in full_url
    ]

    if found_keywords:
        indicators.append(
            "URL contains potentially sensitive-action keywords: "
            + ", ".join(found_keywords)
        )
        score += min(len(found_keywords) * 5, 15)

    # 6. Suspicious encoding
    encoded_parts = re.findall(r"%[0-9a-fA-F]{2}", url)

    if len(encoded_parts) >= 3:
        indicators.append("URL contains multiple encoded characters")
        score += 10

    # 7. HTTP instead of HTTPS
    if parsed.scheme.lower() == "http":
        indicators.append("URL does not use HTTPS")
        score += 10

    # Keep score between 0 and 100
    score = min(score, 100)

    return {
        "static_score": score,
        "indicators": indicators
    }