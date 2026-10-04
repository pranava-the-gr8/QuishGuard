from urllib.parse import urlparse
import ipaddress


def analyze_url(url: str) -> dict:
    parsed = urlparse(url)

    protocol = parsed.scheme.lower()
    domain = parsed.hostname.lower() if parsed.hostname else None
    subdomain = None

    # Detect whether the hostname is an IP address
    is_ip = False

    if domain:
        try:
            ipaddress.ip_address(domain)
            is_ip = True
        except ValueError:
            pass

    # Extract subdomain only for normal domain names
    if domain and not is_ip:
        parts = domain.split(".")

        if len(parts) > 2:
            subdomain = ".".join(parts[:-2])

    port = parsed.port

    if port is None:
        if protocol == "https":
            port = 443
        elif protocol == "http":
            port = 80

    return {
        "normalized_url": url.strip(),
        "protocol": protocol,
        "domain": domain,
        "subdomain": subdomain,
        "port": port,
        "path": parsed.path or None,
        "query_string": parsed.query or None,
        "fragment": parsed.fragment or None
    }