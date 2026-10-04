from urllib.parse import urlparse
from rapidfuzz.fuzz import ratio
import re


KNOWN_DOMAINS = [
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "paypal.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "github.com",
]


CHARACTER_SUBSTITUTIONS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
}


def normalize_domain(domain: str) -> str:
    return domain.lower().strip().removeprefix("www.")


def get_domain_name(domain: str) -> str:
    parts = domain.split(".")

    if len(parts) >= 2:
        return parts[-2]

    return domain


def normalize_lookalike_characters(name: str) -> str:
    for suspicious, legitimate in CHARACTER_SUBSTITUTIONS.items():
        name = name.replace(suspicious, legitimate)

    return name


def get_domain_tokens(domain_name: str) -> list[str]:
    """
    Split a domain such as:

    paypa1-login-verify

    into:

    paypa1
    login
    verify
    """

    return [
        token
        for token in re.split(r"[-_]", domain_name)
        if token
    ]


def analyze_typosquatting(url: str) -> dict:
    parsed = urlparse(url)
    domain = parsed.hostname

    if not domain:
        return {
            "typosquatting_score": 0,
            "matched_domain": None,
            "similarity": 0,
            "warning": None
        }

    domain = normalize_domain(domain)

    # Exact official domain
    if domain in KNOWN_DOMAINS:
        return {
            "typosquatting_score": 0,
            "matched_domain": domain,
            "similarity": 100,
            "warning": None
        }

    domain_name = get_domain_name(domain)
    tokens = get_domain_tokens(domain_name)

    highest_similarity = 0
    matched_domain = None
    matched_token = None
    lookalike_match = False
    exact_brand_match = False

    for known_domain in KNOWN_DOMAINS:

        known_name = get_domain_name(known_domain)

        # Check the complete domain label
        candidates = [domain_name]

        # Also check individual parts:
        # paypa1-login-verify -> paypa1, login, verify
        candidates.extend(tokens)

        for candidate in candidates:

            if len(candidate) < 4 or len(known_name) < 4:
                continue

            # Normal similarity
            similarity = ratio(candidate, known_name)

            # Similarity after replacing look-alike characters
            normalized_candidate = normalize_lookalike_characters(candidate)

            substitution_similarity = ratio(
                normalized_candidate,
                known_name
            )

            best_similarity = max(
                similarity,
                substitution_similarity
            )

            if substitution_similarity == 100 and candidate != known_name:
                lookalike_match = True

            if candidate == known_name and domain != known_domain:
                exact_brand_match = True

            if best_similarity > highest_similarity:
                highest_similarity = best_similarity
                matched_domain = known_domain
                matched_token = candidate

    # Strong look-alike detection
    if lookalike_match and matched_domain:

        return {
            "typosquatting_score": 90,
            "matched_domain": matched_domain,
            "similarity": round(highest_similarity, 2),
            "warning": (
                f"Domain contains a look-alike version of "
                f"{matched_domain}"
            )
        }

    # Exact brand name used inside another domain
    if exact_brand_match and matched_domain:

        return {
            "typosquatting_score": 75,
            "matched_domain": matched_domain,
            "similarity": round(highest_similarity, 2),
            "warning": (
                f"Domain contains the brand name "
                f"{matched_domain} but is not the official domain"
            )
        }

    # Highly similar domain
    if highest_similarity >= 90 and matched_domain:

        return {
            "typosquatting_score": 80,
            "matched_domain": matched_domain,
            "similarity": round(highest_similarity, 2),
            "warning": (
                f"Domain is highly similar to "
                f"{matched_domain}"
            )
        }

    # Moderately similar domain
    if highest_similarity >= 80 and matched_domain:

        return {
            "typosquatting_score": 60,
            "matched_domain": matched_domain,
            "similarity": round(highest_similarity, 2),
            "warning": (
                f"Domain is similar to "
                f"{matched_domain}"
            )
        }

    # Some similarity
    if highest_similarity >= 70 and matched_domain:

        return {
            "typosquatting_score": 30,
            "matched_domain": matched_domain,
            "similarity": round(highest_similarity, 2),
            "warning": (
                f"Domain has some similarity to "
                f"{matched_domain}"
            )
        }

    return {
        "typosquatting_score": 0,
        "matched_domain": matched_domain,
        "similarity": round(highest_similarity, 2),
        "warning": None
    }