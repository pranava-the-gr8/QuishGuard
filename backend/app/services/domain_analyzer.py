import httpx
from datetime import datetime, timezone


def get_registrable_domain(domain: str) -> str:
    """
    Convert a hostname like www.google.com
    into the domain used for registration lookup.
    """

    domain = domain.lower().strip().rstrip(".")

    if domain.startswith("www."):
        domain = domain[4:]

    return domain


def analyze_domain_age(domain: str) -> dict:

    if not domain:
        return {
            "domain_age_days": None,
            "domain_age_score": None,
            "creation_date": None,
            "warning": "Domain is unavailable"
        }

    domain = get_registrable_domain(domain)

    rdap_url = f"https://rdap.org/domain/{domain}"

    try:

        response = httpx.get(
            rdap_url,
            timeout=10,
            follow_redirects=True
        )

        # Domain does not appear to have an RDAP registration record
        if response.status_code == 404:
            return {
                "domain_age_days": None,
                "domain_age_score": 100,
                "creation_date": None,
                "warning": "Domain registration record was not found"
            }

        # RDAP server/provider problem
        if response.status_code != 200:
            return {
                "domain_age_days": None,
                "domain_age_score": None,
                "creation_date": None,
                "warning": (
                    f"Domain registration lookup unavailable "
                    f"(HTTP {response.status_code})"
                )
            }

        data = response.json()

        creation_date = None

        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                creation_date = event.get("eventDate")
                break

        if not creation_date:
            return {
                "domain_age_days": None,
                "domain_age_score": None,
                "creation_date": None,
                "warning": "Domain creation date unavailable"
            }

        created = datetime.fromisoformat(
            creation_date.replace("Z", "+00:00")
        )

        now = datetime.now(timezone.utc)
        age_days = (now - created).days

        if age_days <= 7:
            score = 90
            warning = "Domain was registered very recently"

        elif age_days <= 30:
            score = 70
            warning = "Domain was registered recently"

        elif age_days <= 90:
            score = 40
            warning = "Domain is relatively new"

        else:
            score = 0
            warning = None

        return {
            "domain_age_days": age_days,
            "domain_age_score": score,
            "creation_date": creation_date,
            "warning": warning
        }

    except httpx.RequestError:
        return {
            "domain_age_days": None,
            "domain_age_score": None,
            "creation_date": None,
            "warning": "Unable to connect to domain registration service"
        }

    except Exception as error:
        return {
            "domain_age_days": None,
            "domain_age_score": None,
            "creation_date": None,
            "warning": f"Domain analysis failed: {str(error)}"
        }