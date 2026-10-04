import os
import base64
import httpx
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

VT_BASE_URL = "https://www.virustotal.com/api/v3"


def get_url_id(url: str) -> str:
    """
    Convert a URL into the identifier used by VirusTotal's URL endpoint.
    This does NOT visit or execute the URL.
    """

    encoded = base64.urlsafe_b64encode(
        url.encode()
    ).decode().rstrip("=")

    return encoded


def analyze_virustotal(url: str) -> dict:

    if not VIRUSTOTAL_API_KEY:
        return {
            "virustotal_score": None,
            "malicious": None,
            "suspicious": None,
            "harmless": None,
            "undetected": None,
            "warning": "VirusTotal API key is not configured"
        }

    url_id = get_url_id(url)

    endpoint = f"{VT_BASE_URL}/urls/{url_id}"

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    try:
        response = httpx.get(
            endpoint,
            headers=headers,
            timeout=15
        )

        if response.status_code == 404:
            return {
                "virustotal_score": None,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "warning": "No existing VirusTotal analysis found"
            }

        if response.status_code != 200:
            return {
                "virustotal_score": None,
                "malicious": None,
                "suspicious": None,
                "harmless": None,
                "undetected": None,
                "warning": f"VirusTotal request failed: HTTP {response.status_code}"
            }

        data = response.json()

        stats = (
            data.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        total = malicious + suspicious + harmless + undetected

        if total > 0:
            virustotal_score = (
                (malicious + suspicious) / total
            ) * 100
        else:
            virustotal_score = None

        warning = None

        if malicious > 0:
            warning = (
                f"VirusTotal reports {malicious} security "
                f"engine(s) marking this URL as malicious"
            )

        elif suspicious > 0:
            warning = (
                f"VirusTotal reports {suspicious} security "
                f"engine(s) marking this URL as suspicious"
            )

        return {
            "virustotal_score": round(virustotal_score, 2)
            if virustotal_score is not None else None,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "warning": warning
        }

    except Exception:
        return {
            "virustotal_score": None,
            "malicious": None,
            "suspicious": None,
            "harmless": None,
            "undetected": None,
            "warning": "Unable to retrieve VirusTotal information"
        }