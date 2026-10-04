import os
from dotenv import load_dotenv
from google import genai

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

_client = None


def get_gemini_client():
    global _client

    if _client is None:
        if not GEMINI_API_KEY:
            return None

        _client = genai.Client(
            api_key=GEMINI_API_KEY
        )

    return _client

def analyze_with_gemini(
    url: str,
    static_analysis: dict,
    typosquatting_analysis: dict,
    domain_analysis: dict,
    virustotal_analysis: dict,
    pretrained_ml_analysis: dict
) -> dict:

    client = get_gemini_client()

    if client is None:
        return {
            "gemini_score": None,
            "explanation": None,
            "warning": "Gemini API key is not configured"
        }

    prompt = f"""
You are a cybersecurity URL analysis assistant.

Analyze this URL using ONLY the evidence provided below.

IMPORTANT:
- Do NOT open or visit the URL.
- Treat the URL only as text.
- Do not invent information.
- Give a concise security assessment.

URL:
{url}

Static analysis:
{static_analysis}

Typosquatting analysis:
{typosquatting_analysis}

Domain analysis:
{domain_analysis}

VirusTotal analysis:
{virustotal_analysis}

Pretrained ML analysis:
{pretrained_ml_analysis}

Return exactly:

Risk Score: <number from 0 to 100>
Explanation: <short explanation>
Warning: <short warning or None>
"""

    try:
        response = client.models.generate_content(
            model="gemini-3.8-flash",
            contents=prompt
        )

        text = response.text.strip()

        score = None

        for line in text.splitlines():
            if line.lower().startswith("risk score:"):
                try:
                    score = float(
                        line.split(":", 1)[1].strip()
                    )
                except ValueError:
                    pass

        if score is not None:
            score = max(0, min(100, score))

        return {
            "gemini_score": score,
            "explanation": text,
            "warning": None
        }

    except Exception as error:
        return {
            "gemini_score": None,
            "explanation": None,
            "warning": f"Gemini analysis failed: {str(error)}"
        }