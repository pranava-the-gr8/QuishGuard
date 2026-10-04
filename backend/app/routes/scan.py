import time
from datetime import datetime, timezone

from fastapi import APIRouter, UploadFile, File, Depends
from pydantic import BaseModel, HttpUrl

from app.database.supabase import supabase
from app.auth.dependencies import get_current_user

from app.services.qr_decoder import decode_qr
from app.services.url_analyzer import analyze_url
from app.services.static_analyzer import analyze_static_indicators
from app.services.typosquatting_analyzer import analyze_typosquatting
from app.services.domain_analyzer import analyze_domain_age
from app.services.virustotal_analyzer import analyze_virustotal
from app.services.pretrained_ml import analyze_pretrained_ml
from app.services.gemini import analyze_with_gemini
from app.services.risk_engine import calculate_risk_score


router = APIRouter(prefix="/api", tags=["Scan"])


@router.get("/scans")
def get_scan_history(
    current_user=Depends(get_current_user)
):
    user_id = str(current_user.id)

    response = (
        supabase
        .table("scans")
        .select(
            "id, input_type, original_input, extracted_url, "
            "status, created_at, completed_at, "
            "processing_time_ms, error_message, scan_source"
        )
        .eq("user_id", user_id)
        .order("created_at", desc=True)
        .execute()
    )

    return {
        "user_id": user_id,
        "count": len(response.data),
        "scans": response.data
    }


class ScanRequest(BaseModel):
    url: HttpUrl


@router.post("/scan")
def create_scan(
    request: ScanRequest,
    current_user=Depends(get_current_user)
):
    start_time = time.perf_counter()
    user_id = str(current_user.id)
    url = str(request.url)

    # Check known threat database first
    parsed_url = analyze_url(url)
    domain = parsed_url["domain"]

    known_url_response = (
        supabase
        .table("known_threats")
        .select("*")
        .eq("url", url)
        .limit(1)
        .execute()
    )

    known_domain_response = (
        supabase
        .table("known_threats")
        .select("*")
        .eq("domain", domain)
        .limit(1)
        .execute()
    )

    known_threat = None

    if known_url_response.data:
        known_threat = known_url_response.data[0]

    elif known_domain_response.data:
        known_threat = known_domain_response.data[0]

    # Create scan record
    scan_response = (
        supabase
        .table("scans")
        .insert({
            "input_type": "url",
            "original_input": url,
            "extracted_url": url,
            "status": "processing",
            "user_id": user_id
        })
        .execute()
    )

    scan = scan_response.data[0]
    scan_id = scan["id"]

    # Known malicious threat fast path
    if known_threat:

        # Save URL information
        url_response = (
            supabase
            .table("urls")
            .insert({
                "scan_id": scan_id,
                "original_url": url,
                **parsed_url
            })
            .execute()
        )

        # Save threat result
        supabase.table("threat_results").insert({
            "scan_id": scan_id,
            "risk_score": 100,
            "risk_level": "critical",
            "typosquatting_score": None,
            "domain_age_days": None,
            "domain_age_score": None,
            "virustotal_score": None,
            "ml_score": None,
            "gemini_score": None,
            "final_reason": "Matched known malicious threat database",
            "warnings": {
                "known_threat": known_threat
            }
        }).execute()

        processing_time_ms = int(
            (time.perf_counter() - start_time) * 1000
        )

        completed_at = datetime.now(timezone.utc).isoformat()

        supabase.table("scans").update({
            "status": "completed",
            "completed_at": completed_at,
            "processing_time_ms": processing_time_ms
        }).eq("id", scan_id).execute()

        # Read actual values saved by database
        saved_scan = (
            supabase
            .table("scans")
            .select("completed_at, processing_time_ms")
            .eq("id", scan_id)
            .single()
            .execute()
        )

        return {
            "message": "Known malicious threat detected",
            "scan_id": scan_id,
            "user_id": user_id,
            "known_threat": True,
            "threat_source": known_threat.get("source"),
            "threat_type": known_threat.get("threat_type"),
            "matched_domain": known_threat.get("domain"),
            "matched_url": known_threat.get("url"),
            "confidence": known_threat.get("confidence"),
            "risk_analysis": {
                "risk_score": 100,
                "risk_level": "critical"
            },
            "processing_time_ms": saved_scan.data["processing_time_ms"],
            "completed_at": saved_scan.data["completed_at"],
            "url_record": url_response.data
        }

    try:
        # URL analysis
        url_analysis = analyze_url(url)
        domain = url_analysis["domain"]

        # Static analysis
        static_analysis = analyze_static_indicators(url)

        # Typosquatting analysis
        typosquatting_analysis = analyze_typosquatting(url)

        # Domain analysis
        domain_analysis = analyze_domain_age(domain)

        # VirusTotal analysis
        virustotal_analysis = analyze_virustotal(url)

        # Pretrained ML analysis
        pretrained_ml_analysis = analyze_pretrained_ml(url)

        # Gemini analysis
        gemini_analysis = analyze_with_gemini(
            url=url,
            static_analysis=static_analysis,
            typosquatting_analysis=typosquatting_analysis,
            domain_analysis=domain_analysis,
            virustotal_analysis=virustotal_analysis,
            pretrained_ml_analysis=pretrained_ml_analysis
        )

        # Final risk calculation
        risk_analysis = calculate_risk_score(
            static_score=static_analysis["static_score"],
            typosquatting_score=typosquatting_analysis["typosquatting_score"],
            domain_age_score=domain_analysis["domain_age_score"],
            virustotal_score=virustotal_analysis["virustotal_score"],
            ml_score=pretrained_ml_analysis["ml_score"],
            gemini_score=gemini_analysis["gemini_score"]
        )

        # Save strongly malicious URLs/domains
        # for future fast detection
        if (
            risk_analysis["risk_score"] >= 75
            or (
                pretrained_ml_analysis["ml_score"] is not None
                and pretrained_ml_analysis["ml_score"] >= 90
            )
            or (
                virustotal_analysis["virustotal_score"] is not None
                and virustotal_analysis["virustotal_score"] >= 70
            )
        ):

            existing_threat = (
                supabase
                .table("known_threats")
                .select("id")
                .eq("domain", domain)
                .limit(1)
                .execute()
            )

            if not existing_threat.data:
                supabase.table("known_threats").insert({
                    "domain": domain,
                    "url": url,
                    "threat_type": "malicious_url",
                    "source": "internal_multi_layer_analysis",
                    "confidence": risk_analysis["risk_score"]
                }).execute()

        # Save URL analysis
        url_response = (
            supabase
            .table("urls")
            .insert({
                "scan_id": scan_id,
                "original_url": url,
                **url_analysis
            })
            .execute()
        )

        # Save threat result
        supabase.table("threat_results").insert({
            "scan_id": scan_id,
            "risk_score": risk_analysis["risk_score"],
            "risk_level": risk_analysis["risk_level"],
            "typosquatting_score": typosquatting_analysis["typosquatting_score"],
            "domain_age_days": domain_analysis["domain_age_days"],
            "domain_age_score": domain_analysis["domain_age_score"],
            "virustotal_score": virustotal_analysis["virustotal_score"],
            "ml_score": pretrained_ml_analysis["ml_score"],
            "gemini_score": gemini_analysis["gemini_score"],
            "final_reason": "Multi-layer URL security analysis",
            "warnings": {
                "static": static_analysis["indicators"],
                "typosquatting": typosquatting_analysis,
                "domain": domain_analysis,
                "virustotal": virustotal_analysis,
                "pretrained_ml": pretrained_ml_analysis,
                "gemini": gemini_analysis
            }
        }).execute()

        processing_time_ms = int(
            (time.perf_counter() - start_time) * 1000
        )

        completed_at = datetime.now(timezone.utc).isoformat()

        supabase.table("scans").update({
            "status": "completed",
            "completed_at": completed_at,
            "processing_time_ms": processing_time_ms
        }).eq("id", scan_id).execute()

        # Read actual values saved by database
        saved_scan = (
            supabase
            .table("scans")
            .select("completed_at, processing_time_ms")
            .eq("id", scan_id)
            .single()
            .execute()
        )

        return {
            "message": "URL inspected successfully",
            "scan_id": scan_id,
            "user_id": user_id,
            "url_analysis": url_analysis,
            "static_analysis": static_analysis,
            "typosquatting_analysis": typosquatting_analysis,
            "domain_analysis": domain_analysis,
            "virustotal_analysis": virustotal_analysis,
            "pretrained_ml_analysis": pretrained_ml_analysis,
            "gemini_analysis": gemini_analysis,
            "risk_analysis": risk_analysis,
            "processing_time_ms": saved_scan.data["processing_time_ms"],
            "completed_at": saved_scan.data["completed_at"],
            "url_record": url_response.data
        }

    except Exception as error:

        processing_time_ms = int(
            (time.perf_counter() - start_time) * 1000
        )

        supabase.table("scans").update({
            "status": "failed",
            "error_message": str(error),
            "processing_time_ms": processing_time_ms
        }).eq("id", scan_id).execute()

        raise


@router.post("/scan/qr")
async def scan_qr(
    file: UploadFile = File(...),
    current_user=Depends(get_current_user)
):
    import os

    image_path = f"temp_{file.filename}"

    try:
        with open(image_path, "wb") as buffer:
            buffer.write(await file.read())

        decoded_url = decode_qr(image_path)

        return create_scan(
            ScanRequest(url=decoded_url),
            current_user=current_user
        )

    except Exception as error:

        return {
            "message": "QR scan failed",
            "error": str(error)
        }

    finally:

        if os.path.exists(image_path):
            os.remove(image_path)


@router.get("/scans/{scan_id}")
def get_scan_result(
    scan_id: str,
    current_user=Depends(get_current_user)
):
    user_id = str(current_user.id)

    scan_response = (
        supabase
        .table("scans")
        .select("*")
        .eq("id", scan_id)
        .eq("user_id", user_id)
        .single()
        .execute()
    )

    scan = scan_response.data

    if not scan:
        return {
            "message": "Scan not found"
        }

    url_response = (
        supabase
        .table("urls")
        .select("*")
        .eq("scan_id", scan_id)
        .execute()
    )

    threat_response = (
        supabase
        .table("threat_results")
        .select("*")
        .eq("scan_id", scan_id)
        .single()
        .execute()
    )

    return {
        "scan": scan,
        "url": url_response.data,
        "threat_result": threat_response.data
    }