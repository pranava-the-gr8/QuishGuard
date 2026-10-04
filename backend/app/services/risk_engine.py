def calculate_risk_score(
    static_score=None,
    typosquatting_score=None,
    domain_age_score=None,
    virustotal_score=None,
    ml_score=None,
    gemini_score=None
) -> dict:

    signals = {
        "static": static_score,
        "typosquatting": typosquatting_score,
        "domain_age": domain_age_score,
        "virustotal": virustotal_score,
        "ml": ml_score,
        "gemini": gemini_score
    }

    weights = {
        "static": 0.15,
        "typosquatting": 0.20,
        "domain_age": 0.15,
        "virustotal": 0.30,
        "ml": 0.10,
        "gemini": 0.10
    }

    available_signals = {
        name: score
        for name, score in signals.items()
        if score is not None
    }

    if not available_signals:
        return {
            "risk_score": None,
            "risk_level": "unknown"
        }

    # -----------------------------------------
    # Weighted base score
    # -----------------------------------------

    total_weight = sum(
        weights[name]
        for name in available_signals
    )

    weighted_score = sum(
        available_signals[name] * weights[name]
        for name in available_signals
    )

    base_score = (
        weighted_score / total_weight
        if total_weight > 0
        else 0
    )

    # -----------------------------------------
    # Strong-signal detection
    # -----------------------------------------

    strong_signals = 0

    if typosquatting_score is not None and typosquatting_score >= 80:
        strong_signals += 1

    if domain_age_score is not None and domain_age_score >= 80:
        strong_signals += 1

    if virustotal_score is not None and virustotal_score >= 70:
        strong_signals += 1

    if ml_score is not None and ml_score >= 90:
        strong_signals += 1

    if gemini_score is not None and gemini_score >= 90:
        strong_signals += 1

    # Multiple independent strong signals increase confidence.
    if strong_signals >= 3:
        final_score = max(base_score, 90)

    elif strong_signals == 2:
        final_score = max(base_score, 80)

    else:
        final_score = base_score

    final_score = round(
        min(max(final_score, 0), 100),
        2
    )

    # -----------------------------------------
    # Risk level
    # -----------------------------------------

    if final_score < 25:
        risk_level = "low"

    elif final_score < 50:
        risk_level = "medium"

    elif final_score < 75:
        risk_level = "high"

    else:
        risk_level = "critical"

    return {
        "risk_score": final_score,
        "risk_level": risk_level,
        "strong_signals": strong_signals
    }