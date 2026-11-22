from config import Config

def calculate_risk_score(findings):
    raw_score = sum(f["points"] for f in findings)
    bounded_score = min(max(raw_score, 0), 100)

    if bounded_score <= 19:
        risk_level = "LOW"
        risk_wording = "No strong indicators found by these checks"
        action_recommendation = "Standard caution advised. Always verify the address bar domain before typing passwords."
    elif bounded_score <= 49:
        risk_level = "MEDIUM"
        risk_wording = "Potentially suspicious – verify independently"
        action_recommendation = "Moderate risk indicators detected. Do not enter credentials on unverified third-party pages; independently navigate to the service."
    elif bounded_score <= 74:
        risk_level = "HIGH"
        risk_wording = "Potentially suspicious – verify independently"
        action_recommendation = "High risk indicators found. Do not enter credentials; verify domain authenticity using a trusted out-of-band channel; report suspicious link."
    else:
        risk_level = "CRITICAL"
        risk_wording = "Potentially suspicious – verify independently"
        action_recommendation = "Multiple severe risk indicators present. Cease interaction, do not submit any information or passwords, and report to security operations."

    return {
        "score": bounded_score,
        "risk_level": risk_level,
        "risk_wording": risk_wording,
        "action_recommendation": action_recommendation
    }
