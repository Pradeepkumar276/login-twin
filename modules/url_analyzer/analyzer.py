from urllib.parse import urlparse
from config import Config
from modules.url_analyzer.rules import evaluate_all_rules
from modules.url_analyzer.scoring import calculate_risk_score
from database.repositories import create_url_scan, get_url_scan_by_id, get_recent_url_scans

class URLAnalysisError(Exception):
    pass

def analyze_url(url_string, user_id=None, save_to_db=True):
    """
    Deterministically inspects URL syntax and risk indicators locally without network requests.
    Validates syntax, extracts URL elements, applies local detection rules, computes bounded score.
    """
    if not url_string or not isinstance(url_string, str):
        raise URLAnalysisError("URL string cannot be empty.")

    cleaned_url = url_string.strip()
    if len(cleaned_url) < 3:
        raise URLAnalysisError("Invalid URL length: URL is too short to be valid.")

    # Normalize scheme if missing for parsing purposes
    parse_target = cleaned_url
    if not (cleaned_url.startswith("http://") or cleaned_url.startswith("https://") or cleaned_url.startswith("ftp://")):
        parse_target = "http://" + cleaned_url

    try:
        parsed = urlparse(parse_target)
    except Exception as e:
        raise URLAnalysisError(f"Malformed URL could not be parsed: {str(e)}")

    if not parsed.netloc and not parsed.hostname:
        raise URLAnalysisError("URL does not contain a valid hostname or netloc.")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise URLAnalysisError("Could not extract a valid host from URL.")

    # Apply all deterministic local rules (NO network request is made!)
    findings = evaluate_all_rules(cleaned_url, parsed, Config)
    score_data = calculate_risk_score(findings)

    scan_id = None
    if save_to_db:
        scan_id = create_url_scan(
            submitted_url=cleaned_url,
            normalized_host=hostname,
            score=score_data["score"],
            risk_level=score_data["risk_level"],
            findings=findings,
            user_id=user_id
        )

    return {
        "scan_id": scan_id,
        "submitted_url": cleaned_url,
        "normalized_host": hostname,
        "scheme": parsed.scheme or ("https" if cleaned_url.startswith("https://") else "http"),
        "path": parsed.path or "/",
        "query": parsed.query,
        "score": score_data["score"],
        "risk_level": score_data["risk_level"],
        "risk_wording": score_data["risk_wording"],
        "action_recommendation": score_data["action_recommendation"],
        "findings": findings
    }
