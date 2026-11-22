import ipaddress
from datetime import datetime, timezone
import json

VALID_EVENT_TYPES = {"login", "access_denied", "request_invalid", "url_scan", "logout", "password_reset", "session_start"}
VALID_OUTCOMES = {"success", "failure", "denied", "invalid", "unknown"}

class NormalizationError(Exception):
    pass

def validate_and_normalize_ip(ip_str):
    if not ip_str:
        return None
    cleaned = str(ip_str).strip()
    try:
        ip_obj = ipaddress.ip_address(cleaned)
        return str(ip_obj)
    except ValueError:
        return None

def normalize_timestamp(time_val):
    if not time_val:
        return datetime.now(timezone.utc).isoformat()
    if isinstance(time_val, datetime):
        if time_val.tzinfo is None:
            time_val = time_val.replace(tzinfo=timezone.utc)
        return time_val.isoformat()
    
    time_str = str(time_val).strip()
    # Try parsing common ISO-8601 formats
    formats = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S"
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(time_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            continue
    try:
        # Fallback to fromisoformat
        dt = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except Exception:
        # If unparseable, return current UTC time
        return datetime.now(timezone.utc).isoformat()

def normalize_event(raw_dict, default_source="sample_file"):
    """
    Validates and normalizes raw dictionary into canonical event schema:
    - event_time: ISO-8601 UTC
    - source: string
    - event_type: validated against allowlist
    - outcome: validated against allowlist
    - source_ip: normalized IPv4/IPv6 string
    - account_id: trimmed string or None
    - resource: sanitized string or None
    - details: dict
    - severity_hint: string or None
    """
    if not isinstance(raw_dict, dict):
        raise NormalizationError("Event record must be a JSON object / dictionary.")

    # Event type
    raw_type = str(raw_dict.get("event_type", "unknown")).strip().lower()
    event_type = raw_type if raw_type in VALID_EVENT_TYPES else "unknown"

    # Outcome
    raw_outcome = str(raw_dict.get("outcome", "unknown")).strip().lower()
    outcome = raw_outcome if raw_outcome in VALID_OUTCOMES else "unknown"

    # Timestamp
    event_time = normalize_timestamp(raw_dict.get("event_time"))

    # Source IP
    raw_ip = raw_dict.get("source_ip") or raw_dict.get("ip") or raw_dict.get("client_ip")
    source_ip = validate_and_normalize_ip(raw_ip)

    # Account ID
    account_id = raw_dict.get("account_id") or raw_dict.get("user") or raw_dict.get("username")
    if account_id:
        account_id = str(account_id).strip()

    # Resource
    resource = raw_dict.get("resource") or raw_dict.get("path") or raw_dict.get("endpoint")
    if resource:
        resource = str(resource).strip()

    # Details
    details = raw_dict.get("details", {})
    if isinstance(details, str):
        try:
            details = json.loads(details)
        except Exception:
            details = {"raw_note": details}
    elif not isinstance(details, dict):
        details = {"value": str(details)}

    # Never trust severity hint from external source
    severity_hint = raw_dict.get("severity_hint") or raw_dict.get("severity")

    return {
        "event_time": event_time,
        "source": raw_dict.get("source", default_source),
        "event_type": event_type,
        "outcome": outcome,
        "source_ip": source_ip,
        "account_id": account_id,
        "resource": resource,
        "details": details,
        "severity_hint": str(severity_hint) if severity_hint else None
    }
