import json
from datetime import datetime, timezone, timedelta
from modules.soc_monitor.normalizer import normalize_event, NormalizationError
from modules.soc_monitor.detection_engine import run_all_detection_rules
from database.repositories import insert_security_events_batch, add_audit_log

class IngestionError(Exception):
    pass

def ingest_json_events(raw_data, source="sample_file", auto_detect=True):
    """
    Parses, validates, normalizes, and stores structured JSON security events.
    Transactional safety: invalid JSON raises IngestionError without saving partial corrupt state.
    """
    if isinstance(raw_data, (bytes, str)):
        try:
            parsed = json.loads(raw_data)
        except Exception as e:
            raise IngestionError(f"Malformed JSON payload: {str(e)}")
    elif isinstance(raw_data, (list, dict)):
        parsed = raw_data
    else:
        raise IngestionError("Unsupported data format; JSON array or object required.")

    if isinstance(parsed, dict):
        raw_list = [parsed]
    elif isinstance(parsed, list):
        raw_list = parsed
    else:
        raise IngestionError("JSON content must be a JSON object or array of objects.")

    if not raw_list:
        raise IngestionError("JSON event payload is empty.")

    normalized_events = []
    for idx, item in enumerate(raw_list):
        try:
            norm = normalize_event(item, default_source=source)
            normalized_events.append(norm)
        except Exception as e:
            raise IngestionError(f"Validation error at record #{idx + 1}: {str(e)}")

    inserted_ids = insert_security_events_batch(normalized_events, source=source)
    
    add_audit_log(
        action="LOG_INGEST",
        entity_type="SECURITY_EVENTS",
        entity_id=f"batch_{len(inserted_ids)}",
        details={"count": len(inserted_ids), "source": source}
    )

    alerts = []
    if auto_detect:
        alerts = run_all_detection_rules()

    return {
        "status": "success",
        "ingested_count": len(inserted_ids),
        "first_id": inserted_ids[0] if inserted_ids else None,
        "last_id": inserted_ids[-1] if inserted_ids else None,
        "alerts_triggered": len(alerts)
    }

def generate_demo_events(scenario_type="brute_force"):
    """
    Generates controlled synthetic cybersecurity events to demonstrate
    detection rules, correlation engine, and SIEM triage according to Appendix A.
    Uses documentation-only IP blocks (RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
    """
    now = datetime.now(timezone.utc)
    events = []

    if scenario_type == "brute_force":
        # Five failed sign-ins for a reserved training account trigger DET-001.
        for i in range(5):
            t = (now - timedelta(minutes=4 - i)).isoformat()
            events.append({
                "event_time": t,
                "source": "demo_generator",
                "event_type": "login",
                "outcome": "failure",
                "source_ip": "198.51.100.27",
                "account_id": "m.chen@training.example.invalid",
                "resource": "/auth/sign-in",
                "details": {"attempt": i + 1, "reason": "invalid_password", "client": "browser"}
            })

    elif scenario_type == "password_spray":
        # Single IP 198.51.100.25 targeting 6 distinct accounts in 5 minutes -> triggers DET-002
        accounts = [
            "a.patel@training.example.invalid",
            "d.kim@training.example.invalid",
            "j.williams@training.example.invalid",
            "s.lee@training.example.invalid",
            "m.garcia@training.example.invalid",
            "r.brown@training.example.invalid",
        ]
        for idx, acc in enumerate(accounts):
            t = (now - timedelta(minutes=6 - idx)).isoformat()
            events.append({
                "event_time": t,
                "source": "demo_generator",
                "event_type": "login",
                "outcome": "failure",
                "source_ip": "198.51.100.25",
                "account_id": acc,
                "resource": "/api/v1/auth",
                "details": {"reason": "bad_credentials", "user_agent": "Python-requests/2.28"}
            })

    elif scenario_type == "suspicious_ip":
        # 11 mixed failure/denied/invalid events from 203.0.113.50 in 4 minutes -> triggers DET-003
        for i in range(11):
            t = (now - timedelta(seconds=220 - (i * 20))).isoformat()
            etype = "login" if i % 3 == 0 else ("access_denied" if i % 3 == 1 else "request_invalid")
            outcome = "failure" if i % 3 == 0 else ("denied" if i % 3 == 1 else "invalid")
            events.append({
                "event_time": t,
                "source": "demo_generator",
                "event_type": etype,
                "outcome": outcome,
                "source_ip": "203.0.113.50",
                "account_id": f"probe_user_{i%3}",
                "resource": f"/service/endpoint_{i%4}",
                "details": {"scanner_probe_id": i + 100}
            })

    elif scenario_type == "access_denied":
        # 6 access_denied events to /admin from 192.0.2.88 in 3 minutes -> triggers DET-004
        for i in range(6):
            t = (now - timedelta(seconds=180 - (i * 25))).isoformat()
            events.append({
                "event_time": t,
                "source": "demo_generator",
                "event_type": "access_denied",
                "outcome": "denied",
                "source_ip": "192.0.2.88",
                "account_id": "operator_guest",
                "resource": "/admin/financial_records",
                "details": {"reason": "insufficient_rbac_role", "required": "admin"}
            })

    elif scenario_type == "invalid_requests":
        # 9 malformed requests from 198.51.100.99 in 1 minute -> triggers DET-005
        for i in range(9):
            t = (now - timedelta(seconds=60 - (i * 6))).isoformat()
            events.append({
                "event_time": t,
                "source": "demo_generator",
                "event_type": "request_invalid",
                "outcome": "invalid",
                "source_ip": "198.51.100.99",
                "account_id": None,
                "resource": "/api/v2/telemetry",
                "details": {"error": "malformed_json_syntax", "status_code": 400}
            })

    elif scenario_type == "benign_traffic":
        # Normal benign traffic (successful logins, valid requests, single normal mistake)
        users = ["analyst_jane", "admin_alex", "student_clara", "developer_sam"]
        for idx, u in enumerate(users):
            t = (now - timedelta(minutes=15 - (idx * 3))).isoformat()
            events.append({
                "event_time": t,
                "source": "demo_generator",
                "event_type": "login",
                "outcome": "success",
                "source_ip": f"192.0.2.{20 + idx}",
                "account_id": u,
                "resource": "/dashboard",
                "details": {"auth_method": "sso_token"}
            })
        # Single isolated failure (should NOT trigger brute force)
        events.append({
            "event_time": (now - timedelta(minutes=2)).isoformat(),
            "source": "demo_generator",
            "event_type": "login",
            "outcome": "failure",
            "source_ip": "192.0.2.22",
            "account_id": "developer_sam",
            "resource": "/dashboard",
            "details": {"reason": "caps_lock_mistype"}
        })

    elif scenario_type == "correlated_attack":
        # Multi-stage attack from 192.0.2.100:
        # 1) Password spray across 5 accounts
        # 2) Followed immediately by brute force on admin_master
        # 3) Followed by repeated unauthorized access to /admin/keys
        for idx, acc in enumerate(["user_test1", "user_test2", "user_test3", "user_test4", "user_test5"]):
            t = (now - timedelta(minutes=9 - idx)).isoformat()
            events.append({
                "event_time": t,
                "source": "demo_generator",
                "event_type": "login",
                "outcome": "failure",
                "source_ip": "192.0.2.100",
                "account_id": acc,
                "resource": "/login",
                "details": {"phase": "recon_spray"}
            })
        for i in range(5):
            t = (now - timedelta(minutes=4 - i)).isoformat()
            events.append({
                "event_time": t,
                "source": "demo_generator",
                "event_type": "login",
                "outcome": "failure",
                "source_ip": "192.0.2.100",
                "account_id": "admin_master",
                "resource": "/login",
                "details": {"phase": "brute_force"}
            })
        for i in range(5):
            t = (now - timedelta(seconds=90 - (i * 15))).isoformat()
            events.append({
                "event_time": t,
                "source": "demo_generator",
                "event_type": "access_denied",
                "outcome": "denied",
                "source_ip": "192.0.2.100",
                "account_id": "admin_master",
                "resource": "/admin/keys",
                "details": {"phase": "privilege_abuse"}
            })

    return ingest_json_events(events, source="demo_generator", auto_detect=True)
