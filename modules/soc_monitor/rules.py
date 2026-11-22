from config import Config

RULE_DEFINITIONS = {
    "DET-001": {
        "rule_code": "DET-001",
        "name": "Brute Force Detection",
        "default_severity": "High",
        "confidence": 85,
        "window_seconds": Config.BRUTE_FORCE_WINDOW_SECONDS,
        "threshold": Config.BRUTE_FORCE_THRESHOLD,
        "possible_false_positives": "User mistyped password repeatedly; test automation script; shared team account."
    },
    "DET-002": {
        "rule_code": "DET-002",
        "name": "Password Spraying Detection",
        "default_severity": "High",
        "confidence": 90,
        "window_seconds": Config.SPRAY_WINDOW_SECONDS,
        "threshold": Config.SPRAY_DISTINCT_ACCOUNT_THRESHOLD,
        "possible_false_positives": "Corporate egress NAT IP; shared university proxy; legitimate identity provider batch sync."
    },
    "DET-003": {
        "rule_code": "DET-003",
        "name": "Suspicious IP Activity Burst",
        "default_severity": "Medium",
        "confidence": 75,
        "window_seconds": Config.IP_ACTIVITY_WINDOW_SECONDS,
        "threshold": Config.IP_ACTIVITY_THRESHOLD,
        "possible_false_positives": "Authorized vulnerability scanner; administrative security check."
    },
    "DET-004": {
        "rule_code": "DET-004",
        "name": "Repeated Unauthorized Access",
        "default_severity": "Medium",
        "confidence": 80,
        "window_seconds": Config.DENIED_ACCESS_WINDOW_SECONDS,
        "threshold": Config.DENIED_ACCESS_THRESHOLD,
        "possible_false_positives": "User lacks permissions for newly assigned role and repeatedly retries."
    },
    "DET-005": {
        "rule_code": "DET-005",
        "name": "Abnormal Request Activity",
        "default_severity": "Medium",
        "confidence": 70,
        "window_seconds": Config.INVALID_REQUEST_WINDOW_SECONDS,
        "threshold": Config.INVALID_REQUEST_THRESHOLD,
        "possible_false_positives": "Buggy frontend release, automated regression testing, or malformed browser extension."
    }
}
