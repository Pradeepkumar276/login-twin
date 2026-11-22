import os

class Config:
    PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
    DATABASE_PATH = os.environ.get("LOGIN_TWIN_DB", os.path.join(PROJECT_ROOT, "database", "login_twin.db"))
    SECRET_KEY = os.environ.get("SECRET_KEY", "login-twin-secret-key-soc-security-2026")
    
    # URL Analyzer Configuration
    MAX_URL_LENGTH_THRESHOLD = 75
    MAX_SUBDOMAIN_DEPTH = 3
    URL_RISK_BANDS = {
        "LOW": (0, 19),
        "MEDIUM": (20, 49),
        "HIGH": (50, 74),
        "CRITICAL": (75, 100)
    }

    # Detection Rules Configuration
    # DET-001: Brute Force
    BRUTE_FORCE_WINDOW_SECONDS = 300  # 5 minutes
    BRUTE_FORCE_THRESHOLD = 5         # 5 failed logins for one account

    # DET-002: Password Spraying
    SPRAY_WINDOW_SECONDS = 600        # 10 minutes
    SPRAY_DISTINCT_ACCOUNT_THRESHOLD = 5 # 5 distinct accounts from same IP

    # DET-003: Suspicious IP Activity
    IP_ACTIVITY_WINDOW_SECONDS = 300  # 5 minutes
    IP_ACTIVITY_THRESHOLD = 10        # 10 failed/denied/invalid events

    # DET-004: Repeated Unauthorized Access
    DENIED_ACCESS_WINDOW_SECONDS = 300 # 5 minutes
    DENIED_ACCESS_THRESHOLD = 5        # 5 access_denied events

    # DET-005: Abnormal Request Activity
    INVALID_REQUEST_WINDOW_SECONDS = 120 # 2 minutes
    INVALID_REQUEST_THRESHOLD = 8       # 8 request_invalid events

    # Event Correlation Configuration
    CORRELATION_WINDOW_SECONDS = 600    # 10 minutes
    CORRELATION_MIN_EVIDENCE = 2        # At least 2 events/alerts to correlate
