from database.repositories import get_audit_logs, verify_audit_chain, add_audit_log

def get_audit_history(limit=100):
    return get_audit_logs(limit=limit)

def verify_system_audit_integrity():
    """
    Executes SHA-256 hash-chain verification across all audit records.
    Returns:
        dict: {
            "valid": bool,
            "records_verified": int,
            "message": str,
            "mismatch": dict or None,
            "integrity_level": "Cryptographically Verified" | "Tampering Detected"
        }
    """
    is_valid, count, message, mismatch = verify_audit_chain()
    return {
        "valid": is_valid,
        "records_verified": count,
        "message": message,
        "mismatch": mismatch,
        "integrity_level": "Cryptographically Verified" if is_valid else "Tampering Detected",
        "hash_algorithm": "SHA-256 Merkle-Style Sequential Chaining",
        "educational_note": (
            "Hash chaining provides tamper-evidence: any modification to an existing audit entry's "
            "timestamp, action, entity, or details invalidates all subsequent hashes in the chain. "
            "Note that in accordance with the blueprint, this demonstrates tamper-evidence under stated assumptions, "
            "not absolute tamper-proofing against privileged database root rewrites."
        )
    }
