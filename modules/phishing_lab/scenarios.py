"""
Phishing Awareness Simulation Scenarios
Compliant with Login Twin Technical Blueprint:
- Safe educational simulations
- Uses reserved example domains (.example.invalid)
- Never requests, collects or stores real credentials
"""

DEFAULT_SCENARIOS = [
    {
        "code": "PH-001",
        "title": "Unexpected Urgent Account Verification",
        "category": "Account Security Lure",
        "story": "You receive an alarming email stating your primary service account will be suspended within 24 hours due to an unauthorized login attempt unless you verify your identity immediately.",
        "displayed_sender": "Security Department <security-notice@example.invalid>",
        "displayed_subject": "URGENT: Immediate Account Verification Required [Ref: #99482]",
        "displayed_link": "https://account-check.example.invalid/verify?token=9283fa",
        "body_text": (
            "Dear Valued Customer,\n\n"
            "We detected an unauthorized sign-in attempt from an unrecognized IP address. "
            "To safeguard your data, your account access has been restricted. You have 24 hours to verify "
            "your credentials and avoid permanent account deactivation.\n\n"
            "Please click the secure link below to verify your account:\n"
            "https://account-check.example.invalid/verify\n\n"
            "Thank you for keeping your account secure,\n"
            "Security Team"
        ),
        "available_indicators": [
            {"id": "ind_urgency", "label": "Artificial Urgency & Threat of Suspension (24-hour deadline)"},
            {"id": "ind_domain", "label": "Suspicious External Domain (account-check.example.invalid)"},
            {"id": "ind_generic", "label": "Generic Greeting ('Dear Valued Customer') instead of your name"},
            {"id": "ind_unsolicited", "label": "Unsolicited Account Verification Request"},
            {"id": "ind_perfect_grammar", "label": "Official Digital Corporate Signature (Legitimate Marker)"}
        ],
        "correct_indicator_ids": ["ind_urgency", "ind_domain", "ind_generic", "ind_unsolicited"],
        "safe_action_options": [
            {"id": "act_click", "label": "Click the link and submit username to prevent suspension.", "is_safe": False},
            {"id": "act_reply", "label": "Reply to the email with your password to prove ownership.", "is_safe": False},
            {"id": "act_official", "label": "Open the official app/website independently in a new tab; do not use the email link.", "is_safe": True},
            {"id": "act_forward", "label": "Forward to all coworkers asking if they got it too.", "is_safe": False}
        ],
        "correct_action_id": "act_official",
        "teaching_point": "Phishing attackers routinely simulate panic and time pressure ('24 hours') so victims act impulsively without checking the sender domain."
    },
    {
        "code": "PH-002",
        "title": "Urgent Direct Deposit Payroll Update",
        "category": "Financial / HR Impersonation",
        "story": "An urgent message arrives appearing to come from the Human Resources payroll portal, stating direct deposit banking details failed to process and must be updated before 5:00 PM today.",
        "displayed_sender": "Payroll Support <payroll-notice@example.invalid>",
        "displayed_subject": "ACTION REQUIRED: Direct Deposit Routing Failure - Paycheck Delayed",
        "displayed_link": "http://hr-portal-directdeposit.example.invalid/login",
        "body_text": (
            "Attention Employee,\n\n"
            "Your bi-weekly paycheck direct deposit returned an invalid routing number error. "
            "Failure to update your banking information by 5:00 PM today will result in your payroll being held for 30 days.\n\n"
            "Update your banking credentials here:\n"
            "http://hr-portal-directdeposit.example.invalid/login\n\n"
            "HR Payroll Processing Center"
        ),
        "available_indicators": [
            {"id": "ind_http", "label": "Unencrypted HTTP link (lacks HTTPS encryption for banking data)"},
            {"id": "ind_financial_fear", "label": "Severe Financial Pressure (fear of withheld paycheck)"},
            {"id": "ind_domain_mismatch", "label": "Third-party host domain (hr-portal-directdeposit.example.invalid)"},
            {"id": "ind_unverified_routing", "label": "Unsolicited request to submit banking/routing credentials"},
            {"id": "ind_high_auth", "label": "Signed by Certified Payroll System (Legitimate Marker)"}
        ],
        "correct_indicator_ids": ["ind_http", "ind_financial_fear", "ind_domain_mismatch", "ind_unverified_routing"],
        "safe_action_options": [
            {"id": "act_click_banking", "label": "Enter banking details right away to ensure timely salary payment.", "is_safe": False},
            {"id": "act_verify_hr", "label": "Verify directly with your HR department using known internal contact information or the official HR intranet.", "is_safe": True},
            {"id": "act_email_acc", "label": "Email your bank account details directly to the sender.", "is_safe": False}
        ],
        "correct_action_id": "act_verify_hr",
        "teaching_point": "Attackers target payroll and direct deposits by weaponizing the fear of missed wages. Critical financial updates should always be verified out-of-band."
    },
    {
        "code": "PH-003",
        "title": "Failed Parcel Delivery & Address Reschedule",
        "category": "Delivery / Smishing Lure",
        "story": "You receive a notification claiming a high-priority parcel could not be delivered to your address and a small redelivery scheduling fee must be confirmed.",
        "displayed_sender": "Express Parcel Courier <track@delivery-alerts.example.invalid>",
        "displayed_subject": "Delivery Exception: Package #PKG-77102 Held at Distribution Center",
        "displayed_link": "https://tracking-reschedule.example.invalid/confirm-address",
        "body_text": (
            "Express Parcel Service Alert:\n\n"
            "We were unable to deliver package #PKG-77102 today at 09:42 AM due to an incomplete street address.\n"
            "Please confirm your delivery address and schedule redelivery within 48 hours to prevent the parcel from being returned to sender.\n\n"
            "Track & Reschedule: https://tracking-reschedule.example.invalid/confirm-address\n"
        ),
        "available_indicators": [
            {"id": "ind_no_order", "label": "No prior order tracking confirmation or merchant reference"},
            {"id": "ind_reschedule_link", "label": "External non-standard tracking domain (tracking-reschedule.example.invalid)"},
            {"id": "ind_vague_details", "label": "Vague delivery details lacking package recipient name"},
            {"id": "ind_urgency_return", "label": "Threat to return parcel unless acted upon immediately"}
        ],
        "correct_indicator_ids": ["ind_no_order", "ind_reschedule_link", "ind_vague_details", "ind_urgency_return"],
        "safe_action_options": [
            {"id": "act_pay_fee", "label": "Click the link and input address to recover the package.", "is_safe": False},
            {"id": "act_direct_app", "label": "Check your original store order receipt or log into the courier's official app directly.", "is_safe": True},
            {"id": "act_call_number", "label": "Call any phone number listed in the suspicious email.", "is_safe": False}
        ],
        "correct_action_id": "act_direct_app",
        "teaching_point": "Package delivery scams capitalize on curiosity and anticipation. Always trace packages through the merchant you purchased from."
    },
    {
        "code": "PH-004",
        "title": "Mandatory IT Multi-Factor Authentication (MFA) Re-sync",
        "category": "IT / Credential Harvesting",
        "story": "An internal email seemingly from IT Operations announces a mandatory infrastructure security upgrade requiring all staff to synchronize their MFA tokens.",
        "displayed_sender": "IT Support Operations <helpdesk@it-desk-portal.example.invalid>",
        "displayed_subject": "MANDATORY IT NOTICE: Multi-Factor Authentication (MFA) System Migration",
        "displayed_link": "https://mfa-auth-sync.example.invalid/portal/login",
        "body_text": (
            "Dear Staff,\n\n"
            "IT Operations is migrating to enhanced 2FA/MFA authentication protocols tonight at midnight. "
            "All active users must validate their single sign-on credentials and enter their current authentication token to retain mailbox access.\n\n"
            "Begin MFA Sync: https://mfa-auth-sync.example.invalid/portal/login\n\n"
            "Failure to synchronize before midnight will lock your network workstation.\n"
            "IT Helpdesk Operations"
        ),
        "available_indicators": [
            {"id": "ind_mfa_request", "label": "Asking to enter 2FA/MFA token on an external web page"},
            {"id": "ind_workstation_threat", "label": "Punitive threat of workstation lockout at midnight"},
            {"id": "ind_unusual_portal", "label": "Third-party domain (mfa-auth-sync.example.invalid) posing as IT infrastructure"},
            {"id": "ind_no_advance", "label": "Zero advance warning or internal change announcement from leadership"}
        ],
        "correct_indicator_ids": ["ind_mfa_request", "ind_workstation_threat", "ind_unusual_portal", "ind_no_advance"],
        "safe_action_options": [
            {"id": "act_enter_token", "label": "Go to the link and type your current MFA pass-code.", "is_safe": False},
            {"id": "act_contact_admin", "label": "Contact internal IT through the verified company helpdesk ticket portal or phone.", "is_safe": True},
            {"id": "act_ignore", "label": "Ignore completely without reporting to IT security.", "is_safe": False}
        ],
        "correct_action_id": "act_contact_admin",
        "teaching_point": "Real IT departments will never ask you to synchronize or type temporary MFA one-time passcodes into an external third-party form."
    },
    {
        "code": "PH-005",
        "title": "Confidential Executive Bonus Review Document",
        "category": "Social Engineering / Curiosity Lure",
        "story": "A file-sharing notification states the Executive Committee has shared an encrypted quarterly performance bonus sheet directly with you.",
        "displayed_sender": "Cloud File Sharing <notifications@cloud-share-docs.example.invalid>",
        "displayed_subject": "Confidential Document Shared: Q4_Compensation_Adjustments.pdf",
        "displayed_link": "https://view-cloud-documents.example.invalid/share/preview?doc=77a1",
        "body_text": (
            "A secure document has been shared with you.\n\n"
            "Title: Q4_Executive_Bonus_Matrix.pdf\n"
            "Shared by: Corporate Board of Directors\n"
            "Access expires in: 6 hours\n\n"
            "Click here to review document:\n"
            "https://view-cloud-documents.example.invalid/share/preview?doc=77a1\n"
        ),
        "available_indicators": [
            {"id": "ind_curiosity_bonus", "label": "Curiosity and greed lure concerning confidential compensation"},
            {"id": "ind_unsolicited_share", "label": "Unsolicited file share from an external document service"},
            {"id": "ind_short_expiry", "label": "Short expiration countdown (6 hours) to induce panic"},
            {"id": "ind_external_viewer", "label": "External viewing domain instead of authorized corporate drive"}
        ],
        "correct_indicator_ids": ["ind_curiosity_bonus", "ind_unsolicited_share", "ind_short_expiry", "ind_external_viewer"],
        "safe_action_options": [
            {"id": "act_open_doc", "label": "Click to quickly read the bonus numbers before anyone notices.", "is_safe": False},
            {"id": "act_report_security", "label": "Report the suspicious email to the Information Security / Phishing triage team.", "is_safe": True},
            {"id": "act_forward_friend", "label": "Forward the attachment to a colleague to check if it's real.", "is_safe": False}
        ],
        "correct_action_id": "act_report_security",
        "teaching_point": "Attackers exploit emotional impulses like greed or curiosity. Confidential company documents are never shared via random external cloud drop links."
    }
]
