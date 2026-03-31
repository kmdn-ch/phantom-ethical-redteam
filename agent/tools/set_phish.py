"""Dynamic social engineering template generator (educational only)."""

SCENARIOS = {
    "phishing_email": {
        "subject": "Urgent: Security Alert for your {target} account",
        "body": """Dear User,

Our security systems have detected suspicious login activity on your {target} account
from an unrecognized device in {location}.

If this was not you, please verify your identity immediately:
{link}

Failure to verify within 24 hours will result in temporary account suspension.

Best regards,
{target} Security Team
security-noreply@{target}""",
    },
    "password_reset": {
        "subject": "Password Reset Request \u2014 {target}",
        "body": """Hi,

We received a request to reset the password associated with your {target} account.

Click below to reset your password:
{link}

If you did not request this, please ignore this email or contact support@{target}.

\u2014 {target} Account Services""",
    },
    "mfa_bypass": {
        "subject": "Action Required: Verify your new device \u2014 {target}",
        "body": """Hello,

A new device was registered to your {target} account:
  Device: Chrome on Windows 11
  Location: {location}
  Time: {timestamp}

If this was you, confirm by clicking:
{link}

If not, secure your account immediately.

\u2014 {target} Identity Protection""",
    },
    "invoice": {
        "subject": "Invoice #INV-{invoice_num} from {target}",
        "body": """Dear Customer,

Please find attached your invoice #INV-{invoice_num} for services rendered by {target}.

Amount Due: $4,299.00
Due Date: {due_date}

View and pay your invoice online:
{link}

Questions? Contact billing@{target}

Thank you for your business.
\u2014 {target} Accounts Receivable""",
    },
    "delivery_notification": {
        "subject": "Your {target} package is ready for delivery",
        "body": """Hello,

Great news! Your order from {target} is out for delivery.

Tracking Number: {tracking}
Estimated Delivery: Today by 8:00 PM

Track your package or update delivery preferences:
{link}

\u2014 {target} Shipping""",
    },
}


def run(target: str, scenario: str = "phishing_email") -> str:
    if scenario not in SCENARIOS:
        available = ", ".join(SCENARIOS.keys())
        return f"Unknown scenario '{scenario}'. Available: {available}"

    tmpl = SCENARIOS[scenario]
    placeholders = {
        "target": target,
        "link": f"https://testphp.vulnweb.com/verify?t={target}",
        "location": "Zurich, Switzerland",
        "timestamp": "2026-03-18 14:32 UTC",
        "invoice_num": "20260318-001",
        "due_date": "2026-04-01",
        "tracking": "PH-7382910-CH",
    }

    subject = tmpl["subject"].format(**placeholders)
    body = tmpl["body"].format(**placeholders)

    return f"""[TEMPLATE SOCIAL ENGINEERING \u2014 DO NOT SEND WITHOUT PERMISSION]

Scenario : {scenario}
Target   : {target}

Subject: {subject}

{body}

\u2014\u2014\u2014
[END TEMPLATE \u2014 EDUCATIONAL PURPOSE ONLY \u2014 NO REAL SEND POSSIBLE]"""


TOOL_SPEC = {
    "name": "generate_phish_template",
    "description": (
        "Generate a social engineering template for educational purpose (no real send). "
        "Scenarios: phishing_email, password_reset, mfa_bypass, invoice, delivery_notification."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Target domain"},
            "scenario": {
                "type": "string",
                "default": "phishing_email",
                "description": "Template scenario: phishing_email, password_reset, mfa_bypass, invoice, delivery_notification",
            },
        },
        "required": ["target"],
    },
}
