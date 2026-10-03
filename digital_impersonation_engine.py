# ============================================================
# CYBERGUARD
# Digital Impersonation Detection Engine
# ============================================================

import re
from organisation_data import ORGANISATION, TRUSTED_IDENTITIES


# ============================================================
# 1. TEXT EXTRACTION
# ============================================================

def extract_emails(text):
    """
    Extract email addresses from the message.
    """

    return re.findall(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        text
    )


def find_claimed_identity(text):
    """
    Check whether the message appears to mention
    one of the organisation's trusted identities.
    """

    text_lower = text.lower()

    for identity in TRUSTED_IDENTITIES:

        name = identity["name"].lower()

        if name in text_lower:
            return identity

    return None


def find_claimed_role(text):
    """
    Check whether the message mentions one of the
    trusted identities' roles.
    """

    text_lower = text.lower()

    for identity in TRUSTED_IDENTITIES:

        role = identity["role"].lower()

        if role in text_lower:
            return identity

    return None


# ============================================================
# 2. SENDER ANALYSIS
# ============================================================

def analyze_sender_email(sender_email):
    """
    Compare sender email against the organisation's
    trusted identities and official domains.
    """

    if not sender_email:
        return {
            "sender_provided": False,
            "domain": None,
            "trusted_identity": None,
            "domain_match": False
        }

    sender_email = sender_email.lower().strip()

    if "@" not in sender_email:
        return {
            "sender_provided": True,
            "domain": None,
            "trusted_identity": None,
            "domain_match": False
        }

    domain = sender_email.split("@")[-1]

    trusted_identity = None

    for identity in TRUSTED_IDENTITIES:

        if identity["email"].lower() == sender_email:
            trusted_identity = identity
            break

    domain_match = domain in [
        d.lower()
        for d in ORGANISATION["official_domains"]
    ]

    return {
        "sender_provided": True,
        "domain": domain,
        "trusted_identity": trusted_identity,
        "domain_match": domain_match
    }


# ============================================================
# 3. SUSPICIOUS REQUEST DETECTION
# ============================================================

def detect_suspicious_requests(text):

    text_lower = text.lower()

    indicators = []

    request_patterns = {

        "Financial Request": [
            "transfer money",
            "send money",
            "make a payment",
            "pay immediately",
            "transfer ₹",
            "transfer rs",
            "bank transfer",
            "payment required"
        ],

        "Credential Request": [
            "send your password",
            "share your password",
            "send the otp",
            "share the otp",
            "provide the otp",
            "send otp",
            "share otp",
            "enter your password",
            "provide your password",
            "share your pin",
            "send your pin",
            "share cvv"
        ],

        "Sensitive Information Request": [
            "send the employee list",
            "send employee data",
            "send confidential data",
            "send the database",
            "share confidential information",
            "send company documents",
            "send the documents"
        ],

        "Urgency": [
            "urgent",
            "immediately",
            "right now",
            "as soon as possible",
            "act now",
            "within 30 minutes",
            "within an hour"
        ]
    }

    for category, patterns in request_patterns.items():

        matched = [
            pattern
            for pattern in patterns
            if pattern in text_lower
        ]

        if matched:

            indicators.append({
                "category": category,
                "matches": matched
            })

    return indicators


# ============================================================
# 4. IDENTITY MISMATCH DETECTION
# ============================================================

def detect_identity_mismatch(
    claimed_identity,
    sender_analysis
):

    indicators = []

    if not claimed_identity:
        return indicators

    trusted_email = claimed_identity["email"].lower()

    sender_identity = sender_analysis.get(
        "trusted_identity"
    )

    if sender_analysis["sender_provided"]:

        sender_domain = sender_analysis.get(
            "domain"
        )

        trusted_domain = trusted_email.split("@")[-1]

        # Sender claims to be trusted person,
        # but email address is different.

        if sender_identity is None:

            indicators.append(
                {
                    "type": "Identity Mismatch",
                    "message": (
                        f"Message appears to represent "
                        f"{claimed_identity['name']}, but the "
                        f"sender address does not match the "
                        f"trusted identity."
                    )
                }
            )

        # Sender domain differs from trusted identity domain.

        if (
            sender_domain
            and sender_domain != trusted_domain
        ):

            indicators.append(
                {
                    "type": "Domain Mismatch",
                    "message": (
                        f"Trusted identity uses "
                        f"{trusted_domain}, but the "
                        f"message was sent from "
                        f"{sender_domain}."
                    )
                }
            )

    return indicators


# ============================================================
# 5. ROLE IMPERSONATION
# ============================================================

def detect_role_impersonation(
    claimed_role_identity,
    sender_analysis
):

    if not claimed_role_identity:
        return None

    if not sender_analysis["sender_provided"]:
        return None

    sender_identity = sender_analysis.get(
        "trusted_identity"
    )

    if sender_identity is None:

        return {
            "type": "Role Impersonation",
            "message": (
                f"Message appears to claim the role "
                f"'{claimed_role_identity['role']}', "
                f"but the sender could not be matched "
                f"to the trusted identity."
            )
        }

    return None


# ============================================================
# 6. RISK SCORE
# ============================================================

def calculate_impersonation_risk(
    claimed_identity,
    claimed_role,
    sender_analysis,
    identity_indicators,
    role_indicator,
    request_indicators
):

    score = 0
    reasons = []

    # --------------------------------------------------------
    # Trusted identity mentioned
    # --------------------------------------------------------

    if claimed_identity:

        score += 20

        reasons.append(
            f"Trusted identity mentioned: "
            f"{claimed_identity['name']}"
        )

    # --------------------------------------------------------
    # Sender mismatch
    # --------------------------------------------------------

    for indicator in identity_indicators:

        if indicator["type"] == "Identity Mismatch":

            score += 30

            reasons.append(
                indicator["message"]
            )

        elif indicator["type"] == "Domain Mismatch":

            score += 25

            reasons.append(
                indicator["message"]
            )

    # --------------------------------------------------------
    # Role impersonation
    # --------------------------------------------------------

    if role_indicator:

        score += 25

        reasons.append(
            role_indicator["message"]
        )

    # --------------------------------------------------------
    # Suspicious requests
    # --------------------------------------------------------

    for indicator in request_indicators:

        category = indicator["category"]

        if category == "Financial Request":

            score += 20

            reasons.append(
                "Financial request detected."
            )

        elif category == "Credential Request":

            score += 25

            reasons.append(
                "Credential or authentication "
                "information requested."
            )

        elif category == "Sensitive Information Request":

            score += 20

            reasons.append(
                "Sensitive organisational information requested."
            )

        elif category == "Urgency":

            score += 10

            reasons.append(
                "Urgency or pressure detected."
            )

    # --------------------------------------------------------
    # High-risk combinations
    # --------------------------------------------------------

    categories = [
        indicator["category"]
        for indicator in request_indicators
    ]

    if (
        claimed_identity
        and "Financial Request" in categories
        and "Urgency" in categories
    ):

        score += 20

        reasons.append(
            "Trusted identity + financial request + "
            "urgency combination detected."
        )

    if (
        claimed_identity
        and "Credential Request" in categories
    ):

        score += 20

        reasons.append(
            "Trusted identity appears to be used "
            "to request authentication information."
        )

    score = min(score, 100)

    # --------------------------------------------------------
    # Risk level
    # --------------------------------------------------------

    if score >= 75:
        risk_level = "High Risk"

    elif score >= 40:
        risk_level = "Medium Risk"

    else:
        risk_level = "Low Risk"

    return score, risk_level, reasons


# ============================================================
# 7. MAIN ANALYSIS FUNCTION
# ============================================================

def analyze_impersonation(
    message,
    sender_email=None
):

    if not message or not message.strip():

        return {
            "status": "No message provided",
            "risk_level": "Low Risk",
            "risk_score": 0,
            "organisation": ORGANISATION["name"],
            "claimed_identity": None,
            "claimed_role": None,
            "sender": sender_email,
            "detected_indicators": [],
            "recommendation": (
                "Provide a message for analysis."
            )
        }

    message = message.strip()

    # --------------------------------------------------------
    # Identity / role extraction
    # --------------------------------------------------------

    claimed_identity = find_claimed_identity(
        message
    )

    claimed_role = find_claimed_role(
        message
    )

    # --------------------------------------------------------
    # Sender analysis
    # --------------------------------------------------------

    sender_analysis = analyze_sender_email(
        sender_email
    )

    # --------------------------------------------------------
    # Suspicious request analysis
    # --------------------------------------------------------

    request_indicators = detect_suspicious_requests(
        message
    )

    # --------------------------------------------------------
    # Identity mismatch
    # --------------------------------------------------------

    identity_indicators = detect_identity_mismatch(
        claimed_identity,
        sender_analysis
    )

    # --------------------------------------------------------
    # Role impersonation
    # --------------------------------------------------------

    role_indicator = detect_role_impersonation(
        claimed_role,
        sender_analysis
    )

    # --------------------------------------------------------
    # Risk calculation
    # --------------------------------------------------------

    score, risk_level, reasons = (
        calculate_impersonation_risk(
            claimed_identity,
            claimed_role,
            sender_analysis,
            identity_indicators,
            role_indicator,
            request_indicators
        )
    )

    # --------------------------------------------------------
    # Combine indicators
    # --------------------------------------------------------

    detected_indicators = []

    detected_indicators.extend(
        identity_indicators
    )

    if role_indicator:

        detected_indicators.append(
            role_indicator
        )

    for indicator in request_indicators:

        detected_indicators.append(
            {
                "type": indicator["category"],
                "message": ", ".join(
                    indicator["matches"]
                )
            }
        )

    # --------------------------------------------------------
    # Status
    # --------------------------------------------------------

    if score >= 75:

        status = (
            "Potential Digital Impersonation Threat"
        )

    elif score >= 40:

        status = (
            "Suspicious Identity Activity Detected"
        )

    elif score > 0:

        status = (
            "Low-Level Identity Risk Detected"
        )

    else:

        status = (
            "No Immediate Impersonation Threat Detected"
        )

    # --------------------------------------------------------
    # Recommendation
    # --------------------------------------------------------

    if score >= 75:

        recommendation = (
            "Do not follow the request. Verify the person's "
            "identity through an official organisational "
            "communication channel before taking action."
        )

    elif score >= 40:

        recommendation = (
            "Verify the sender's identity and the request "
            "through an independent official channel."
        )

    else:

        recommendation = (
            "No major impersonation indicators were detected. "
            "Continue to verify unexpected requests."
        )

    # --------------------------------------------------------
    # Final report
    # --------------------------------------------------------

    return {

        "organisation":
            ORGANISATION["name"],

        "status":
            status,

        "risk_level":
            risk_level,

        "risk_score":
            score,

        "claimed_identity":
            claimed_identity,

        "claimed_role":
            claimed_role,

        "sender":
            sender_email,

        "sender_analysis":
            sender_analysis,

        "detected_indicators":
            detected_indicators,

        "reasons":
            reasons,

        "recommendation":
            recommendation
    }
