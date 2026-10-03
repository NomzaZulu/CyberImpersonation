# ============================================================
# CYBERGUARD
# Digital Impersonation Detection Engine
# ============================================================

import re

from organisation_data import (
    ORGANISATION,
    TRUSTED_IDENTITIES
)


# ============================================================
# 1. TEXT EXTRACTION
# ============================================================

def extract_emails(text):
    """
    Extract email addresses from message text.
    """

    if not text:
        return []

    return re.findall(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        text
    )


# ============================================================
# 2. CLAIMED IDENTITY DETECTION
# ============================================================

def find_claimed_identity(text):
    """
    Detect whether the message explicitly mentions
    a trusted person's name.
    """

    if not text:
        return None

    text_lower = text.lower()

    for identity in TRUSTED_IDENTITIES:

        name = identity["name"].lower()

        if name in text_lower:
            return identity

    return None


# ============================================================
# 3. CLAIMED ROLE DETECTION
# ============================================================

def find_claimed_role(text):
    """
    Detect whether the message claims or mentions
    a role belonging to a trusted identity.

    Returns the trusted identity associated with
    that role.
    """

    if not text:
        return None

    text_lower = text.lower()

    for identity in TRUSTED_IDENTITIES:

        role = identity["role"].lower()

        if role in text_lower:

            return identity

    return None


# ============================================================
# 4. SENDER ANALYSIS
# ============================================================

def analyze_sender_email(sender_email):
    """
    Analyse the sender's email address.

    Important:
    An official organisation domain does NOT automatically
    mean that the sender is a trusted person.
    """

    if not sender_email:

        return {
            "sender_provided": False,
            "email": None,
            "domain": None,
            "domain_match": False,
            "trusted_identity": None,
            "identity_verified": False
        }

    sender_email = sender_email.lower().strip()

    if "@" not in sender_email:

        return {
            "sender_provided": True,
            "email": sender_email,
            "domain": None,
            "domain_match": False,
            "trusted_identity": None,
            "identity_verified": False
        }

    domain = sender_email.split("@")[-1]

    official_domains = [
        d.lower()
        for d in ORGANISATION["official_domains"]
    ]

    domain_match = domain in official_domains

    trusted_identity = None

    for identity in TRUSTED_IDENTITIES:

        if identity["email"].lower() == sender_email:

            trusted_identity = identity
            break

    identity_verified = trusted_identity is not None

    return {

        "sender_provided": True,

        "email": sender_email,

        "domain": domain,

        "domain_match": domain_match,

        "trusted_identity": trusted_identity,

        "identity_verified": identity_verified
    }


# ============================================================
# 5. SUSPICIOUS REQUEST DETECTION
# ============================================================

def detect_suspicious_requests(text):

    if not text:
        return []

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
            "payment required",
            "process the payment",
            "send the payment"
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
            "share cvv",
            "send the verification code",
            "share the verification code"
        ],

        "Sensitive Information Request": [

            "send the employee list",
            "send employee data",
            "send confidential data",
            "send the database",
            "share confidential information",
            "send company documents",
            "send the documents",
            "send employee records",
            "share employee records"
        ],

        "Urgency": [

            "urgent",
            "immediately",
            "right now",
            "as soon as possible",
            "act now",
            "within 30 minutes",
            "within an hour",
            "asap"
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
# 6. IDENTITY MISMATCH
# ============================================================

def detect_identity_mismatch(
    claimed_identity,
    sender_analysis
):

    indicators = []

    if not claimed_identity:
        return indicators

    if not sender_analysis["sender_provided"]:
        return indicators

    sender_identity = sender_analysis.get(
        "trusted_identity"
    )

    sender_email = sender_analysis.get(
        "email"
    )

    trusted_email = claimed_identity["email"].lower()

    # --------------------------------------------------------
    # Sender is not the trusted person
    # --------------------------------------------------------

    if sender_identity is None:

        indicators.append({

            "type": "Identity Mismatch",

            "message": (
                f"Message appears to represent "
                f"{claimed_identity['name']}, but the "
                f"sender address ({sender_email}) does not "
                f"match the trusted identity."
            )
        })

    # --------------------------------------------------------
    # Sender is another trusted person
    # --------------------------------------------------------

    elif sender_identity["email"].lower() != trusted_email:

        indicators.append({

            "type": "Identity Mismatch",

            "message": (
                f"Message mentions {claimed_identity['name']}, "
                f"but it was sent from the trusted account of "
                f"{sender_identity['name']}."
            )
        })

    return indicators


# ============================================================
# 7. ROLE IMPERSONATION
# ============================================================

def detect_role_impersonation(
    claimed_role_identity,
    sender_analysis
):

    if not claimed_role_identity:
        return None

    expected_email = (
        claimed_role_identity["email"].lower()
    )

    expected_name = (
        claimed_role_identity["name"]
    )

    expected_role = (
        claimed_role_identity["role"]
    )

    # --------------------------------------------------------
    # No sender available
    # --------------------------------------------------------

    if not sender_analysis["sender_provided"]:

        return {

            "type": "Role Verification Required",

            "message": (
                f"The message references the role "
                f"'{expected_role}', which is associated "
                f"with {expected_name}. The sender identity "
                f"could not be verified."
            )
        }

    sender_email = sender_analysis.get(
        "email"
    )

    # --------------------------------------------------------
    # Sender is NOT the trusted person for this role
    # --------------------------------------------------------

    if sender_email.lower() != expected_email:

        return {

            "type": "Role Impersonation",

            "message": (
                f"The message references the role "
                f"'{expected_role}', which is associated "
                f"with {expected_name}, but the sender "
                f"({sender_email}) does not match that "
                f"trusted identity."
            )
        }

    # --------------------------------------------------------
    # Sender matches expected person
    # --------------------------------------------------------

    return None


# ============================================================
# 8. RISK SCORE
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

    # ========================================================
    # EXPLICIT TRUSTED IDENTITY MENTION
    # ========================================================

    if claimed_identity:

        score += 10

        reasons.append(
            f"Trusted identity mentioned: "
            f"{claimed_identity['name']}"
        )

    # ========================================================
    # IDENTITY MISMATCH
    # ========================================================

    for indicator in identity_indicators:

        if indicator["type"] == "Identity Mismatch":

            score += 25

            reasons.append(
                indicator["message"]
            )

    # ========================================================
    # ROLE IMPERSONATION
    # ========================================================

    if role_indicator:

        if role_indicator["type"] == "Role Impersonation":

            score += 25

            reasons.append(
                role_indicator["message"]
            )

        elif role_indicator["type"] == "Role Verification Required":

            score += 10

            reasons.append(
                role_indicator["message"]
            )

    # ========================================================
    # SUSPICIOUS REQUESTS
    # ========================================================

    categories = []

    for indicator in request_indicators:

        category = indicator["category"]

        categories.append(category)

        # ----------------------------------------------------
        # Financial
        # ----------------------------------------------------

        if category == "Financial Request":

            score += 20

            reasons.append(
                "Financial request detected."
            )

        # ----------------------------------------------------
        # Credentials
        # ----------------------------------------------------

        elif category == "Credential Request":

            score += 25

            reasons.append(
                "Credential or authentication "
                "information requested."
            )

        # ----------------------------------------------------
        # Sensitive data
        # ----------------------------------------------------

        elif category == "Sensitive Information Request":

            score += 20

            reasons.append(
                "Sensitive organisational information "
                "requested."
            )

        # ----------------------------------------------------
        # Urgency
        # ----------------------------------------------------

        elif category == "Urgency":

            score += 10

            reasons.append(
                "Urgency or pressure detected."
            )

    # ========================================================
    # HIGH-RISK COMBINATIONS
    # ========================================================

    if (
        claimed_identity
        and "Financial Request" in categories
        and "Urgency" in categories
    ):

        score += 15

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

    if (
        claimed_role
        and role_indicator
        and "Sensitive Information Request" in categories
    ):

        score += 15

        reasons.append(
            "Role impersonation combined with a "
            "sensitive information request."
        )

    # ========================================================
    # SCORE LIMIT
    # ========================================================

    score = min(score, 100)

    # ========================================================
    # RISK LEVEL
    # ========================================================

    if score >= 75:

        risk_level = "High Risk"

    elif score >= 40:

        risk_level = "Medium Risk"

    elif score > 0:

        risk_level = "Low Risk"

    else:

        risk_level = "No Risk Detected"

    return score, risk_level, reasons


# ============================================================
# 9. MAIN ANALYSIS FUNCTION
# ============================================================

def analyze_impersonation(
    message,
    sender_email=None
):

    # ========================================================
    # EMPTY MESSAGE
    # ========================================================

    if not message or not message.strip():

        return {

            "organisation":
                ORGANISATION["name"],

            "status":
                "No message provided",

            "risk_level":
                "No Risk Detected",

            "risk_score":
                0,

            "claimed_identity":
                None,

            "claimed_role":
                None,

            "sender":
                sender_email,

            "sender_analysis":
                analyze_sender_email(sender_email),

            "detected_indicators":
                [],

            "reasons":
                [],

            "recommendation":
                "Provide a message for analysis."
        }

    message = message.strip()

    # ========================================================
    # IDENTITY / ROLE EXTRACTION
    # ========================================================

    claimed_identity = find_claimed_identity(
        message
    )

    claimed_role = find_claimed_role(
        message
    )

    # ========================================================
    # SENDER ANALYSIS
    # ========================================================

    sender_analysis = analyze_sender_email(
        sender_email
    )

    # ========================================================
    # REQUEST ANALYSIS
    # ========================================================

    request_indicators = detect_suspicious_requests(
        message
    )

    # ========================================================
    # IDENTITY MISMATCH
    # ========================================================

    identity_indicators = detect_identity_mismatch(
        claimed_identity,
        sender_analysis
    )

    # ========================================================
    # ROLE IMPERSONATION
    # ========================================================

    role_indicator = detect_role_impersonation(
        claimed_role,
        sender_analysis
    )

    # ========================================================
    # RISK CALCULATION
    # ========================================================

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

    # ========================================================
    # COMBINE INDICATORS
    # ========================================================

    detected_indicators = []

    detected_indicators.extend(
        identity_indicators
    )

    if role_indicator:

        detected_indicators.append(
            role_indicator
        )

    for indicator in request_indicators:

        detected_indicators.append({

            "type":
                indicator["category"],

            "message":
                ", ".join(
                    indicator["matches"]
                )
        })

    # ========================================================
    # STATUS
    # ========================================================

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

    # ========================================================
    # RECOMMENDATION
    # ========================================================

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

    elif score > 0:

        recommendation = (
            "Some identity or request indicators were detected. "
            "Verify the sender before taking action."
        )

    else:

        recommendation = (
            "No immediate impersonation indicators were detected. "
            "Continue to verify unexpected requests."
        )

    # ========================================================
    # FINAL REPORT
    # ========================================================

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
