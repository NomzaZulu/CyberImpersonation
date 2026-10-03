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

    if not text:
        return []

    return re.findall(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        text
    )


def find_claimed_identity(text):
    """
    Check whether the message appears to mention
    one of the organisation's trusted identities.

    Returns the matched trusted identity or None.
    """

    if not text:
        return None

    text_lower = text.lower()

    for identity in TRUSTED_IDENTITIES:

        name = identity.get("name", "").lower().strip()

        if name and name in text_lower:
            return identity

    return None


def find_claimed_role(text):
    """
    Check whether the message mentions the role of
    one of the trusted identities.

    Returns the matched trusted identity or None.
    """

    if not text:
        return None

    text_lower = text.lower()

    for identity in TRUSTED_IDENTITIES:

        role = identity.get("role", "").lower().strip()

        if role and role in text_lower:
            return identity

    return None


# ============================================================
# 2. SENDER ANALYSIS
# ============================================================

def analyze_sender_email(sender_email):
    """
    Compare the sender email against:
    - trusted identities
    - official organisation domains
    """

    if not sender_email:

        return {
            "sender_provided": False,
            "email": None,
            "domain": None,
            "trusted_identity": None,
            "domain_match": False
        }

    sender_email = sender_email.lower().strip()

    if "@" not in sender_email:

        return {
            "sender_provided": True,
            "email": sender_email,
            "domain": None,
            "trusted_identity": None,
            "domain_match": False
        }

    domain = sender_email.split("@", 1)[1]

    trusted_identity = None

    for identity in TRUSTED_IDENTITIES:

        trusted_email = identity.get(
            "email",
            ""
        ).lower().strip()

        if trusted_email == sender_email:

            trusted_identity = identity
            break

    official_domains = [
        domain_name.lower().strip()
        for domain_name in ORGANISATION.get(
            "official_domains",
            []
        )
    ]

    domain_match = domain in official_domains

    return {
        "sender_provided": True,
        "email": sender_email,
        "domain": domain,
        "trusted_identity": trusted_identity,
        "domain_match": domain_match
    }


# ============================================================
# 3. SUSPICIOUS REQUEST DETECTION
# ============================================================

def detect_suspicious_requests(text):
    """
    Detect requests commonly associated with
    digital impersonation attacks.
    """

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
            "send the payment",
            "process the payment",
            "pay the invoice",
            "make the transfer"
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
            "send cvv",
            "provide your login",
            "send your login details",
            "share your login details"
        ],

        "Sensitive Information Request": [
            "send the employee list",
            "send employee data",
            "send confidential data",
            "send the database",
            "share confidential information",
            "send company documents",
            "send the documents",
            "share employee information",
            "send employee information",
            "send internal documents",
            "share internal data"
        ],

        "Urgency": [
            "urgent",
            "immediately",
            "right now",
            "as soon as possible",
            "act now",
            "within 30 minutes",
            "within an hour",
            "before the end of the day",
            "this is urgent"
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
    """
    Determine whether the sender actually matches
    the person being claimed.
    """

    indicators = []

    if not claimed_identity:
        return indicators

    if not sender_analysis.get(
        "sender_provided",
        False
    ):
        return indicators

    sender_identity = sender_analysis.get(
        "trusted_identity"
    )

    sender_domain = sender_analysis.get(
        "domain"
    )

    claimed_email = claimed_identity.get(
        "email",
        ""
    ).lower().strip()

    claimed_domain = ""

    if "@" in claimed_email:
        claimed_domain = claimed_email.split(
            "@",
            1
        )[1]

    # --------------------------------------------------------
    # Exact identity comparison
    # --------------------------------------------------------

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

    else:

        sender_identity_name = sender_identity.get(
            "name",
            ""
        )

        claimed_identity_name = claimed_identity.get(
            "name",
            ""
        )

        if (
            sender_identity_name.lower().strip()
            != claimed_identity_name.lower().strip()
        ):

            indicators.append(
                {
                    "type": "Identity Mismatch",
                    "message": (
                        f"Message appears to represent "
                        f"{claimed_identity_name}, but the "
                        f"sender belongs to "
                        f"{sender_identity_name}."
                    )
                }
            )

    # --------------------------------------------------------
    # Domain comparison
    # --------------------------------------------------------

    if (
        sender_domain
        and claimed_domain
        and sender_domain.lower()
        != claimed_domain.lower()
    ):

        indicators.append(
            {
                "type": "Domain Mismatch",
                "message": (
                    f"Trusted identity uses "
                    f"{claimed_domain}, but the "
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
    """
    Detect whether somebody appears to be claiming
    another trusted person's organisational role.
    """

    if not claimed_role_identity:
        return None

    if not sender_analysis.get(
        "sender_provided",
        False
    ):
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

    claimed_name = claimed_role_identity.get(
        "name",
        ""
    ).lower().strip()

    sender_name = sender_identity.get(
        "name",
        ""
    ).lower().strip()

    if claimed_name != sender_name:

        return {
            "type": "Role Impersonation",
            "message": (
                f"Message appears to represent "
                f"{claimed_role_identity['name']} "
                f"({claimed_role_identity['role']}), "
                f"but the sender belongs to "
                f"{sender_identity['name']}."
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
    """
    Calculate impersonation risk.

    IMPORTANT:
    Merely mentioning a trusted identity is NOT a risk.

    Risk is generated by suspicious behaviour,
    identity mismatch, role mismatch, suspicious
    requests and urgency.
    """

    score = 0

    reasons = []

    # --------------------------------------------------------
    # Trusted identity mentioned
    # --------------------------------------------------------

    # DO NOT add risk merely because a trusted identity
    # was mentioned.
    #
    # Example:
    #
    # Rahul Mehta sends a normal email.
    #
    # Mentioning Rahul should contribute 0 risk.

    if claimed_identity:

        reasons.append(
            f"Trusted identity mentioned: "
            f"{claimed_identity['name']}"
        )

    # --------------------------------------------------------
    # Identity / domain mismatch
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
                "Sensitive organisational "
                "information requested."
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

    # Trusted identity + financial request + urgency

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

    # Trusted identity + credential request

    if (
        claimed_identity
        and "Credential Request" in categories
    ):

        score += 20

        reasons.append(
            "Trusted identity appears to be used "
            "to request authentication information."
        )

    # Identity mismatch + suspicious request

    if (
        identity_indicators
        and len(request_indicators) > 0
    ):

        score += 10

        reasons.append(
            "Identity mismatch is combined with "
            "a suspicious request."
        )

    # --------------------------------------------------------
    # Keep score between 0 and 100
    # --------------------------------------------------------

    score = min(
        max(score, 0),
        100
    )

    # --------------------------------------------------------
    # Risk level
    # --------------------------------------------------------

    if score >= 75:

        risk_level = "High Risk"

    elif score >= 40:

        risk_level = "Medium Risk"

    else:

        risk_level = "Low Risk"

    return (
        score,
        risk_level,
        reasons
    )


# ============================================================
# 7. MAIN ANALYSIS FUNCTION
# ============================================================

def analyze_impersonation(
    message,
    sender_email=None
):
    """
    Main Digital Impersonation Detection function.
    """

    # --------------------------------------------------------
    # Empty message
    # --------------------------------------------------------

    if not message or not message.strip():

        return {

            "organisation":
                ORGANISATION["name"],

            "status":
                "No message provided",

            "risk_level":
                "Low Risk",

            "risk_score":
                0,

            "claimed_identity":
                None,

            "claimed_role":
                None,

            "sender":
                sender_email,

            "sender_analysis":
                {},

            "detected_indicators":
                [],

            "reasons":
                [],

            "recommendation":
                "Provide a message for analysis."
        }

    message = message.strip()

    # --------------------------------------------------------
    # Identity extraction
    # --------------------------------------------------------

    claimed_identity = find_claimed_identity(
        message
    )

    # --------------------------------------------------------
    # Role extraction
    # --------------------------------------------------------

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
    # Suspicious requests
    # --------------------------------------------------------

    request_indicators = (
        detect_suspicious_requests(
            message
        )
    )

    # --------------------------------------------------------
    # Identity mismatch
    # --------------------------------------------------------

    identity_indicators = (
        detect_identity_mismatch(
            claimed_identity,
            sender_analysis
        )
    )

    # --------------------------------------------------------
    # Role impersonation
    # --------------------------------------------------------

    role_indicator = (
        detect_role_impersonation(
            claimed_role,
            sender_analysis
        )
    )

    # --------------------------------------------------------
    # Risk calculation
    # --------------------------------------------------------

    (
        score,
        risk_level,
        reasons
    ) = calculate_impersonation_risk(

        claimed_identity,

        claimed_role,

        sender_analysis,

        identity_indicators,

        role_indicator,

        request_indicators
    )

    # --------------------------------------------------------
    # Combine detected indicators
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
                "type":
                    indicator["category"],

                "message":
                    ", ".join(
                        indicator["matches"]
                    )
            }
        )

    # --------------------------------------------------------
    # Status
    # --------------------------------------------------------

    if score >= 75:

        status = (
            "Potential Digital "
            "Impersonation Threat"
        )

    elif score >= 40:

        status = (
            "Suspicious Identity "
            "Activity Detected"
        )

    elif score > 0:

        status = (
            "Low-Level Identity "
            "Risk Detected"
        )

    else:

        status = (
            "No Immediate Impersonation "
            "Threat Detected"
        )

    # --------------------------------------------------------
    # Recommendation
    # --------------------------------------------------------

    if score >= 75:

        recommendation = (
            "Do not follow the request. "
            "Verify the person's identity "
            "through an official organisational "
            "communication channel before "
            "taking action."
        )

    elif score >= 40:

        recommendation = (
            "Verify the sender's identity "
            "and the request through an "
            "independent official channel."
        )

    elif score > 0:

        recommendation = (
            "Review the detected indicators "
            "and verify the request through "
            "an official channel."
        )

    else:

        recommendation = (
            "No major impersonation indicators "
            "were detected. Continue to verify "
            "unexpected requests."
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
