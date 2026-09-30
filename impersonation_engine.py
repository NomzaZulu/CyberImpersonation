# ============================================================
# CYBERGUARD
# DIGITAL IMPERSONATION DETECTION ENGINE
# ============================================================

import re
from urllib.parse import urlparse


# ============================================================
# 1. IDENTITY CATEGORIES
# ============================================================

IDENTITY_CATEGORIES = {

    "Government Official": [
        "government",
        "minister",
        "officer",
        "official",
        "collector",
        "commissioner",
        "police",
        "ias",
        "ips"
    ],

    "Senior Management": [
        "ceo",
        "cfo",
        "coo",
        "director",
        "manager",
        "senior manager",
        "executive",
        "chairman",
        "founder"
    ],

    "Teacher or University Authority": [
        "teacher",
        "professor",
        "principal",
        "dean",
        "hod",
        "head of department",
        "university",
        "college",
        "lecturer",
        "faculty"
    ],

    "Financial Institution": [
        "bank",
        "bank manager",
        "bank officer",
        "financial institution",
        "credit card",
        "insurance",
        "loan officer"
    ],

    "Organisation or Brand": [
        "company",
        "organisation",
        "organization",
        "brand",
        "support team",
        "customer care",
        "customer support",
        "official support"
    ],

    "Friend or Relative": [
        "friend",
        "brother",
        "sister",
        "father",
        "mother",
        "uncle",
        "aunt",
        "relative",
        "family"
    ]
}


# ============================================================
# 2. IDENTITY DETECTION
# ============================================================

def detect_claimed_identity(text):

    text_lower = text.lower()

    detected = {}

    for category, keywords in IDENTITY_CATEGORIES.items():

        matches = [
            keyword
            for keyword in keywords
            if keyword in text_lower
        ]

        if matches:
            detected[category] = matches

    return detected


# ============================================================
# 3. IMPERSONATION LANGUAGE
# ============================================================

def detect_impersonation_language(message):

    text = message.lower()

    indicators = []

    patterns = {

        "Authority Claim": [
            "i am from",
            "i am the",
            "this is the",
            "speaking from",
            "calling from",
            "officially from",
            "on behalf of"
        ],

        "Identity Verification Pressure": [
            "verify your identity",
            "confirm your identity",
            "prove your identity",
            "send your id",
            "send your aadhaar",
            "send your pan"
        ],

        "Urgency": [
            "urgent",
            "immediately",
            "right now",
            "as soon as possible",
            "act now",
            "within 10 minutes",
            "within 30 minutes",
            "today only"
        ],

        "Secrecy": [
            "keep this confidential",
            "do not tell anyone",
            "don't tell anyone",
            "keep this between us",
            "do not share this",
            "keep it secret"
        ],

        "Authority Pressure": [
            "you must",
            "you are required",
            "mandatory",
            "failure to comply",
            "legal action",
            "account will be blocked",
            "account will be suspended"
        ]
    }

    for category, keywords in patterns.items():

        matches = [
            keyword
            for keyword in keywords
            if keyword in text
        ]

        if matches:
            indicators.append({
                "category": category,
                "matches": matches
            })

    return indicators


# ============================================================
# 4. SENSITIVE REQUEST DETECTION
# ============================================================

def detect_sensitive_requests(message):

    text = message.lower()

    requests = {

        "Credentials": [
            "password",
            "otp",
            "pin",
            "cvv",
            "passcode"
        ],

        "Financial Information": [
            "bank account",
            "account number",
            "card number",
            "credit card",
            "debit card",
            "upi",
            "upi id"
        ],

        "Personal Information": [
            "aadhaar",
            "pan card",
            "date of birth",
            "personal details",
            "identity proof",
            "id proof"
        ],

        "Payment": [
            "send money",
            "transfer money",
            "make a payment",
            "pay now",
            "pay the fee",
            "processing fee"
        ]
    }

    detected = {}

    for category, keywords in requests.items():

        matches = [
            keyword
            for keyword in keywords
            if keyword in text
        ]

        if matches:
            detected[category] = matches

    return detected


# ============================================================
# 5. EMAIL / DOMAIN ANALYSIS
# ============================================================

def analyze_sender_metadata(
    sender_name="",
    sender_email="",
    claimed_organization=""
):

    indicators = []

    sender_email = sender_email.strip().lower()
    claimed_organization = claimed_organization.strip().lower()

    if sender_email:

        if "@" not in sender_email:

            indicators.append(
                "Invalid sender email format"
            )

        else:

            domain = sender_email.split("@")[-1]

            free_email_domains = [
                "gmail.com",
                "yahoo.com",
                "outlook.com",
                "hotmail.com",
                "proton.me",
                "protonmail.com"
            ]

            if domain in free_email_domains:

                indicators.append(
                    "Sender uses a public email provider"
                )

            if claimed_organization:

                organization_words = re.findall(
                    r"[a-z0-9]+",
                    claimed_organization
                )

                organization_match = any(
                    word in domain
                    for word in organization_words
                    if len(word) >= 4
                )

                if not organization_match:

                    indicators.append(
                        "Sender email domain does not appear "
                        "to match the claimed organization"
                    )

    return indicators


# ============================================================
# 6. COMMUNICATION STYLE ANALYSIS
# ============================================================

def analyze_communication_style(message):

    text = message.strip()

    indicators = []

    if not text:
        return indicators

    # Excessive capitalization
    uppercase_chars = sum(
        1 for char in text
        if char.isupper()
    )

    alphabetic_chars = sum(
        1 for char in text
        if char.isalpha()
    )

    if (
        alphabetic_chars >= 20
        and uppercase_chars / alphabetic_chars > 0.5
    ):

        indicators.append(
            "Unusually high use of capital letters"
        )

    # Excessive exclamation marks
    if text.count("!") >= 3:

        indicators.append(
            "Excessive exclamation marks"
        )

    # Excessive urgency
    urgency_count = sum(
        phrase in text.lower()
        for phrase in [
            "urgent",
            "immediately",
            "right now",
            "act now",
            "today only"
        ]
    )

    if urgency_count >= 2:

        indicators.append(
            "Repeated urgency language"
        )

    # Very short message containing a sensitive request
    if len(text.split()) <= 15:

        sensitive_terms = [
            "otp",
            "password",
            "pin",
            "payment",
            "money",
            "transfer"
        ]

        if any(
            term in text.lower()
            for term in sensitive_terms
        ):

            indicators.append(
                "Short message combined with a sensitive request"
            )

    return indicators


# ============================================================
# 7. BEHAVIOURAL PATTERN ANALYSIS
# ============================================================

def analyze_behavior(
    message,
    previous_messages=None
):

    indicators = []

    text = message.lower()

    if previous_messages is None:
        previous_messages = []

    # Sudden financial request
    if any(
        term in text
        for term in [
            "send money",
            "transfer money",
            "pay now",
            "payment"
        ]
    ):

        indicators.append(
            "Financial request detected"
        )

    # Sudden credential request
    if any(
        term in text
        for term in [
            "otp",
            "password",
            "pin",
            "cvv"
        ]
    ):

        indicators.append(
            "Credential request detected"
        )

    # Change of communication pattern
    if previous_messages:

        previous_text = " ".join(
            previous_messages
        ).lower()

        previous_length = len(
            previous_text.split()
        )

        current_length = len(
            message.split()
        )

        if (
            previous_length > 20
            and current_length <= 10
        ):

            indicators.append(
                "Sudden change in message length"
            )

    return indicators


# ============================================================
# 8. RISK SCORE
# ============================================================

def calculate_impersonation_risk(
    identity_matches,
    impersonation_indicators,
    sensitive_requests,
    metadata_indicators,
    communication_indicators,
    behavioral_indicators
):

    score = 0
    reasons = []

    # Identity
    if identity_matches:

        score += 10

        reasons.append(
            "Identity or authority claim detected"
        )

    # Impersonation language
    for item in impersonation_indicators:

        category = item["category"]

        if category == "Authority Claim":
            score += 15

        elif category == "Identity Verification Pressure":
            score += 15

        elif category == "Urgency":
            score += 10

        elif category == "Secrecy":
            score += 15

        elif category == "Authority Pressure":
            score += 10

        reasons.append(
            f"{category} detected"
        )

    # Sensitive requests
    if sensitive_requests:

        score += 25

        reasons.append(
            "Sensitive information request detected"
        )

    # Metadata
    if metadata_indicators:

        score += min(
            len(metadata_indicators) * 10,
            25
        )

        reasons.extend(
            metadata_indicators
        )

    # Communication style
    if communication_indicators:

        score += min(
            len(communication_indicators) * 5,
            15
        )

        reasons.extend(
            communication_indicators
        )

    # Behaviour
    if behavioral_indicators:

        score += min(
            len(behavioral_indicators) * 5,
            15
        )

        reasons.extend(
            behavioral_indicators
        )

    score = min(score, 100)

    if score >= 75:
        risk_level = "High Risk"

    elif score >= 30:
        risk_level = "Medium Risk"

    else:
        risk_level = "Low Risk"

    return score, risk_level, reasons


# ============================================================
# 9. MAIN DIGITAL IMPERSONATION ANALYZER
# ============================================================

def analyze_digital_impersonation(data):

    message = data.get(
        "message",
        ""
    ).strip()

    sender_name = data.get(
        "sender_name",
        ""
    ).strip()

    sender_email = data.get(
        "sender_email",
        ""
    ).strip()

    claimed_organization = data.get(
        "claimed_organization",
        ""
    ).strip()

    previous_messages = data.get(
        "previous_messages",
        []
    )

    if not message:

        return {
            "error": "Message is required"
        }

    # ----------------------------------------
    # Analysis
    # ----------------------------------------

    identity_matches = detect_claimed_identity(
        (
            sender_name
            + " "
            + claimed_organization
            + " "
            + message
        )
    )

    impersonation_indicators = (
        detect_impersonation_language(
            message
        )
    )

    sensitive_requests = (
        detect_sensitive_requests(
            message
        )
    )

    metadata_indicators = (
        analyze_sender_metadata(
            sender_name,
            sender_email,
            claimed_organization
        )
    )

    communication_indicators = (
        analyze_communication_style(
            message
        )
    )

    behavioral_indicators = (
        analyze_behavior(
            message,
            previous_messages
        )
    )

    # ----------------------------------------
    # Risk
    # ----------------------------------------

    score, risk_level, reasons = (
        calculate_impersonation_risk(
            identity_matches,
            impersonation_indicators,
            sensitive_requests,
            metadata_indicators,
            communication_indicators,
            behavioral_indicators
        )
    )

    # ----------------------------------------
    # Status
    # ----------------------------------------

    if score >= 75:

        status = (
            "Potential Digital Impersonation Threat"
        )

    elif score >= 30:

        status = (
            "Suspicious Identity or Communication Detected"
        )

    else:

        status = (
            "No Immediate Impersonation Threat Detected"
        )

    # ----------------------------------------
    # Recommendation
    # ----------------------------------------

    if score >= 75:

        recommendation = (
            "Do not share sensitive information or "
            "make payments. Independently verify the "
            "person's identity using a trusted official channel."
        )

    elif score >= 30:

        recommendation = (
            "Verify the sender's identity and organization "
            "through an independent trusted channel before "
            "taking any requested action."
        )

    else:

        recommendation = (
            "No major impersonation indicators were detected. "
            "Still verify unexpected requests independently."
        )

    return {

        "status": status,

        "risk_level": risk_level,

        "risk_score": score,

        "claimed_identity_categories":
            identity_matches,

        "impersonation_indicators":
            impersonation_indicators,

        "sensitive_requests":
            sensitive_requests,

        "metadata_indicators":
            metadata_indicators,

        "communication_style_indicators":
            communication_indicators,

        "behavioral_indicators":
            behavioral_indicators,

        "risk_reasons":
            reasons,

        "recommendation":
            recommendation
    }
