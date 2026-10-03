import streamlit as st

from digital_impersonation_engine import analyze_impersonation
from organisation_data import ORGANISATION, TRUSTED_IDENTITIES


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="CyberGuard - Impersonation Detection",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ CyberGuard")

st.subheader(
    "Organisation-Specific Digital Impersonation Detection"
)

st.write(
    "Analyze messages for possible impersonation of "
    "trusted organisational identities."
)

st.divider()


# ============================================================
# ORGANISATION INFORMATION
# ============================================================

st.header("🏢 Organisation")

st.info(
    f"Currently configured organisation: "
    f"**{ORGANISATION['name']}**"
)

with st.expander("View Synthetic Trusted Identities"):

    for identity in TRUSTED_IDENTITIES:

        st.write(
            f"**{identity['name']}** — "
            f"{identity['role']} — "
            f"{identity['department']}"
        )

        st.caption(
            identity["email"]
        )


st.divider()


# ============================================================
# INPUT
# ============================================================

st.header("📩 Message Analysis")

sender_email = st.text_input(
    "Sender Email Address",
    placeholder="example@gmail.com"
)

message = st.text_area(
    "Message",
    height=220,
    placeholder=(
        "Paste the message you want CyberGuard to analyze..."
    )
)


# ============================================================
# ANALYZE BUTTON
# ============================================================

if st.button(
    "🔍 Analyze for Impersonation",
    type="primary",
    use_container_width=True
):

    if not message.strip():

        st.warning(
            "Please enter a message before analyzing."
        )

    else:

        with st.spinner(
            "CyberGuard is analyzing the message..."
        ):

            result = analyze_impersonation(
                message=message,
                sender_email=sender_email.strip()
                if sender_email.strip()
                else None
            )


        # ====================================================
        # THREAT REPORT
        # ====================================================

        st.divider()

        st.header("🛡️ CyberGuard Threat Report")


        # ====================================================
        # SUMMARY
        # ====================================================

        col1, col2, col3 = st.columns(3)

        with col1:

            st.metric(
                "Status",
                result["status"]
            )

        with col2:

            st.metric(
                "Risk Level",
                result["risk_level"]
            )

        with col3:

            st.metric(
                "Risk Score",
                f"{result['risk_score']} / 100"
            )


        # ====================================================
        # IDENTITY INFORMATION
        # ====================================================

        st.subheader(
            "👤 Identity Analysis"
        )

        identity_col1, identity_col2 = st.columns(2)


        with identity_col1:

            st.write("**Claimed Identity**")

            claimed_identity = result.get(
                "claimed_identity"
            )

            if claimed_identity:

                st.success(
                    claimed_identity["name"]
                )

                st.write(
                    f"**Role:** "
                    f"{claimed_identity['role']}"
                )

                st.write(
                    f"**Department:** "
                    f"{claimed_identity['department']}"
                )

                st.write(
                    f"**Official Email:** "
                    f"{claimed_identity['email']}"
                )

            else:

                st.info(
                    "No trusted identity was detected "
                    "in the message."
                )


        with identity_col2:

            st.write("**Sender**")

            if sender_email.strip():

                st.code(
                    sender_email.strip()
                )

            else:

                st.info(
                    "No sender email provided."
                )


        # ====================================================
        # ROLE
        # ====================================================

        claimed_role = result.get(
            "claimed_role"
        )

        if claimed_role:

            st.subheader(
                "🎭 Role Analysis"
            )

            st.write(
                f"**Detected Role:** "
                f"{claimed_role['role']}"
            )

            st.write(
                f"**Associated Identity:** "
                f"{claimed_role['name']}"
            )

            st.write(
                f"**Department:** "
                f"{claimed_role['department']}"
            )


        # ====================================================
        # SENDER ANALYSIS
        # ====================================================

        st.subheader(
            "📧 Sender Verification"
        )

        sender_analysis = result.get(
            "sender_analysis",
            {}
        )

        sender_col1, sender_col2 = st.columns(2)


        with sender_col1:

            if sender_analysis.get(
                "sender_provided"
            ):

                st.write(
                    "**Sender Domain:**"
                )

                st.code(
                    sender_analysis.get(
                        "domain",
                        "Unknown"
                    )
                )

            else:

                st.info(
                    "Sender address was not provided."
                )


        with sender_col2:

            if sender_analysis.get(
                "domain_match"
            ):

                st.success(
                    "✅ Official organisation domain"
                )

            elif sender_analysis.get(
                "sender_provided"
            ):

                st.error(
                    "❌ Sender domain does not match "
                    "the configured organisation domain"
                )


        # ====================================================
        # DETECTED INDICATORS
        # ====================================================

        st.subheader(
            "⚠️ Detected Threat Indicators"
        )

        indicators = result.get(
            "detected_indicators",
            []
        )

        if indicators:

            for indicator in indicators:

                st.warning(
                    f"**{indicator['type']}** — "
                    f"{indicator['message']}"
                )

        else:

            st.success(
                "No impersonation indicators detected."
            )


        # ====================================================
        # REASONS
        # ====================================================

        reasons = result.get(
            "reasons",
            []
        )

        if reasons:

            st.subheader(
                "🔎 Analysis Reasons"
            )

            for reason in reasons:

                st.write(
                    f"• {reason}"
                )


        # ====================================================
        # RECOMMENDATION
        # ====================================================

        st.subheader(
            "💡 Recommendation"
        )

        st.info(
            result["recommendation"]
        )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "CyberGuard Prototype — Synthetic organisational data "
    "is used for demonstration and testing."
)
