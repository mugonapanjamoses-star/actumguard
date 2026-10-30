"""ActumGuard rules registry.

Every rule is "not yet reviewed" until you add it to REVIEWED with a real reviewer,
date and primary-source URL. The scan output shows that status to the customer, so
the product never claims more than you can back up.
"""
RULES_VERSION = "2026-10-31-draft"

# Fill this in as a lawyer signs off each rule, e.g.:
# REVIEWED["ZA-POPIA-S71"] = {"reviewed_by": "Name, Firm", "last_reviewed": "2026-11-15", "source_url": "https://..."}
REVIEWED: dict = {}


def rule(id, jur, law, trigger, severity, title, detail, fix, kind="Potential Risk", industries=None):
    return {"id": id, "jurisdiction": jur, "law": law, "trigger": trigger, "severity": severity,
            "type": kind, "title": title, "detail": detail, "remediation": fix, "industries": industries}

AIC = {"uses_ai_for_consumer_decisions": True}
AIE = {"uses_ai_in_employment": True}
BOT = {"uses_chatbots": True}
# Decisions about people: hiring or consumer-facing. Matches if either is true.
DEC = {"any": ["uses_ai_in_employment", "uses_ai_for_consumer_decisions"]}
SENS = {"collects_sensitive_data": True}

RULES = [
    # Africa
    rule("ZA-POPIA-S71", "ZA", "POPIA Section 71", DEC, "high",
         "South Africa: Decisions based solely on automated processing",
         "POPIA restricts decisions with legal or substantial effects that rest solely on automated processing, subject to exceptions and safeguards such as letting the person make representations.",
         ["Add a human review path for adverse automated decisions.", "Document the logic the AI uses."]),
    rule("ZA-POPIA-SPI", "ZA", "POPIA special personal information", SENS, "high",
         "South Africa: Special personal information (e.g. health data)",
         "POPIA sets stricter conditions for health, biometric and similar data, and requires a written agreement with any operator (such as an AI vendor) that processes data for you.",
         ["Confirm your lawful basis for processing.", "Sign an operator agreement with each AI vendor.", "Check security safeguards."]),
    rule("NG-NDPA-2023", "NG", "Nigeria Data Protection Act 2023", AIC, "high",
         "Nigeria: Right against solely automated decisions",
         "Data subjects may have the right not to be subject to solely automated decisions with legal or similar effects, unless an exception applies.",
         ["Check whether an exception such as consent applies.", "Provide a human-review path."]),
    rule("KE-DPA-2019", "KE", "Kenya Data Protection Act 2019", AIC, "high",
         "Kenya: Automated decision-making safeguards",
         "Section 35 gives data subjects a right not to be subject to a decision based solely on automated processing, subject to exceptions.",
         ["Disclose automated decision-making.", "Offer human intervention and a way to contest."]),
    rule("EG-PDPL-2020", "EG", "Egypt Personal Data Protection Law", SENS, "medium",
         "Egypt: Sensitive data processing",
         "The PDPL places strict controls on sensitive personal data and sets breach-notification duties.",
         ["Put a breach-notification process in place.", "Map your personal data processing to PDPL requirements."]),
    # Europe
    rule("EU-AI-ACT-ART-50", "EU", "EU AI Act Article 50", BOT, "high",
         "EU: AI chatbot transparency",
         "People interacting with an AI system generally must be told it is AI. Check the current application date for this duty.",
         ["Show an AI disclosure at the start of each chatbot interaction.", "Record when you deployed it."]),
    rule("EU-AI-ACT-ANNEX-III-HR", "EU", "EU AI Act Annex III (employment)", AIE, "high",
         "EU: Hiring AI is classed as high-risk",
         "AI used to recruit, screen or evaluate candidates is listed as high-risk, with duties on risk management, human oversight, logging and transparency. Application dates may have shifted, so confirm the current timeline.",
         ["List every hiring AI tool in an inventory.", "Document human oversight of its output.", "Ask each vendor for its conformity documentation."]),
    rule("EU-GDPR-ART-22", "EU", "GDPR Article 22", DEC, "high",
         "EU: Automated decision safeguards",
         "Individuals have the right not to be subject to solely automated decisions with legal or similarly significant effects, subject to exceptions.",
         ["Give meaningful information about the logic.", "Offer human intervention and a right to contest.", "Consider a DPIA."]),
    rule("UK-GDPR-ART-22", "UK", "UK GDPR Article 22 (as amended)", DEC, "high",
         "UK: Automated decision safeguards",
         "UK rules on solely automated decisions were reformed by the Data (Use and Access) Act 2025. Safeguards such as human review and the right to contest remain central.",
         ["Add human review of automated decisions.", "Document the logic involved.", "Check the current text with a UK adviser."]),
    # North America
    rule("US-CO-AI", "US-CO", "Colorado AI Act (verify bill number and dates)", AIE, "high",
         "Colorado: High-risk AI in employment decisions",
         "Colorado regulates AI used in consequential decisions such as hiring. Its effective date and requirements have been revised, so confirm the current status before relying on this.",
         ["Inventory all AI hiring tools.", "Define a human-review path for rejected candidates."]),
    rule("US-NY-LL144", "US-NY-NYC", "NYC Local Law 144", AIE, "high",
         "NYC: Bias audit for automated hiring tools",
         "Employers and employment agencies using automated employment decision tools for NYC roles need an independent bias audit within the past year and must give candidates notice.",
         ["Commission an independent bias audit.", "Give candidates the required notice."]),
    rule("US-IL-HB3773", "US-IL", "Illinois HB 3773", AIE, "high",
         "Illinois: AI and employment discrimination",
         "Illinois prohibits AI use that discriminates in employment decisions and requires notice to affected employees and applicants.",
         ["Assess tools for disparate impact.", "Give the required notice.", "Keep records of AI-assisted decisions."]),
    rule("US-FHA", "US", "Fair Housing Act", AIC, "high",
         "US: Algorithmic tenant screening",
         "Housing providers can face liability for discriminatory effects of screening tools, including third-party ones. Federal disparate-impact enforcement priorities have shifted; state law and private lawsuits remain active risks.",
         ["Document the tool and the data it uses.", "Require human review before a rejection is final.", "Consider a fair-housing impact assessment."],
         industries=["Property"]),
    rule("CA-PIPEDA", "CA", "PIPEDA", AIC, "medium",
         "Canada: Fair information principles",
         "PIPEDA's principles apply to automated processing of personal information. Federal AI legislation has been uncertain, so check current status.",
         ["Apply fair-information principles.", "Explain the logic of automated decisions."]),
    # South America
    rule("BR-LGPD", "BR", "Brazil LGPD", AIC, "high",
         "Brazil: Review of automated decisions",
         "The LGPD gives people the right to request review of decisions made solely by automated processing that affect their interests.",
         ["Provide a way to request review.", "Document the criteria used."]),
    rule("CL-LEY-21719", "CL", "Chile Law 21.719", AIC, "high",
         "Chile: Automated decisions under the new data law",
         "Chile's new data protection law regulates decisions based on automated processing and gives people information rights about the logic. Check its phased start date.",
         ["Prepare to explain how decisions are made.", "Check whether you must appoint a data protection officer."]),
    # Asia
    rule("KR-AI-BASIC-ACT", "KR", "South Korea AI Basic Act", BOT, "high",
         "South Korea: Notice for generative AI",
         "Operators of generative AI must tell users in advance that AI is in use.",
         ["Add a notice before generative AI interactions."]),
    rule("CN-GENAI", "CN", "China Generative AI Measures", BOT, "critical",
         "China: Security assessment and filing for public generative AI",
         "Public-facing generative AI services in China may need a security assessment and filing with the regulator before launch, and must label AI-generated content.",
         ["Get local counsel before launching.", "Label AI-generated content."]),
    rule("IN-DPDP", "IN", "India DPDP Act 2023", AIC, "medium",
         "India: Data principal rights",
         "The DPDP Act gives people rights over their personal data, including grievance redress. Check how its rules apply to automated decisions.",
         ["Set up a grievance process.", "Get verifiable parental consent for children's data."]),
    rule("JP-AI-ACT", "JP", "Japan AI Promotion Act", BOT, "low",
         "Japan: Cooperation with AI guidance",
         "Japan's act is mostly soft law, asking businesses that use AI to cooperate with government measures.",
         ["Follow the government's AI Basic Plan.", "Consider voluntary guidelines."]),
    # Oceania
    rule("AU-APP-ADM", "AU", "Australian Privacy Principles (automated decisions)", AIC, "high",
         "Australia: Disclose automated decision-making",
         "From December 2026, privacy policies must describe automated decisions that significantly affect people.",
         ["Update your privacy policy.", "Provide a path to human review."]),
    rule("NZ-PRIVACY-ACT", "NZ", "New Zealand Privacy Act 2020", AIC, "medium",
         "New Zealand: Privacy Act and responsible AI guidance",
         "New Zealand relies on the Privacy Act 2020 and voluntary AI guidance rather than an AI-specific law.",
         ["Apply the Privacy Act to AI use.", "Follow the responsible-AI guidance."]),
    # Global baselines, only checked when the business uses AI at all
    rule("GAP-VENDORS", "GLOBAL", "Vendor governance", {"has_vendor_contracts": False}, "high",
         "No written data agreement with your AI vendors",
         "You said you do not have written data processing agreements with your AI vendors. Many privacy laws expect one.",
         ["Use the Vendor Questionnaire.", "Avoid vendors that will not sign."], kind="Confirmed Gap"),
    rule("GAP-HUMAN-REVIEW", "GLOBAL", "Human oversight", {"has_human_review_process": False}, "high",
         "No documented human review",
         "You said you have no documented human-review process, so you could not show that a person checked an AI decision.",
         ["Use the Acceptable Use Policy template.", "Make no AI decision final until a person approves it."], kind="Confirmed Gap"),
]

JURISDICTIONS = {r["jurisdiction"] for r in RULES if r["jurisdiction"] != "GLOBAL"}
