"""
ActumGuard Backend — V2 (Legal Defensibility & DeepSeek)
"""
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
import sqlite3, os, json, hmac, hashlib
from datetime import datetime, timezone
from pathlib import Path
from openai import OpenAI

app = FastAPI(title="ActumGuard")
DB = Path(os.getenv("ACTUMGUARD_DB", "actumguard.db"))

DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
deepseek_client = OpenAI(api_key=DEEPSEEK_API_KEY, base_url="https://api.deepseek.com")

def init_db():
    with sqlite3.connect(DB) as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS leads (
                id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, industry TEXT,
                jurisdictions TEXT, risk_score INTEGER, exposure TEXT, created_at TEXT
            )
        """)
        c.commit()
init_db()

# UPDATED RULES: Explicitly separates Potential Risk from Confirmed Gaps
RULES = [
    {
        "id": "ZA-POPIA-S71", "jurisdiction": "ZA", "law": "POPIA Section 71",
        "trigger": {"uses_ai_for_consumer_decisions": True}, "severity": "high",
        "type": "Potential Risk",
        "title": "Automated decisions affecting consumers",
        "detail": "You use AI to influence consumer decisions. POPIA Section 71 requires you to provide a human review process if the decision has significant legal effects on the consumer.",
        "remediation": ["Implement a human review path for rejected applications.", "Document the logic used by the AI."]
    },
    {
        "id": "EU-AI-ACT-ART-50", "jurisdiction": "EU", "law": "EU AI Act Article 50",
        "trigger": {"uses_chatbots": True}, "severity": "high",
        "type": "Potential Risk",
        "title": "Chatbot transparency disclosure",
        "detail": "From 2 Aug 2026, any AI system interacting with people must disclose it is AI. This is a strict liability requirement.",
        "remediation": ["Add an AI-disclosure banner at the start of every chatbot interaction.", "Log the deployment date."]
    },
    {
        "id": "US-CO-ADMT", "jurisdiction": "US-CO", "law": "Colorado SB 26-189",
        "trigger": {"uses_ai_in_employment": True}, "severity": "high",
        "type": "Potential Risk",
        "title": "ADMT employment disclosure",
        "detail": "Colorado's new ADMT law requires disclosure before a consequential decision (like hiring) and human review after an adverse outcome.",
        "remediation": ["Document all AI hiring tools.", "Define a human-review path for rejected candidates."]
    },
    {
        "id": "CONFIRMED-GAP-VENDORS", "jurisdiction": "GLOBAL", "law": "Vendor Governance",
        "trigger": {"has_vendor_contracts": False}, "severity": "high",
        "type": "Confirmed Gap",
        "title": "Missing AI Vendor Contracts (DPAs)",
        "detail": "You indicated you DO NOT have written Data Processing Agreements (DPAs) with your AI vendors. This is a confirmed compliance gap and a major liability if the vendor has a data breach.",
        "remediation": ["Download our Vendor Questionnaire.", "Send it to all AI suppliers immediately.", "Do not use vendors who refuse to sign a DPA."]
    },
    {
        "id": "CONFIRMED-GAP-HUMAN-REVIEW", "jurisdiction": "GLOBAL", "law": "Human Oversight",
        "trigger": {"has_human_review_process": False}, "severity": "high",
        "type": "Confirmed Gap",
        "title": "Missing Human Review Process",
        "detail": "You indicated you DO NOT have a documented human-review process for adverse AI outcomes. This is a confirmed gap. If an AI makes a mistake, you have no proof a human checked it.",
        "remediation": ["Use our Acceptable Use Policy template.", "Mandate that no AI decision is final until a human clicks 'Approve'."]
    }
]

class ScanRequest(BaseModel):
    email: str
    industry: str
    jurisdictions: list[str]
    uses_ai_in_employment: bool = False
    uses_ai_for_consumer_decisions: bool = False
    collects_sensitive_data: bool = False
    uses_chatbots: bool = False
    has_vendor_contracts: bool = False
    has_human_review_process: bool = False

def evaluate(scan: ScanRequest):
    findings = []
    for rule in RULES:
        if rule["jurisdiction"] != "GLOBAL" and rule["jurisdiction"] not in scan.jurisdictions:
            continue
        match = True
        for field, expected in rule["trigger"].items():
            if getattr(scan, field, None) != expected:
                match = False
                break
        if match:
            findings.append(rule)
            
    # Scoring: Confirmed Gaps weigh heavier than Potential Risks
    score = 0
    for f in findings:
        if f["type"] == "Confirmed Gap": score += 4
        else: score += 2
    
    exposure = "LOW" if score <= 2 else "MEDIUM" if score <= 5 else "HIGH" if score <= 9 else "CRITICAL"
    return findings, score, exposure

@app.post("/api/scan")
def scan(req: ScanRequest):
    findings, score, exposure = evaluate(req)
    with sqlite3.connect(DB) as c:
        c.execute("INSERT INTO leads (email, industry, jurisdictions, risk_score, exposure, created_at) VALUES (?,?,?,?,?,?)",
                  (req.email, req.industry, json.dumps(req.jurisdictions), score, exposure, datetime.now(timezone.utc).isoformat()))
        c.commit()
    return {"findings": findings, "risk_score": score, "exposure": exposure}

@app.post("/api/webhooks/paystack")
async def paystack_webhook(request: Request):
    signature = request.headers.get('x-paystack-signature', '')
    body = await request.body()
    secret_key = os.getenv("pk_test_c77eb2b404c47451da4fcf75364a336d4baaa9e3"sk_test_YOUR_SECRET_KEY")
    
    computed_hash = hmac.new(secret_key.encode('utf-8'), msg=body, digestmod=hashlib.sha512).hexdigest()
    if not hmac.compare_digest(computed_hash, signature):
        return JSONResponse(status_code=400, content={"message": "Invalid signature"})

    event = json.loads(body)
    if event.get('event') == 'charge.success':
        data = event.get('data', {})
        customer_email = data.get('customer', {}).get('email')
        metadata = data.get('metadata', {})
        product_name = "Starter Pack"
        for field in metadata.get('custom_fields', []):
            if field.get('variable_name') == 'product':
                product_name = field.get('value')

        if product_name == "Instant AI Policy":
            try:
                response = deepseek_client.chat.completions.create(
                    model="deepseek-chat",
                    messages=[
                        {"role": "system", "content": "You are an expert AI compliance lawyer. Write a professional, 1-page AI Acceptable Use Policy. Include rules on data privacy, human review of AI decisions, and vendor management. Add a disclaimer that this is a template, not legal advice."},
                        {"role": "user", "content": f"Generate the policy for a company in the {data.get('customer', {}).get('metadata', {}).get('industry', 'general')} industry."}
                    ]
                )
                print(f"✅ Policy generated for {customer_email}")
                print(response.choices[0].message.content)
            except Exception as e:
                print(f"❌ DeepSeek Error: {str(e)}")

        with sqlite3.connect(DB) as c:
            c.execute("INSERT INTO leads (email, industry, jurisdictions, risk_score, exposure, created_at) VALUES (?,?,?,?,?,?)",
                      (customer_email, product_name, "[]", 0, "PAID", datetime.now(timezone.utc).isoformat()))
            c.commit()
    return JSONResponse(content={"status": "success"})

@app.get("/health")
def health(): return {"status": "ok"}

@app.get("/", response_class=HTMLResponse)
def home(): return SCAN_HTML

# The HTML is embedded below in the code block.
