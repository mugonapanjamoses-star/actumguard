"""
ActumGuard Backend — V3 (Global Jurisdictions & DeepSeek)
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

DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "not-needed")
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

# ==========================================
# GLOBAL RULES REGISTRY
# ==========================================
RULES = [
    # --- AFRICA ---
    {
        "id": "ZA-POPIA-S71", "jurisdiction": "ZA", "law": "POPIA Section 71",
        "trigger": {"uses_ai_for_consumer_decisions": True}, "severity": "high", "type": "Potential Risk",
        "title": "South Africa: Automated decisions affecting consumers",
        "detail": "POPIA Section 71 requires you to provide a human review process if an AI decision has significant legal effects on the consumer.",
        "remediation": ["Implement a human review path for rejected applications.", "Document the logic used by the AI."]
    },
    {
        "id": "NG-NDPA-2023", "jurisdiction": "NG", "law": "Nigeria Data Protection Act",
        "trigger": {"uses_ai_for_consumer_decisions": True}, "severity": "high", "type": "Potential Risk",
        "title": "Nigeria: Right against solely automated decisions",
        "detail": "Data subjects have the right not to be subject to solely automated decisions with legal effects, unless they consent or the law authorises it.",
        "remediation": ["Obtain explicit consent where automated decision-making is used.", "Provide a human-review path."]
    },
    {
        "id": "KE-DPA-2019", "jurisdiction": "KE", "law": "Kenya Data Protection Act",
        "trigger": {"uses_ai_for_consumer_decisions": True}, "severity": "high", "type": "Potential Risk",
        "title": "Kenya: Automated decision-making safeguards",
        "detail": "Section 35 gives data subjects the right not to be subject to a decision based solely on automated processing.",
        "remediation": ["Disclose automated decision-making.", "Offer human intervention and a right to contest."]
    },
    {
        "id": "EG-PDPL-2020", "jurisdiction": "EG", "law": "Egypt Personal Data Protection Law",
        "trigger": {"collects_sensitive_data": True}, "severity": "medium", "type": "Potential Risk",
        "title": "Egypt: Sensitive data processing",
        "detail": "The PDPL requires 72-hour breach notification and strict controls on sensitive personal data.",
        "remediation": ["Implement a 72-hour breach-notification process.", "Map all personal data processing to PDPL requirements."]
    },

    # --- EUROPE ---
    {
        "id": "EU-AI-ACT-ART-50", "jurisdiction": "EU", "law": "EU AI Act Article 50",
        "trigger": {"uses_chatbots": True}, "severity": "high", "type": "Potential Risk",
        "title": "EU: AI chatbot transparency disclosure",
        "detail": "Any AI system interacting with people must disclose it is AI. Agents must disclose the person on whose behalf they act.",
        "remediation": ["Add an AI-disclosure banner at the start of every chatbot interaction.", "Log the deployment date."]
    },
    {
        "id": "EU-GDPR-ART-22", "jurisdiction": "EU", "law": "GDPR Article 22",
        "trigger": {"uses_ai_for_consumer_decisions": True}, "severity": "high", "type": "Potential Risk",
        "title": "EU: Automated decision safeguards",
        "detail": "Data subjects have the right not to be subject to solely automated decisions with legal or similarly significant effects.",
        "remediation": ["Provide meaningful information about the logic.", "Offer human intervention and the right to contest.", "Conduct a DPIA."]
    },
    {
        "id": "UK-GDPR-ART-22", "jurisdiction": "UK", "law": "UK GDPR Article 22",
        "trigger": {"uses_ai_for_consumer_decisions": True}, "severity": "high", "type": "Potential Risk",
        "title": "UK: Automated decision safeguards",
        "detail": "UK GDPR gives individuals the right not to be subject to solely automated decisions with legal effects.",
        "remediation": ["Implement human review processes for automated decisions.", "Document the logic involved."]
    },

    # --- NORTH AMERICA ---
    {
        "id": "US-CO-ADMT", "jurisdiction": "US-CO", "law": "Colorado SB 26-189",
        "trigger": {"uses_ai_in_employment": True}, "severity": "high", "type": "Potential Risk",
        "title": "US-CO: ADMT employment disclosure",
        "detail": "Colorado's law requires disclosure before a consequential decision (like hiring) and human review after an adverse outcome.",
        "remediation": ["Document all AI hiring tools.", "Define a human-review path for rejected candidates."]
    },
    {
        "id": "US-NY-LL144", "jurisdiction": "US-NY-NYC", "law": "NYC Local Law 144",
        "trigger": {"uses_ai_in_employment": True}, "severity": "high", "type": "Potential Risk",
        "title": "US-NYC: Bias audit required for hiring AI",
        "detail": "Employers using automated employment decision tools must conduct an annual independent bias audit.",
        "remediation": ["Commission an independent bias audit.", "Provide notice to candidates."]
    },
    {
        "id": "US-IL-HB3773", "jurisdiction": "US-IL", "law": "Illinois HB 3773",
        "trigger": {"uses_ai_in_employment": True}, "severity": "high", "type": "Potential Risk",
        "title": "US-IL: AI employment discrimination",
        "detail": "Illinois prohibits discriminatory AI use across hiring, promotion, and termination.",
        "remediation": ["Assess AI tools for disparate impact.", "Retain records of AI-assisted decisions."]
    },
    {
        "id": "CA-PIPEDA", "jurisdiction": "CA", "law": "PIPEDA",
        "trigger": {"uses_ai_for_consumer_decisions": True}, "severity": "medium", "type": "Potential Risk",
        "title": "Canada: Fair information principles for AI",
        "detail": "PIPEDA's fair-information principles apply to automated processing. Canada's AIDA is pending.",
        "remediation": ["Apply fair-information principles.", "Provide meaningful information about the logic."]
    },

    # --- SOUTH AMERICA ---
    {
        "id": "BR-LGPD", "jurisdiction": "BR", "law": "Brazil LGPD",
        "trigger": {"uses_ai_for_consumer_decisions": True}, "severity": "high", "type": "Potential Risk",
        "title": "Brazil: Automated decision review rights",
        "detail": "LGPD provides rights to review solely automated decisions that affect the data subject's interests.",
        "remediation": ["Provide a right to review automated decisions.", "Document the criteria used."]
    },
    {
        "id": "CL-LEY-21719", "jurisdiction": "CL", "law": "Chile Ley 21.719",
        "trigger": {"uses_ai_for_consumer_decisions": True}, "severity": "high", "type": "Potential Risk",
        "title": "Chile: Automated decision explanation",
        "detail": "Chile's new data protection law regulates decisions based on automated processing and requires reconstructive explanations.",
        "remediation": ["Implement a right to explanation.", "Appoint a data protection officer where required."]
    },

    # --- ASIA ---
    {
        "id": "KR-AI-BASIC-ACT", "jurisdiction": "KR", "law": "South Korea AI Basic Act",
        "trigger": {"uses_chatbots": True}, "severity": "high", "type": "Potential Risk",
        "title": "South Korea: Prior notification for generative AI",
        "detail": "Generative AI operators must notify users in advance that AI is being used.",
        "remediation": ["Add a prior-notification notice before generative AI interaction."]
    },
    {
        "id": "CN-GENAI-FILING", "jurisdiction": "CN", "law": "China Generative AI Measures",
        "trigger": {"uses_chatbots": True}, "severity": "critical", "type": "Potential Risk",
        "title": "China: CAC security assessment and filing",
        "detail": "Public-facing generative AI services must complete a security assessment and algorithm filing before launch.",
        "remediation": ["Complete CAC security assessment.", "Apply labels to AI-generated content."]
    },
    {
        "id": "IN-DPDP", "jurisdiction": "IN", "law": "India DPDP Act 2023",
        "trigger": {"uses_ai_for_consumer_decisions": True}, "severity": "medium", "type": "Potential Risk",
        "title": "India: Right to contest automated decisions",
        "detail": "The DPDP Act gives data principals the right to contest decisions based solely on automated processing.",
        "remediation": ["Provide a mechanism to contest automated decisions.", "Obtain verifiable parental consent for children's data."]
    },
    {
        "id": "JP-AI-ACT", "jurisdiction": "JP", "law": "Japan AI Promotion Act",
        "trigger": {"uses_chatbots": True}, "severity": "low", "type": "Potential Risk",
        "title": "Japan: AI utilisation cooperation",
        "detail": "Japan's soft-law act requires AI-utilising businesses to cooperate with government measures.",
        "remediation": ["Monitor the AI Basic Plan.", "Participate in voluntary compliance frameworks."]
    },

    # --- OCEANIA ---
    {
        "id": "AU-OAIC-ADM", "jurisdiction": "AU", "law": "Australian Privacy Principles 1.7-1.9",
        "trigger": {"uses_ai_for_consumer_decisions": True}, "severity": "high", "type": "Potential Risk",
        "title": "Australia: Disclose automated decision-making",
        "detail": "From Dec 2026, APP entities must disclose AI and automated decision-making in privacy policies.",
        "remediation": ["Update privacy policies to disclose ADM use.", "Provide a path for human review."]
    },
    {
        "id": "NZ-PRIVACY-ACT", "jurisdiction": "NZ", "law": "New Zealand Privacy Act",
        "trigger": {"uses_ai_for_consumer_decisions": True}, "severity": "medium", "type": "Potential Risk",
        "title": "New Zealand: Responsible AI Guidance",
        "detail": "NZ relies on the Privacy Act 2020 and voluntary responsible AI guidance. Algorithm Charter applies to government agencies.",
        "remediation": ["Apply responsible-AI guidance.", "Comply with the Privacy Act 2020 for personal data."]
    },

    # --- GLOBAL BASELINES (Confirmed Gaps) ---
    {
        "id": "CONFIRMED-GAP-VENDORS", "jurisdiction": "GLOBAL", "law": "Vendor Governance",
        "trigger": {"has_vendor_contracts": False}, "severity": "high", "type": "Confirmed Gap",
        "title": "Missing AI Vendor Contracts (DPAs)",
        "detail": "You indicated you DO NOT have written Data Processing Agreements (DPAs) with your AI vendors. This is a major liability.",
        "remediation": ["Download our Vendor Questionnaire.", "Do not use vendors who refuse to sign a DPA."]
    },
    {
        "id": "CONFIRMED-GAP-HUMAN-REVIEW", "jurisdiction": "GLOBAL", "law": "Human Oversight",
        "trigger": {"has_human_review_process": False}, "severity": "high", "type": "Confirmed Gap",
        "title": "Missing Human Review Process",
        "detail": "You indicated you DO NOT have a documented human-review process. If an AI makes a mistake, you have no proof a human checked it.",
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
    secret_key = os.getenv("PAYSTACK_SECRET_KEY", "sk_test_YOUR_SECRET_KEY")
    
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

SCAN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>ActumGuard — Free AI Risk Scan</title>
<style>
body{font-family:system-ui,sans-serif;background:#0b1020;color:#e8ecf5;margin:0;padding:20px}
.wrap{max-width:640px;margin:0 auto}
h1{font-size:26px;margin:0 0 4px}
p{color:#8a94a8;line-height:1.5}
label{display:block;margin:14px 0 4px;font-size:14px}
input,select{width:100%;padding:12px;border-radius:8px;border:1px solid #2a3450;background:#151b2e;color:#e8ecf5;font-size:15px;box-sizing:border-box}
.chk{display:flex;align-items:flex-start;margin:8px 0;font-size:14px;color:#c0c8d8}
.chk input{width:auto;margin-right:8px;margin-top:3px}
button{width:100%;padding:14px;border:none;border-radius:8px;background:#4f8cff;color:#fff;font-size:16px;font-weight:600;margin-top:16px}
.card{background:#151b2e;border:1px solid #222b42;border-radius:12px;padding:18px;margin-top:14px}
.badge{display:inline-block;padding:4px 10px;border-radius:20px;font-size:12px;font-weight:700;margin-bottom:8px}
.high{background:#3a1518;color:#ff5c5c}.medium{background:#3a2e15;color:#f0b34a}.low{background:#153a26;color:#38c98a}.critical{background:#4a0f0f;color:#ff8a8a}
.small{font-size:12px;color:#6a7488;margin-top:20px}
.continent-group { max-height: 250px; overflow-y: auto; border: 1px solid #2a3450; padding: 12px; border-radius: 8px; background: #151b2e; margin-bottom: 16px; }
.continent-title { display: block; margin-top: 12px; margin-bottom: 6px; color: #4f8cff; font-weight: 700; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }
.continent-title:first-child { margin-top: 0; }
</style>
</head>
<body>
<div class="wrap">
<h1>Free AI Risk Scan</h1>
<p>Answer 8 questions. Get a snapshot of your AI exposure. Not legal advice.</p>

<label>Email (for your report)</label>
<input id="email" type="email" placeholder="you@company.com"/>

<label>Industry</label>
<select id="industry">
<option>Accounting / professional services</option>
<option>Logistics / supply chain</option>
<option>Private education / training</option>
<option>Healthcare (administrative)</option>
<option>Recruitment</option>
<option>Insurance</option>
<option>Property</option>
<option>Legal</option>
<option>Other</option>
</select>

<label>Where do you operate? (Select all that apply)</label>
<div class="continent-group">
    <span class="continent-title">Africa</span>
    <div class="chk"><input type="checkbox" class="jur" value="ZA"/> South Africa</div>
    <div class="chk"><input type="checkbox" class="jur" value="NG"/> Nigeria</div>
    <div class="chk"><input type="checkbox" class="jur" value="KE"/> Kenya</div>
    <div class="chk"><input type="checkbox" class="jur" value="EG"/> Egypt</div>
    
    <span class="continent-title">Europe</span>
    <div class="chk"><input type="checkbox" class="jur" value="EU"/> European Union</div>
    <div class="chk"><input type="checkbox" class="jur" value="UK"/> United Kingdom</div>
    
    <span class="continent-title">North America</span>
    <div class="chk"><input type="checkbox" class="jur" value="US-CO"/> USA - Colorado</div>
    <div class="chk"><input type="checkbox" class="jur" value="US-NY-NYC"/> USA - New York City</div>
    <div class="chk"><input type="checkbox" class="jur" value="US-IL"/> USA - Illinois</div>
    <div class="chk"><input type="checkbox" class="jur" value="CA"/> Canada</div>

    <span class="continent-title">South America</span>
    <div class="chk"><input type="checkbox" class="jur" value="BR"/> Brazil</div>
    <div class="chk"><input type="checkbox" class="jur" value="CL"/> Chile</div>

    <span class="continent-title">Asia</span>
    <div class="chk"><input type="checkbox" class="jur" value="KR"/> South Korea</div>
    <div class="chk"><input type="checkbox" class="jur" value="CN"/> China</div>
    <div class="chk"><input type="checkbox" class="jur" value="IN"/> India</div>
    <div class="chk"><input type="checkbox" class="jur" value="JP"/> Japan</div>

    <span class="continent-title">Oceania</span>
    <div class="chk"><input type="checkbox" class="jur" value="AU"/> Australia</div>
    <div class="chk"><input type="checkbox" class="jur" value="NZ"/> New Zealand</div>
</div>

<label>AI Usage (Check all that apply)</label>
<div class="chk"><input type="checkbox" id="employment"/> We use AI in hiring, promotion, or termination</div>
<div class="chk"><input type="checkbox" id="consumer"/> We use AI to make or influence consumer decisions</div>
<div class="chk"><input type="checkbox" id="chatbots"/> We deploy chatbots, AI assistants, or AI agents</div>

<label>Current Governance (Check ONLY if you have this in place)</label>
<div class="chk"><input type="checkbox" id="vendors"/> We have written Data Processing Agreements (DPAs) with ALL AI vendors</div>
<div class="chk"><input type="checkbox" id="human"/> We have a documented human-review process for adverse AI outcomes</div>

<button onclick="run()">Run Scan</button>
<div id="out"></div>
<p class="small">ActumGuard is not a law firm. This is a directional assessment, not legal advice.</p>
</div>
<script>
async function run(){
  const email=document.getElementById('email').value;
  if(!email){alert('Enter your email');return;}
  const jurisdictions=[...document.querySelectorAll('.jur:checked')].map(x=>x.value);
  if(jurisdictions.length === 0) { alert("Please select at least one jurisdiction."); return; }
  
  const body={
    email, industry:document.getElementById('industry').value, jurisdictions,
    uses_ai_in_employment:document.getElementById('employment').checked,
    uses_ai_for_consumer_decisions:document.getElementById('consumer').checked,
    uses_chatbots:document.getElementById('chatbots').checked,
    has_vendor_contracts:document.getElementById('vendors').checked,
    has_human_review_process:document.getElementById('human').checked
  };
  const r=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const data=await r.json();
  const cls=data.exposure.toLowerCase();
  let html=`<div class="card"><div class="badge ${cls}">${data.exposure} EXPOSURE</div><h2>Score: ${data.risk_score}</h2>`;
  if(data.findings.length===0){html+='<p>No rule-based findings triggered. This does not mean you are compliant.</p>';}
  data.findings.forEach(f=>{
    const typeColor = f.type === "Confirmed Gap" ? "#ff5c5c" : "#f0b34a";
    html+=`<div style="border-top:1px solid #2a3450;padding-top:12px;margin-top:12px">
    <strong>${f.title}</strong> <span style="color:${typeColor};font-size:12px;font-weight:bold;">[${f.type}]</span>
    <p style="font-size:13px">${f.detail}</p>
    <p style="font-size:13px;color:#38c98a"><strong>Fix it:</strong> ${f.remediation.join(' · ')}</p></div>`;
  });
  html+='</div>';
  document.getElementById('out').innerHTML=html;
}
</script>
</body>
</html>"""
