"""
ActumGuard MVP — single-file backend
Free AI Risk Scan + email capture + rules engine.
Deploy on Render free tier. No login required for the free scan.
"""

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
import sqlite3, os, json
from datetime import datetime, timezone
from pathlib import Path

app = FastAPI(title="ActumGuard")

DB = Path(os.getenv("ACTUMGUARD_DB", "actumguard.db"))

def init_db():
    with sqlite3.connect(DB) as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS leads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT,
                industry TEXT,
                jurisdictions TEXT,
                risk_score INTEGER,
                exposure TEXT,
                created_at TEXT
            )
        """)
        c.commit()
init_db()

# ---------------- RULES REGISTRY (MVP SUBSET) ----------------
RULES = [
    {
        "id": "EU-AI-ACT-ART-50",
        "jurisdiction": "EU",
        "law": "EU AI Act Article 50",
        "trigger": {"uses_chatbots": True},
        "severity": "high",
        "title": "AI chatbot transparency required",
        "detail": "From 2 Aug 2026, any AI system interacting with people must disclose it is AI, unless obvious from context. Agents must disclose who they act for.",
        "remediation": [
            "Add an AI-disclosure notice at the start of every chatbot or agent interaction.",
            "State the entity on whose behalf the agent acts.",
            "Keep a record of the disclosure version and deployment date."
        ]
    },
    {
        "id": "ZA-POPIA-S71",
        "jurisdiction": "ZA",
        "law": "POPIA Section 71",
        "trigger": {"uses_ai_for_consumer_decisions": True},
        "severity": "high",
        "title": "Automated decisions need human review",
        "detail": "POPIA s.71 governs decisions based solely on automated processing that significantly affect a data subject.",
        "remediation": [
            "Identify solely automated decisions that significantly affect individuals.",
            "Provide meaningful information about the underlying logic.",
            "Offer a right to human review and to make representations."
        ]
    },
    {
        "id": "US-CO-ADMT",
        "jurisdiction": "US-CO",
        "law": "Colorado SB 26-189",
        "trigger": {"uses_ai_in_employment": True},
        "severity": "high",
        "title": "ADMT employment disclosure",
        "detail": "From 1 Jan 2027, deployers of ADMTs in employment must disclose use before a consequential decision and offer human review after an adverse outcome.",
        "remediation": [
            "Document every AI tool used in hiring, promotion, or termination.",
            "Add a plain-language disclosure to the application flow.",
            "Define a human-review path for adverse outcomes."
        ]
    },
    {
        "id": "US-NYC-LL144",
        "jurisdiction": "US-NY-NYC",
        "law": "NYC Local Law 144",
        "trigger": {"uses_ai_in_employment": True},
        "severity": "high",
        "title": "Bias audit required for hiring AI",
        "detail": "Employers using automated employment decision tools must conduct an annual independent bias audit and provide notice.",
        "remediation": [
            "Identify every automated employment decision tool.",
            "Commission an independent bias audit annually.",
            "Provide notice to candidates at least 10 business days before use."
        ]
    },
    {
        "id": "KR-AI-BASIC-ACT",
        "jurisdiction": "KR",
        "law": "South Korea AI Basic Act",
        "trigger": {"uses_chatbots": True},
        "severity": "medium",
        "title": "Prior notification for generative AI",
        "detail": "In force since 22 Jan 2026. Generative AI operators must notify users in advance that AI is being used. Grace period on fines expected to end around Jan 2027.",
        "remediation": [
            "Add a prior-notification notice before generative AI interaction.",
            "Document the notification method and user acknowledgment.",
            "Prepare for the end of the grace period."
        ]
    },
    {
        "id": "NG-NDPA-S41",
        "jurisdiction": "NG",
        "law": "Nigeria NDPA 2023 s.41",
        "trigger": {"uses_ai_for_consumer_decisions": True},
        "severity": "high",
        "title": "Right against solely automated decisions",
        "detail": "Data subjects have the right not to be subject to solely automated decisions with legal or similarly significant effects, unless they consent or the law authorises it.",
        "remediation": [
            "Identify solely automated decisions affecting legal rights.",
            "Obtain explicit consent where used.",
            "Provide a human-review path and a right to contest."
        ]
    },
    {
        "id": "KE-DPA-S35",
        "jurisdiction": "KE",
        "law": "Kenya Data Protection Act 2019 s.35",
        "trigger": {"uses_ai_for_consumer_decisions": True},
        "severity": "high",
        "title": "Right against solely automated decisions",
        "detail": "Data subjects may not be subject to solely automated decisions with legal or similarly significant effects. Human intervention must be available.",
        "remediation": [
            "Disclose automated decision-making to the data subject.",
            "Provide meaningful information about the logic.",
            "Offer human intervention and a right to contest."
        ]
    },
    {
        "id": "EU-GDPR-ART22",
        "jurisdiction": "EU",
        "law": "GDPR Article 22",
        "trigger": {"uses_ai_for_consumer_decisions": True},
        "severity": "high",
        "title": "Automated decision safeguards",
        "detail": "Data subjects have the right not to be subject to solely automated decisions with legal or similarly significant effects, subject to exceptions and safeguards.",
        "remediation": [
            "Identify decisions within Article 22.",
            "Provide meaningful information about the logic.",
            "Offer human intervention and the right to contest.",
            "Conduct a DPIA."
        ]
    },
    {
        "id": "US-IL-HB3773",
        "jurisdiction": "US-IL",
        "law": "Illinois HB 3773",
        "trigger": {"uses_ai_in_employment": True},
        "severity": "high",
        "title": "AI employment discrimination prohibited",
        "detail": "Effective 1 Jan 2026. Prohibits discriminatory AI use in hiring, promotion, and termination.",
        "remediation": [
            "Assess AI tools for disparate impact.",
            "Document business necessity for AI-driven decisions.",
            "Retain records of AI-assisted decisions."
        ]
    },
    {
        "id": "AU-OAIC-ADM",
        "jurisdiction": "AU",
        "law": "Australian Privacy Principles 1.7–1.9",
        "trigger": {"uses_ai_for_consumer_decisions": True},
        "severity": "medium",
        "title": "Disclose automated decision-making",
        "detail": "From 10 Dec 2026, APP entities must disclose AI and automated decision-making in privacy policies and collection notices.",
        "remediation": [
            "Update privacy policies to disclose ADM use.",
            "Describe the types of decisions made by ADM.",
            "Provide a path for human review."
        ]
    },
    {
        "id": "CN-GENAI-FILING",
        "jurisdiction": "CN",
        "law": "China Generative AI Measures",
        "trigger": {"uses_chatbots": True},
        "severity": "critical",
        "title": "CAC security assessment and filing",
        "detail": "Public-facing generative AI services must complete a security assessment and algorithm filing before launch. AI-generated content must be labelled.",
        "remediation": [
            "Complete CAC security assessment and algorithm filing.",
            "Apply visible and invisible labels to AI-generated content.",
            "Maintain content-management and training-data security systems."
        ]
    },
    {
        "id": "BR-LGPD-ADM",
        "jurisdiction": "BR",
        "law": "Brazil LGPD",
        "trigger": {"uses_ai_for_consumer_decisions": True},
        "severity": "medium",
        "title": "Automated decision review rights",
        "detail": "LGPD provides rights to review solely automated decisions that affect the data subject's interests. Brazil's AI bill (PL 2338) is pending.",
        "remediation": [
            "Provide a right to review automated decisions.",
            "Document the criteria and logic used.",
            "Monitor PL 2338/2023 for enactment."
        ]
    },
    {
        "id": "CA-PIPEDA-ADM",
        "jurisdiction": "CA",
        "law": "PIPEDA",
        "trigger": {"uses_ai_for_consumer_decisions": True},
        "severity": "low",
        "title": "Fair information principles for AI",
        "detail": "Canada has no federal AI statute in force (AIDA died in Jan 2025). PIPEDA's fair-information principles apply to automated processing.",
        "remediation": [
            "Apply fair-information principles to automated decisions.",
            "Provide meaningful information about the logic.",
            "Monitor for any replacement federal AI framework."
        ]
    },
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
        if rule["jurisdiction"] not in scan.jurisdictions:
            continue
        match = True
        for field, expected in rule["trigger"].items():
            if getattr(scan, field, None) != expected:
                match = False
                break
        if match:
            findings.append({
                "law": rule["law"],
                "jurisdiction": rule["jurisdiction"],
                "severity": rule["severity"],
                "title": rule["title"],
                "detail": rule["detail"],
                "remediation": rule["remediation"],
            })
    weights = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    score = sum(weights.get(f["severity"], 1) for f in findings)
    exposure = "LOW" if score <= 2 else "MEDIUM" if score <= 5 else "HIGH" if score <= 9 else "CRITICAL"
    return findings, score, exposure

@app.post("/api/scan")
def scan(req: ScanRequest):
    findings, score, exposure = evaluate(req)
    with sqlite3.connect(DB) as c:
        c.execute("INSERT INTO leads (email, industry, jurisdictions, risk_score, exposure, created_at) VALUES (?,?,?,?,?,?)",
                  (req.email, req.industry, json.dumps(req.jurisdictions), score, exposure,
                   datetime.now(timezone.utc).isoformat()))
        c.commit()
    return {"findings": findings, "risk_score": score, "exposure": exposure}

@app.get("/health")
def health():
    return {"status": "ok", "app": "ActumGuard"}

@app.get("/", response_class=HTMLResponse)
def home():
    return SCAN_HTML

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
</style>
</head>
<body>
<div class="wrap">
<h1>Free AI Risk Scan</h1>
<p>Answer 8 questions. Get a directional snapshot of your AI exposure across the jurisdictions where you operate. Not legal advice.</p>

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

<label>Where do you operate?</label>
<div class="chk"><input type="checkbox" class="jur" value="ZA"/> South Africa</div>
<div class="chk"><input type="checkbox" class="jur" value="EU"/> European Union</div>
<div class="chk"><input type="checkbox" class="jur" value="US-CO"/> Colorado (US)</div>
<div class="chk"><input type="checkbox" class="jur" value="US-NY-NYC"/> New York City (US)</div>
<div class="chk"><input type="checkbox" class="jur" value="US-IL"/> Illinois (US)</div>
<div class="chk"><input type="checkbox" class="jur" value="KR"/> South Korea</div>
<div class="chk"><input type="checkbox" class="jur" value="NG"/> Nigeria</div>
<div class="chk"><input type="checkbox" class="jur" value="KE"/> Kenya</div>
<div class="chk"><input type="checkbox" class="jur" value="AU"/> Australia</div>
<div class="chk"><input type="checkbox" class="jur" value="CN"/> China</div>
<div class="chk"><input type="checkbox" class="jur" value="BR"/> Brazil</div>
<div class="chk"><input type="checkbox" class="jur" value="CA"/> Canada</div>

<label>AI use</label>
<div class="chk"><input type="checkbox" id="employment"/> We use AI in hiring, promotion, or termination</div>
<div class="chk"><input type="checkbox" id="consumer"/> We use AI to make or influence consumer decisions</div>
<div class="chk"><input type="checkbox" id="sensitive"/> We process sensitive personal data</div>
<div class="chk"><input type="checkbox" id="chatbots"/> We deploy chatbots, AI assistants, or AI agents</div>
<div class="chk"><input type="checkbox" id="vendors"/> We have written contracts with AI vendors</div>
<div class="chk"><input type="checkbox" id="human"/> We have a documented human-review process for adverse AI outcomes</div>

<button onclick="run()">Run Scan</button>
<div id="out"></div>
<p class="small">ActumGuard is not a law firm. This is a directional assessment, not legal advice. Confirm obligations with qualified counsel.</p>
</div>
<script>
async function run(){
  const email=document.getElementById('email').value;
  if(!email){alert('Enter your email');return;}
  const jurisdictions=[...document.querySelectorAll('.jur:checked')].map(x=>x.value);
  const body={
    email, industry:document.getElementById('industry').value, jurisdictions,
    uses_ai_in_employment:document.getElementById('employment').checked,
    uses_ai_for_consumer_decisions:document.getElementById('consumer').checked,
    collects_sensitive_data:document.getElementById('sensitive').checked,
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
    html+=`<div style="border-top:1px solid #2a3450;padding-top:12px;margin-top:12px">
    <strong>${f.title}</strong> <span style="color:#6a7488;font-size:12px">(${f.jurisdiction})</span>
    <p style="font-size:13px">${f.detail}</p>
    <p style="font-size:13px;color:#38c98a"><strong>Fix it:</strong> ${f.remediation.join(' · ')}</p></div>`;
  });
  html+='</div>';
  document.getElementById('out').innerHTML=html;
}
</script>
</body>
</html>"""
