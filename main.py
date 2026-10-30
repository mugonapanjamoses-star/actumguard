"""ActumGuard backend v4: scan engine, Paystack fulfilment, policy delivery."""
import hashlib, hmac, json, logging, os, smtplib, sqlite3, time
from collections import defaultdict, deque
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from openai import OpenAI
from pydantic import BaseModel, EmailStr, Field, field_validator

from rules import JURISDICTIONS, REVIEWED, RULES, RULES_VERSION

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("actumguard")

DB = Path(os.getenv("ACTUMGUARD_DB", "actumguard.db"))  # point at a persistent disk in production
BASE = Path(__file__).parent
DISCLAIMER = ("ActumGuard is not a law firm and does not give legal advice. Results are directional and "
              "do not guarantee compliance or any regulatory outcome.")
INDUSTRIES = ["Accounting / professional services", "Logistics / supply chain", "Private education / training",
              "Healthcare (administrative)", "Recruitment", "Insurance", "Property", "Legal", "Other"]
# Paystack amounts are in the smallest unit (cents). Keep in sync with your Paystack products.
PRICES = {("Instant AI Policy", "ZAR"): 29900, ("Instant AI Policy", "USD"): 1900}

app = FastAPI(title="ActumGuard")
origins = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()]
if origins:
    app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["POST", "GET"], allow_headers=["*"])


# ---------- database ----------
def db():
    c = sqlite3.connect(DB, timeout=10)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    with db() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("""CREATE TABLE IF NOT EXISTS leads (
            id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, industry TEXT, jurisdictions TEXT,
            risk_score INTEGER, exposure TEXT, rules_version TEXT, consent_at TEXT, created_at TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS orders (
            reference TEXT PRIMARY KEY, email TEXT, product TEXT, industry TEXT, status TEXT,
            policy_text TEXT, error TEXT, created_at TEXT, delivered_at TEXT)""")
init_db()

def now():
    return datetime.now(timezone.utc).isoformat()


# ---------- scan engine ----------
class ScanRequest(BaseModel):
    email: EmailStr
    consent: bool
    industry: str = Field(max_length=80)
    jurisdictions: list[str] = Field(min_length=1, max_length=30)
    uses_ai_in_employment: bool
    uses_ai_for_consumer_decisions: bool
    collects_sensitive_data: bool
    uses_chatbots: bool
    has_vendor_contracts: bool
    has_human_review_process: bool

    @field_validator("consent")
    @classmethod
    def need_consent(cls, v):
        if not v:
            raise ValueError("Consent is required to run the scan and store your email.")
        return v

    @field_validator("jurisdictions")
    @classmethod
    def known(cls, v):
        bad = [j for j in v if j not in JURISDICTIONS]
        if bad:
            raise ValueError(f"Unknown jurisdictions: {bad}")
        return v

POINTS = {"low": 1, "medium": 2, "high": 3, "critical": 4}

def public(rule):
    meta = REVIEWED.get(rule["id"])
    out = {k: rule[k] for k in ("id", "jurisdiction", "law", "severity", "type", "title", "detail", "remediation")}
    out["verification"] = ({"status": "reviewed", **meta} if meta else {"status": "not_yet_reviewed"})
    return out

def evaluate(scan: ScanRequest):
    places = set(scan.jurisdictions)
    if any(j.startswith("US-") for j in places):
        places.add("US")  # state-level presence implies US federal law
    uses_ai = scan.uses_ai_in_employment or scan.uses_ai_for_consumer_decisions or scan.uses_chatbots
    findings = []
    for r in RULES:
        if r["jurisdiction"] == "GLOBAL":
            if not uses_ai:
                continue
        elif r["jurisdiction"] not in places:
            continue
        if r["industries"] and scan.industry not in r["industries"]:
            continue
        t = r["trigger"]
        hit = any(getattr(scan, f) for f in t["any"]) if "any" in t else all(getattr(scan, f) == v for f, v in t.items())
        if hit:
            findings.append(r)
    score = sum(POINTS[f["severity"]] + (1 if f["type"] == "Confirmed Gap" else 0) for f in findings)
    exposure = "LOW" if score <= 2 else "MEDIUM" if score <= 6 else "HIGH" if score <= 12 else "CRITICAL"
    return [public(f) for f in findings], score, exposure


# ---------- simple per-IP rate limit ----------
_hits = defaultdict(deque)
def rate_limited(ip, limit=10, window=3600):
    q, t = _hits[ip], time.time()
    while q and q[0] < t - window:
        q.popleft()
    if len(q) >= limit:
        return True
    q.append(t)
    return False

@app.post("/api/scan")
def scan(req: ScanRequest, request: Request):
    ip = (request.headers.get("x-forwarded-for") or request.client.host or "?").split(",")[0].strip()
    if rate_limited(ip):
        raise HTTPException(429, "Too many scans from this address. Try again later.")
    findings, score, exposure = evaluate(req)
    with db() as c:
        c.execute("INSERT INTO leads (email, industry, jurisdictions, risk_score, exposure, rules_version, consent_at, created_at)"
                  " VALUES (?,?,?,?,?,?,?,?)",
                  (req.email, req.industry, json.dumps(req.jurisdictions), score, exposure, RULES_VERSION, now(), now()))
    return {"findings": findings, "risk_score": score, "exposure": exposure,
            "rules_version": RULES_VERSION, "disclaimer": DISCLAIMER}


# ---------- policy generation and delivery ----------
POLICY_SYSTEM = (
    "You draft plain-language business policy templates. You are not a lawyer and must not claim to be. "
    "Write a one to two page AI Acceptable Use Policy template with these sections: Purpose, Scope, Approved AI tools, "
    "Data protection, Human review of AI decisions, Vendor management, Transparency to customers and staff, "
    "Incident reporting, Staff training, Review schedule, Approval record. Use placeholders like [Company name] "
    "and [Date]. Start with: 'AI-drafted template. Have a qualified lawyer review it before you adopt it.'"
)

def generate_policy(industry: str) -> str:
    key = os.getenv("LLM_API_KEY")
    if not key:
        raise RuntimeError("LLM_API_KEY is not set")
    # Any OpenAI-compatible provider. Choose one with a signed data processing agreement and suitable hosting.
    client = OpenAI(api_key=key, base_url=os.getenv("LLM_BASE_URL") or None)
    resp = client.chat.completions.create(
        model=os.getenv("LLM_MODEL", "gpt-4o-mini"),
        messages=[{"role": "system", "content": POLICY_SYSTEM},
                  {"role": "user", "content": f"Industry: {industry}. Do not ask questions; produce the template."}],
        timeout=60)
    return resp.choices[0].message.content

def send_email(to: str, subject: str, body: str):
    host = os.getenv("SMTP_HOST")
    if not host:
        raise RuntimeError("SMTP_HOST is not set")
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = os.getenv("MAIL_FROM", "policies@actumguard.com"), to, subject
    m.set_content(body + "\n\n---\n" + DISCLAIMER)
    with smtplib.SMTP(host, int(os.getenv("SMTP_PORT", "587")), timeout=30) as s:
        s.starttls()
        s.login(os.getenv("SMTP_USER", ""), os.getenv("SMTP_PASSWORD", ""))
        s.send_message(m)

def fulfil(reference: str):
    with db() as c:
        o = c.execute("SELECT * FROM orders WHERE reference=?", (reference,)).fetchone()
    if not o or o["status"] == "delivered":
        return
    try:
        text = o["policy_text"] or generate_policy(o["industry"])
        with db() as c:
            c.execute("UPDATE orders SET policy_text=? WHERE reference=?", (text, reference))
        send_email(o["email"], "Your draft AI use policy from ActumGuard", text)
        with db() as c:
            c.execute("UPDATE orders SET status='delivered', error=NULL, delivered_at=? WHERE reference=?", (now(), reference))
        log.info("order %s delivered", reference)
    except Exception as e:
        log.exception("order %s failed", reference)
        with db() as c:
            c.execute("UPDATE orders SET status='failed', error=? WHERE reference=?", (str(e)[:300], reference))


# ---------- Paystack webhook ----------
@app.post("/api/webhooks/paystack")
async def paystack_webhook(request: Request, background: BackgroundTasks):
    secret = os.getenv("pk_test_c77eb2b404c47451da4fcf75364a336d4baaa9e3")
    if not secret:  # fail closed: never fall back to a default key
        log.error("PAYSTACK_SECRET_KEY not set")
        return JSONResponse(status_code=503, content={"message": "Not configured"})
    body = await request.body()
    expected = hmac.new(secret.encode(), body, hashlib.sha512).hexdigest()
    if not hmac.compare_digest(expected, request.headers.get("x-paystack-signature", "")):
        return JSONResponse(status_code=400, content={"message": "Invalid signature"})
    try:
        event = json.loads(body)
    except ValueError:
        return JSONResponse(status_code=400, content={"message": "Bad JSON"})
    if event.get("event") != "charge.success":
        return {"status": "ignored"}

    data = event.get("data", {})
    fields = {f.get("variable_name"): f.get("value") for f in (data.get("metadata") or {}).get("custom_fields", [])}
    product = fields.get("product", "")
    industry = fields.get("industry") if fields.get("industry") in INDUSTRIES else "Other"
    reference, email = data.get("reference"), (data.get("customer") or {}).get("email")
    # The buyer controls metadata, so check the amount actually paid against the price list.
    if not reference or not email or PRICES.get((product, data.get("currency"))) != data.get("amount"):
        log.warning("charge ignored: product/amount mismatch (ref=%s)", reference)
        return {"status": "ignored"}  # 200 so Paystack stops retrying

    with db() as c:
        added = c.execute("INSERT OR IGNORE INTO orders (reference, email, product, industry, status, created_at)"
                          " VALUES (?,?,?,?,?,?)", (reference, email, product, industry, "pending", now())).rowcount
    if added:  # duplicates from webhook retries are skipped
        background.add_task(fulfil, reference)
    return {"status": "success"}


# ---------- admin: see and retry failed deliveries ----------
def check_admin(token):
    expected = os.getenv("ADMIN_TOKEN")
    if not expected or not hmac.compare_digest(token or "", expected):
        raise HTTPException(401, "Unauthorized")

@app.get("/api/admin/orders")
def admin_orders(status: str = "failed", x_admin_token: str = Header(None)):
    check_admin(x_admin_token)
    with db() as c:
        rows = c.execute("SELECT reference, email, product, status, error, created_at FROM orders WHERE status=?", (status,)).fetchall()
    return [dict(r) for r in rows]

@app.post("/api/admin/orders/{reference}/retry")
def admin_retry(reference: str, background: BackgroundTasks, x_admin_token: str = Header(None)):
    check_admin(x_admin_token)
    background.add_task(fulfil, reference)
    return {"status": "retrying"}


# ---------- pages ----------
@app.get("/health")
def health():
    return {"status": "ok", "rules_version": RULES_VERSION}

@app.get("/")
def home():
    return FileResponse(BASE / "static" / "scan.html")
