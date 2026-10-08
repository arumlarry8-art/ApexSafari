"""
AI Router — /ai/* endpoints
Uses ai_service.py (unchanged). All Claude API calls server-side.
API key never touches the browser.
"""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional, List
from database import get_db, ScopeAnalysis, generate_id
from auth_service import get_current
from ai_service import (
    generate_test_question, grade_answer, analyze_scope,
    predict_bounty, check_duplicate, write_report,
    chat, get_intelligence, learning_module, admin_insights
)
from datetime import datetime

router   = APIRouter(prefix="/ai", tags=["ai"])
security = HTTPBearer()

def tok(c: HTTPAuthorizationCredentials = Depends(security)):
    return c.credentials

def auth(token: str, db: Session):
    h = get_current(db, token)
    if not h:
        raise HTTPException(status_code=401, detail="Unauthorized.")
    return h

HACKING_STEPS = [
    {"id":1,  "title":"Reconnaissance",          "topics":["Passive recon","Active recon","Google Dorking","WHOIS","Shodan","Cert transparency"]},
    {"id":2,  "title":"OSINT",                   "topics":["Email harvesting","LinkedIn recon","GitHub recon","Maltego","Public records"]},
    {"id":3,  "title":"Scanning & Enumeration",  "topics":["Port scanning","Subdomain enum","Directory busting","Service detection","Banner grabbing"]},
    {"id":4,  "title":"Vulnerability Analysis",  "topics":["CVE identification","CVSS scoring","Attack surface mapping","Automated scanning"]},
    {"id":5,  "title":"Exploitation",            "topics":["Web app attacks","Metasploit","Custom exploits","Payload crafting"]},
    {"id":6,  "title":"Post-Exploitation",       "topics":["Persistence","Data exfiltration","Pivoting","C2 frameworks","Credential dumping"]},
    {"id":7,  "title":"Privilege Escalation",    "topics":["Linux privesc","Windows privesc","SUID abuse","Kernel exploits","Sudo abuse"]},
    {"id":8,  "title":"Lateral Movement",        "topics":["Pass-the-hash","Network traversal","Credential reuse","Remote services"]},
    {"id":9,  "title":"Password Attacks",        "topics":["Brute force","Dictionary attacks","Hash cracking","Credential stuffing","Rainbow tables"]},
    {"id":10, "title":"Web Application Hacking", "topics":["OWASP Top 10","SQLi","XSS","SSRF","IDOR","JWT attacks","XXE","SSTI","CORS"]},
    {"id":11, "title":"Network Attacks",         "topics":["MITM","ARP spoofing","DNS poisoning","Packet sniffing","SSL stripping"]},
    {"id":12, "title":"Wireless Attacks",        "topics":["WPA2 cracking","Evil twin AP","WPS attacks","Deauth attacks","PMKID"]},
    {"id":13, "title":"Social Engineering",      "topics":["Phishing","Pretexting","Vishing","Spear phishing","Baiting"]},
    {"id":14, "title":"Malware Analysis",        "topics":["Static analysis","Dynamic analysis","Reverse engineering","Sandbox analysis"]},
    {"id":15, "title":"Forensics & Evasion",     "topics":["Log clearing","AV evasion","Memory forensics","Steganography","AMSI bypass"]},
    {"id":16, "title":"Report Writing",          "topics":["Executive summary","CVSS scoring","Proof of concept","Remediation","References"]},
]

# ── ENTRY TEST ────────────────────────────────────────────────────
@router.get("/test/question/{step_index}")
def get_question(step_index: int, token: str = Depends(tok), db: Session = Depends(get_db)):
    h = auth(token, db)
    if not 0 <= step_index <= 15:
        raise HTTPException(status_code=400, detail="Step index must be 0-15.")
    step = HACKING_STEPS[step_index]
    return generate_test_question(step["title"], step["topics"], h.level)

class GradeReq(BaseModel):
    step_index: int
    question:   str
    answer:     str

@router.post("/test/grade")
def grade(req: GradeReq, token: str = Depends(tok), db: Session = Depends(get_db)):
    h    = auth(token, db)
    step = HACKING_STEPS[req.step_index]
    return grade_answer(step["title"], req.question, req.answer)

class CompleteTestReq(BaseModel):
    scores: List[dict]

@router.post("/test/complete")
def complete_test(req: CompleteTestReq, token: str = Depends(tok), db: Session = Depends(get_db)):
    h = auth(token, db)
    passed          = sum(1 for s in req.scores if s.get("verdict") == "PASS") >= 10
    h.test_attempts += 1
    h.test_passed    = passed
    h.test_score     = sum(1 for s in req.scores if s.get("verdict") == "PASS")
    h.certified      = passed
    db.commit()
    return {"passed": passed, "score": h.test_score, "attempts": h.test_attempts}

# ── SCOPE PARSER ──────────────────────────────────────────────────
class ScopeReq(BaseModel):
    program_name:     Optional[str] = ""
    platform:         str           = "HackerOne"
    screenshot_count: int           = 0

@router.post("/scope/analyze")
def scope_analyze(req: ScopeReq, token: str = Depends(tok), db: Session = Depends(get_db)):
    h      = auth(token, db)
    result = analyze_scope(req.program_name or "Unknown", req.platform, req.screenshot_count)
    entry  = ScopeAnalysis(
        id               = generate_id(),
        hunter_id        = h.id,
        program_name     = req.program_name,
        platform         = req.platform,
        analysis         = result,
        screenshot_count = req.screenshot_count,
    )
    db.add(entry)
    db.commit()
    return {"analysis": result, "id": entry.id}

@router.get("/scope/history")
def scope_history(token: str = Depends(tok), db: Session = Depends(get_db)):
    h     = auth(token, db)
    items = db.query(ScopeAnalysis).filter(
        ScopeAnalysis.hunter_id == h.id
    ).order_by(ScopeAnalysis.created_at.desc()).limit(20).all()
    return [{
        "id":       a.id,
        "program":  a.program_name,
        "platform": a.platform,
        "date":     a.created_at.isoformat(),
        "analysis": a.analysis,
    } for a in items]

# ── BOUNTY PREDICTOR ──────────────────────────────────────────────
class PredictReq(BaseModel):
    vuln_type:   str
    severity:    str
    program:     str
    platform:    str
    description: Optional[str] = ""

@router.post("/bounty/predict")
def predict(req: PredictReq, token: str = Depends(tok), db: Session = Depends(get_db)):
    auth(token, db)
    return {"result": predict_bounty(req.vuln_type, req.severity, req.program, req.platform, req.description)}

# ── DUPLICATE DETECTOR ────────────────────────────────────────────
class DupeReq(BaseModel):
    vuln_type:   str
    target:      str
    description: str

@router.post("/bounty/duplicate-check")
def dupe_check(req: DupeReq, token: str = Depends(tok), db: Session = Depends(get_db)):
    auth(token, db)
    return {"result": check_duplicate(req.vuln_type, req.target, req.description)}

# ── REPORT WRITER ─────────────────────────────────────────────────
class ReportReq(BaseModel):
    vuln_type: str
    target:    str
    steps:     str
    impact:    str
    poc:       Optional[str] = ""
    severity:  Optional[str] = "High"

@router.post("/report/write")
def write(req: ReportReq, token: str = Depends(tok), db: Session = Depends(get_db)):
    auth(token, db)
    return {"report": write_report(req.vuln_type, req.target, req.steps, req.impact, req.poc, req.severity)}

# ── AI CHAT ───────────────────────────────────────────────────────
class ChatReq(BaseModel):
    message: str
    history: List[dict] = []

@router.post("/chat")
def ai_chat(req: ChatReq, token: str = Depends(tok), db: Session = Depends(get_db)):
    auth(token, db)
    return {"response": chat(req.message, req.history)}

# ── INTELLIGENCE ──────────────────────────────────────────────────
@router.get("/intelligence/{intel_type}")
def intelligence(intel_type: str, token: str = Depends(tok), db: Session = Depends(get_db)):
    auth(token, db)
    valid = ["threats", "bounties", "trends", "cve", "news", "surface"]
    if intel_type not in valid:
        raise HTTPException(status_code=400, detail=f"Must be one of: {valid}")
    return {"data": get_intelligence(intel_type)}

# ── LEARNING ──────────────────────────────────────────────────────
class LearnReq(BaseModel):
    step_title: str
    topics:     List[str]
    is_weak:    bool = False

@router.post("/learning/module")
def learning(req: LearnReq, token: str = Depends(tok), db: Session = Depends(get_db)):
    auth(token, db)
    return {"content": learning_module(req.step_title, req.topics, req.is_weak)}

# ── ADMIN AI INSIGHTS ─────────────────────────────────────────────
@router.post("/admin/insights")
def insights(token: str = Depends(tok), db: Session = Depends(get_db)):
    from auth_service import require_admin
    from database import Bounty, Hunter
    a = require_admin(db, token)
    if not a:
        raise HTTPException(status_code=403, detail="Admin only.")
    total   = db.query(Hunter).filter(Hunter.role == "hunter").count()
    certs   = db.query(Hunter).filter(Hunter.certified == True).count()
    bounties= db.query(Bounty).filter(Bounty.status == "verified").all()
    revenue = sum(b.platform_fee for b in bounties)
    stats   = {"total_hunters": total, "certified": certs, "revenue_usd": revenue, "bounties": len(bounties)}
    return {"insights": admin_insights(stats)}
