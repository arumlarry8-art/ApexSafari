from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from models.database import get_db, Hunter, Bounty, Payment, SecurityEvent, Announcement, HallOfFame, generate_id
from services.auth import require_admin, log_event
from services import ai
from datetime import datetime

router   = APIRouter(prefix="/admin", tags=["admin"])
security = HTTPBearer()

def tok(c: HTTPAuthorizationCredentials = Depends(security)):
    return c.credentials

def admin(token: str, db: Session):
    h = require_admin(db, token)
    if not h: raise HTTPException(403, "Admin access required.")
    return h

def refresh_rankings(db: Session):
    """Recalculate all hunter rankings"""
    hunters = db.query(Hunter).filter(
        Hunter.role == "hunter", Hunter.banned == False
    ).order_by(Hunter.earnings.desc()).all()
    for i, h in enumerate(hunters, 1):
        h.rank = i
    db.commit()

# ── DASHBOARD STATS ───────────────────────────────────────────────
@router.get("/stats")
def stats(token: str = Depends(tok), db: Session = Depends(get_db)):
    admin(token, db)
    total_hunters  = db.query(Hunter).filter(Hunter.role == "hunter").count()
    certified      = db.query(Hunter).filter(Hunter.certified == True).count()
    countries      = db.query(Hunter.country).distinct().count()
    today          = datetime.utcnow().replace(hour=0, minute=0, second=0)
    active_today   = db.query(Hunter).filter(Hunter.last_seen >= today).count()
    pending_bounties= db.query(Bounty).filter(Bounty.status == "pending").count()
    verified_bounties= db.query(Bounty).filter(Bounty.status == "verified").all()
    total_revenue  = sum(b.platform_fee for b in verified_bounties)
    total_paid_out = sum(b.hunter_keeps for b in verified_bounties)

    # Revenue by payment method
    mpesa_rev  = sum(b.platform_fee for b in verified_bounties if b.payment_method == "mpesa")
    paypal_rev = sum(b.platform_fee for b in verified_bounties if b.payment_method == "paypal")
    btc_rev    = sum(b.platform_fee for b in verified_bounties if b.payment_method == "bitcoin")

    return {
        "total_hunters":      total_hunters,
        "certified_hunters":  certified,
        "countries":          countries,
        "active_today":       active_today,
        "pending_bounties":   pending_bounties,
        "total_revenue_usd":  round(total_revenue, 2),
        "total_paid_to_hunters": round(total_paid_out, 2),
        "revenue_by_method": {
            "mpesa":   round(mpesa_rev, 2),
            "paypal":  round(paypal_rev, 2),
            "bitcoin": round(btc_rev, 2),
        },
        "total_bounties_verified": len(verified_bounties),
    }

# ── HUNTERS MANAGEMENT ────────────────────────────────────────────
@router.get("/hunters")
def all_hunters(limit: int = 100, token: str = Depends(tok), db: Session = Depends(get_db)):
    admin(token, db)
    hunters = db.query(Hunter).order_by(Hunter.created_at.desc()).limit(limit).all()
    return [{
        "id":           h.id,
        "username":     h.username,
        "email":        h.email,
        "country":      h.country,
        "level":        h.level,
        "role":         h.role,
        "certified":    h.certified,
        "rank":         h.rank,
        "earnings":     h.earnings,
        "bugs":         h.bugs_found,
        "test_score":   h.test_score,
        "test_attempts":h.test_attempts,
        "banned":       h.banned,
        "mpesa_number": h.mpesa_number,
        "last_seen":    h.last_seen.isoformat(),
        "created_at":   h.created_at.isoformat(),
    } for h in hunters]

class BanReq(BaseModel):
    reason: str

@router.post("/hunters/{hunter_id}/ban")
def ban_hunter(hunter_id: str, req: BanReq, token: str = Depends(tok), db: Session = Depends(get_db)):
    a = admin(token, db)
    h = db.query(Hunter).filter(Hunter.id == hunter_id).first()
    if not h: raise HTTPException(404, "Hunter not found.")
    h.banned = True; h.ban_reason = req.reason
    db.commit()
    log_event(db, "hunter_banned", "warning", hunter_id=a.id, details=f"Banned {h.username}: {req.reason}")
    return {"status": "banned"}

@router.post("/hunters/{hunter_id}/unban")
def unban_hunter(hunter_id: str, token: str = Depends(tok), db: Session = Depends(get_db)):
    a = admin(token, db)
    h = db.query(Hunter).filter(Hunter.id == hunter_id).first()
    if not h: raise HTTPException(404, "Hunter not found.")
    h.banned = False; h.ban_reason = None
    db.commit()
    log_event(db, "hunter_unbanned", "info", hunter_id=a.id, details=f"Unbanned {h.username}")
    return {"status": "unbanned"}

@router.post("/hunters/{hunter_id}/certify")
def certify_hunter(hunter_id: str, token: str = Depends(tok), db: Session = Depends(get_db)):
    admin(token, db)
    h = db.query(Hunter).filter(Hunter.id == hunter_id).first()
    if not h: raise HTTPException(404, "Hunter not found.")
    h.certified = True
    db.commit()
    return {"status": "certified"}

# ── BOUNTY VERIFICATION ───────────────────────────────────────────
@router.get("/bounties/pending")
def pending_bounties(token: str = Depends(tok), db: Session = Depends(get_db)):
    admin(token, db)
    bounties = db.query(Bounty).filter(Bounty.status == "pending").order_by(Bounty.created_at.desc()).all()
    return [{
        "id":       b.id,
        "hunter":   b.hunter.username if b.hunter else "Unknown",
        "program":  b.program_name,
        "platform": b.platform,
        "amount":   b.amount_usd,
        "fee":      b.platform_fee,
        "fee_paid": b.fee_paid,
        "method":   b.payment_method,
        "date":     b.created_at.isoformat(),
    } for b in bounties]

class VerifyReq(BaseModel):
    approved: bool
    notes:    Optional[str] = ""

@router.post("/bounties/{bounty_id}/verify")
def verify_bounty(bounty_id: str, req: VerifyReq, token: str = Depends(tok), db: Session = Depends(get_db)):
    a      = admin(token, db)
    bounty = db.query(Bounty).filter(Bounty.id == bounty_id).first()
    if not bounty: raise HTTPException(404, "Bounty not found.")

    bounty.status      = "verified" if req.approved else "rejected"
    bounty.verified_by = a.id
    bounty.verified_at = datetime.utcnow()
    bounty.notes       = req.notes

    if req.approved:
        hunter = db.query(Hunter).filter(Hunter.id == bounty.hunter_id).first()
        if hunter:
            hunter.earnings   += bounty.hunter_keeps
            hunter.bugs_found += 1
            db.commit()
            refresh_rankings(db)

    db.commit()
    return {"status": bounty.status}

# ── SECURITY EVENTS ───────────────────────────────────────────────
@router.get("/security-events")
def security_events(limit: int = 100, token: str = Depends(tok), db: Session = Depends(get_db)):
    admin(token, db)
    events = db.query(SecurityEvent).order_by(SecurityEvent.created_at.desc()).limit(limit).all()
    return [{
        "id":       e.id,
        "type":     e.event_type,
        "severity": e.severity,
        "ip":       e.ip_address,
        "details":  e.details,
        "time":     e.created_at.isoformat(),
    } for e in events]

# ── ANNOUNCEMENTS ─────────────────────────────────────────────────
class AnnounceReq(BaseModel):
    title:   str
    content: str
    type:    Optional[str] = "update"

@router.post("/announcements")
def post_announcement(req: AnnounceReq, token: str = Depends(tok), db: Session = Depends(get_db)):
    admin(token, db)
    a = Announcement(id=generate_id(), title=req.title, content=req.content, type=req.type)
    db.add(a)
    db.commit()
    return {"id": a.id, "status": "posted"}

@router.get("/announcements")
def get_announcements(db: Session = Depends(get_db)):
    items = db.query(Announcement).order_by(Announcement.created_at.desc()).limit(20).all()
    return [{"id": a.id, "title": a.title, "content": a.content, "type": a.type, "date": a.created_at.isoformat()} for a in items]

# ── HALL OF FAME ──────────────────────────────────────────────────
class HofReq(BaseModel):
    hunter_id:  str
    finding:    str
    bounty_usd: float
    category:   str

@router.post("/hall-of-fame")
def add_hof(req: HofReq, token: str = Depends(tok), db: Session = Depends(get_db)):
    admin(token, db)
    e = HallOfFame(id=generate_id(), hunter_id=req.hunter_id, finding=req.finding, bounty_usd=req.bounty_usd, category=req.category)
    db.add(e)
    db.commit()
    return {"id": e.id, "status": "added"}

# ── AI INSIGHTS ───────────────────────────────────────────────────
@router.post("/ai-insights")
def ai_insights(token: str = Depends(tok), db: Session = Depends(get_db)):
    admin(token, db)
    total   = db.query(Hunter).filter(Hunter.role == "hunter").count()
    certs   = db.query(Hunter).filter(Hunter.certified == True).count()
    bounties= db.query(Bounty).filter(Bounty.status == "verified").all()
    revenue = sum(b.platform_fee for b in bounties)
    stats   = {"total_hunters": total, "certified": certs, "total_revenue_usd": revenue, "bounties": len(bounties)}
    return {"insights": ai.admin_insights(stats)}
