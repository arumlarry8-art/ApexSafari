from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from database import get_db, Hunter, Post, HallOfFame, Bounty, generate_id
from auth_service import get_current
from datetime import datetime

router   = APIRouter(prefix="/hunters", tags=["hunters"])
security = HTTPBearer()

def tok(c: HTTPAuthorizationCredentials = Depends(security)): return c.credentials
def auth(token, db):
    h = get_current(db, token)
    if not h: raise HTTPException(401, "Unauthorized.")
    return h

@router.get("/leaderboard")
def leaderboard(limit: int = 50, db: Session = Depends(get_db)):
    hunters = db.query(Hunter).filter(Hunter.role=="hunter", Hunter.banned==False).order_by(Hunter.earnings.desc()).limit(limit).all()
    return [{"rank":h.rank,"username":h.username,"country":h.country,"earnings":h.earnings,"bugs":h.bugs_found,"certified":h.certified,"level":h.level} for h in hunters]

@router.get("/stats")
def stats(db: Session = Depends(get_db)):
    total     = db.query(Hunter).filter(Hunter.role=="hunter").count()
    certified = db.query(Hunter).filter(Hunter.certified==True).count()
    countries = db.query(Hunter.country).distinct().count()
    bounties  = db.query(Bounty).filter(Bounty.status=="verified").all()
    total_paid= sum(b.amount_usd for b in bounties)
    avg       = round(total_paid/len(bounties),2) if bounties else 0
    return {"total_hunters":total,"certified":certified,"countries":countries,"total_bounties_paid":f"${total_paid:,.0f}","average_payout":f"${avg:,.0f}"}

@router.get("/profile/{username}")
def profile(username: str, db: Session = Depends(get_db)):
    h = db.query(Hunter).filter(Hunter.username==username, Hunter.banned==False).first()
    if not h: raise HTTPException(404, "Hunter not found.")
    return {"username":h.username,"country":h.country,"level":h.level,"certified":h.certified,"rank":h.rank,"earnings":h.earnings,"bugs":h.bugs_found,"joined":h.created_at.isoformat()}

class UpdateReq(BaseModel):
    country:      Optional[str] = None
    level:        Optional[str] = None
    mpesa_number: Optional[str] = None
    btc_address:  Optional[str] = None

@router.patch("/profile")
def update_profile(req: UpdateReq, token: str = Depends(tok), db: Session = Depends(get_db)):
    h = auth(token, db)
    if req.country:      h.country      = req.country
    if req.level:        h.level        = req.level
    if req.mpesa_number: h.mpesa_number = req.mpesa_number
    if req.btc_address:  h.btc_address  = req.btc_address
    db.commit()
    return {"message": "Profile updated."}

@router.get("/posts")
def get_posts(limit: int = 50, db: Session = Depends(get_db)):
    posts = db.query(Post).order_by(Post.pinned.desc(), Post.created_at.desc()).limit(limit).all()
    return [{"id":p.id,"hunter":p.hunter.username if p.hunter else "Unknown","country":p.hunter.country if p.hunter else "","content":p.content,"category":p.category,"likes":p.likes,"pinned":p.pinned,"time":p.created_at.isoformat()} for p in posts]

class PostReq(BaseModel):
    content:  str
    category: Optional[str] = "General"

@router.post("/posts")
def create_post(req: PostReq, token: str = Depends(tok), db: Session = Depends(get_db)):
    h = auth(token, db)
    if not h.certified: raise HTTPException(403, "Only certified hunters can post.")
    p = Post(id=generate_id(), hunter_id=h.id, content=req.content, category=req.category)
    db.add(p); db.commit()
    return {"id": p.id, "status": "posted"}

@router.post("/posts/{post_id}/like")
def like_post(post_id: str, token: str = Depends(tok), db: Session = Depends(get_db)):
    auth(token, db)
    p = db.query(Post).filter(Post.id==post_id).first()
    if not p: raise HTTPException(404, "Post not found.")
    p.likes += 1; db.commit()
    return {"likes": p.likes}

@router.get("/hall-of-fame")
def hall_of_fame(db: Session = Depends(get_db)):
    entries = db.query(HallOfFame).order_by(HallOfFame.bounty_usd.desc()).limit(20).all()
    return [{"hunter_id":e.hunter_id,"finding":e.finding,"bounty":e.bounty_usd,"category":e.category,"date":e.created_at.isoformat()} for e in entries]
