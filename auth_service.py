"""
Auth Service — JWT tokens + bcrypt passwords
All credentials stay on the server
"""
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from database import Hunter, SecurityEvent, generate_id
import os, resend

SECRET_KEY  = os.getenv("SECRET_KEY", "change-this-in-production")
ALGORITHM   = "HS256"
EXPIRE_MINS = 1440  # 24 hours

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ── EMAIL ─────────────────────────────────────────────────────────
resend.api_key = os.getenv("RESEND_API_KEY", "")
ADMIN_EMAIL    = os.getenv("ADMIN_EMAIL", "cybersafari54@gmail.com")

def send_email(to: str, subject: str, body: str):
    """Send email via Resend (free 3000/month)"""
    try:
        if resend.api_key:
            resend.Emails.send({
                "from":    "Apex Safari <noreply@apexsafari.io>",
                "to":      [to],
                "subject": subject,
                "html":    body,
            })
    except Exception as e:
        print(f"Email error: {e}")

# ── PASSWORD ──────────────────────────────────────────────────────
def hash_password(plain: str) -> str:
    return pwd.hash(plain)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd.verify(plain, hashed)

# ── JWT ───────────────────────────────────────────────────────────
def create_token(data: dict, expires_minutes: int = EXPIRE_MINS) -> str:
    payload = {**data, "exp": datetime.utcnow() + timedelta(minutes=expires_minutes)}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None

# ── REGISTER ──────────────────────────────────────────────────────
def register(db: Session, email: str, password: str, username: str, country: str, level: str) -> dict:
    if db.query(Hunter).filter(Hunter.email == email).first():
        return {"error": "Email already registered."}
    if db.query(Hunter).filter(Hunter.username == username).first():
        return {"error": "Username already taken."}
    if len(password) < 8:
        return {"error": "Password must be at least 8 characters."}

    h = Hunter(
        id            = generate_id(),
        username      = username,
        email         = email,
        password_hash = hash_password(password),
        country       = country or "Unknown",
        level         = level   or "beginner",
    )
    db.add(h)
    db.commit()
    db.refresh(h)

    # Welcome email
    send_email(email, "Welcome to Apex Safari!", f"""
    <h2>Welcome to Apex Safari, {username}!</h2>
    <p>You have joined the elite bug bounty intelligence platform by Safari Intelligence.</p>
    <p>Next step: take the AI Entry Test to get certified and unlock full platform access.</p>
    <p>Good luck hunting.</p>
    <br><p>— Larry Phillip Ochieng, CEO, Safari Intelligence</p>
    """)

    token = create_token({"sub": h.id, "role": "hunter", "email": email})
    return {"token": token, "hunter": _to_dict(h)}

# ── LOGIN ─────────────────────────────────────────────────────────
def login(db: Session, email: str, password: str, ip: str = "") -> dict:
    h = db.query(Hunter).filter(Hunter.email == email).first()

    if not h or not verify_password(password, h.password_hash):
        log_event(db, "login_failed", "warning", ip, details=f"Failed login: {email}")
        return {"error": "Incorrect email or password."}

    if h.banned:
        return {"error": f"Account suspended: {h.ban_reason or 'Contact support.'}"}

    # Admin requires 2FA
    if h.role == "admin":
        temp = create_token({"sub": h.id, "role": "admin", "email": email, "needs_2fa": True}, expires_minutes=10)
        # Generate OTP and send to admin email
        import random
        otp = str(random.randint(100000, 999999))
        # Store OTP temporarily in token metadata (or use Redis in production)
        full_temp = create_token({"sub": h.id, "role": "admin", "email": email, "needs_2fa": True, "otp": otp}, expires_minutes=5)
        send_email(email, "Apex Safari Admin Login Code", f"""
        <h2>Admin Login Verification</h2>
        <p>Your one-time login code is:</p>
        <h1 style="color:#F0A500;letter-spacing:8px;font-size:36px">{otp}</h1>
        <p>Valid for 5 minutes. Do not share this code.</p>
        """)
        log_event(db, "admin_login_otp_sent", "info", ip, hunter_id=h.id, details="OTP sent to admin email")
        return {"requires_2fa": True, "temp_token": full_temp, "message": "OTP sent to your email"}

    h.last_seen = datetime.utcnow()
    db.commit()
    log_event(db, "login_success", "success", ip, hunter_id=h.id)
    token = create_token({"sub": h.id, "role": h.role, "email": email})
    return {"token": token, "hunter": _to_dict(h)}

# ── ADMIN 2FA ─────────────────────────────────────────────────────
def verify_2fa(db: Session, temp_token: str, code: str, ip: str = "") -> dict:
    payload = decode_token(temp_token)
    if not payload or not payload.get("needs_2fa"):
        return {"error": "Invalid or expired session."}

    stored_otp = payload.get("otp", "")
    if code != stored_otp:
        log_event(db, "admin_2fa_failed", "warning", ip, details="Wrong OTP entered")
        return {"error": "Invalid code. Please try again."}

    h = db.query(Hunter).filter(Hunter.id == payload["sub"]).first()
    if not h:
        return {"error": "Account not found."}

    h.last_seen = datetime.utcnow()
    db.commit()
    log_event(db, "admin_login_success", "success", ip, hunter_id=h.id)
    token = create_token({"sub": h.id, "role": "admin", "email": h.email})
    return {"token": token, "hunter": _to_dict(h)}

# ── GET CURRENT HUNTER ────────────────────────────────────────────
def get_current(db: Session, token: str) -> Hunter | None:
    payload = decode_token(token)
    if not payload or payload.get("needs_2fa"):
        return None
    return db.query(Hunter).filter(Hunter.id == payload.get("sub")).first()

def require_admin(db: Session, token: str) -> Hunter | None:
    h = get_current(db, token)
    return h if h and h.role == "admin" else None

# ── HELPERS ───────────────────────────────────────────────────────
def _to_dict(h: Hunter) -> dict:
    return {
        "id":           h.id,
        "username":     h.username,
        "email":        h.email,
        "country":      h.country,
        "level":        h.level,
        "role":         h.role,
        "certified":    h.certified,
        "rank":         h.rank,
        "earnings":     h.earnings,
        "bugs_found":   h.bugs_found,
        "test_passed":  h.test_passed,
        "test_score":   h.test_score,
        "test_attempts":h.test_attempts,
        "subscription": h.subscription,
        "created_at":   h.created_at.isoformat(),
        "last_seen":    h.last_seen.isoformat(),
    }

def log_event(db, event_type, severity, ip="", hunter_id=None, details=""):
    db.add(SecurityEvent(
        id=generate_id(), event_type=event_type, severity=severity,
        ip_address=ip, hunter_id=hunter_id, details=details
    ))
    db.commit()
