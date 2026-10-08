from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from models.database import get_db, Bounty, Payment, Hunter, generate_id
from services.auth import get_current, require_admin
from services.payments import mpesa, paypal, bitcoin, calculate_fee
from datetime import datetime

router   = APIRouter(prefix="/payments", tags=["payments"])
security = HTTPBearer()

def tok(c: HTTPAuthorizationCredentials = Depends(security)):
    return c.credentials

def auth(token: str, db: Session):
    h = get_current(db, token)
    if not h: raise HTTPException(401, "Unauthorized.")
    return h

# ── CALCULATE FEE ─────────────────────────────────────────────────
@router.get("/calculate-fee/{amount_usd}")
def calc_fee(amount_usd: float, token: str = Depends(tok), db: Session = Depends(get_db)):
    auth(token, db)
    return calculate_fee(amount_usd)

# ── REPORT BOUNTY ─────────────────────────────────────────────────
class BountyReq(BaseModel):
    program:  str
    platform: str
    amount:   float
    method:   str  # mpesa | paypal | bitcoin

@router.post("/report-bounty")
def report_bounty(req: BountyReq, token: str = Depends(tok), db: Session = Depends(get_db)):
    h = auth(token, db)
    fee   = calculate_fee(req.amount)
    b     = Bounty(
        id             = generate_id(),
        hunter_id      = h.id,
        program_name   = req.program,
        platform       = req.platform,
        amount_usd     = req.amount,
        platform_fee   = fee["platform_fee_usd"],
        hunter_keeps   = fee["hunter_keeps_usd"],
        payment_method = req.method,
        status         = "pending",
    )
    db.add(b)
    db.commit()
    return {
        "bounty_id": b.id,
        "fee":       fee,
        "message":   "Bounty recorded. Pay the platform fee to unlock your account.",
    }

# ═══════════════════════════════════════════════════════════════════
# M-PESA
# ═══════════════════════════════════════════════════════════════════
class MPesaReq(BaseModel):
    bounty_id: str
    phone:     str  # hunter's M-Pesa number e.g. 0712345678

@router.post("/mpesa/pay")
def mpesa_pay(req: MPesaReq, token: str = Depends(tok), db: Session = Depends(get_db)):
    """
    Hunter enters their M-Pesa number.
    Platform sends STK push to their phone.
    Hunter enters PIN → fee arrives in Larry's number +254 790 091 529.
    """
    h      = auth(token, db)
    bounty = db.query(Bounty).filter(Bounty.id == req.bounty_id, Bounty.hunter_id == h.id).first()
    if not bounty:
        raise HTTPException(404, "Bounty not found.")
    if bounty.fee_paid:
        raise HTTPException(400, "Fee already paid for this bounty.")

    fee_kes = calculate_fee(bounty.amount_usd)["platform_fee_kes"]

    # Send STK push
    result = mpesa.stk_push(req.phone, fee_kes, bounty.id)
    if "error" in result:
        raise HTTPException(400, result["error"])

    # Record pending payment
    pmt = Payment(
        id        = generate_id(),
        hunter_id = h.id,
        bounty_id = bounty.id,
        method    = "mpesa",
        amount_usd= bounty.platform_fee,
        amount_local= fee_kes,
        currency  = "KES",
        status    = "pending",
        tx_id     = result.get("checkout_id"),
    )
    db.add(pmt)
    db.commit()

    return {
        "success": True,
        "message": result.get("message", f"STK push sent to {req.phone}. Enter your M-Pesa PIN to pay KES {fee_kes:,.0f}."),
        "checkout_id": result.get("checkout_id"),
        "amount_kes": fee_kes,
        "goes_to": "Apex Safari (+254 790 091 529)",
    }

@router.post("/mpesa/callback")
async def mpesa_callback(request: Request, db: Session = Depends(get_db)):
    """Safaricom calls this URL when payment is complete"""
    data   = await request.json()
    result = mpesa.handle_callback(db, data)
    return {"ResultCode": 0, "ResultDesc": "Accepted"}

@router.get("/mpesa/status/{checkout_id}")
def mpesa_status(checkout_id: str, token: str = Depends(tok), db: Session = Depends(get_db)):
    """Poll payment status"""
    auth(token, db)
    pmt = db.query(Payment).filter(Payment.tx_id == checkout_id).first()
    if not pmt:
        raise HTTPException(404, "Payment not found.")
    return {"status": pmt.status, "receipt": pmt.mpesa_receipt}

# ═══════════════════════════════════════════════════════════════════
# PAYPAL
# ═══════════════════════════════════════════════════════════════════
class PayPalReq(BaseModel):
    bounty_id: str

@router.post("/paypal/create-order")
def paypal_create(req: PayPalReq, token: str = Depends(tok), db: Session = Depends(get_db)):
    """Create PayPal order — returns approval URL for hunter to pay"""
    h      = auth(token, db)
    bounty = db.query(Bounty).filter(Bounty.id == req.bounty_id, Bounty.hunter_id == h.id).first()
    if not bounty:
        raise HTTPException(404, "Bounty not found.")
    if bounty.fee_paid:
        raise HTTPException(400, "Fee already paid.")

    result = paypal.create_order(bounty.platform_fee, bounty.id)
    if "error" in result:
        raise HTTPException(400, result["error"])

    # Record pending payment
    pmt = Payment(
        id        = generate_id(),
        hunter_id = h.id,
        bounty_id = bounty.id,
        method    = "paypal",
        amount_usd= bounty.platform_fee,
        currency  = "USD",
        status    = "pending",
        paypal_order = result.get("order_id"),
    )
    db.add(pmt)
    db.commit()

    return {
        "order_id":    result["order_id"],
        "approve_url": result["approve_url"],
        "amount_usd":  bounty.platform_fee,
        "goes_to":     "cybersafari54@gmail.com",
    }

class PayPalCaptureReq(BaseModel):
    order_id:  str
    bounty_id: str

@router.post("/paypal/capture")
def paypal_capture(req: PayPalCaptureReq, token: str = Depends(tok), db: Session = Depends(get_db)):
    """Capture (confirm) PayPal payment after hunter approves"""
    auth(token, db)
    result = paypal.capture_order(db, req.order_id, req.bounty_id)
    if "error" in result:
        raise HTTPException(400, result["error"])

    # Update payment record
    pmt = db.query(Payment).filter(Payment.paypal_order == req.order_id).first()
    if pmt:
        pmt.status       = "confirmed"
        pmt.confirmed_at = datetime.utcnow()
        db.commit()

    return {"success": True, "message": "Payment confirmed. Your bounty is now verified."}

# ═══════════════════════════════════════════════════════════════════
# BITCOIN
# ═══════════════════════════════════════════════════════════════════
class BitcoinReq(BaseModel):
    bounty_id: str

@router.post("/bitcoin/get-address")
def bitcoin_address(req: BitcoinReq, token: str = Depends(tok), db: Session = Depends(get_db)):
    """Return BTC address + amount for hunter to send payment"""
    h      = auth(token, db)
    bounty = db.query(Bounty).filter(Bounty.id == req.bounty_id, Bounty.hunter_id == h.id).first()
    if not bounty:
        raise HTTPException(404, "Bounty not found.")
    if bounty.fee_paid:
        raise HTTPException(400, "Fee already paid.")

    result = bitcoin.get_payment_details(bounty.platform_fee, bounty.id)
    if "error" in result:
        raise HTTPException(400, result["error"])

    # Record pending payment
    pmt = Payment(
        id         = generate_id(),
        hunter_id  = h.id,
        bounty_id  = bounty.id,
        method     = "bitcoin",
        amount_usd = bounty.platform_fee,
        amount_local= result.get("btc_amount"),
        currency   = "BTC",
        status     = "pending",
    )
    db.add(pmt)
    db.commit()

    return result

class BitcoinVerifyReq(BaseModel):
    tx_hash:   str
    bounty_id: str

@router.post("/bitcoin/verify")
def bitcoin_verify(req: BitcoinVerifyReq, token: str = Depends(tok), db: Session = Depends(get_db)):
    """Hunter submits their BTC tx hash — backend verifies on blockchain"""
    h      = auth(token, db)
    bounty = db.query(Bounty).filter(Bounty.id == req.bounty_id, Bounty.hunter_id == h.id).first()
    if not bounty:
        raise HTTPException(404, "Bounty not found.")

    result = bitcoin.verify_payment(db, req.tx_hash, req.bounty_id, bounty.platform_fee)
    if "error" in result:
        raise HTTPException(400, result["error"])

    return result

# ── PAYMENT HISTORY ───────────────────────────────────────────────
@router.get("/history")
def payment_history(token: str = Depends(tok), db: Session = Depends(get_db)):
    h       = auth(token, db)
    bounties= db.query(Bounty).filter(Bounty.hunter_id == h.id).order_by(Bounty.created_at.desc()).all()
    return [{
        "id":       b.id,
        "program":  b.program_name,
        "platform": b.platform,
        "amount":   b.amount_usd,
        "fee":      b.platform_fee,
        "keeps":    b.hunter_keeps,
        "method":   b.payment_method,
        "fee_paid": b.fee_paid,
        "status":   b.status,
        "date":     b.created_at.isoformat(),
    } for b in bounties]
