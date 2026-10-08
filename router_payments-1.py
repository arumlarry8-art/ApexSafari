from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from database import get_db, Bounty, Payment, Hunter, generate_id
from auth_service import get_current
from payments_service import mpesa, paypal, bitcoin, calculate_fee
from datetime import datetime

router   = APIRouter(prefix="/payments", tags=["payments"])
security = HTTPBearer()

def tok(c: HTTPAuthorizationCredentials = Depends(security)): return c.credentials
def auth(token, db):
    h = get_current(db, token)
    if not h: raise HTTPException(401, "Unauthorized.")
    return h

@router.get("/calculate-fee/{amount_usd}")
def calc_fee(amount_usd: float, token: str=Depends(tok), db: Session=Depends(get_db)):
    auth(token, db)
    return calculate_fee(amount_usd)

class BountyReq(BaseModel):
    program: str; platform: str; amount: float; method: str

@router.post("/report-bounty")
def report_bounty(req: BountyReq, token: str=Depends(tok), db: Session=Depends(get_db)):
    h   = auth(token, db)
    fee = calculate_fee(req.amount)
    b   = Bounty(id=generate_id(),hunter_id=h.id,program_name=req.program,platform=req.platform,
                 amount_usd=req.amount,platform_fee=fee["platform_fee_usd"],
                 hunter_keeps=fee["hunter_keeps_usd"],payment_method=req.method,status="pending")
    db.add(b); db.commit()
    return {"bounty_id":b.id,"fee":fee,"message":"Bounty recorded. Pay the platform fee to unlock."}

# ── M-PESA STK PUSH ───────────────────────────────────────────────
class MPesaReq(BaseModel):
    bounty_id: str
    phone:     str   # hunter's number e.g. 0712345678

@router.post("/mpesa/pay")
def mpesa_pay(req: MPesaReq, token: str=Depends(tok), db: Session=Depends(get_db)):
    """
    Hunter enters their M-Pesa number.
    STK push sent to their phone → they enter PIN.
    Fee arrives in +254 790 091 529 (Larry).
    """
    h = auth(token, db)
    b = db.query(Bounty).filter(Bounty.id==req.bounty_id, Bounty.hunter_id==h.id).first()
    if not b: raise HTTPException(404, "Bounty not found.")
    if b.fee_paid: raise HTTPException(400, "Fee already paid.")
    fee_kes = calculate_fee(b.amount_usd)["platform_fee_kes"]
    result  = mpesa.stk_push(req.phone, fee_kes, b.id)
    if "error" in result: raise HTTPException(400, result["error"])
    pmt = Payment(id=generate_id(),hunter_id=h.id,bounty_id=b.id,method="mpesa",
                  amount_usd=b.platform_fee,amount_local=fee_kes,currency="KES",
                  status="pending",tx_id=result.get("checkout_id"))
    db.add(pmt); db.commit()
    return {"success":True,"message":result.get("message",f"STK push sent to {req.phone}. Enter your PIN."),"amount_kes":fee_kes,"goes_to":"+254 790 091 529"}

@router.post("/mpesa/callback")
async def mpesa_callback(request: Request, db: Session=Depends(get_db)):
    data   = await request.json()
    result = mpesa.handle_callback(db, data)
    return {"ResultCode":0,"ResultDesc":"Accepted"}

@router.get("/mpesa/status/{checkout_id}")
def mpesa_status(checkout_id: str, token: str=Depends(tok), db: Session=Depends(get_db)):
    auth(token, db)
    pmt = db.query(Payment).filter(Payment.tx_id==checkout_id).first()
    if not pmt: raise HTTPException(404, "Payment not found.")
    return {"status":pmt.status,"receipt":pmt.mpesa_receipt}

# ── PAYPAL ────────────────────────────────────────────────────────
class PayPalReq(BaseModel):
    bounty_id: str

@router.post("/paypal/create-order")
def paypal_create(req: PayPalReq, token: str=Depends(tok), db: Session=Depends(get_db)):
    h = auth(token, db)
    b = db.query(Bounty).filter(Bounty.id==req.bounty_id, Bounty.hunter_id==h.id).first()
    if not b: raise HTTPException(404, "Bounty not found.")
    if b.fee_paid: raise HTTPException(400, "Fee already paid.")
    result = paypal.create_order(b.platform_fee, b.id)
    if "error" in result: raise HTTPException(400, result["error"])
    pmt = Payment(id=generate_id(),hunter_id=h.id,bounty_id=b.id,method="paypal",
                  amount_usd=b.platform_fee,currency="USD",status="pending",paypal_order=result.get("order_id"))
    db.add(pmt); db.commit()
    return {"order_id":result["order_id"],"approve_url":result["approve_url"],"amount_usd":b.platform_fee,"goes_to":"cybersafari54@gmail.com"}

class PayPalCaptureReq(BaseModel):
    order_id: str; bounty_id: str

@router.post("/paypal/capture")
def paypal_capture(req: PayPalCaptureReq, token: str=Depends(tok), db: Session=Depends(get_db)):
    auth(token, db)
    result = paypal.capture_order(db, req.order_id, req.bounty_id)
    if "error" in result: raise HTTPException(400, result["error"])
    pmt = db.query(Payment).filter(Payment.paypal_order==req.order_id).first()
    if pmt: pmt.status="confirmed"; pmt.confirmed_at=datetime.utcnow(); db.commit()
    return {"success":True,"message":"PayPal payment confirmed."}

# ── BITCOIN ───────────────────────────────────────────────────────
class BTCReq(BaseModel):
    bounty_id: str

@router.post("/bitcoin/get-address")
def btc_address(req: BTCReq, token: str=Depends(tok), db: Session=Depends(get_db)):
    h = auth(token, db)
    b = db.query(Bounty).filter(Bounty.id==req.bounty_id, Bounty.hunter_id==h.id).first()
    if not b: raise HTTPException(404, "Bounty not found.")
    if b.fee_paid: raise HTTPException(400, "Fee already paid.")
    result = bitcoin.get_payment_details(b.platform_fee, b.id)
    if "error" in result: raise HTTPException(400, result["error"])
    pmt = Payment(id=generate_id(),hunter_id=h.id,bounty_id=b.id,method="bitcoin",
                  amount_usd=b.platform_fee,amount_local=result.get("btc_amount"),currency="BTC",status="pending")
    db.add(pmt); db.commit()
    return result

class BTCVerifyReq(BaseModel):
    tx_hash: str; bounty_id: str

@router.post("/bitcoin/verify")
def btc_verify(req: BTCVerifyReq, token: str=Depends(tok), db: Session=Depends(get_db)):
    h = auth(token, db)
    b = db.query(Bounty).filter(Bounty.id==req.bounty_id, Bounty.hunter_id==h.id).first()
    if not b: raise HTTPException(404, "Bounty not found.")
    result = bitcoin.verify_payment(db, req.tx_hash, req.bounty_id, b.platform_fee)
    if "error" in result: raise HTTPException(400, result["error"])
    return result

@router.get("/history")
def history(token: str=Depends(tok), db: Session=Depends(get_db)):
    h = auth(token, db)
    return [{"id":b.id,"program":b.program_name,"platform":b.platform,"amount":b.amount_usd,"fee":b.platform_fee,"keeps":b.hunter_keeps,"method":b.payment_method,"fee_paid":b.fee_paid,"status":b.status,"date":b.created_at.isoformat()} for b in db.query(Bounty).filter(Bounty.hunter_id==h.id).order_by(Bounty.created_at.desc()).all()]
