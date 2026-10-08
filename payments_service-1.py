"""
Payment Service
M-Pesa STK Push  → fee goes to Larry's number +254 790 091 529
PayPal           → fee goes to cybersafari54@gmail.com
Bitcoin          → fee goes to Larry's BTC wallet address
"""
import os, httpx, base64, hashlib
from datetime import datetime
from sqlalchemy.orm import Session
from database import Payment, Bounty, Hunter, generate_id

PLATFORM_FEE    = 0.10                # 10%
ADMIN_MPESA     = os.getenv("ADMIN_MPESA_NUMBER",  "254790091529")   # Larry's number
ADMIN_PAYPAL    = os.getenv("ADMIN_PAYPAL_EMAIL",  "cybersafari54@gmail.com")
ADMIN_BTC       = os.getenv("ADMIN_BTC_ADDRESS",   "")               # Set your BTC address
USD_TO_KES      = 130                 # approximate rate, update live in production

def calculate_fee(amount_usd: float) -> dict:
    fee    = round(amount_usd * PLATFORM_FEE, 2)
    keeps  = round(amount_usd - fee, 2)
    fee_kes= round(fee * USD_TO_KES, 0)
    return {
        "bounty_usd":   amount_usd,
        "platform_fee_usd": fee,
        "platform_fee_kes": int(fee_kes),
        "hunter_keeps_usd": keeps,
        "fee_percent":  10,
        "admin_mpesa":  ADMIN_MPESA,
        "admin_paypal": ADMIN_PAYPAL,
        "admin_btc":    ADMIN_BTC,
    }

# ═══════════════════════════════════════════════════════════════════
# M-PESA STK PUSH
# ═══════════════════════════════════════════════════════════════════
class MPesa:
    def __init__(self):
        self.consumer_key    = os.getenv("MPESA_CONSUMER_KEY", "")
        self.consumer_secret = os.getenv("MPESA_CONSUMER_SECRET", "")
        self.shortcode       = os.getenv("MPESA_SHORTCODE", "")
        self.passkey         = os.getenv("MPESA_PASSKEY", "")
        self.callback_url    = os.getenv("MPESA_CALLBACK_URL", "")
        # Use sandbox for testing, switch to api.safaricom.co.ke for production
        self.base            = "https://sandbox.safaricom.co.ke"

    def _token(self) -> str:
        creds = base64.b64encode(f"{self.consumer_key}:{self.consumer_secret}".encode()).decode()
        r = httpx.get(
            f"{self.base}/oauth/v1/generate?grant_type=client_credentials",
            headers={"Authorization": f"Basic {creds}"},
            timeout=10
        )
        return r.json().get("access_token", "")

    def stk_push(self, hunter_phone: str, amount_kes: int, bounty_id: str) -> dict:
        """
        Send STK push to hunter's phone.
        Hunter enters their PIN → payment goes to Larry's number.
        """
        if not self.consumer_key:
            return {"error": "M-Pesa not configured. Contact admin."}

        token     = self._token()
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        password  = base64.b64encode(
            f"{self.shortcode}{self.passkey}{timestamp}".encode()
        ).decode()

        # Normalize phone: 0712345678 → 254712345678
        phone = hunter_phone.strip().replace("+", "").replace(" ", "")
        if phone.startswith("0"):
            phone = "254" + phone[1:]

        payload = {
            "BusinessShortCode": self.shortcode,
            "Password":          password,
            "Timestamp":         timestamp,
            "TransactionType":   "CustomerPayBillOnline",
            "Amount":            amount_kes,
            "PartyA":            phone,           # hunter pays from this number
            "PartyB":            ADMIN_MPESA,     # goes to Larry's number
            "PhoneNumber":       phone,
            "CallBackURL":       self.callback_url,
            "AccountReference":  f"ApexSafari-{bounty_id[:8]}",
            "TransactionDesc":   "Apex Safari Platform Fee",
        }

        try:
            r = httpx.post(
                f"{self.base}/mpesa/stkpush/v1/processrequest",
                json=payload,
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                timeout=15
            )
            data = r.json()
            if data.get("ResponseCode") == "0":
                return {
                    "success":      True,
                    "checkout_id":  data.get("CheckoutRequestID"),
                    "message":      f"STK push sent to {phone}. Check your phone to enter PIN.",
                }
            return {"error": data.get("errorMessage", "M-Pesa request failed.")}
        except Exception as e:
            return {"error": f"M-Pesa error: {str(e)}"}

    def handle_callback(self, db: Session, data: dict) -> dict:
        """Called by Safaricom when payment completes"""
        try:
            cb = data.get("Body", {}).get("stkCallback", {})
            if cb.get("ResultCode") == 0:
                items  = {i["Name"]: i.get("Value") for i in cb.get("CallbackMetadata", {}).get("Item", [])}
                receipt= items.get("MpesaReceiptNumber", "")
                amount = items.get("Amount", 0)
                phone  = str(items.get("PhoneNumber", ""))
                checkout_id = cb.get("CheckoutRequestID", "")

                # Find matching payment and confirm it
                payment = db.query(Payment).filter(
                    Payment.tx_id == checkout_id,
                    Payment.status == "pending"
                ).first()

                if payment:
                    payment.status       = "confirmed"
                    payment.mpesa_receipt= receipt
                    payment.confirmed_at = datetime.utcnow()
                    # Mark bounty fee as paid
                    if payment.bounty_id:
                        bounty = db.query(Bounty).filter(Bounty.id == payment.bounty_id).first()
                        if bounty:
                            bounty.fee_paid  = True
                            bounty.fee_tx_id = receipt
                    db.commit()
                    return {"success": True, "receipt": receipt}

            return {"success": False, "code": cb.get("ResultCode")}
        except Exception as e:
            return {"error": str(e)}

# ═══════════════════════════════════════════════════════════════════
# PAYPAL
# ═══════════════════════════════════════════════════════════════════
class PayPal:
    def __init__(self):
        self.client_id     = os.getenv("PAYPAL_CLIENT_ID", "")
        self.client_secret = os.getenv("PAYPAL_CLIENT_SECRET", "")
        self.mode          = os.getenv("PAYPAL_MODE", "sandbox")
        self.base          = "https://api-m.sandbox.paypal.com" if self.mode == "sandbox" else "https://api-m.paypal.com"

    def _token(self) -> str:
        r = httpx.post(
            f"{self.base}/v1/oauth2/token",
            data={"grant_type": "client_credentials"},
            auth=(self.client_id, self.client_secret),
            timeout=10
        )
        return r.json().get("access_token", "")

    def create_order(self, amount_usd: float, bounty_id: str) -> dict:
        """Create a PayPal order for the platform fee"""
        if not self.client_id:
            return {"error": "PayPal not configured. Contact admin."}
        try:
            token = self._token()
            r = httpx.post(
                f"{self.base}/v2/checkout/orders",
                json={
                    "intent": "CAPTURE",
                    "purchase_units": [{
                        "amount":      {"currency_code": "USD", "value": str(round(amount_usd, 2))},
                        "description": f"Apex Safari Platform Fee - {bounty_id[:8]}",
                        "payee":       {"email_address": ADMIN_PAYPAL},
                    }],
                },
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                timeout=15
            )
            data = r.json()
            order_id    = data.get("id")
            approve_url = next((l["href"] for l in data.get("links", []) if l["rel"] == "approve"), None)
            return {"order_id": order_id, "approve_url": approve_url, "success": True}
        except Exception as e:
            return {"error": str(e)}

    def capture_order(self, db: Session, order_id: str, bounty_id: str) -> dict:
        """Capture (confirm) a PayPal payment after hunter approves"""
        if not self.client_id:
            return {"error": "PayPal not configured."}
        try:
            token = self._token()
            r = httpx.post(
                f"{self.base}/v2/checkout/orders/{order_id}/capture",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                timeout=15
            )
            data = r.json()
            if data.get("status") == "COMPLETED":
                # Mark bounty fee as paid
                bounty = db.query(Bounty).filter(Bounty.id == bounty_id).first()
                if bounty:
                    bounty.fee_paid  = True
                    bounty.fee_tx_id = order_id
                    db.commit()
                return {"success": True, "order_id": order_id, "status": "COMPLETED"}
            return {"error": "Payment not completed.", "status": data.get("status")}
        except Exception as e:
            return {"error": str(e)}

# ═══════════════════════════════════════════════════════════════════
# BITCOIN
# ═══════════════════════════════════════════════════════════════════
class Bitcoin:
    def __init__(self):
        self.wallet_address = ADMIN_BTC
        # Using Blockstream API (free, no key needed) to check transactions
        self.api = "https://blockstream.info/api"

    def get_payment_details(self, amount_usd: float, bounty_id: str) -> dict:
        """Return BTC address and expected amount for hunter to pay"""
        if not self.wallet_address:
            return {"error": "Bitcoin wallet not configured. Contact admin."}

        # Get live BTC price
        try:
            r = httpx.get("https://api.coindesk.com/v1/bpi/currentprice/USD.json", timeout=5)
            btc_price = r.json()["bpi"]["USD"]["rate_float"]
            btc_amount= round(amount_usd / btc_price, 8)
        except:
            btc_amount = round(amount_usd / 65000, 8)  # fallback estimate

        return {
            "success":     True,
            "btc_address": self.wallet_address,
            "btc_amount":  btc_amount,
            "usd_amount":  amount_usd,
            "reference":   f"APEX-{bounty_id[:8].upper()}",
            "instructions": [
                f"Send exactly {btc_amount} BTC to the address below",
                "Include the reference code in the transaction memo if possible",
                "Confirmation takes 10-30 minutes (1 blockchain confirmation required)",
                "Your account will be credited automatically once confirmed",
            ],
            "qr_data": f"bitcoin:{self.wallet_address}?amount={btc_amount}&label=ApexSafari-Fee",
        }

    def verify_payment(self, db: Session, tx_hash: str, bounty_id: str, expected_btc: float) -> dict:
        """Check if a BTC transaction has been confirmed"""
        try:
            r = httpx.get(f"{self.api}/tx/{tx_hash}", timeout=10)
            if r.status_code != 200:
                return {"error": "Transaction not found. Check the transaction hash."}

            tx     = r.json()
            status = tx.get("status", {})
            confirmed = status.get("confirmed", False)

            if not confirmed:
                return {"pending": True, "message": "Transaction found but not yet confirmed. Check back in a few minutes."}

            # Check if payment went to our wallet
            outputs = tx.get("vout", [])
            paid    = any(o.get("scriptpubkey_address") == self.wallet_address for o in outputs)

            if not paid:
                return {"error": "Transaction does not send funds to the correct wallet address."}

            # Confirm in database
            bounty = db.query(Bounty).filter(Bounty.id == bounty_id).first()
            if bounty:
                bounty.fee_paid  = True
                bounty.fee_tx_id = tx_hash
                # Record payment
                db.add(Payment(
                    id=generate_id(), hunter_id=bounty.hunter_id, bounty_id=bounty_id,
                    method="bitcoin", amount_usd=bounty.platform_fee,
                    status="confirmed", btc_txhash=tx_hash,
                    confirmed_at=datetime.utcnow()
                ))
                db.commit()
            return {"success": True, "confirmed": True, "tx_hash": tx_hash}

        except Exception as e:
            return {"error": str(e)}

# ── Singleton instances ────────────────────────────────────────────
mpesa   = MPesa()
paypal  = PayPal()
bitcoin = Bitcoin()
