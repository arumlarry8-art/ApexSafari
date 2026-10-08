from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from typing import Optional
from models.database import get_db
from services.auth import register, login, verify_2fa, get_current, _to_dict

router   = APIRouter(prefix="/auth", tags=["auth"])
security = HTTPBearer()

def token(c: HTTPAuthorizationCredentials = Depends(security)):
    return c.credentials

class RegisterReq(BaseModel):
    email:    EmailStr
    password: str
    username: str
    country:  Optional[str] = "Unknown"
    level:    Optional[str] = "beginner"

class LoginReq(BaseModel):
    email:    EmailStr
    password: str

class TwoFAReq(BaseModel):
    temp_token: str
    code:       str

@router.post("/register")
def do_register(req: RegisterReq, request: Request, db: Session = Depends(get_db)):
    result = register(db, req.email, req.password, req.username, req.country, req.level)
    if "error" in result: raise HTTPException(400, result["error"])
    return result

@router.post("/login")
def do_login(req: LoginReq, request: Request, db: Session = Depends(get_db)):
    result = login(db, req.email, req.password, request.client.host)
    if "error" in result: raise HTTPException(401, result["error"])
    return result

@router.post("/verify-2fa")
def do_2fa(req: TwoFAReq, request: Request, db: Session = Depends(get_db)):
    result = verify_2fa(db, req.temp_token, req.code, request.client.host)
    if "error" in result: raise HTTPException(401, result["error"])
    return result

@router.get("/me")
def me(tok: str = Depends(token), db: Session = Depends(get_db)):
    h = get_current(db, tok)
    if not h: raise HTTPException(401, "Invalid token.")
    return _to_dict(h)
