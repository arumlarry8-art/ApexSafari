"""
Apex Safari Backend — Safari Intelligence
FastAPI + PostgreSQL + M-Pesa + PayPal + Bitcoin + Claude AI Proxy
Deploy on Railway: railway.app
"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import os

app = FastAPI(
    title       = "Apex Safari API",
    description = "Elite Bug Bounty Intelligence Platform — Safari Intelligence",
    version     = "2.0.0",
)

# ── CORS ──────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins     = ["*"],   # restrict to your Netlify URL in production
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

# ── SECURITY HEADERS ──────────────────────────────────────────────
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["X-Frame-Options"]           = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response

# ── ROUTERS ───────────────────────────────────────────────────────
from router_auth import router as auth_router
from router_ai import router as ai_router
from router_hunters import router as hunters_router
from router_admin import router as admin_router

app.include_router(auth_router)
app.include_router(ai_router)
app.include_router(hunters_router)
app.include_router(admin_router)

# ── STARTUP ───────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    from database import create_tables
    create_tables()
    print("Apex Safari backend running")

# ── HEALTH ────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {"platform": "Apex Safari", "company": "Safari Intelligence", "status": "running", "version": "2.0.0"}

@app.get("/health")
def health():
    return {"status": "healthy"}
