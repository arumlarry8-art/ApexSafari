"""Apex Safari database models and helpers.

This project originally expected a Postgres/Supabase schema, but the repository
was missing the actual implementation. The app is now wired to a lightweight
SQLite database by default so it works locally without external services.
"""

import os
import uuid
from datetime import datetime
from typing import Iterator

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.orm import Session, declarative_base, relationship, sessionmaker


Base = declarative_base()


DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./apex_safari.db")
ENGINE_KWARGS = {"connect_args": {"check_same_thread": False}} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, **ENGINE_KWARGS)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def generate_id() -> str:
    return str(uuid.uuid4())


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_tables() -> None:
    Base.metadata.create_all(bind=engine)


class Hunter(Base):
    __tablename__ = "hunters"

    id = Column(String, primary_key=True, default=generate_id)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    country = Column(String, default="Unknown")
    level = Column(String, default="beginner")
    role = Column(String, default="hunter")
    certified = Column(Boolean, default=False)
    rank = Column(Integer, default=9999)
    earnings = Column(Float, default=0.0)
    bugs_found = Column(Integer, default=0)
    test_passed = Column(Boolean, default=False)
    test_score = Column(Integer, default=0)
    test_attempts = Column(Integer, default=0)
    subscription = Column(String, default="free")
    banned = Column(Boolean, default=False)
    ban_reason = Column(String, nullable=True)
    mpesa_number = Column(String, nullable=True)
    btc_address = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)


class Bounty(Base):
    __tablename__ = "bounties"

    id = Column(String, primary_key=True, default=generate_id)
    hunter_id = Column(String, ForeignKey("hunters.id"), nullable=False)
    program_name = Column(String, nullable=False)
    platform = Column(String, nullable=False)
    amount_usd = Column(Float, nullable=False)
    platform_fee = Column(Float, nullable=False)
    hunter_keeps = Column(Float, nullable=False)
    payment_method = Column(String, default="mpesa")
    payment_proof = Column(String, nullable=True)
    fee_proof = Column(String, nullable=True)
    status = Column(String, default="pending")
    verified_by = Column(String, nullable=True)
    verified_at = Column(DateTime, nullable=True)
    notes = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    hunter = relationship("Hunter")


class Payment(Base):
    __tablename__ = "payments"

    id = Column(String, primary_key=True, default=generate_id)
    bounty_id = Column(String, ForeignKey("bounties.id"), nullable=True)
    hunter_id = Column(String, ForeignKey("hunters.id"), nullable=True)
    tx_id = Column(String, nullable=True)
    method = Column(String, default="mpesa")
    amount = Column(Float, default=0.0)
    currency = Column(String, default="USD")
    status = Column(String, default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)
    confirmed_at = Column(DateTime, nullable=True)
    mpesa_receipt = Column(String, nullable=True)


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(String, primary_key=True, default=generate_id)
    event_type = Column(String, nullable=False)
    severity = Column(String, default="info")
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    hunter_id = Column(String, ForeignKey("hunters.id"), nullable=True)
    details = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class ScopeAnalysis(Base):
    __tablename__ = "scope_analyses"

    id = Column(String, primary_key=True, default=generate_id)
    hunter_id = Column(String, ForeignKey("hunters.id"), nullable=False)
    program_name = Column(String, nullable=True)
    platform = Column(String, nullable=True)
    analysis = Column(Text, nullable=False)
    screenshot_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)


class Post(Base):
    __tablename__ = "posts"

    id = Column(String, primary_key=True, default=generate_id)
    hunter_id = Column(String, ForeignKey("hunters.id"), nullable=False)
    content = Column(Text, nullable=False)
    category = Column(String, default="General")
    likes = Column(Integer, default=0)
    pinned = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    hunter = relationship("Hunter")


class Announcement(Base):
    __tablename__ = "announcements"

    id = Column(String, primary_key=True, default=generate_id)
    title = Column(String, nullable=False)
    content = Column(Text, nullable=False)
    type = Column(String, default="update")
    created_by = Column(String, ForeignKey("hunters.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class HallOfFame(Base):
    __tablename__ = "hall_of_fame"

    id = Column(String, primary_key=True, default=generate_id)
    hunter_id = Column(String, ForeignKey("hunters.id"), nullable=True)
    finding = Column(Text, nullable=False)
    bounty_usd = Column(Float, nullable=False)
    category = Column(String, nullable=False)
    featured_by = Column(String, ForeignKey("hunters.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class Team(Base):
    __tablename__ = "teams"

    id = Column(String, primary_key=True, default=generate_id)
    name = Column(String, unique=True, nullable=False)
    leader_id = Column(String, ForeignKey("hunters.id"), nullable=True)
    description = Column(String, nullable=True)
    earnings = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow)


class TeamMember(Base):
    __tablename__ = "team_members"

    team_id = Column(String, ForeignKey("teams.id"), primary_key=True)
    hunter_id = Column(String, ForeignKey("hunters.id"), primary_key=True)
    split_pct = Column(Float, default=0.0)
    joined_at = Column(DateTime, default=datetime.utcnow)


__all__ = [
    "Base",
    "SessionLocal",
    "engine",
    "generate_id",
    "get_db",
    "create_tables",
    "Hunter",
    "Bounty",
    "Payment",
    "SecurityEvent",
    "ScopeAnalysis",
    "Post",
    "Announcement",
    "HallOfFame",
    "Team",
    "TeamMember",
]
