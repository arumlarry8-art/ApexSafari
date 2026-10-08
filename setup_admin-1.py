"""
Run ONCE on Railway shell to create admin account.
Usage: python3 setup_admin.py
"""
import os, sys
from dotenv import load_dotenv
load_dotenv()

from database import create_tables, SessionLocal, Hunter, generate_id
from auth_service import hash_password

def setup():
    print("=== Apex Safari Admin Setup ===\n")
    email    = input("Email [cybersafari54@gmail.com]: ").strip() or "cybersafari54@gmail.com"
    username = input("Username [larry]: ").strip() or "larry"
    password = input("Password (min 8 chars, 1 uppercase, 1 number): ").strip()

    if len(password) < 8: print("Too short."); sys.exit(1)
    if not any(c.isupper() for c in password): print("Need uppercase."); sys.exit(1)
    if not any(c.isdigit() for c in password): print("Need a number."); sys.exit(1)

    create_tables()
    db = SessionLocal()

    existing = db.query(Hunter).filter(Hunter.email == email).first()
    if existing:
        confirm = input(f"\n{email} exists. Update as admin? (yes/no): ").strip()
        if confirm != "yes": sys.exit(0)
        existing.password_hash = hash_password(password)
        existing.role = "admin"; existing.username = username; existing.certified = True
        db.commit()
        print(f"Updated {email} as admin.")
    else:
        db.add(Hunter(
            id=generate_id(), username=username, email=email,
            password_hash=hash_password(password),
            country="Kenya", level="elite", role="admin", certified=True, rank=0,
        ))
        db.commit()
        print(f"Admin created: {email}")

    db.close()
    print("\nDone. Login at apexsafari.netlify.app")

if __name__ == "__main__":
    setup()
