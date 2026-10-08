"""
Run this ONCE on Railway to create Larry's admin account.

Usage:
  railway run python3 setup_admin.py
  
Or locally after setting DATABASE_URL:
  python3 setup_admin.py
"""
import os, sys
from dotenv import load_dotenv
load_dotenv()

from models.database import create_tables, SessionLocal, Hunter, generate_id
from services.auth import hash_password

def setup():
    print("=== Apex Safari Admin Setup ===\n")

    email    = input("Admin email [cybersafari54@gmail.com]: ").strip() or "cybersafari54@gmail.com"
    username = input("Admin username [larry]: ").strip() or "larry"
    password = input("Admin password (min 8 chars): ").strip()

    if len(password) < 8:
        print("Password too short."); sys.exit(1)
    if not any(c.isupper() for c in password):
        print("Password needs at least one uppercase letter."); sys.exit(1)
    if not any(c.isdigit() for c in password):
        print("Password needs at least one number."); sys.exit(1)

    create_tables()
    db = SessionLocal()

    existing = db.query(Hunter).filter(Hunter.email == email).first()
    if existing:
        confirm = input(f"\n{email} already exists. Update password + set as admin? (yes/no): ").strip()
        if confirm != "yes":
            print("Cancelled."); sys.exit(0)
        existing.password_hash = hash_password(password)
        existing.role          = "admin"
        existing.username      = username
        existing.certified     = True
        db.commit()
        print(f"\nAdmin account updated for {email}")
    else:
        admin = Hunter(
            id            = generate_id(),
            username      = username,
            email         = email,
            password_hash = hash_password(password),
            country       = "Kenya",
            level         = "elite",
            role          = "admin",
            certified     = True,
            rank          = 0,
        )
        db.add(admin)
        db.commit()
        print(f"\nAdmin account created for {email}")

    db.close()
    print("\n=== Done ===")
    print(f"Email:    {email}")
    print(f"Username: {username}")
    print("Password: [set above]")
    print("\nDeploy your backend and login at apexsafari.netlify.app")

if __name__ == "__main__":
    setup()
