import os
import secrets
import random
from datetime import datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import Base, User, Payment, AuditLog
from auth import hash_password

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./payments.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def generate_receipt_id() -> str:
    date_str = datetime.utcnow().strftime("%Y%m%d")
    suffix = secrets.token_hex(3).upper()
    return f"TXN-{date_str}-{suffix}"


def init_db():
    Base.metadata.create_all(bind=engine)


def seed_db():
    db = SessionLocal()
    if db.query(User).count() > 0:
        db.close()
        return
    users_data = [
        ("admin",    "admin@finpay.kz",    "AdminPass1!",   "analyst"),
        ("analyst1", "analyst1@finpay.kz", "AnalystPass1!", "analyst"),
        ("user1",    "user1@finpay.kz",    "UserPass1!",    "user"),
        ("user2",    "user2@finpay.kz",    "UserPass2!",    "user"),
        ("user3",    "user3@finpay.kz",    "UserPass3!",    "user"),
    ]
    user_objs = []
    for uname, email, pw, role in users_data:
        u = User(username=uname, email=email, password_hash=hash_password(pw), role=role)
        db.add(u)
        user_objs.append(u)
    db.flush()
    db.commit()

    currencies = ["KZT", "USD", "EUR", "RUB"]
    recipients = [
        "Kaspi Bank", "Halyk Bank", "BCC Bank", "ForteBank", "Jysan Bank",
        "Alpha Pay", "QazPay", "Swift Transfer", "Western Union", "PayNet",
    ]
    statuses_w = ["completed"] * 6 + ["pending"] * 2 + ["flagged"] * 1 + ["rejected"] * 1
    user_ids = [3, 4, 5]
    for i in range(210):
        st = random.choice(statuses_w)
        risk = round(random.uniform(0.0, 0.4), 2)
        if st == "flagged":
            risk = round(random.uniform(0.7, 1.0), 2)
        elif st == "rejected":
            risk = round(random.uniform(0.5, 0.8), 2)
        created = datetime.utcnow() - timedelta(
            days=random.randint(0, 90), hours=random.randint(0, 23)
        )
        p = Payment(
            receipt_id=generate_receipt_id(),
            user_id=random.choice(user_ids),
            amount=round(random.uniform(100, 500000), 2),
            currency=random.choice(currencies),
            recipient=random.choice(recipients),
            description=f"Payment #{i + 1}",
            status=st,
            risk_score=risk,
            created_at=created,
        )
        db.add(p)
    db.commit()
    db.close()
