import csv
import io
import logging
import os
from datetime import datetime, timedelta

from dotenv import load_dotenv

load_dotenv()

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from auth import (
    MAX_FAILED,
    LOCKOUT_MINUTES,
    TOKEN_EXPIRE_MINUTES,
    create_token,
    decode_token,
    get_current_user,
    hash_password,
    require_analyst,
    validate_password,
    verify_password,
)
from database import SessionLocal, generate_receipt_id, get_db, init_db, seed_db
from models import AuditLog, Payment, User

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='{"time": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": "%(message)s"}',
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("finpay.main")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SECRET_KEY = os.getenv("SECRET_KEY", "")
SESSION_SECRET = SECRET_KEY
DEBUG = os.getenv("DEBUG", "false").lower() == "true"
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:8000").split(",")
PAGE_SIZE = 20

# ---------------------------------------------------------------------------
# App & Middleware
# ---------------------------------------------------------------------------
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="FinPay AI Edition", debug=False)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, https_only=not DEBUG)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

csrf_serializer = URLSafeTimedSerializer(SESSION_SECRET, salt="csrf")

# ---------------------------------------------------------------------------
# CSRF helpers
# ---------------------------------------------------------------------------

def generate_csrf_token(request: Request) -> str:
    token = csrf_serializer.dumps(request.session.get("user_id", "anon"))
    request.session["csrf_token"] = token
    return token


def validate_csrf(request: Request, form_token: str) -> bool:
    session_token = request.session.get("csrf_token", "")
    if not form_token or form_token != session_token:
        return False
    try:
        csrf_serializer.loads(form_token, max_age=3600)
        return True
    except (BadSignature, SignatureExpired):
        return False

# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------

def audit(
    db: Session,
    action: str,
    user_id: int = None,
    username: str = None,
    resource: str = "",
    details: str = "",
    ip: str = "",
):
    entry = AuditLog(
        user_id=user_id,
        username=username,
        action=action,
        resource=resource,
        details=details,
        ip_address=ip,
    )
    db.add(entry)
    db.commit()
    logger.info('action="%s" user="%s" ip="%s" resource="%s"', action, username or "", ip, resource)

# ---------------------------------------------------------------------------
# Template context helper
# ---------------------------------------------------------------------------

def tpl(request: Request, **kwargs):
    token = request.cookies.get("access_token")
    user = decode_token(token) if token else None
    csrf = generate_csrf_token(request)
    return {"request": request, "user": user, "csrf_token": csrf, **kwargs}

# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

@app.on_event("startup")
def on_startup():
    init_db()
    seed_db()

# ---------------------------------------------------------------------------
# Global exception handler
# ---------------------------------------------------------------------------

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception: %s", exc, exc_info=True)
    return templates.TemplateResponse(
        "base.html",
        tpl(request, error="Internal server error"),
        status_code=500,
    )

# ---------------------------------------------------------------------------
# Home
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    token = request.cookies.get("access_token")
    if token and decode_token(token):
        return RedirectResponse("/dashboard", status_code=302)
    return RedirectResponse("/login", status_code=302)

# ---------------------------------------------------------------------------
# Register
# ---------------------------------------------------------------------------

@app.get("/register", response_class=HTMLResponse)
async def register_get(request: Request):
    return templates.TemplateResponse("register.html", tpl(request))


@app.post("/register", response_class=HTMLResponse)
async def register_post(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    if not validate_csrf(request, csrf_token):
        return templates.TemplateResponse("register.html", tpl(request, error="Invalid CSRF token"), status_code=403)

    username = username.strip()[:50]
    email = email.strip()[:100]

    if not username or not email or not password:
        return templates.TemplateResponse("register.html", tpl(request, error="All fields are required"))

    if not validate_password(password):
        return templates.TemplateResponse(
            "register.html",
            tpl(request, error="Password must be at least 8 characters and include uppercase, lowercase, digit, and special character (!@#$%^&*)"),
        )

    if db.query(User).filter(User.username == username).first():
        return templates.TemplateResponse("register.html", tpl(request, error="Username already taken"))

    if db.query(User).filter(User.email == email).first():
        return templates.TemplateResponse("register.html", tpl(request, error="Email already registered"))

    user = User(username=username, email=email, password_hash=hash_password(password), role="user")
    db.add(user)
    db.commit()
    db.refresh(user)

    ip = request.client.host if request.client else "unknown"
    audit(db, "register", user_id=user.id, username=username, resource="user", ip=ip)

    return RedirectResponse("/login?registered=1", status_code=302)

# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request, registered: str = None):
    success = "Registration successful. Please log in." if registered else None
    return templates.TemplateResponse("login.html", tpl(request, success=success))


@app.post("/login", response_class=HTMLResponse)
@limiter.limit("5/minute")
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    if not validate_csrf(request, csrf_token):
        return templates.TemplateResponse("login.html", tpl(request, error="Invalid CSRF token"), status_code=403)

    ip = request.client.host if request.client else "unknown"
    username = username.strip()[:50]
    user = db.query(User).filter(User.username == username).first()

    def fail_response():
        return templates.TemplateResponse("login.html", tpl(request, error="Invalid username or password"))

    if not user:
        logger.info('action="login_failed" username="%s" ip="%s"', username, ip)
        return fail_response()

    if user.locked_until and user.locked_until > datetime.utcnow():
        audit(db, "login_locked", user_id=user.id, username=username, resource="login", ip=ip)
        return fail_response()

    if not verify_password(password, user.password_hash):
        user.failed_attempts = (user.failed_attempts or 0) + 1
        if user.failed_attempts >= MAX_FAILED:
            user.locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
            audit(db, "login_locked", user_id=user.id, username=username, resource="login", ip=ip)
        else:
            audit(db, "login_failed", user_id=user.id, username=username, resource="login", ip=ip)
        db.commit()
        return fail_response()

    user.failed_attempts = 0
    user.locked_until = None
    db.commit()

    audit(db, "login_success", user_id=user.id, username=username, resource="login", ip=ip)

    token = create_token(
        {"sub": user.username, "role": user.role, "uid": user.id},
        timedelta(minutes=TOKEN_EXPIRE_MINUTES),
    )
    request.session["user_id"] = user.id
    response = RedirectResponse("/dashboard", status_code=302)
    response.set_cookie(
        "access_token",
        token,
        httponly=True,
        samesite="lax",
        secure=not DEBUG,
        max_age=TOKEN_EXPIRE_MINUTES * 60,
    )
    return response

# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

@app.post("/logout")
async def logout(
    request: Request,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    if not validate_csrf(request, csrf_token):
        return RedirectResponse("/login", status_code=302)

    token = request.cookies.get("access_token")
    payload = decode_token(token) if token else {}
    ip = request.client.host if request.client else "unknown"
    if payload:
        audit(db, "logout", username=payload.get("sub"), resource="session", ip=ip)

    request.session.clear()
    response = RedirectResponse("/login", status_code=302)
    response.delete_cookie("access_token")
    return response

# ---------------------------------------------------------------------------
# Dashboard — user's own payments
# ---------------------------------------------------------------------------

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    page: int = 1,
    db: Session = Depends(get_db),
):
    try:
        current_user = get_current_user(request)
    except HTTPException as e:
        if e.status_code == 302:
            return RedirectResponse("/login", status_code=302)
        raise

    uid = current_user.get("uid")
    if page < 1:
        page = 1

    total = db.query(Payment).filter(Payment.user_id == uid).count()
    payments = (
        db.query(Payment)
        .filter(Payment.user_id == uid)
        .order_by(Payment.created_at.desc())
        .offset((page - 1) * PAGE_SIZE)
        .limit(PAGE_SIZE)
        .all()
    )
    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)

    return templates.TemplateResponse(
        "dashboard.html",
        tpl(
            request,
            payments=payments,
            page=page,
            total_pages=total_pages,
            total=total,
        ),
    )

# ---------------------------------------------------------------------------
# New payment
# ---------------------------------------------------------------------------

@app.get("/payments/new", response_class=HTMLResponse)
async def payment_new_get(request: Request):
    try:
        get_current_user(request)
    except HTTPException:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("payment_new.html", tpl(request))


@app.post("/payments/new", response_class=HTMLResponse)
async def payment_new_post(
    request: Request,
    amount: float = Form(...),
    currency: str = Form(...),
    recipient: str = Form(...),
    description: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    try:
        current_user = get_current_user(request)
    except HTTPException:
        return RedirectResponse("/login", status_code=302)

    if not validate_csrf(request, csrf_token):
        return templates.TemplateResponse("payment_new.html", tpl(request, error="Invalid CSRF token"), status_code=403)

    ip = request.client.host if request.client else "unknown"
    errors = []

    if amount <= 0 or amount > 5_000_000:
        errors.append("Amount must be between 0 and 5,000,000")
    recipient = recipient.strip()[:100]
    if not recipient:
        errors.append("Recipient is required")
    description = description.strip()[:500]
    allowed_currencies = ["KZT", "USD", "EUR", "RUB"]
    if currency not in allowed_currencies:
        currency = "KZT"

    if errors:
        return templates.TemplateResponse("payment_new.html", tpl(request, error="; ".join(errors)))

    risk_score = round(min(amount / 5_000_000, 1.0), 4)
    status = "pending"
    if amount > 200_000 or risk_score > 0.7:
        status = "flagged"

    payment = Payment(
        receipt_id=generate_receipt_id(),
        user_id=current_user.get("uid"),
        amount=amount,
        currency=currency,
        recipient=recipient,
        description=description,
        status=status,
        risk_score=risk_score,
    )
    db.add(payment)
    db.commit()
    db.refresh(payment)

    audit(
        db,
        "payment_created",
        user_id=current_user.get("uid"),
        username=current_user.get("sub"),
        resource=payment.receipt_id,
        details=f"amount={amount} currency={currency} status={status}",
        ip=ip,
    )

    return RedirectResponse("/dashboard", status_code=302)

# ---------------------------------------------------------------------------
# Analyst dashboard
# ---------------------------------------------------------------------------

@app.get("/analyst", response_class=HTMLResponse)
async def analyst_dashboard(
    request: Request,
    page: int = 1,
    status_filter: str = "",
    db: Session = Depends(get_db),
):
    try:
        current_user = require_analyst(request)
    except HTTPException as e:
        if e.status_code == 302:
            return RedirectResponse("/login", status_code=302)
        return templates.TemplateResponse("base.html", tpl(request, error="Analyst access required"), status_code=403)

    if page < 1:
        page = 1

    q = db.query(Payment)
    if status_filter:
        q = q.filter(Payment.status == status_filter)

    total = q.count()
    payments = q.order_by(Payment.created_at.desc()).offset((page - 1) * PAGE_SIZE).limit(PAGE_SIZE).all()
    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)

    stats = {
        "total": db.query(Payment).count(),
        "flagged": db.query(Payment).filter(Payment.status == "flagged").count(),
        "rejected": db.query(Payment).filter(Payment.status == "rejected").count(),
        "high_risk": db.query(Payment).filter(Payment.risk_score > 0.7).count(),
        "completed": db.query(Payment).filter(Payment.status == "completed").count(),
    }

    return templates.TemplateResponse(
        "analyst.html",
        tpl(
            request,
            payments=payments,
            stats=stats,
            page=page,
            total_pages=total_pages,
            total=total,
            status_filter=status_filter,
        ),
    )


@app.post("/analyst/payments/{payment_id}/flag")
async def flag_payment(
    request: Request,
    payment_id: int,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    try:
        current_user = require_analyst(request)
    except HTTPException as e:
        if e.status_code == 302:
            return RedirectResponse("/login", status_code=302)
        raise

    if not validate_csrf(request, csrf_token):
        return RedirectResponse("/analyst", status_code=302)

    payment = db.query(Payment).filter(Payment.id == payment_id).first()
    if not payment:
        raise HTTPException(status_code=404, detail="Payment not found")

    payment.status = "flagged"
    db.commit()

    ip = request.client.host if request.client else "unknown"
    audit(
        db,
        "payment_flagged",
        user_id=current_user.get("uid"),
        username=current_user.get("sub"),
        resource=payment.receipt_id,
        details=f"payment_id={payment_id}",
        ip=ip,
    )
    return RedirectResponse("/analyst", status_code=302)


@app.post("/analyst/payments/{payment_id}/reject")
async def reject_payment(
    request: Request,
    payment_id: int,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    try:
        current_user = require_analyst(request)
    except HTTPException as e:
        if e.status_code == 302:
            return RedirectResponse("/login", status_code=302)
        raise

    if not validate_csrf(request, csrf_token):
        return RedirectResponse("/analyst", status_code=302)

    payment = db.query(Payment).filter(Payment.id == payment_id).first()
    if not payment:
        raise HTTPException(status_code=404, detail="Payment not found")

    payment.status = "rejected"
    db.commit()

    ip = request.client.host if request.client else "unknown"
    audit(
        db,
        "payment_rejected",
        user_id=current_user.get("uid"),
        username=current_user.get("sub"),
        resource=payment.receipt_id,
        details=f"payment_id={payment_id}",
        ip=ip,
    )
    return RedirectResponse("/analyst", status_code=302)

# ---------------------------------------------------------------------------
# Analyst audit log
# ---------------------------------------------------------------------------

@app.get("/analyst/audit", response_class=HTMLResponse)
async def analyst_audit(
    request: Request,
    page: int = 1,
    db: Session = Depends(get_db),
):
    try:
        require_analyst(request)
    except HTTPException as e:
        if e.status_code == 302:
            return RedirectResponse("/login", status_code=302)
        return templates.TemplateResponse("base.html", tpl(request, error="Analyst access required"), status_code=403)

    if page < 1:
        page = 1

    total = db.query(AuditLog).count()
    logs = (
        db.query(AuditLog)
        .order_by(AuditLog.created_at.desc())
        .offset((page - 1) * PAGE_SIZE)
        .limit(PAGE_SIZE)
        .all()
    )
    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)

    return templates.TemplateResponse(
        "audit.html",
        tpl(request, logs=logs, page=page, total_pages=total_pages, total=total),
    )

# ---------------------------------------------------------------------------
# Analyst CSV export
# ---------------------------------------------------------------------------

@app.get("/analyst/export")
async def analyst_export(
    request: Request,
    db: Session = Depends(get_db),
):
    try:
        current_user = require_analyst(request)
    except HTTPException as e:
        if e.status_code == 302:
            return RedirectResponse("/login", status_code=302)
        raise

    ip = request.client.host if request.client else "unknown"
    audit(
        db,
        "payment_export",
        user_id=current_user.get("uid"),
        username=current_user.get("sub"),
        resource="payments_csv",
        ip=ip,
    )

    payments = db.query(Payment).order_by(Payment.created_at.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "receipt_id", "user_id", "amount", "currency", "recipient", "description", "status", "risk_score", "created_at"])
    for p in payments:
        writer.writerow([
            p.id, p.receipt_id, p.user_id, p.amount, p.currency,
            p.recipient, p.description, p.status, p.risk_score, p.created_at,
        ])

    filename = f"payments_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8")),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
