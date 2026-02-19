from flask import Flask, render_template, request, redirect, url_for, session, abort, send_file
import os
import secrets
import threading
import time
import re
import json
import hmac
from datetime import datetime
from datetime import timedelta
from io import BytesIO

import qrcode
from supabase import create_client
from werkzeug.security import generate_password_hash, check_password_hash

APP_ROOT = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

secret_key = os.getenv("FLASK_SECRET_KEY", "").strip()
if not secret_key:
    raise RuntimeError("FLASK_SECRET_KEY is required.")
app.secret_key = secret_key
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "true").strip().lower() != "false",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)

FEMALE_SERVICES = [
    "Women's Haircut",
    "Blowout & Styling",
    "Hair Color",
    "Highlights / Balayage",
    "Hair Spa Treatment",
    "Manicure",
    "Pedicure",
    "Facial",
    "Waxing",
    "Brow & Threading",
]

MALE_SERVICES = [
    "Men's Haircut",
    "Beard Trim",
    "Hot Towel Shave",
    "Hair & Beard Color",
    "Scalp Treatment",
    "Kids Haircut",
    "Eyebrow Trim",
]

DEFAULT_SERVICES = list(dict.fromkeys(FEMALE_SERVICES + MALE_SERVICES))

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "").strip().lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "").strip()
OWNER_PASSWORD = os.getenv("OWNER_PASSWORD", "").strip()

SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY", "").strip()

_supabase = None


def get_supabase():
    global _supabase
    if _supabase is None:
        key = SUPABASE_SERVICE_ROLE_KEY or SUPABASE_ANON_KEY
        if not SUPABASE_URL or not key:
            raise RuntimeError("Supabase is not configured. Set SUPABASE_URL and key.")
        _supabase = create_client(SUPABASE_URL, key)
    return _supabase


def sb_exec(query):
    res = query.execute()
    if getattr(res, "error", None):
        raise RuntimeError(str(res.error))
    return res.data or []


def sb_fetch_one(query):
    data = sb_exec(query)
    return data[0] if data else None


def json_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value) or []
        except Exception:
            return []
    return []


def json_dict(value):
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value) or {}
        except Exception:
            return {}
    return {}


def parse_time_value(value):
    if value is None:
        raise ValueError("Missing time value")
    if isinstance(value, str):
        cleaned = value.strip()
        cleaned = cleaned.replace("Z", "")
        cleaned = cleaned.split("+", 1)[0].strip()
        for fmt in (
            "%H:%M:%S.%f",
            "%H:%M:%S",
            "%H:%M",
            "%I:%M %p",
            "%I:%M%p",
            "%I %p",
            "%I%p",
        ):
            try:
                return datetime.strptime(cleaned, fmt).time()
            except ValueError:
                continue
    raise ValueError("Invalid time format")


def slugify(value):
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    value = value.strip("-")
    return value or "salon"


def unique_slug(base):
    slug = base
    n = 2
    supabase = get_supabase()
    while True:
        row = sb_fetch_one(
            supabase.table("owners").select("id").eq("slug", slug).limit(1)
        )
        if row is None:
            break
        slug = f"{base}-{n}"
        n += 1
    return slug


def require_login():
    if "user_id" not in session:
        return False
    return True


def require_admin():
    return session.get("is_admin") is True


def build_public_url(path):
    base = os.getenv("PUBLIC_BASE_URL", "").strip().rstrip("/")
    if base:
        return f"{base}{path}"
    return path


def generate_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


@app.context_processor
def inject_owner_status():
    email = session.get("email")
    if not email:
        return {"has_owner": False}
    supabase = get_supabase()
    row = sb_fetch_one(
        supabase.table("owners").select("id").eq("email", email).limit(1)
    )
    has_owner = row is not None
    return {"has_owner": has_owner}


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": generate_csrf_token()}


def send_booking_sms(to_number, salon_name, client_name, preferred_date, preferred_time, service, barber_name, manage_link=None):
    sid = os.getenv("TWILIO_SID", "").strip()
    token = os.getenv("TWILIO_TOKEN", "").strip()
    sender = os.getenv("TWILIO_FROM", "").strip()
    if not sid or not token or not sender:
        return False, "Twilio not configured"
    try:
        from twilio.rest import Client
    except ImportError:
        return False, "Twilio library not installed"

    stylist = barber_name or "Any stylist"
    body = (
        f"Hi {client_name}, your booking is received for {salon_name}.\n"
        f"Service: {service}\n"
        f"Stylist: {stylist}\n"
        f"Date: {preferred_date}\n"
        f"Time: {preferred_time}\n"
        f"We'll send you a reminder before your appointment."
    )
    if manage_link:
        body = f"{body}\nManage: {manage_link}"
    client = Client(sid, token)
    try:
        client.messages.create(
            to=to_number,
            from_=sender,
            body=body,
        )
        return True, None
    except Exception as exc:
        return False, str(exc)


def send_status_sms(to_number, salon_name, client_name, status, preferred_date, preferred_time, service, barber_name):
    sid = os.getenv("TWILIO_SID", "").strip()
    token = os.getenv("TWILIO_TOKEN", "").strip()
    sender = os.getenv("TWILIO_FROM", "").strip()
    if not sid or not token or not sender:
        return False, "Twilio not configured"
    try:
        from twilio.rest import Client
    except ImportError:
        return False, "Twilio library not installed"

    stylist = barber_name or "Any stylist"
    body = (
        f"Hi {client_name}, your appointment is {status} for {salon_name}.\n"
        f"Service: {service}\n"
        f"Stylist: {stylist}\n"
        f"Date: {preferred_date}\n"
        f"Time: {preferred_time}"
    )
    client = Client(sid, token)
    try:
        client.messages.create(
            to=to_number,
            from_=sender,
            body=body,
        )
        return True, None
    except Exception as exc:
        return False, str(exc)


def send_reminder_sms(to_number, salon_name, client_name, preferred_date, preferred_time, service, barber_name, manage_link):
    sid = os.getenv("TWILIO_SID", "").strip()
    token = os.getenv("TWILIO_TOKEN", "").strip()
    sender = os.getenv("TWILIO_FROM", "").strip()
    if not sid or not token or not sender:
        return False, "Twilio not configured"
    try:
        from twilio.rest import Client
    except ImportError:
        return False, "Twilio library not installed"

    stylist = barber_name or "Any stylist"
    body = (
        f"Reminder for {client_name}: {salon_name} appointment.\n"
        f"Service: {service}\n"
        f"Stylist: {stylist}\n"
        f"Date: {preferred_date}\n"
        f"Time: {preferred_time}\n"
        f"Manage: {manage_link}"
    )
    client = Client(sid, token)
    try:
        client.messages.create(
            to=to_number,
            from_=sender,
            body=body,
        )
        return True, None
    except Exception as exc:
        return False, str(exc)


def reminder_worker():
    while True:
        try:
            now = datetime.now().isoformat(timespec="seconds")
            supabase = get_supabase()
            rows = sb_exec(
                supabase.table("reminders")
                .select("id, booking_id")
                .is_("sent_at", "null")
                .lte("send_at", now)
            )
            for row in rows:
                booking = sb_fetch_one(
                    supabase.table("bookings")
                    .select(
                        "id, owner_id, client_phone, client_name, preferred_date, preferred_time, service, barber_name, manage_token"
                    )
                    .eq("id", row["booking_id"])
                    .limit(1)
                )
                if booking is None:
                    continue
                owner = sb_fetch_one(
                    supabase.table("owners")
                    .select("salon_name, slug")
                    .eq("id", booking["owner_id"])
                    .limit(1)
                )
                if owner is None:
                    continue
                manage_link = build_public_url(f"/manage/{booking['manage_token']}")
                ok, err = send_reminder_sms(
                    booking["client_phone"],
                    owner["salon_name"],
                    booking["client_name"],
                    booking["preferred_date"],
                    booking["preferred_time"],
                    booking["service"],
                    booking.get("barber_name", ""),
                    manage_link,
                )
                if not ok:
                    app.logger.warning("Reminder SMS failed: %s", err)
                    continue
                sb_exec(
                    supabase.table("reminders")
                    .update({"sent_at": datetime.now().isoformat(timespec="seconds")})
                    .eq("id", row["id"])
                )
        except Exception:
            app.logger.exception("Reminder worker failed")
        time.sleep(60)


@app.before_request
def protect_owner_routes():
    path = request.path or ""
    if path.startswith("/owner") and "email" not in session and not require_admin():
        return redirect(url_for("landing"))


@app.before_request
def csrf_protect():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        token = session.get("_csrf_token", "")
        req_token = request.form.get("_csrf_token", "") or request.headers.get(
            "X-CSRF-Token", ""
        )
        if not token or not req_token or not hmac.compare_digest(token, req_token):
            abort(400)


@app.route("/")
def landing():
    return render_template("landing.html")


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if not ADMIN_EMAIL or not ADMIN_PASSWORD:
            return render_template(
                "admin_login.html",
                error="Admin login is not configured.",
            )
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()
        if hmac.compare_digest(email, ADMIN_EMAIL) and hmac.compare_digest(
            password, ADMIN_PASSWORD
        ):
            session["is_admin"] = True
            session.permanent = True
            return redirect(url_for("admin_dashboard"))
        return render_template("admin_login.html", error="Invalid admin credentials.")
    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    return redirect(url_for("admin_login"))


@app.route("/admin")
def admin_dashboard():
    if not require_admin():
        return redirect(url_for("admin_login"))
    supabase = get_supabase()
    rows = sb_exec(supabase.table("owners").select("*").order("id", desc=True))
    bookings = sb_exec(supabase.table("bookings").select("*").order("created_at", desc=True))
    notif_rows = sb_exec(
        supabase.table("admin_notifications")
        .select("*")
        .order("created_at", desc=True)
        .limit(15)
    )
    count_res = supabase.table("admin_notifications").select("id", count="exact").is_("read_at", "null").execute()
    if getattr(count_res, "error", None):
        raise RuntimeError(str(count_res.error))
    unread_count = count_res.count or 0

    owner_map = {row["id"]: row for row in rows}
    booking_map = {row["id"]: row for row in bookings}
    notifications = []
    for note in notif_rows:
        booking = booking_map.get(note["booking_id"])
        owner = owner_map.get(booking["owner_id"]) if booking else None
        merged = dict(note)
        if booking:
            merged.update(
                {
                    "client_name": booking.get("client_name"),
                    "service": booking.get("service"),
                    "preferred_date": booking.get("preferred_date"),
                    "preferred_time": booking.get("preferred_time"),
                }
            )
        if owner:
            merged["salon_name"] = owner.get("salon_name")
        notifications.append(merged)

    for booking in bookings:
        owner = owner_map.get(booking["owner_id"])
        if owner:
            booking["salon_name"] = owner.get("salon_name")
            booking["slug"] = owner.get("slug")
    owners = []
    for row in rows:
        owners.append(
            {
                "id": row["id"],
                "email": row["email"],
                "salon_name": row["salon_name"],
                "slug": row["slug"],
                "created_at": row["created_at"],
                "active": bool(row["active"]),
            }
        )
    return render_template(
        "admin_dashboard.html",
        owners=owners,
        bookings=bookings,
        notifications=notifications,
        unread_count=unread_count,
    )


@app.route("/admin/notifications/read/<int:notification_id>", methods=["POST"])
def admin_notification_read(notification_id):
    if not require_admin():
        return redirect(url_for("admin_login"))
    supabase = get_supabase()
    sb_exec(
        supabase.table("admin_notifications")
        .update({"read_at": datetime.utcnow().isoformat(timespec="seconds")})
        .eq("id", notification_id)
    )
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/notifications/read-all", methods=["POST"])
def admin_notification_read_all():
    if not require_admin():
        return redirect(url_for("admin_login"))
    supabase = get_supabase()
    sb_exec(
        supabase.table("admin_notifications")
        .update({"read_at": datetime.utcnow().isoformat(timespec="seconds")})
        .is_("read_at", "null")
    )
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/toggle/<int:owner_id>", methods=["POST"])
def admin_toggle_owner(owner_id):
    if not require_admin():
        return redirect(url_for("admin_login"))
    supabase = get_supabase()
    row = sb_fetch_one(supabase.table("owners").select("active").eq("id", owner_id).limit(1))
    if row is None:
        abort(404)
    new_value = not bool(row["active"])
    sb_exec(supabase.table("owners").update({"active": new_value}).eq("id", owner_id))
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/booking/<int:booking_id>", methods=["POST"])
def admin_update_booking(booking_id):
    if not require_admin():
        return redirect(url_for("admin_login"))
    status = request.form.get("status", "Pending").strip()
    preferred_date = request.form.get("preferred_date", "").strip()
    preferred_time = request.form.get("preferred_time", "").strip()
    barber_name = request.form.get("barber_name", "").strip()
    service = request.form.get("service", "").strip()
    client_name = request.form.get("client_name", "").strip()
    client_phone = request.form.get("client_phone", "").strip()

    supabase = get_supabase()
    sb_exec(
        supabase.table("bookings")
        .update(
            {
                "status": status or "Pending",
                "preferred_date": preferred_date,
                "preferred_time": preferred_time,
                "barber_name": barber_name,
                "service": service,
                "client_name": client_name,
                "client_phone": client_phone,
            }
        )
        .eq("id", booking_id)
    )
    return redirect(url_for("admin_dashboard"))


@app.route("/signup-page")
def signup_page():
    return render_template("signup.html")


@app.route("/signup", methods=["POST"])
def signup():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    phone = request.form.get("phone", "").strip()
    password = request.form.get("password", "").strip()

    if not name or not email or not phone or not password:
        return render_template(
            "signup.html",
            error="Please fill all signup fields.",
        )
    if len(password) < 8:
        return render_template(
            "signup.html",
            error="Password must be at least 8 characters.",
        )

    supabase = get_supabase()
    row = sb_fetch_one(
        supabase.table("users").select("id").eq("email", email).limit(1)
    )
    if row is not None:
        return render_template(
            "landing.html",
            error="Email already registered. Please log in.",
            error_source="login",
        )

    sb_exec(
        supabase.table("users").insert(
            {
                "email": email,
                "name": name,
                "phone": phone,
                "password_hash": generate_password_hash(password),
                "created_at": datetime.utcnow().isoformat(timespec="seconds"),
            }
        )
    )

    session["user_id"] = email
    session["email"] = email
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("email"):
        return redirect(url_for("owner_setup"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()
        if not email or not password:
            return render_template(
                "login.html",
                error="Email and password are required.",
            )
        supabase = get_supabase()
        row = sb_fetch_one(
            supabase.table("users")
            .select("id, password_hash")
            .eq("email", email)
            .limit(1)
        )
        if row is None:
            return render_template(
                "signup.html",
                error="Email not found. Please sign up.",
            )
        password_hash = row.get("password_hash") if isinstance(row, dict) else None
        if not password_hash:
            # First-time password set for legacy accounts without a password.
            sb_exec(
                supabase.table("users")
                .update({"password_hash": generate_password_hash(password)})
                .eq("email", email)
            )
        elif not check_password_hash(password_hash, password):
            return render_template(
                "login.html",
                error="Invalid email or password.",
            )

        session["user_id"] = email
        session["email"] = email
        return redirect(url_for("owner_setup"))
    return render_template("login.html")


@app.route("/post-login")
def post_login():
    if not require_login():
        return redirect(url_for("landing"))
    return redirect(url_for("owner_setup"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("landing"))


@app.route("/owner/setup", methods=["GET"])
def owner_setup():
    if "email" not in session:
        return redirect(url_for("landing"))
    return render_template(
        "owner_setup.html",
        email=session.get("email"),
        services_female=FEMALE_SERVICES,
        services_male=MALE_SERVICES,
    )


@app.route("/owner/dashboards")
def owner_dashboards():
    if "email" not in session:
        return redirect(url_for("landing"))
    email = session.get("email")
    supabase = get_supabase()
    rows = sb_exec(
        supabase.table("owners").select("*").eq("email", email).order("id", desc=True)
    )

    dashboards = []
    for row in rows:
        dashboards.append(
            {
                "id": row["id"],
                "salon_name": row["salon_name"],
                "theme": row["theme"],
                "chairs": row["chairs"],
                "open_time": row["open_time"],
                "close_time": row["close_time"],
                "barbers": json_list(row.get("barbers_json")),
                "services": json_list(row.get("services_json")),
                "details": json_dict(row.get("details_json")),
                "slug": row["slug"],
                "created_at": row["created_at"],
                "active": bool(row["active"]),
            }
        )

    return render_template("owner_dashboards.html", dashboards=dashboards, email=email)


@app.route("/owner/toggle/<int:owner_id>", methods=["POST"])
def owner_toggle(owner_id):
    if "email" not in session:
        return redirect(url_for("landing"))
    email = session.get("email")
    supabase = get_supabase()
    row = sb_fetch_one(
        supabase.table("owners")
        .select("active")
        .eq("id", owner_id)
        .eq("email", email)
        .limit(1)
    )
    if row is None:
        abort(404)
    new_value = not bool(row["active"])
    sb_exec(supabase.table("owners").update({"active": new_value}).eq("id", owner_id))
    return redirect(url_for("owner_dashboards"))


@app.route("/owner/edit/<slug>", methods=["GET", "POST"])
def owner_edit(slug):
    if "email" not in session and not require_admin():
        return redirect(url_for("landing"))
    email = session.get("email")
    is_admin = require_admin()
    supabase = get_supabase()
    if is_admin:
        row = sb_fetch_one(
            supabase.table("owners").select("*").eq("slug", slug).limit(1)
        )
    else:
        row = sb_fetch_one(
            supabase.table("owners")
            .select("*")
            .eq("slug", slug)
            .eq("email", email)
            .limit(1)
        )
    if row is None:
        abort(404)

    if request.method == "POST":
        salon_name = request.form.get("salon_name", "").strip()
        theme = request.form.get("theme", "sand").strip()
        chairs = request.form.get("chairs", "0").strip()
        open_time = request.form.get("open_time", "").strip()
        close_time = request.form.get("close_time", "").strip()
        address = request.form.get("address", "").strip()
        phone = request.form.get("phone", "").strip()
        about = request.form.get("about", "").strip()
        selected_services = request.form.getlist("services")
        custom_services = request.form.get("custom_services", "")
        custom_list = [s.strip() for s in custom_services.splitlines() if s.strip()]
        if custom_list:
            selected_services.extend(custom_list)
        price_names = request.form.getlist("service_price_name")
        price_values = request.form.getlist("service_price_value")
        services_pricing = []
        for idx in range(len(price_names)):
            name = price_names[idx].strip()
            price = price_values[idx].strip() if idx < len(price_values) else ""
            if not name and not price:
                continue
            services_pricing.append({"name": name or f"Service {idx + 1}", "price": price})
        booking_settings = {
            "title": request.form.get("booking_title", "").strip() or "Reserve your chair",
            "subtitle": request.form.get("booking_subtitle", "").strip() or "Book your beauty appointment in seconds.",
            "badge": request.form.get("booking_badge", "").strip() or "Book in 60s",
            "availability_prefix": request.form.get("booking_availability", "").strip() or "Availability",
            "show_barbers": request.form.get("booking_show_barbers") == "on",
            "show_packages": request.form.get("booking_show_packages") == "on",
            "note": request.form.get("booking_note", "").strip(),
        }
        package_names = request.form.getlist("package_name")
        package_prices = request.form.getlist("package_price")
        package_durations = request.form.getlist("package_duration")
        package_descs = request.form.getlist("package_desc")
        reminders = {
            "sms": request.form.get("reminder_sms") == "on",
            "whatsapp": request.form.get("reminder_whatsapp") == "on",
            "email": request.form.get("reminder_email") == "on",
            "note": request.form.get("reminder_note", "").strip(),
        }
        extras = {
            "title": request.form.get("extras_title", "").strip(),
            "items": [
                item.strip()
                for item in request.form.get("extras_items", "").splitlines()
                if item.strip()
            ],
        }

        barber_names = request.form.getlist("barber_name")
        barber_cnics = request.form.getlist("barber_cnic")
        barber_active = request.form.getlist("barber_active")

        if not salon_name:
            return render_template(
                "owner_edit.html",
                email=email,
                services_female=FEMALE_SERVICES,
                services_male=MALE_SERVICES,
                error="Salon name is required.",
                owner=row,
                barbers=json_list(row.get("barbers_json")),
                selected_services=json_list(row.get("services_json")),
                details=json_dict(row.get("details_json")),
                services_pricing=json_list(row.get("services_pricing_json")),
            )

        try:
            chairs_int = int(chairs)
            if chairs_int <= 0:
                raise ValueError
        except ValueError:
            return render_template(
                "owner_edit.html",
                email=email,
                services_female=FEMALE_SERVICES,
                services_male=MALE_SERVICES,
                error="Chairs must be a positive number.",
                owner=row,
                barbers=json_list(row.get("barbers_json")),
                selected_services=json_list(row.get("services_json")),
                details=json_dict(row.get("details_json")),
                services_pricing=json_list(row.get("services_pricing_json")),
            )

        if not open_time or not close_time:
            return render_template(
                "owner_edit.html",
                email=email,
                services_female=FEMALE_SERVICES,
                services_male=MALE_SERVICES,
                error="Open and close times are required.",
                owner=row,
                barbers=json_list(row.get("barbers_json")),
                selected_services=json_list(row.get("services_json")),
                details=json_dict(row.get("details_json")),
                services_pricing=json_list(row.get("services_pricing_json")),
            )

        if not selected_services:
            return render_template(
                "owner_edit.html",
                email=email,
                services_female=FEMALE_SERVICES,
                services_male=MALE_SERVICES,
                error="Select at least one service.",
                owner=row,
                barbers=json_list(row.get("barbers_json")),
                selected_services=json_list(row.get("services_json")),
                details=json_dict(row.get("details_json")),
                services_pricing=json_list(row.get("services_pricing_json")),
            )

        barbers = []
        for idx, name in enumerate(barber_names):
            clean = name.strip()
            if not clean:
                continue
            cnic = barber_cnics[idx].strip() if idx < len(barber_cnics) else ""
            if not cnic:
                return render_template(
                    "owner_edit.html",
                    email=email,
                    services_female=FEMALE_SERVICES,
                    services_male=MALE_SERVICES,
                    error="CNIC is required for each stylist.",
                    owner=row,
                    barbers=json_list(row.get("barbers_json")),
                    selected_services=json_list(row.get("services_json")),
                    details=json_dict(row.get("details_json")),
                    services_pricing=json_list(row.get("services_pricing_json")),
                )
            is_active = clean in barber_active
            barbers.append({"name": clean, "cnic": cnic, "active": is_active})

        if not barbers:
            return render_template(
                "owner_edit.html",
                email=email,
                services_female=FEMALE_SERVICES,
                services_male=MALE_SERVICES,
                error="Add at least one stylist.",
                owner=row,
                barbers=json_list(row.get("barbers_json")),
                selected_services=json_list(row.get("services_json")),
                details=json_dict(row.get("details_json")),
                services_pricing=json_list(row.get("services_pricing_json")),
            )

        details = {"address": address, "phone": phone, "about": about}
        packages = []
        for idx in range(len(package_names)):
            name = package_names[idx].strip()
            price = package_prices[idx].strip() if idx < len(package_prices) else ""
            duration = package_durations[idx].strip() if idx < len(package_durations) else ""
            description = package_descs[idx].strip() if idx < len(package_descs) else ""
            if not any([name, price, duration, description]):
                continue
            packages.append(
                {
                    "name": name or f"Package {idx + 1}",
                    "price": price,
                    "duration": duration,
                    "description": description,
                }
            )

        sb_exec(
            supabase.table("owners")
            .update(
                {
                    "salon_name": salon_name,
                    "theme": theme,
                    "chairs": chairs_int,
                    "open_time": open_time,
                    "close_time": close_time,
                    "barbers_json": barbers,
                    "services_json": selected_services,
                    "details_json": details,
                    "packages_json": packages,
                    "reminders_json": reminders,
                    "extras_json": extras,
                    "booking_settings_json": booking_settings,
                    "services_pricing_json": services_pricing,
                }
            )
            .eq("id", row["id"])
        )
        return redirect(url_for("owner_dashboards"))

    barbers = json_list(row.get("barbers_json"))
    selected_services = json_list(row.get("services_json"))
    details = json_dict(row.get("details_json"))
    packages = json_list(row.get("packages_json"))
    reminders = json_dict(row.get("reminders_json"))
    extras = json_dict(row.get("extras_json"))
    booking_settings = json_dict(row.get("booking_settings_json"))
    services_pricing = json_list(row.get("services_pricing_json"))

    return render_template(
        "owner_edit.html",
        email=email,
        services_female=FEMALE_SERVICES,
        services_male=MALE_SERVICES,
        owner=row,
        barbers=barbers,
        selected_services=selected_services,
        details=details,
        packages=packages,
        reminders=reminders,
        extras=extras,
        booking_settings=booking_settings,
        services_pricing=services_pricing,
    )


@app.route("/create", methods=["POST"])
def create_dashboard():
    if "email" not in session:
        return redirect(url_for("landing"))

    salon_name = request.form.get("salon_name", "").strip()
    theme = request.form.get("theme", "sand").strip()
    chairs = request.form.get("chairs", "0").strip()
    open_time = request.form.get("open_time", "").strip()
    close_time = request.form.get("close_time", "").strip()

    address = request.form.get("address", "").strip()
    phone = request.form.get("phone", "").strip()
    about = request.form.get("about", "").strip()

    selected_services = request.form.getlist("services")
    custom_services = request.form.get("custom_services", "")
    custom_list = [s.strip() for s in custom_services.splitlines() if s.strip()]
    if custom_list:
        selected_services.extend(custom_list)
    price_names = request.form.getlist("service_price_name")
    price_values = request.form.getlist("service_price_value")
    services_pricing = []
    for idx in range(len(price_names)):
        name = price_names[idx].strip()
        price = price_values[idx].strip() if idx < len(price_values) else ""
        if not name and not price:
            continue
        services_pricing.append({"name": name or f"Service {idx + 1}", "price": price})
    booking_settings = {
        "title": request.form.get("booking_title", "").strip() or "Reserve your chair",
        "subtitle": request.form.get("booking_subtitle", "").strip() or "Book your beauty appointment in seconds.",
        "badge": request.form.get("booking_badge", "").strip() or "Book in 60s",
        "availability_prefix": request.form.get("booking_availability", "").strip() or "Availability",
        "show_barbers": request.form.get("booking_show_barbers") == "on",
        "show_packages": request.form.get("booking_show_packages") == "on",
        "note": request.form.get("booking_note", "").strip(),
    }
    package_names = request.form.getlist("package_name")
    package_prices = request.form.getlist("package_price")
    package_durations = request.form.getlist("package_duration")
    package_descs = request.form.getlist("package_desc")
    reminders = {
        "sms": request.form.get("reminder_sms") == "on",
        "whatsapp": request.form.get("reminder_whatsapp") == "on",
        "email": request.form.get("reminder_email") == "on",
        "note": request.form.get("reminder_note", "").strip(),
    }
    extras = {
        "title": request.form.get("extras_title", "").strip(),
        "items": [
            item.strip()
            for item in request.form.get("extras_items", "").splitlines()
            if item.strip()
        ],
    }

    barber_names = request.form.getlist("barber_name")
    barber_cnics = request.form.getlist("barber_cnic")
    barber_active = request.form.getlist("barber_active")

    if not salon_name:
        return render_template(
        "owner_setup.html",
        email=session.get("email"),
        services_female=FEMALE_SERVICES,
        services_male=MALE_SERVICES,
        error="Salon name is required.",
    )

    try:
        chairs_int = int(chairs)
        if chairs_int <= 0:
            raise ValueError
    except ValueError:
        return render_template(
        "owner_setup.html",
        email=session.get("email"),
        services_female=FEMALE_SERVICES,
        services_male=MALE_SERVICES,
        error="Chairs must be a positive number.",
    )

    if not open_time or not close_time:
        return render_template(
        "owner_setup.html",
        email=session.get("email"),
        services_female=FEMALE_SERVICES,
        services_male=MALE_SERVICES,
        error="Open and close times are required.",
    )

    if not selected_services:
        return render_template(
        "owner_setup.html",
        email=session.get("email"),
        services_female=FEMALE_SERVICES,
        services_male=MALE_SERVICES,
        error="Select at least one service.",
    )

    barbers = []
    for idx, name in enumerate(barber_names):
        clean = name.strip()
        if not clean:
            continue
        cnic = barber_cnics[idx].strip() if idx < len(barber_cnics) else ""
        if not cnic:
            return render_template(
            "owner_setup.html",
            email=session.get("email"),
            services_female=FEMALE_SERVICES,
            services_male=MALE_SERVICES,
            error="CNIC is required for each stylist.",
        )
        is_active = clean in barber_active
        barbers.append({"name": clean, "cnic": cnic, "active": is_active})

    if not barbers:
        return render_template(
        "owner_setup.html",
        email=session.get("email"),
        services_female=FEMALE_SERVICES,
        services_male=MALE_SERVICES,
        error="Add at least one stylist.",
    )

    base = slugify(salon_name)
    slug = unique_slug(base)

    details = {"address": address, "phone": phone, "about": about}
    packages = []
    for idx in range(len(package_names)):
        name = package_names[idx].strip()
        price = package_prices[idx].strip() if idx < len(package_prices) else ""
        duration = package_durations[idx].strip() if idx < len(package_durations) else ""
        description = package_descs[idx].strip() if idx < len(package_descs) else ""
        if not any([name, price, duration, description]):
            continue
        packages.append(
            {
                "name": name or f"Package {idx + 1}",
                "price": price,
                "duration": duration,
                "description": description,
            }
        )

    supabase = get_supabase()
    sb_exec(
        supabase.table("owners").insert(
            {
                "email": session.get("email"),
                "salon_name": salon_name,
                "theme": theme,
                "chairs": chairs_int,
                "open_time": open_time,
                "close_time": close_time,
                "barbers_json": barbers,
                "services_json": selected_services,
                "details_json": details,
                "slug": slug,
                "created_at": datetime.utcnow().isoformat(timespec="seconds"),
                "active": True,
                "packages_json": packages,
                "reminders_json": reminders,
                "extras_json": extras,
                "booking_settings_json": booking_settings,
                "services_pricing_json": services_pricing,
            }
        )
    )

    dashboard_link = url_for("dashboard", slug=slug, _external=True)
    booking_link = url_for("book", slug=slug, _external=True)
    qr_link = url_for("qr", slug=slug)
    return render_template(
        "created.html",
        salon_name=salon_name,
        dashboard_link=dashboard_link,
        booking_link=booking_link,
        qr_link=qr_link,
        dashboards_link=url_for("owner_dashboards"),
        slug=slug,
    )


@app.route("/dashboard/<slug>")
def dashboard(slug):
    supabase = get_supabase()
    row = sb_fetch_one(
        supabase.table("owners").select("*").eq("slug", slug).limit(1)
    )
    if row is None:
        abort(404)

    if not row["active"]:
        return render_template("inactive.html", salon_name=row["salon_name"])

    bookings = sb_exec(
        supabase.table("bookings").select("*").eq("owner_id", row["id"]).order("created_at", desc=True)
    )

    barbers = json_list(row.get("barbers_json"))
    services = json_list(row.get("services_json"))
    services_pricing = json_list(row.get("services_pricing_json"))
    details = json_dict(row.get("details_json"))
    packages = json_list(row.get("packages_json"))
    reminders = json_dict(row.get("reminders_json"))
    extras = json_dict(row.get("extras_json"))
    booking_settings = json_dict(row.get("booking_settings_json"))
    service_price_map = {
        item.get("name"): item.get("price")
        for item in services_pricing
        if isinstance(item, dict) and item.get("name")
    }
    today = datetime.utcnow().date()
    total_count = len(bookings)
    today_count = 0
    next_seven_count = 0
    recent_bookings = []
    new_today_count = 0
    service_counts = {svc: 0 for svc in services}
    for booking in bookings:
        try:
            booking_date = datetime.strptime(booking["preferred_date"], "%Y-%m-%d").date()
            if booking_date == today:
                today_count += 1
            if 0 <= (booking_date - today).days <= 7:
                next_seven_count += 1
        except (ValueError, TypeError):
            pass
        try:
            created_at = datetime.fromisoformat(booking["created_at"]).date()
            if created_at == today:
                new_today_count += 1
        except (ValueError, TypeError):
            created_at = None
        recent_bookings.append(
            {
                "client_name": booking["client_name"],
                "service": booking["service"],
                "preferred_date": booking["preferred_date"],
                "preferred_time": booking["preferred_time"],
                "created_at": booking["created_at"],
                "is_new": created_at == today if created_at else False,
            }
        )
        svc = booking["service"]
        if svc in service_counts:
            service_counts[svc] += 1
        else:
            service_counts[svc] = 1

    return render_template(
        "dashboard.html",
        salon_name=row["salon_name"],
        theme=row["theme"],
        chairs=row["chairs"],
        open_time=row["open_time"],
        close_time=row["close_time"],
        barbers=barbers,
        services=services,
        details=details,
        slug=row["slug"],
        bookings=bookings,
        total_count=total_count,
        today_count=today_count,
        next_seven_count=next_seven_count,
        service_counts=service_counts,
        service_price_map=service_price_map,
        packages=packages,
        reminders=reminders,
        extras=extras,
        booking_settings=booking_settings,
        recent_bookings=recent_bookings[:6],
        new_today_count=new_today_count,
    )


@app.route("/scan")
def scan_qr_landing():
    slug = request.args.get("slug", "").strip()
    if slug:
        return redirect(url_for("scan_qr", slug=slug))
    return render_template("scan.html", slug=None)


@app.route("/scan/<slug>")
def scan_qr(slug):
    return render_template("scan.html", slug=slug)


@app.route("/book/<slug>", methods=["GET", "POST"])
def book(slug):
    supabase = get_supabase()
    row = sb_fetch_one(
        supabase.table("owners").select("*").eq("slug", slug).limit(1)
    )
    if row is None:
        abort(404)

    services = json_list(row.get("services_json"))
    services_pricing = json_list(row.get("services_pricing_json"))
    packages = json_list(row.get("packages_json"))
    barbers = json_list(row.get("barbers_json"))
    booking_settings = json_dict(row.get("booking_settings_json"))
    service_price_map = {
        item.get("name"): item.get("price")
        for item in services_pricing
        if isinstance(item, dict) and item.get("name")
    }
    if request.method == "POST":
        client_name = request.form.get("client_name", "").strip()
        client_phone = request.form.get("client_phone", "").strip()
        service = request.form.get("service", "").strip()
        if not service:
            service = request.form.get("package_service", "").strip()
        barber_name = request.form.get("barber_name", "").strip()
        preferred_date = request.form.get("preferred_date", "").strip()
        preferred_time = request.form.get("preferred_time", "").strip()
        reminder_enabled = request.form.get("reminder_enabled") == "on"
        reminder_offset = request.form.get("reminder_offset", "60").strip()

        if not client_name or not client_phone or not service:
            return render_template(
                "book.html",
                salon_name=row["salon_name"],
                theme=row["theme"],
                slug=slug,
                services=services,
                service_price_map=service_price_map,
                packages=packages,
                barbers=barbers,
                booking_settings=booking_settings,
                error="Please fill all required fields.",
            )

        if booking_settings.get("show_barbers") and not barber_name:
            return render_template(
                "book.html",
                salon_name=row["salon_name"],
                theme=row["theme"],
                slug=slug,
                services=services,
                service_price_map=service_price_map,
                packages=packages,
                barbers=barbers,
                booking_settings=booking_settings,
                error="Please choose a stylist.",
            )

        if not preferred_date or not preferred_time:
            return render_template(
                "book.html",
                salon_name=row["salon_name"],
                theme=row["theme"],
                slug=slug,
                services=services,
                service_price_map=service_price_map,
                packages=packages,
                barbers=barbers,
                booking_settings=booking_settings,
                error="Please select a date and time.",
            )

        # Prevent double booking for the same time
        check_query = (
            supabase.table("bookings")
            .select("id")
            .eq("owner_id", row["id"])
            .eq("preferred_date", preferred_date)
            .eq("preferred_time", preferred_time)
        )
        if barber_name:
            check_query = check_query.eq("barber_name", barber_name)
        else:
            check_query = check_query.eq("barber_name", "")
        if sb_fetch_one(check_query.limit(1)) is not None:
            return render_template(
                "book.html",
                salon_name=row["salon_name"],
                theme=row["theme"],
                slug=slug,
                services=services,
                service_price_map=service_price_map,
                packages=packages,
                barbers=barbers,
                booking_settings=booking_settings,
                error="This time is already booked. Please select another time.",
            )

        manage_token = secrets.token_urlsafe(24)
        inserted = sb_exec(
            supabase.table("bookings").insert(
                {
                    "owner_id": row["id"],
                    "client_name": client_name,
                    "client_phone": client_phone,
                    "service": service,
                    "preferred_date": preferred_date,
                    "preferred_time": preferred_time,
                    "created_at": datetime.utcnow().isoformat(timespec="seconds"),
                    "barber_name": barber_name or "",
                    "status": "Pending",
                    "manage_token": manage_token,
                }
            )
        )
        booking_id = inserted[0]["id"] if inserted else None
        if reminder_enabled:
            try:
                offset_min = int(reminder_offset)
            except ValueError:
                offset_min = 60
            try:
                appt_dt = datetime.strptime(
                    f"{preferred_date} {preferred_time}",
                    "%Y-%m-%d %H:%M",
                )
                send_at = appt_dt - timedelta(minutes=offset_min)
                now_local = datetime.now()
                if send_at < now_local:
                    send_at = now_local + timedelta(minutes=1)
                if booking_id is not None:
                    sb_exec(
                        supabase.table("reminders").insert(
                            {
                                "booking_id": booking_id,
                                "send_at": send_at.isoformat(timespec="seconds"),
                                "created_at": datetime.now().isoformat(timespec="seconds"),
                            }
                        )
                    )
            except Exception:
                app.logger.exception("Failed to schedule reminder")
        if booking_id is not None:
            sb_exec(
                supabase.table("admin_notifications").insert(
                    {
                        "booking_id": booking_id,
                        "created_at": datetime.utcnow().isoformat(timespec="seconds"),
                    }
                )
            )
        sms_error = None
        manage_path = url_for("manage_booking", token=manage_token)
        manage_link = build_public_url(manage_path)
        try:
            ok, err = send_booking_sms(
                client_phone,
                row["salon_name"],
                client_name,
                preferred_date,
                preferred_time,
                service,
                barber_name,
                manage_link,
            )
            if not ok:
                sms_error = err
                app.logger.warning("SMS send failed: %s", err)
        except Exception:
            sms_error = "SMS failed"
            app.logger.exception("SMS send failed with exception")

        success_msg = "Thanks for booking! We will confirm shortly."
        if sms_error:
            success_msg = f"{success_msg} (SMS not sent)"
        return render_template(
            "book.html",
            salon_name=row["salon_name"],
            theme=row["theme"],
            slug=slug,
            services=services,
            service_price_map=service_price_map,
            packages=packages,
            barbers=barbers,
            booking_settings=booking_settings,
            success=success_msg,
        )

    return render_template(
        "book.html",
        salon_name=row["salon_name"],
        theme=row["theme"],
        slug=slug,
        open_time=row["open_time"],
        close_time=row["close_time"],
        services=services,
        service_price_map=service_price_map,
        packages=packages,
        barbers=barbers,
        booking_settings=booking_settings,
    )


@app.route("/qr/<slug>")
def qr(slug):
    link = url_for("book", slug=slug, _external=True)
    img = qrcode.make(link)
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    return send_file(buffer, mimetype="image/png")


@app.route("/api/availability/<slug>", endpoint="api_availability")
def availability(slug):
    date_str = request.args.get("date", "").strip()
    barber_name = request.args.get("barber", "").strip()
    supabase = get_supabase()
    row = sb_fetch_one(
        supabase.table("owners").select("id, open_time, close_time").eq("slug", slug).limit(1)
    )
    if row is None:
        abort(404)

    try:
        day = datetime.strptime(date_str, "%Y-%m-%d").date()
        open_time = parse_time_value(row.get("open_time"))
        close_time = parse_time_value(row.get("close_time"))
    except (ValueError, TypeError):
        return {"slots": []}

    bookings_query = (
        supabase.table("bookings")
        .select("preferred_time")
        .eq("owner_id", row["id"])
        .eq("preferred_date", day.isoformat())
    )
    if barber_name:
        bookings_query = bookings_query.eq("barber_name", barber_name)
    else:
        bookings_query = bookings_query.eq("barber_name", "")
    bookings = sb_exec(bookings_query)
    booked = {r["preferred_time"] for r in bookings}

    slots = []
    current = datetime.combine(day, open_time)
    end = datetime.combine(day, close_time)
    while current < end:
        slot = current.strftime("%H:%M")
        if slot not in booked:
            slots.append(slot)
        current += timedelta(minutes=60)

    return {"slots": slots}


@app.route("/manage/<token>", methods=["GET", "POST"])
def manage_booking(token):
    supabase = get_supabase()
    booking = sb_fetch_one(
        supabase.table("bookings").select("*").eq("manage_token", token).limit(1)
    )
    if booking is None:
        abort(404)

    owner = sb_fetch_one(
        supabase.table("owners")
        .select("id, salon_name, slug, barbers_json")
        .eq("id", booking["owner_id"])
        .limit(1)
    )
    if owner is None:
        abort(404)
    booking["salon_name"] = owner.get("salon_name")
    booking["slug"] = owner.get("slug")
    barbers = json_list(owner.get("barbers_json"))
    error = None
    success = None

    if request.method == "POST":
        action = request.form.get("action", "").strip()
        if action == "cancel":
            sb_exec(
                supabase.table("bookings")
                .update({"status": "Cancelled"})
                .eq("id", booking["id"])
            )
            ok, err = send_status_sms(
                booking["client_phone"],
                booking["salon_name"],
                booking["client_name"],
                "cancelled",
                booking["preferred_date"],
                booking["preferred_time"],
                booking["service"],
                booking["barber_name"],
            )
            if not ok:
                app.logger.warning("Cancel SMS failed: %s", err)
            success = "Your appointment has been cancelled."
        elif action == "reschedule":
            new_date = request.form.get("preferred_date", "").strip()
            new_time = request.form.get("preferred_time", "").strip()
            new_barber = request.form.get("barber_name", "").strip()
            if not new_date or not new_time or not new_barber:
                error = "Please choose a stylist, date, and time."
            else:
                clash = sb_fetch_one(
                    supabase.table("bookings")
                    .select("id")
                    .eq("owner_id", booking["owner_id"])
                    .eq("preferred_date", new_date)
                    .eq("preferred_time", new_time)
                    .eq("barber_name", new_barber)
                    .neq("id", booking["id"])
                    .limit(1)
                )
                if clash is not None:
                    error = "This time is already booked. Please select another time."
                else:
                    try:
                        reminder_row = sb_fetch_one(
                            supabase.table("reminders")
                            .select("id")
                            .eq("booking_id", booking["id"])
                            .is_("sent_at", "null")
                            .limit(1)
                        )
                        if reminder_row is not None:
                            appt_dt = datetime.strptime(f"{new_date} {new_time}", "%Y-%m-%d %H:%M")
                            send_at = appt_dt - timedelta(minutes=60)
                            now_local = datetime.now()
                            if send_at < now_local:
                                send_at = now_local + timedelta(minutes=1)
                            sb_exec(
                                supabase.table("reminders")
                                .update({"send_at": send_at.isoformat(timespec="seconds")})
                                .eq("id", reminder_row["id"])
                            )
                    except Exception:
                        app.logger.exception("Failed to update reminder")
                    sb_exec(
                        supabase.table("bookings")
                        .update(
                            {
                                "preferred_date": new_date,
                                "preferred_time": new_time,
                                "barber_name": new_barber,
                                "status": "Rescheduled",
                            }
                        )
                        .eq("id", booking["id"])
                    )
                    ok, err = send_status_sms(
                        booking["client_phone"],
                        booking["salon_name"],
                        booking["client_name"],
                        "rescheduled",
                        new_date,
                        new_time,
                        booking["service"],
                        new_barber,
                    )
                    if not ok:
                        app.logger.warning("Reschedule SMS failed: %s", err)
                    success = "Your appointment has been rescheduled."
        else:
            error = "Invalid action."

    return render_template(
        "manage_booking.html",
        booking=booking,
        barbers=barbers,
        error=error,
        success=success,
    )


if __name__ == "__main__":
    thread = threading.Thread(target=reminder_worker, daemon=True)
    thread.start()
    debug = os.getenv("FLASK_DEBUG", "").strip().lower() in ("1", "true", "yes")
    app.run(debug=debug, use_reloader=False)
