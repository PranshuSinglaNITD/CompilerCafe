# main.py - Digital Dining (RAW SQL)
import os
from datetime import datetime
from functools import wraps

from flask import (
    Flask, request, redirect, url_for, session, render_template,
    render_template_string, flash, jsonify
)


from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import session as _session
import pymysql
import pymysql.cursors

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
from datetime import datetime, timedelta


# optional: Gemini chatbot (if you have API key)
# -----------------------------
# Gemini Setup
# -----------------------------
try:
    from dotenv import load_dotenv
    load_dotenv()

    import google.generativeai as genai
    GEMINI_API_KEY = os.getenv("GOOGLE_API_KEY")
    GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemma-3-4b-it")

    if GEMINI_API_KEY:
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel(GEMINI_MODEL)
        GEMINI_AVAILABLE = True
    else:
        GEMINI_AVAILABLE = False

except Exception as e:
    print("❌ Gemini init error:", e)
    GEMINI_AVAILABLE = False


# -----------------------------
# App config
# -----------------------------
app = Flask(__name__)
app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False  
)

app.secret_key = os.getenv("FLASK_SECRET", "secret_key_change_me")


login_manager = LoginManager(app)
login_manager.login_view = "staff_login"

# DB config (XAMPP settings confirmed)
DB_HOST = os.getenv("DB_HOST", "")
DB_USER = os.getenv("DB_USER", "root")
DB_PASS = os.getenv("DB_PASS", "")
DB_NAME = os.getenv("DB_NAME", "digital_dining")

SMTP_EMAIL = os.getenv("SMTP_EMAIL", "YOUR EMAIL HERE")
SMTP_PASS = os.getenv("SMTP_PASS", "YOUR EMAIL CODE HERE")


# -----------------------------
# DB helpers (pymysql)
# -----------------------------
def get_db():
    return pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME,
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True
    )

def fetch_one(query, params=()):
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute(query, params)
            return cur.fetchone()
    finally:
        db.close()

def fetch_all(query, params=()):
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute(query, params)
            return cur.fetchall()
    finally:
        db.close()

def execute(query, params=()):
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute(query, params)
            return cur.lastrowid
    finally:
        db.close()

def execute_many(query, seq_params):
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.executemany(query, seq_params)
            return cur.rowcount
    finally:
        db.close()


def send_otp(email):
    otp = str(random.randint(100000, 999999))
    expires = datetime.now() + timedelta(minutes=5)

    execute(
        "INSERT INTO otp_codes (email, code, expires_at) VALUES (%s,%s,%s)",
        (email, otp, expires)
    )

    msg = MIMEMultipart()
    msg["From"] = f"Compiler Cafe <{SMTP_EMAIL}>"
    msg["To"] = email
    msg["Subject"] = "Your OTP - Compiler Cafe"

    body = f"Your OTP is {otp}. It is valid for 5 minutes."
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(SMTP_EMAIL, SMTP_PASS)
        server.sendmail(SMTP_EMAIL, email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print("SMTP ERROR:", e)
        return False

# -----------------------------
# Create schema helper (run once if tables missing)
# -----------------------------
SCHEMA_SQL = [
"""
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(120) NOT NULL,
  email VARCHAR(200) NOT NULL UNIQUE,
  password_hash VARCHAR(300) NOT NULL,
  role VARCHAR(50) DEFAULT 'customer',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;
""",
"""
CREATE TABLE IF NOT EXISTS staff (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(120) NOT NULL,
  email VARCHAR(200) NOT NULL UNIQUE,
  password_hash VARCHAR(300),
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;
""",
"""
CREATE TABLE IF NOT EXISTS manager (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(120) NOT NULL,
  email VARCHAR(200) NOT NULL UNIQUE,
  password_hash VARCHAR(300),
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;
""",
"""
CREATE TABLE IF NOT EXISTS tables (
  id INT AUTO_INCREMENT PRIMARY KEY,
  number VARCHAR(100) NOT NULL UNIQUE,
  seats INT DEFAULT 4,
  status VARCHAR(50) DEFAULT 'available'
) ENGINE=InnoDB;
""",
"""
CREATE TABLE IF NOT EXISTS menu_categories (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(150) NOT NULL,
  display_order INT DEFAULT 0
) ENGINE=InnoDB;
""",
"""
CREATE TABLE IF NOT EXISTS menu_items (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(250) NOT NULL,
  description TEXT,
  price DOUBLE NOT NULL,
  category_id INT,
  is_available TINYINT(1) DEFAULT 1,
  FOREIGN KEY (category_id) REFERENCES menu_categories(id) ON DELETE SET NULL
) ENGINE=InnoDB;
""",
"""
CREATE TABLE IF NOT EXISTS dining_sessions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  customer_id INT NOT NULL,
  table_id INT NOT NULL,
  staff_id INT,
  started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  ended_at DATETIME NULL,
  is_active TINYINT(1) DEFAULT 1,
  FOREIGN KEY (customer_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (table_id) REFERENCES tables(id) ON DELETE CASCADE
) ENGINE=InnoDB;
""",
"""
CREATE TABLE IF NOT EXISTS orders (
  id INT AUTO_INCREMENT PRIMARY KEY,
  session_id INT NOT NULL,
  status VARCHAR(50) DEFAULT 'Placed',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (session_id) REFERENCES dining_sessions(id) ON DELETE CASCADE
) ENGINE=InnoDB;
""",
"""
CREATE TABLE IF NOT EXISTS order_items (
  id INT AUTO_INCREMENT PRIMARY KEY,
  order_id INT NOT NULL,
  menu_item_id INT NOT NULL,
  name VARCHAR(250) NOT NULL,
  quantity INT DEFAULT 1,
  price_each DOUBLE NOT NULL,
  FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
  FOREIGN KEY (menu_item_id) REFERENCES menu_items(id) ON DELETE SET NULL
) ENGINE=InnoDB;
"""
    ,

"""
CREATE TABLE IF NOT EXISTS otp_codes (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(200) NOT NULL,
  code VARCHAR(10) NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;
"""

]

def create_schema_and_seed():
    # Try to create tables (DB must exist)
    try:
        db = get_db()
    except Exception as e:
        print("⚠ Could not connect to DB. Make sure database exists:", e)
        return

    with db:
        with db.cursor() as cur:
            for sql in SCHEMA_SQL:
                cur.execute(sql)
        db.commit()

    # seed minimal data if empty
    if fetch_one("SELECT COUNT(*) AS c FROM tables") and fetch_one("SELECT COUNT(*) AS c FROM tables")["c"] == 0:
        for i in range(1, 7):
            execute("INSERT INTO tables (number, seats) VALUES (%s, %s)", (f"Table {i}", 4))

   

    if fetch_one("SELECT COUNT(*) AS c FROM manager") and fetch_one("SELECT COUNT(*) AS c FROM manager")["c"] == 0:
        execute("INSERT INTO manager (name, email, password_hash) VALUES (%s,%s,%s)",
                ("Manager", "manager@dining.com", generate_password_hash("1234")))

    

# -----------------------------
# Login wrapper classes for Flask-Login
# -----------------------------
class Customer(UserMixin):
    def __init__(self, row):
        self.id = row["id"]
        self.email = row["email"]
        self.username = row.get("username") or ""
        self.role = row.get("role") or "customer"

    def get_id(self):
        return f"user-{self.id}"

class StaffUser(UserMixin):
    def __init__(self, row):
        self.id = row["id"]
        self.email = row["email"]
        self.name = row.get("name") or ""

    def get_id(self):
        return f"staff-{self.id}"

class ManagerUser(UserMixin):
    def __init__(self, row):
        self.id = row["id"]
        self.email = row["email"]
        self.name = row.get("name") or ""

    def get_id(self):
        return f"manager-{self.id}"

@login_manager.user_loader
def load_user(prefixed_id):
    if not prefixed_id:
        return None
    try:
        role, real_id = prefixed_id.split("-", 1)
    except Exception:
        return None
    if role == "user":
        row = fetch_one("SELECT * FROM users WHERE id=%s", (real_id,))
        return Customer(row) if row else None
    if role == "staff":
        row = fetch_one("SELECT * FROM staff WHERE id=%s", (real_id,))
        print("[DBG] load_user -> staff row:", bool(row))
        print("[DBG] load_user -> staff row:", bool(row))
        return StaffUser(row) if row else None
    if role == "manager":
        row = fetch_one("SELECT * FROM manager WHERE id=%s", (real_id,))
        return ManagerUser(row) if row else None
    return None

# -----------------------------
# Small helpers
# -----------------------------
def require_customer(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.get_id().startswith("user-"):
            flash("Customers only", "danger")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapped

def _prefixed_id():
    try:
        return getattr(current_user, "get_id", lambda: "")() or ""
    except Exception:
        return ""

def is_manager():
    return _prefixed_id().startswith("manager-")

def is_staff():
    return _prefixed_id().startswith("staff-")

def is_customer():
    return _prefixed_id().startswith("user-")

def ensure_cart():
    if "cart" not in session:
        session["cart"] = []
    return session["cart"]

def cart_total(cart):
    return round(sum(item["qty"] * item["price_each"] for item in cart), 2)

# -----------------------------
# Base bootstrap (simple)
# -----------------------------
BASE_BOOTSTRAP = """
<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ title or "Digital Dining" }}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  </head>
  <body class="bg-light">
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
      <div class="container-fluid">
        <a class="navbar-brand" href="/">Digital Dining</a>
        <div class="d-flex">
          {% if current_user.is_authenticated %}
            {% if is_manager() %}<a class="nav-link text-white" href="/manager/dashboard">Manager</a>{% endif %}
            {% if is_staff() %}<a class="nav-link text-white" href="/staff/dashboard">Staff</a>{% endif %}
            <a class="nav-link text-white" href="/logout">Logout</a>
          {% else %}
            <a class="nav-link text-white" href="/login">Login</a>
            <a class="nav-link text-white" href="/signup">Signup</a>
          {% endif %}
          <a class="nav-link text-white" href="/bot">Chatbot</a>
        </div>
      </div>
    </nav>
    <div class="container my-4">
      {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
          {% for cat, msg in messages %}
            <div class="alert alert-{{ cat }}">{{ msg }}</div>
          {% endfor %}
        {% endif %}
      {% endwith %}
      {{ body|safe }}
    </div>
  </body>
</html>
"""

def send_bill_email(to_email, bill_html):
    msg = MIMEMultipart("alternative")
    msg["From"] = f"Compiler Cafe <{SMTP_EMAIL}>"
    msg["To"] = to_email
    msg["Subject"] = "Your Bill - Compiler Cafe"

    part = MIMEText(bill_html, "html")
    msg.attach(part)

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(SMTP_EMAIL, SMTP_PASS)
        server.sendmail(SMTP_EMAIL, to_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print("EMAIL ERROR:", e)
        return False


# -----------------------------
# Routes
# -----------------------------
@app.route("/")
def index():
    tables = fetch_all("SELECT * FROM tables ORDER BY number ASC")
    return render_template("index.html", tables=tables)

# Signup
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not (name and email and password):
            flash("All fields required", "warning")
            return redirect(url_for("signup"))

        # Email must not already exist
        existing = fetch_one("""
            SELECT 1 FROM users WHERE email=%s
            UNION SELECT 1 FROM staff WHERE email=%s
            UNION SELECT 1 FROM manager WHERE email=%s
            LIMIT 1
        """, (email, email, email))

        if existing:
            flash("Email already exists", "danger")
            return redirect(url_for("signup"))

        # Save temporary data in session
        session["signup_temp"] = {
            "name": name,
            "email": email,
            "password": password
        }

        if not send_otp(email):
            flash("Failed to send OTP. Check email config.", "danger")
            return redirect(url_for("signup"))

        flash("OTP sent to your email! Enter it to complete signup.", "info")
        return redirect(url_for("signup_verify"))

    return render_template("signup.html")

@app.route("/signup/verify", methods=["GET", "POST"])
def signup_verify():
    if request.method == "POST":
        otp = (request.form.get("otp") or "").strip()
        temp = session.get("signup_temp")

        if not temp:
            flash("Session expired. Please sign up again.", "danger")
            return redirect(url_for("signup"))

        email = temp["email"]

        row = fetch_one("""
            SELECT * FROM otp_codes
            WHERE email=%s AND code=%s
            ORDER BY created_at DESC
            LIMIT 1
        """, (email, otp))

        if not row:
            flash("Invalid OTP", "danger")
            return redirect(url_for("signup_verify"))

        if datetime.now() > row["expires_at"]:
            flash("OTP expired. Please sign up again.", "danger")
            return redirect(url_for("signup"))

        # Create user in DB
        hashed = generate_password_hash(temp["password"])
        execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (%s,%s,%s,%s)",
            (temp["name"], temp["email"], hashed, "customer")
        )

        # clear temp data
        session.pop("signup_temp", None)

        flash("Account created! Please login.", "success")
        return redirect(url_for("login"))

    return render_template("signup_verify.html")


# Customer login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        # Fetch user
        row = fetch_one("SELECT * FROM users WHERE email=%s LIMIT 1", (email,))
        if not row:
            flash("Invalid credentials", "danger")
            return redirect(url_for("login"))

        # Verify password
        if not check_password_hash(row["password_hash"], password):
            flash("Invalid credentials", "danger")
            return redirect(url_for("login"))

        # Login user
        user_obj = Customer(row)
        login_user(user_obj)
        flash("Login successful!", "success")

        # Retrieve scanned table
        scanned_table_id = session.pop("scanned_table", None)

        # If user scanned a table before logging in
        if scanned_table_id:
            table = fetch_one("SELECT * FROM tables WHERE id=%s", (scanned_table_id,))

            # Auto-reserve table ALWAYS for this customer
            execute("UPDATE tables SET status='reserved' WHERE id=%s", (table["id"],))

            # Start new dining session
            sid = execute("""
                INSERT INTO dining_sessions (customer_id, table_id, staff_id, started_at, ended_at, is_active)
                VALUES (%s, %s, NULL, NOW(), NULL, 1)
            """, (row["id"], table["id"]))

            return redirect(url_for("menu", session_id=sid))

        # If user already has an active dining session → go to menu
        active = fetch_one("""
            SELECT * FROM dining_sessions 
            WHERE customer_id=%s AND is_active=1 
            ORDER BY started_at DESC LIMIT 1
        """, (row["id"],))

        if active:
            return redirect(url_for("menu", session_id=active["id"]))

        # Default redirect → homepage
        return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()

        user = fetch_one("SELECT * FROM users WHERE email=%s", (email,))
        if not user:
            flash("No account found with that email", "danger")
            return redirect(url_for("forgot"))

        session["reset_email"] = email

        if not send_otp(email):
            flash("Failed to send OTP. Try again later.", "danger")
            return redirect(url_for("forgot"))

        flash("OTP sent to your email. Enter it with your new password.", "info")
        return redirect(url_for("forgot_reset"))

    return render_template("forgot.html")
  

@app.route("/forgot/reset", methods=["GET", "POST"])
def forgot_reset():
    if request.method == "POST":
        email = session.get("reset_email")
        otp = (request.form.get("otp") or "").strip()
        new_pw = (request.form.get("password") or "").strip()

        if not email:
            flash("Session expired. Start again.", "danger")
            return redirect(url_for("forgot"))

        if not new_pw:
            flash("New password required", "warning")
            return redirect(url_for("forgot_reset"))

        row = fetch_one("""
            SELECT * FROM otp_codes
            WHERE email=%s AND code=%s
            ORDER BY created_at DESC
            LIMIT 1
        """, (email, otp))

        if not row:
            flash("Invalid OTP", "danger")
            return redirect(url_for("forgot_reset"))

        if datetime.now() > row["expires_at"]:
            flash("OTP expired. Request a new one.", "danger")
            return redirect(url_for("forgot"))

        hashed = generate_password_hash(new_pw)
        execute("UPDATE users SET password_hash=%s WHERE email=%s", (hashed, email))

        session.pop("reset_email", None)

        flash("Password updated! Login with your new password.", "success")
        return redirect(url_for("login"))

    return render_template("forgot_reset.html")



# Logout

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out", "info")
    return redirect(url_for("index"))


@app.route("/otp/request", methods=["POST"])
def request_otp():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()

    if not email:
        return jsonify({"status": "error", "msg": "Email required"})

    # Send OTP
    sent = send_otp(email)

    if not sent:
        return jsonify({"status": "error", "msg": "Failed to send OTP. Check SMTP config."})

    return jsonify({"status": "success", "msg": "OTP sent to your email"})


@app.route("/otp/verify", methods=["POST"])
def verify_otp():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    code = (data.get("otp") or "").strip()

    if not (email and code):
        return jsonify({"status": "error", "msg": "Email and OTP required"})

    row = fetch_one("""
        SELECT * FROM otp_codes
        WHERE email=%s AND code=%s
        ORDER BY created_at DESC
        LIMIT 1
    """, (email, code))

    if not row:
        return jsonify({"status": "error", "msg": "Invalid OTP"})

    if datetime.now() > row["expires_at"]:
        return jsonify({"status": "error", "msg": "OTP expired"})

    # OTP valid → either login existing user or auto-signup
    user = fetch_one("SELECT * FROM users WHERE email=%s LIMIT 1", (email,))

    if user:
        login_user(Customer(user))
        return jsonify({"status": "logged_in", "msg": "Logged in via OTP"})

    # Auto-create user if not exists
    username = email.split("@")[0]
    dummy_pw_hash = generate_password_hash("otp_login")

    new_id = execute("""
        INSERT INTO users (username, email, password_hash, role)
        VALUES (%s,%s,%s,%s)
    """, (username, email, dummy_pw_hash, "customer"))

    new_user = fetch_one("SELECT * FROM users WHERE id=%s", (new_id,))
    login_user(Customer(new_user))

    return jsonify({"status": "signed_up", "msg": "Account created & logged in via OTP"})



# Staff login
@app.route("/staff/login", methods=["GET", "POST"])
def staff_login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        row = fetch_one("SELECT * FROM staff WHERE email=%s LIMIT 1", (email,))
        if not row:
            flash("Invalid staff credentials", "danger")
            return redirect(url_for("staff_login"))

        stored = row.get("password_hash") or ""
        print("LOGIN ROW:", row)
        print("EMAIL ENTERED:", email)
        print("HASH RETRIEVED:", repr(row.get("password_hash")))

        # 🔥 Correct password check
        if check_password_hash(stored, password):
            login_user(StaffUser(row))
            flash("Staff login successful!", "success")
            return redirect(url_for("staff_dashboard"))

        flash("Invalid staff credentials", "danger")
        return redirect(url_for("staff_login"))

    return render_template("staff_login.html")




# Manager login
@app.route("/manager/login", methods=["GET", "POST"])
def manager_login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pw = request.form.get("password", "")

        row = fetch_one("SELECT * FROM manager WHERE email=%s LIMIT 1", (email,))
        if not row:
            flash("Invalid manager credentials", "danger")
            return redirect(url_for("manager_login"))

        if check_password_hash(row["password_hash"], pw):
            login_user(ManagerUser(row))
            flash("Manager logged in!", "success")
            return redirect(url_for("manager_dashboard"))

        # plaintext fallback
        if row["password_hash"] == pw:
            new_hash = generate_password_hash(pw)
            execute("UPDATE manager SET password_hash=%s WHERE id=%s", (new_hash, row["id"]))
            login_user(ManagerUser(row))
            return redirect(url_for("manager_dashboard"))

        flash("Invalid manager credentials", "danger")
        return redirect(url_for("manager_login"))

    return render_template("manager_login.html")

# Scan (QR)
@app.route("/scan")
def scan():
    # Users who are NOT logged in must scan first → then login
    table_number = request.args.get("table")

    if not table_number:
        flash("Invalid QR code", "danger")
        return redirect(url_for("index"))

    # Fetch table info
    table = fetch_one("SELECT * FROM tables WHERE number=%s", (table_number,))
    if not table:
        flash("Table not found!", "danger")
        return redirect(url_for("index"))

    # Save table ID so customer is auto-connected after login
    session["scanned_table"] = table["id"]

    # If user is NOT logged in → go login
    if not current_user.is_authenticated:
        flash(f"Scanned {table['number']} — please login to continue.", "info")
        return redirect(url_for("login"))

    # If staff/manager scans → reject
    uid = current_user.get_id()
    if uid.startswith("staff-") or uid.startswith("manager-"):
        flash("Only customers can scan tables!", "danger")
        return redirect(url_for("index"))

    # At this point user is a CUSTOMER and already logged in

    # Auto-reserve table for this customer ALWAYS
    execute("UPDATE tables SET status='reserved' WHERE id=%s", (table["id"],))

    # Check if customer has an active dining session already
    active = fetch_one("""
        SELECT * FROM dining_sessions 
        WHERE customer_id=%s AND is_active=1 
        ORDER BY started_at DESC LIMIT 1
    """, (current_user.id,))

    if active:
        return redirect(url_for("menu", session_id=active["id"]))

    # Start NEW dining session
    session_id = execute("""
        INSERT INTO dining_sessions (customer_id, table_id, staff_id, started_at, ended_at, is_active)
        VALUES (%s, %s, NULL, NOW(), NULL, 1)
    """, (current_user.id, table["id"]))

    flash(f"Dining session started for {table['number']}!", "success")
    return redirect(url_for("menu", session_id=session_id))


# Menu
@app.route("/menu/<int:session_id>")
@login_required
def menu(session_id):
    ds = fetch_one("SELECT * FROM dining_sessions WHERE id=%s", (session_id,))
    if not ds:
        flash("Session not found", "danger")
        return redirect(url_for("index"))
    if not is_customer() or ds["customer_id"] != current_user.id:
        flash("Unauthorized session access", "danger")
        return redirect(url_for("index"))
    categories = fetch_all("SELECT * FROM menu_categories ORDER BY display_order ASC")
    menu_data = []
    for cat in categories:
        items = fetch_all("SELECT * FROM menu_items WHERE category_id=%s AND is_available=1 ORDER BY name ASC", (cat["id"],))
        if items:
            menu_data.append((cat["name"], items))
    cart = ensure_cart()
    cart_count = sum(i["qty"] for i in cart)
    return render_template("menu.html", session_id=session_id, menu_data=menu_data, cart_count=cart_count)

# Cart add/update/view
@app.route("/cart/add", methods=["POST"])
@login_required
def cart_add():
    if not is_customer():
        flash("Customers only", "danger")
        return redirect(url_for("index"))
    menu_item_id = int(request.form.get("menu_item_id"))
    qty = int(request.form.get("qty", 1))
    session_id = int(request.form.get("session_id"))
    item = fetch_one("SELECT * FROM menu_items WHERE id=%s", (menu_item_id,))
    if not item or not item.get("is_available"):
        flash("Item not available", "danger")
        return redirect(url_for("menu", session_id=session_id))
    cart = ensure_cart()
    for c in cart:
        if c["menu_item_id"] == menu_item_id:
            c["qty"] += qty
            break
    else:
        cart.append({"menu_item_id": menu_item_id, "name": item["name"], "qty": qty, "price_each": float(item["price"])})
    session["cart"] = cart
    flash(f"Added {qty} × {item['name']}", "success")
    return redirect(url_for("menu", session_id=session_id))

@app.route("/cart/update", methods=["POST"])
@login_required
def cart_update():
    if not is_customer():
        flash("Customers only", "danger")
        return redirect(url_for("index"))
    cart = ensure_cart()
    menu_item_id = int(request.form.get("menu_item_id"))
    session_id = int(request.form.get("session_id"))
    action = request.form.get("action")
    for it in list(cart):
        if it["menu_item_id"] == menu_item_id:
            if action == "increase":
                it["qty"] += 1
            elif action == "decrease":
                it["qty"] -= 1
                if it["qty"] <= 0:
                    cart.remove(it)
                    flash("Item removed", "info")
            elif action == "remove":
                cart.remove(it)
                flash("Item removed", "info")
            break
    session["cart"] = cart
    return redirect(url_for("cart_view"))

@app.route("/cart")
@login_required
def cart_view():
    if not is_customer():
        flash("Customers only", "danger")
        return redirect(url_for("index"))
    cart = ensure_cart()
    total = cart_total(cart)
    ds = fetch_one("SELECT * FROM dining_sessions WHERE customer_id=%s AND is_active=1 ORDER BY started_at DESC LIMIT 1", (current_user.id,))
    return render_template("cart.html", cart=cart, total=total, ds=ds)

# Place order
@app.route("/order/place", methods=["POST"])
@login_required
def order_place():
    if not is_customer():
        flash("Customers only", "danger")
        return redirect(url_for("index"))
    cart = ensure_cart()
    if not cart:
        flash("Cart is empty!", "warning")
        return redirect(url_for("cart_view"))
    session_id = int(request.form.get("session_id"))
    ds = fetch_one("SELECT * FROM dining_sessions WHERE id=%s", (session_id,))
    if not ds or ds["customer_id"] != current_user.id:
        flash("Invalid session", "danger")
        return redirect(url_for("cart_view"))
    order_id = execute("INSERT INTO orders (session_id, status) VALUES (%s, 'Placed')", (session_id,))
    for item in cart:
        execute("INSERT INTO order_items (order_id, menu_item_id, name, quantity, price_each) VALUES (%s,%s,%s,%s,%s)",
                (order_id, item["menu_item_id"], item["name"], item["qty"], item["price_each"]))
    session["cart"] = []
    flash(f"Order #{order_id} placed!", "success")
    return redirect(url_for("order_status", session_id=session_id))

# Order status
@app.route("/order/status")
@app.route("/order/status/<int:session_id>")
@login_required
def order_status(session_id=None):
    if not is_customer():
        flash("Forbidden", "danger")
        return redirect(url_for("index"))
    if session_id:
        sess = fetch_one("SELECT * FROM dining_sessions WHERE id=%s", (session_id,))
        if not sess:
            flash("Session not found", "danger")
            return redirect(url_for("index"))
        sessions = [sess]
    else:
        sessions = fetch_all("SELECT * FROM dining_sessions WHERE customer_id=%s ORDER BY started_at DESC", (current_user.id,))
    tables = {}
    orders_map = {}
    for s in sessions:
        table = fetch_one("SELECT * FROM tables WHERE id=%s", (s["table_id"],)) if s else None
        tables[s["id"]] = table["number"] if table else "N/A"
        orders = fetch_all("SELECT * FROM orders WHERE session_id=%s ORDER BY created_at DESC", (s["id"],))
        orders_map[s["id"]] = orders
    return render_template("orders.html", sessions=sessions, tables=tables, orders_map=orders_map)

# View session orders
@app.route("/session/<int:session_id>/orders")
@login_required
def view_session_orders(session_id):
    if not is_customer():
        flash("Customers only", "danger")
        return redirect(url_for("index"))
    ds = fetch_one("SELECT * FROM dining_sessions WHERE id=%s", (session_id,))
    if not ds or ds["customer_id"] != current_user.id:
        flash("Unauthorized session", "danger")
        return redirect(url_for("index"))
    table = fetch_one("SELECT * FROM tables WHERE id=%s", (ds["table_id"],))
    orders = fetch_all("SELECT * FROM orders WHERE session_id=%s ORDER BY created_at DESC", (session_id,))
    order_items = {}
    total = 0
    for o in orders:
        items = fetch_all("SELECT * FROM order_items WHERE order_id=%s", (o["id"],))
        order_items[o["id"]] = items
        for i in items:
            total += i["quantity"] * i["price_each"]
    return render_template("session_orders.html", ds=ds, table=table, orders=orders, order_items=order_items, total=total, session_id=session_id)

# Staff dashboard & actions
@app.route("/staff/dashboard")
@login_required
def staff_dashboard():
    if not is_staff():
        flash("Forbidden — Staff only", "danger")
        return redirect(url_for("staff_login"))

    tables = fetch_all("SELECT * FROM tables ORDER BY number ASC")

    recent_orders = fetch_all("""
        SELECT o.*, ds.table_id, t.number AS table_number
        FROM orders o
        JOIN dining_sessions ds ON ds.id = o.session_id
        JOIN tables t ON t.id = ds.table_id
        ORDER BY o.created_at DESC LIMIT 50
    """)

    return render_template(
        "staff_dashboard.html",
        staff=current_user,      # 🔥 THE MAGIC LINE
        tables=tables,
        recent_orders=recent_orders
    )


@app.route("/staff/orders")
@login_required
def staff_orders():
    if not is_staff():
        flash("Staff only", "danger")
        return redirect(url_for("staff_login"))

    orders = fetch_all("""
    SELECT 
        o.id AS id,
        o.status,
        o.created_at,
        t.number AS table_number
    FROM orders o
    JOIN dining_sessions ds ON ds.id = o.session_id
    JOIN tables t ON t.id = ds.table_id
    WHERE ds.is_active = 1
    ORDER BY o.created_at DESC
    """)


    return render_template("staff_orders.html", orders=orders)


@app.route("/debug/session")
def debug_session():
    info = {
        "is_authenticated": getattr(current_user, "is_authenticated", False),
        "get_id": getattr(current_user, "get_id", lambda: None)(),
        "current_user_repr": repr(current_user)
    }
    return jsonify(info)


@app.route("/staff/tables")
@login_required
def staff_tables():
    if not is_staff():
        flash("Staff only", "danger")
        return redirect(url_for("staff_login"))
    tables = fetch_all("SELECT * FROM tables ORDER BY number ASC")
    return render_template("staff_tables.html", tables=tables)

@app.route("/staff/menu")
@login_required
def staff_menu():
    if not is_staff():
        flash("Staff only", "danger")
        return redirect(url_for("staff_login"))
    items = fetch_all("""SELECT mi.*, mc.name AS category_name
                         FROM menu_items mi
                         LEFT JOIN menu_categories mc ON mc.id = mi.category_id
                         ORDER BY mc.display_order ASC, mi.name ASC""")
    return render_template("staff_menu.html", items=items)

@app.route("/staff/order/update/<int:order_id>", methods=["POST"])
@login_required
def staff_update_order(order_id):
    if not is_staff():
        flash("Staff only", "danger")
        return redirect(url_for("staff_login"))
    new_status = request.form.get("status")
    if new_status not in ("Placed", "Preparing", "Served"):
        flash("Invalid status", "danger")
        return redirect(url_for("staff_orders"))
    execute("UPDATE orders SET status=%s WHERE id=%s", (new_status, order_id))
    # optionally free table if no non-served orders remain for session
    o = fetch_one("SELECT * FROM orders WHERE id=%s", (order_id,))
    # if o:
    #     session_id = o["session_id"]
    #     remaining = fetch_one("SELECT COUNT(*) AS cnt FROM orders WHERE session_id=%s AND status!='Served'", (session_id,))
    #     if remaining and remaining["cnt"] == 0:
    #         ds = fetch_one("SELECT * FROM dining_sessions WHERE id=%s", (session_id,))
    #         if ds:
    #             execute("UPDATE dining_sessions SET is_active=0, ended_at=NOW() WHERE id=%s", (session_id,))
    #             execute("UPDATE tables SET status='available' WHERE id=%s", (ds["table_id"],))
    flash("Order updated", "success")
    return redirect(url_for("staff_orders"))

@app.route("/staff/menu/toggle/<int:item_id>", methods=["POST"])
@login_required

def staff_menu_toggle(item_id):
    if not is_staff():
        flash("Staff only", "danger")
        return redirect(url_for("staff_login"))
    row = fetch_one("SELECT is_available FROM menu_items WHERE id=%s", (item_id,))
    if not row:
        flash("Item not found", "danger")
        return redirect(url_for("staff_menu"))
    current = row["is_available"]
    new_val = 0 if current else 1
    execute("UPDATE menu_items SET is_available=%s WHERE id=%s", (new_val, item_id))
    flash("Toggled availability", "success")
    print("🔥 staff_menu_toggle HIT", item_id)
    return redirect(url_for("staff_menu"))

@app.route("/staff/order/<int:order_id>")
@login_required
def staff_order_detail(order_id):
    if not is_staff():
        flash("Staff only", "danger")
        return redirect(url_for("staff_login"))
    order = fetch_one("SELECT * FROM orders WHERE id=%s", (order_id,))
    if not order:
        flash("Order not found", "danger")
        return redirect(url_for("staff_orders"))
    ds = fetch_one("SELECT * FROM dining_sessions WHERE id=%s", (order["session_id"],))
    table = fetch_one("SELECT * FROM tables WHERE id=%s", (ds["table_id"],)) if ds else None
    items = fetch_all("SELECT * FROM order_items WHERE order_id=%s", (order_id,))
    return render_template("staff_order_detail.html", order=order, table=table, items=items)

# Manager routes
@app.route("/manager/dashboard")
@login_required
def manager_dashboard():
    if not is_manager():
        flash("Manager only", "danger")
        return redirect(url_for("manager_login"))
    # LAST 8 ORDERS
    last_orders = fetch_all("""
        SELECT 
            o.id AS order_id,
            o.status,
            o.created_at,
            t.number AS table_number,
            ds.customer_id
        FROM orders o
        JOIN dining_sessions ds ON ds.id = o.session_id
        JOIN tables t ON t.id = ds.table_id
        ORDER BY o.created_at DESC
        LIMIT 8
    """)
    
    return render_template("manager_dashboard.html", last_orders=last_orders)

@app.route("/manager/menu")
@login_required
def manager_menu_page():
    if not is_manager():
        flash("Manager only", "danger")
        return redirect(url_for("manager_login"))

    items = fetch_all("""
        SELECT mi.*, mc.name AS category_name
        FROM menu_items mi
        LEFT JOIN menu_categories mc ON mc.id = mi.category_id
        ORDER BY mc.display_order ASC, mi.name ASC
    """)

    categories = fetch_all("SELECT * FROM menu_categories ORDER BY display_order ASC")

    return render_template("manager_menu_page.html", items=items, categories=categories)


@app.route("/manager/menu/add", methods=["POST"])
@login_required
def manager_menu_add():
    if not is_manager():
        flash("Manager only", "danger")
        return redirect(url_for("manager_login"))
    name = request.form.get("name", "").strip()
    price = request.form.get("price", "").strip()
    description = request.form.get("description", "").strip()
    category_id = request.form.get("category_id") or None
    if not name or not price:
        flash("Name and price required", "warning")
        return redirect(url_for("manager_dashboard"))
    try:
        price_val = float(price)
    except Exception:
        flash("Invalid price", "warning")
        return redirect(url_for("manager_dashboard"))
    execute("INSERT INTO menu_items (name, description, price, category_id, is_available) VALUES (%s,%s,%s,%s,1)",
            (name, description, price_val, category_id))
    flash("Menu item added", "success")
    return redirect(url_for("manager_dashboard"))

@app.route("/manager/menu/delete/<int:item_id>", methods=["POST"])
@login_required
def manager_menu_delete(item_id):
    if not is_manager():
        flash("Manager only", "danger")
        return redirect(url_for("manager_login"))
    ref = fetch_one("SELECT COUNT(*) AS c FROM order_items WHERE menu_item_id=%s", (item_id,))
    if ref and ref["c"] > 0:
        execute("UPDATE menu_items SET is_available=0 WHERE id=%s", (item_id,))
        flash("Item has historical orders — marked as unavailable instead of deleted", "info")
    else:
        execute("DELETE FROM menu_items WHERE id=%s", (item_id,))
        flash("Item deleted", "info")
    return redirect(url_for("manager_dashboard"))


@app.route("/manager/menu/edit/<int:item_id>", methods=["GET", "POST"])
@login_required
def manager_menu_edit(item_id):
    if not is_manager():
        flash("Manager only", "danger")
        return redirect(url_for("manager_login"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        price = request.form.get("price", "").strip()
        description = request.form.get("description", "").strip()
        category_id = request.form.get("category_id") or None
        is_av = 1 if request.form.get("is_available") == "on" else 0
        if not name or not price:
            flash("Name and price required", "warning")
            return redirect(url_for("manager_menu_edit", item_id=item_id))
        try:
            price_val = float(price)
        except:
            flash("Invalid price", "warning")
            return redirect(url_for("manager_menu_edit", item_id=item_id))
        execute("UPDATE menu_items SET name=%s, description=%s, price=%s, category_id=%s, is_available=%s WHERE id=%s",
                (name, description, price_val, category_id, is_av, item_id))
        flash("Item updated", "success")
        return redirect(url_for("manager_dashboard"))
    item = fetch_one("SELECT * FROM menu_items WHERE id=%s", (item_id,))
    categories = fetch_all("SELECT * FROM menu_categories ORDER BY display_order ASC")
    return render_template("manager_menu_edit.html", item=item, categories=categories)

@app.route("/manager/staff")
@login_required
def manager_staff_page():
    if not is_manager():
        flash("Manager only", "danger")
        return redirect(url_for("manager_login"))

    staff_list = fetch_all("SELECT * FROM staff ORDER BY id ASC")

    return render_template("manager_staff_page.html", staff_list=staff_list)


@app.route("/manager/staff/add", methods=["POST"])
@login_required
def manager_staff_add():
    if not is_manager():
        flash("Manager only", "danger")
        return redirect(url_for("manager_login"))

    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    pw = request.form.get("password", "").strip()

    # VALIDATION
    if not (name and email and pw):
        flash("All fields are required", "warning")
        return redirect(url_for("manager_staff_page"))

    # CHECK EMAIL NOT USED ANYWHERE
    existing = fetch_one("""
        SELECT 1 FROM staff WHERE email=%s
        UNION
        SELECT 1 FROM users WHERE email=%s
        UNION
        SELECT 1 FROM manager WHERE email=%s
        LIMIT 1
    """, (email, email, email))

    if existing:
        flash("Email already exists in the system", "danger")
        return redirect(url_for("manager_staff_page"))

    # HASHED PASSWORD
    hashed_pw = generate_password_hash(pw)

    # INSERT STAFF
    execute(
        "INSERT INTO staff (name, email, password_hash) VALUES (%s, %s, %s)",
        (name, email, hashed_pw)
    )

    flash("Staff added successfully!", "success")
    return redirect(url_for("manager_staff_page"))


@app.route("/manager/staff/delete/<int:staff_id>", methods=["POST"])
@login_required
def manager_staff_delete(staff_id):
    if not is_manager():
        flash("Manager only", "danger")
        return redirect(url_for("manager_login"))

    # Delete staff
    execute("DELETE FROM staff WHERE id=%s", (staff_id,))

    flash("Staff deleted successfully", "info")
    return redirect(url_for("manager_staff_page"))


@app.route("/manager/category")
@login_required
def manager_category_page():
    if not is_manager():
        flash("Manager only", "danger")
        return redirect(url_for("manager_login"))

    categories = fetch_all("SELECT * FROM menu_categories ORDER BY display_order ASC")

    return render_template("manager_category.html", categories=categories)


@app.route("/manager/category/add", methods=["POST"])
@login_required
def manager_category_add():
    if not is_manager():
        flash("Manager only", "danger")
        return redirect(url_for("manager_login"))

    name = request.form.get("name", "").strip()
    order = int(request.form.get("display_order") or 0)

    if not name:
        flash("Name required", "warning")
        return redirect(url_for("manager_category_page"))

    execute("INSERT INTO menu_categories (name, display_order) VALUES (%s,%s)",
            (name, order))

    flash("Category added", "success")
    return redirect(url_for("manager_category_page"))

@app.route("/manager/category/delete/<int:cat_id>", methods=["POST"])
@login_required
def manager_category_delete(cat_id):
    if not is_manager():
        flash("Manager only", "danger")
        return redirect(url_for("manager_login"))

    ref = fetch_one("SELECT COUNT(*) AS c FROM menu_items WHERE category_id=%s", (cat_id,))

    if ref and ref["c"] > 0:
        flash("Cannot delete category with items inside", "warning")
    else:
        execute("DELETE FROM menu_categories WHERE id=%s", (cat_id,))
        flash("Category deleted", "info")

    return redirect(url_for("manager_category_page"))

# -----------------------------
# UPDATED Chatbot API (FULL INTEGRATION)
# -----------------------------
if GEMINI_AVAILABLE:
    genai.configure(api_key=os.getenv("GOOGLE_API_KEY", "AIzaSyAuKGRRGZvHbpQXnUNjIuS5Se1ykYjzvcQ"))
    model = genai.GenerativeModel(os.getenv("GEMINI_MODEL", "gemma-3-4b-it"))
def is_vibe_message(text: str) -> bool:
    vibe_keywords = [
        "recommend", "suggest", "craving", "hungry",
        "food", "eat", "dish", "menu", "meal", "vibe",
        "snack", "serve", "dinner", "lunch", "breakfast",
        "something", "some", "drink"
    ]
    return any(word in text.lower() for word in vibe_keywords)

def get_menu_text():
    items = fetch_all("SELECT * FROM menu_items WHERE is_available=1")
    if not items:
        return "No menu items available."
    return "\n".join(f"- {i['name']} (₹{i['price']}) — {i.get('description','')}"
                     for i in items)

@app.route("/api/chat", methods=["POST"])
def chat_api():
    data = request.get_json() or {}
    user_msg = (data.get("message") or "").strip()
    
    if not user_msg:
        return jsonify({"reply": "Hey, say something first 😅"})

    # -------------------------
    # Detect vibe-based (food/menu) message
    # -------------------------
    if is_vibe_message(user_msg):
        menu_text = get_menu_text()

        prompt = f"""
You are **DineBot**, a restaurant chatbot with strict menu rules:

1. ONLY recommend items that exist in the MENU provided.
2. Never invent new dishes, drinks, flavors, or combos.
3. If something the user asks isn't on the menu, say:
   "Hmm, I don’t have that exact thing, but here’s what I can offer…"
4. Keep tone casual, chill, friendly—like a foodie friend.

USER:
"{user_msg}"

MENU (official list):
{menu_text}

Reply casually but stay 100% loyal to the MENU.
"""

    else:
        # -------------------------
        # Normal conversation (non-food)
        # -------------------------
        prompt = f"""
You are **DineBot**, a friendly foodie chatbot.
The user said: "{user_msg}"

Reply casually, friendly, human-like.
Do NOT recommend dishes unless user asks for food or a vibe-based suggestion.
Just chat normally.
"""

    # -------------------------
    # Generate response
    # -------------------------
    if GEMINI_AVAILABLE:
        try:
            response = model.generate_content(prompt)
            reply = getattr(response, "text", "") or "Hmm… couldn't think of a reply 😅"
        except Exception as e:
            reply = f"😢 Oops, something went wrong: {e}"
    else:
        # fallback (no gemini)
        if is_vibe_message(user_msg):
            reply = f"Here’s what we have on the menu:\n{get_menu_text()}"
        else:
            reply = "Yo! I'm DineBot — talk to me about food or vibes 😄"

    return jsonify({"reply": reply})

#bot 
@app.route("/bot")
def bot_page():
    return render_template("chat.html")


# End dining route (matches your pretty dining_end.html)
@app.route("/end_dining/<int:session_id>", methods=["POST", "GET"])
@login_required
def end_dining(session_id):
    if not is_customer():
        flash("Forbidden", "danger")
        return redirect(url_for("index"))

    ds = fetch_one("SELECT * FROM dining_sessions WHERE id=%s", (session_id,))
    if not ds or ds["customer_id"] != current_user.id:
        flash("Invalid session", "danger")
        return redirect(url_for("index"))

    table = fetch_one("SELECT * FROM tables WHERE id=%s", (ds["table_id"],))

    items = fetch_all("""
        SELECT oi.quantity, oi.price_each
        FROM order_items oi
        JOIN orders o ON oi.order_id = o.id
        WHERE o.session_id=%s
    """, (session_id,))
    
    total = sum(i["quantity"] * i["price_each"] for i in items) if items else 0.0

    # Close session
    execute("UPDATE dining_sessions SET is_active=0, ended_at=NOW() WHERE id=%s", (session_id,))
    execute("UPDATE tables SET status='available' WHERE id=%s", (ds["table_id"],))

    return render_template("dining_end.html", table=table, ds=ds, total=total)

@app.route("/payment/<int:session_id>")
@login_required
def payment_page(session_id):
    ds = fetch_one("SELECT * FROM dining_sessions WHERE id=%s", (session_id,))
    if not ds or ds["customer_id"] != current_user.id:
        flash("Invalid session", "danger")
        return redirect(url_for("index"))

    items = fetch_all("""
        SELECT oi.quantity, oi.price_each
        FROM order_items oi
        JOIN orders o ON oi.order_id = o.id
        WHERE o.session_id=%s
    """, (session_id,))

    subtotal = sum(i["quantity"] * i["price_each"] for i in items)
    tax = round(subtotal * 0.05, 2)
    total = subtotal + tax

    bill = {
        "subtotal": subtotal,
        "tax_amount": tax,
        "discount": 0,
        "total_amount": total
    }

    return render_template("bill_payment.html", bill=bill, session_id=session_id)

@app.route("/payment/confirm/<int:session_id>", methods=["POST"])
@login_required
def payment_confirm(session_id):
    ds = fetch_one("SELECT * FROM dining_sessions WHERE id=%s", (session_id,))
    if not ds or ds["customer_id"] != current_user.id:
        flash("Invalid session", "danger")
        return redirect(url_for("index"))

    items = fetch_all("""
        SELECT oi.name, oi.quantity, oi.price_each
        FROM order_items oi
        JOIN orders o ON oi.order_id = o.id
        WHERE o.session_id=%s
    """, (session_id,))

    subtotal = sum(i["quantity"] * i["price_each"] for i in items)
    tax = round(subtotal * 0.05, 2)
    total = subtotal + tax
    payment_method = request.form.get("payment_method", "upi")

    # Get table
    table = fetch_one("SELECT * FROM tables WHERE id=%s", (ds["table_id"],))

    # Bill Date
    now = datetime.now().strftime("%d %b %Y, %I:%M %p")

    # Build HTML BILL
    bill_html = render_template(
        "email_bill.html",
        items=items,
        subtotal=subtotal,
        tax=tax,
        total=total,
        table=table,
        payment_method=payment_method,
        datetime=now,
        username=current_user.username,
        session_id=session_id
    )

    # Send email
    send_bill_email(current_user.email, bill_html)

    # Log user out after payment
    logout_user()

    return render_template("thank_you_page.html", session={
        "id": session_id,
        "total_amount": total,
        "payment_method": payment_method
    })



# -----------------------------
# Launch app
# -----------------------------
if __name__ == "__main__":
    # create schema & seed defaults (DB must exist)
    create_schema_and_seed()
    print("✅ Ready. DB:", DB_NAME, "User:", DB_USER)
    app.run(host="0.0.0.0", port=5000, debug=True)
