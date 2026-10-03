import os, re, secrets, time
from datetime import datetime
from functools import wraps
from hmac import compare_digest
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///complaints.db")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
)
db = SQLAlchemy(app)
application = app  # AWS Elastic Beanstalk entry point

CATEGORIES = ["Harassment", "Infrastructure", "Academics", "Finance", "Safety", "Other"]
STATUSES = ["Pending", "In Progress", "Resolved", "Rejected"]

CODE_RE = re.compile(r"^[A-F0-9]{10}$")
MAX_TRIES, WINDOW = 5, 600  # 5 lookups per 10 minutes per client
_attempts: dict[str, list[float]] = {}


def rate_limited(key: str) -> bool:
    now = time.time()
    hits = [t for t in _attempts.get(key, []) if now - t < WINDOW]
    _attempts[key] = hits
    if len(hits) >= MAX_TRIES:
        return True
    hits.append(now)
    return False


def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


def csrf_ok() -> bool:
    return compare_digest(request.form.get("csrf", ""), session.get("csrf", "x"))



class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.String(12), unique=True, nullable=False, index=True)
    user_id = db.Column(db.String(64), nullable=False, index=True)  # anonymous alias
    category = db.Column(db.String(40), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default="Pending", nullable=False, index=True)
    admin_note = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


with app.app_context():
    db.create_all()


def admin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get("admin"):
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        f = request.form
        if not csrf_ok():
            flash("Your form expired. Please try again.")
            return redirect(url_for("index"))
        if f.get("category") not in CATEGORIES or not f.get("title", "").strip() or not f.get("description", "").strip():
            flash("Please fill all fields correctly.")
            return redirect(url_for("index"))
        user_id = f.get("user_id", "").strip()[:64] or "anon-" + secrets.token_hex(4)
        c = Complaint(ticket_id=secrets.token_hex(5).upper(), user_id=user_id,
                      category=f["category"], title=f["title"].strip()[:200],
                      description=f["description"].strip())
        db.session.add(c); db.session.commit()
        return render_template("submitted.html", c=c)
    return render_template("index.html", categories=CATEGORIES)


@app.route("/track", methods=["GET", "POST"])
def track():
    """Secure status lookup: tracking code only, submitted by POST so the code
    never lands in the URL, browser history, logs or referrer headers."""
    result, error = None, None
    if request.method == "POST":
        code = request.form.get("code", "").strip().upper().replace(" ", "").replace("-", "")
        client = request.headers.get("X-Forwarded-For", request.remote_addr or "?").split(",")[0].strip()
        if not csrf_ok():
            error = "Your form expired. Please try again."
        elif rate_limited(client):
            error = "Too many attempts. Please wait a few minutes and try again."
        elif not CODE_RE.match(code):
            error = "That tracking code is not valid."
        else:
            # Same generic message whether or not the code exists, so codes
            # cannot be guessed by comparing responses.
            result = Complaint.query.filter_by(ticket_id=code).first()
            if result is None:
                error = "No complaint matches that tracking code."
    resp = app.make_response(render_template("track.html", result=result, error=error,
                                             tries_left=MAX_TRIES))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Robots-Tag"] = "noindex, nofollow"
    return resp



@app.route("/admin/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        pw_hash = generate_password_hash(os.environ.get("ADMIN_PASSWORD", "admin123"))
        if request.form.get("username") == os.environ.get("ADMIN_USER", "admin") and \
                check_password_hash(pw_hash, request.form.get("password", "")):
            session["admin"] = True
            return redirect(url_for("admin"))
        flash("Invalid credentials")
    return render_template("login.html")


@app.route("/admin/logout")
def logout():
    session.clear(); return redirect(url_for("index"))


@app.route("/admin")
@admin_required
def admin():
    cat, st = request.args.get("category", ""), request.args.get("status", "")
    q = Complaint.query
    if cat: q = q.filter_by(category=cat)
    if st: q = q.filter_by(status=st)
    items = q.order_by(Complaint.category, Complaint.created_at.desc()).all()
    grouped = {}
    for c in items:
        grouped.setdefault(c.category, []).append(c)
    counts = {s: Complaint.query.filter_by(status=s).count() for s in STATUSES}
    return render_template("admin.html", grouped=grouped, categories=CATEGORIES,
                           statuses=STATUSES, cat=cat, st=st, counts=counts)


@app.route("/admin/update/<int:cid>", methods=["POST"])
@admin_required
def update(cid):
    c = db.get_or_404(Complaint, cid)
    if request.form.get("status") in STATUSES:
        c.status = request.form["status"]
    c.admin_note = request.form.get("admin_note", "")
    db.session.commit()
    return redirect(request.referrer or url_for("admin"))


if __name__ == "__main__":
    app.run(debug=True)
