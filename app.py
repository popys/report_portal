\
import os
import argparse
from datetime import datetime
from pathlib import Path
from typing import Optional

from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ------------------- Config -------------------
BASE_DIR = Path(__file__).resolve().parent
UPLOAD_FOLDER = BASE_DIR / "uploads"
UPLOAD_FOLDER.mkdir(exist_ok=True)

DEFAULT_ALLOWED_EXTS = {"pdf","doc","docx","xls","xlsx","png","jpg","jpeg","txt","csv"}
ALLOWED_EXTS = set(os.getenv("ALLOWED_EXTS", ",".join(DEFAULT_ALLOWED_EXTS)).split(","))
MAX_MB = int(os.getenv("UPLOAD_MAX_MB", "25"))
MAX_CONTENT_LENGTH = MAX_MB * 1024 * 1024

STATUS_OPTIONS = ["Nuevo", "En revisión", "Completado", "Cerrado"]
PRIORITY_OPTIONS = ["Baja", "Media", "Alta"]
DEFAULT_STATUS = STATUS_OPTIONS[0]
DEFAULT_PRIORITY = PRIORITY_OPTIONS[1]

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", os.urandom(24).hex())
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{BASE_DIR / 'report_portal.db'}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH  # Limit upload size

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# ------------------- Models -------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    filename = db.Column(db.String(255), nullable=True)  # stored name on disk
    original_filename = db.Column(db.String(255), nullable=True)  # original name
    category = db.Column(db.String(120), nullable=True)
    status = db.Column(db.String(50), nullable=False, default=DEFAULT_STATUS)
    priority = db.Column(db.String(20), nullable=False, default=DEFAULT_PRIORITY)
    assigned_to = db.Column(db.String(120), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    user = db.relationship("User", backref=db.backref("reports", lazy=True))

# ------------------- Auth -------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTS

def admin_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return fn(*args, **kwargs)
    return wrapper

# ------------------- Routes -------------------
@app.route("/")
@login_required
def index():
    if current_user.is_admin:
        # Admin sees all reports
        reports = Report.query.order_by(Report.created_at.desc()).all()
    else:
        # Users see only their reports
        reports = Report.query.filter_by(user_id=current_user.id).order_by(Report.created_at.desc()).all()
    return render_template("dashboard.html", reports=reports)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Bienvenido/a", "success")
            return redirect(url_for("index"))
        flash("Usuario o contraseña incorrectos", "danger")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Sesión cerrada", "info")
    return redirect(url_for("login"))

@app.route("/submit", methods=["GET", "POST"])
@login_required
def submit_report():
    if request.method == "POST":
        title = request.form.get("title","").strip()
        description = request.form.get("description","").strip()
        file = request.files.get("file")
        category = request.form.get("category", "").strip()
        notes = request.form.get("notes", "").strip()
        if not title or not description:
            flash("Título y descripción son obligatorios.", "warning")
            return redirect(request.url)

        saved_name = None
        original_name = None
        if file and file.filename:
            if not allowed_file(file.filename):
                flash(f"Archivo no permitido. Extensiones válidas: {', '.join(sorted(ALLOWED_EXTS))}", "warning")
                return redirect(request.url)
            original_name = secure_filename(file.filename)
            # Prefix stored filename with timestamp and user id to avoid collisions
            stored = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{current_user.id}_{original_name}"
            file.save(UPLOAD_FOLDER / stored)
            saved_name = stored

        status_raw = request.form.get("status", "").strip()
        priority_raw = request.form.get("priority", "").strip()
        assigned_raw = request.form.get("assigned_to", "").strip()

        status_value = status_raw if status_raw in STATUS_OPTIONS else DEFAULT_STATUS
        priority_value = priority_raw if priority_raw in PRIORITY_OPTIONS else DEFAULT_PRIORITY
        assigned_to = assigned_raw or None

        rep = Report(
            title=title,
            description=description,
            filename=saved_name,
            original_filename=original_name,
            category=(category or None),
            status=status_value,
            priority=priority_value,
            assigned_to=assigned_to,
            notes=(notes or None),
            user_id=current_user.id
        )
        db.session.add(rep)
        db.session.commit()
        flash("Reporte enviado.", "success")
        return redirect(url_for("index"))
    return render_template(
        "submit_report.html",
        allowed_exts=", ".join(sorted(ALLOWED_EXTS)),
        max_mb=MAX_MB,
        status_choices=STATUS_OPTIONS,
        priority_choices=PRIORITY_OPTIONS,
        default_status=DEFAULT_STATUS,
        default_priority=DEFAULT_PRIORITY,
    )

@app.route("/reports/<int:report_id>")
@login_required
def view_report(report_id):
    rep = Report.query.get_or_404(report_id)
    if (not current_user.is_admin) and (rep.user_id != current_user.id):
        abort(403)
    return render_template("view_report.html", report=rep)

@app.route("/uploads/<path:filename>")
@login_required
def download_file(filename):
    # Allow download only if the file belongs to the current user or user is admin
    rep = Report.query.filter_by(filename=filename).first()
    if rep is None:
        abort(404)
    if (not current_user.is_admin) and (rep.user_id != current_user.id):
        abort(403)
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=True, download_name=rep.original_filename or filename)

# Admin: create users
@app.route("/admin/users/new", methods=["GET", "POST"])
@login_required
@admin_required
def new_user():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        full_name = request.form.get("full_name","").strip()
        password = request.form.get("password","")
        is_admin = bool(request.form.get("is_admin"))
        if not username or not full_name or not password:
            flash("Todos los campos son obligatorios.", "warning")
            return redirect(request.url)
        if User.query.filter_by(username=username).first():
            flash("Ese usuario ya existe.", "danger")
            return redirect(request.url)
        u = User(username=username, full_name=full_name, is_admin=is_admin)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        flash("Usuario creado.", "success")
        return redirect(url_for("index"))
    return render_template("register_user.html")

# ------------------- CLI helpers -------------------
def _init_db():
    db.create_all()
    print("Base de datos inicializada.")

def _create_admin(username: str, password: str, full_name: str):
    if User.query.filter_by(username=username).first():
        print("El usuario ya existe.")
        return
    u = User(username=username, full_name=full_name, is_admin=True)
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    print(f"Admin '{username}' creado.")

def main():
    parser = argparse.ArgumentParser(description="Report Portal")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("run", help="Inicia el servidor Flask (modo desarrollo)")

    sub.add_parser("init-db", help="Crea las tablas de la base de datos")

    ca = sub.add_parser("create-admin", help="Crea un usuario administrador")
    ca.add_argument("--username", required=True)
    ca.add_argument("--password", required=True)
    ca.add_argument("--full-name", required=True)

    args = parser.parse_args()

    if args.command == "run":
        app.run(debug=True)
    elif args.command == "init-db":
        with app.app_context():
            _init_db()
    elif args.command == "create-admin":
        with app.app_context():
            _create_admin(args.username, args.password, args.full_name)

if __name__ == "__main__":
    main()
