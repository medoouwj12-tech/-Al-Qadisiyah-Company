"""Local-first raw materials inventory application.

Run `python server.py --create-admin` once to create the first manager, then
`python server.py`. SQLite is stored beside this file and remains after restart.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
import secrets
import shutil
import sqlite3
import time
from datetime import date, datetime, timedelta
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("RAKHAM_DB", ROOT / "raw_materials.db"))
BACKUP_DIR = Path(os.environ.get("RAKHAM_BACKUPS", ROOT / "backups"))
SESSION_TTL = 60 * 60 * 12
DEFAULT_PERMISSIONS = {"materials.read": True, "purchases.create": True,
                       "sales.create": True, "movements.read_own": True}


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    db = sqlite3.connect(DB_PATH, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA busy_timeout=15000")
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return salt.hex() + ":" + digest.hex()


def check_password(password: str, saved: str) -> bool:
    try:
        salt_hex, digest_hex = saved.split(":", 1)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 310_000)
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def initialize() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connect() as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript("""
          CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
            display_name TEXT NOT NULL, password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('manager','employee')),
            permissions TEXT NOT NULL DEFAULT '{}', active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
          CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at INTEGER NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
          CREATE TABLE IF NOT EXISTS suppliers (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL, contact TEXT DEFAULT '', phone TEXT DEFAULT '',
            email TEXT DEFAULT '', address TEXT DEFAULT '', country TEXT DEFAULT '',
            category TEXT DEFAULT '', notes TEXT DEFAULT '', active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
          CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL, contact TEXT DEFAULT '', phone TEXT DEFAULT '',
            email TEXT DEFAULT '', address TEXT DEFAULT '', notes TEXT DEFAULT '', active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
          CREATE TABLE IF NOT EXISTS warehouses (
            id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, location TEXT DEFAULT '', active INTEGER NOT NULL DEFAULT 1);
          CREATE TABLE IF NOT EXISTS materials (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL, sku TEXT UNIQUE NOT NULL,
            category TEXT DEFAULT '', unit TEXT NOT NULL DEFAULT 'طن', stock REAL NOT NULL DEFAULT 0,
            min_stock REAL NOT NULL DEFAULT 0, purchase_price REAL NOT NULL DEFAULT 0,
            sale_price REAL NOT NULL DEFAULT 0, supplier_id INTEGER REFERENCES suppliers(id) ON DELETE SET NULL,
            warehouse_id INTEGER REFERENCES warehouses(id), updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
          CREATE TABLE IF NOT EXISTS movements (
            id INTEGER PRIMARY KEY, type TEXT NOT NULL CHECK(type IN ('receipt','sale','adjustment','return')),
            material_id INTEGER NOT NULL REFERENCES materials(id), quantity REAL NOT NULL CHECK(quantity > 0),
            party TEXT NOT NULL DEFAULT '', user_id INTEGER NOT NULL REFERENCES users(id),
            unit_cost REAL NOT NULL DEFAULT 0, unit_sale REAL NOT NULL DEFAULT 0,
            notes TEXT DEFAULT '', reference TEXT DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
          CREATE TABLE IF NOT EXISTS operation_keys (
            key TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
            request_hash TEXT NOT NULL, movement_id INTEGER NOT NULL REFERENCES movements(id),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
          CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            username TEXT DEFAULT '', action TEXT NOT NULL, entity TEXT NOT NULL,
            entity_id TEXT DEFAULT '', details TEXT DEFAULT '{}', ip TEXT DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
          CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY, username TEXT NOT NULL, ip TEXT NOT NULL, success INTEGER NOT NULL,
            created_at INTEGER NOT NULL);
          CREATE INDEX IF NOT EXISTS movement_date_idx ON movements(created_at);
          CREATE INDEX IF NOT EXISTS movement_material_idx ON movements(material_id);
          CREATE INDEX IF NOT EXISTS movement_user_idx ON movements(user_id);
          CREATE INDEX IF NOT EXISTS audit_date_idx ON audit_log(created_at);
          INSERT OR IGNORE INTO warehouses(id,name,location) VALUES(1,'المخزن الرئيسي','');
        """)
        # Upgrade databases created by the earlier prototype without losing records.
        columns = {r[1] for r in db.execute("PRAGMA table_info(suppliers)")}
        for name, decl in (("email", "TEXT DEFAULT ''"), ("address", "TEXT DEFAULT ''"),
                           ("country", "TEXT DEFAULT ''"), ("active", "INTEGER NOT NULL DEFAULT 1")):
            if name not in columns:
                db.execute(f"ALTER TABLE suppliers ADD COLUMN {name} {decl}")
        material_cols = {r[1] for r in db.execute("PRAGMA table_info(materials)")}
        if "warehouse_id" not in material_cols:
            db.execute("ALTER TABLE materials ADD COLUMN warehouse_id INTEGER REFERENCES warehouses(id)")
            db.execute("UPDATE materials SET warehouse_id=1")
        user_cols = {r[1] for r in db.execute("PRAGMA table_info(users)")}
        if "permissions" not in user_cols:
            db.execute("ALTER TABLE users ADD COLUMN permissions TEXT NOT NULL DEFAULT '{}' ")
            db.execute("UPDATE users SET permissions=? WHERE role='employee'", (json.dumps(DEFAULT_PERMISSIONS),))
        movement_cols = {r[1] for r in db.execute("PRAGMA table_info(movements)")}
        if "reference" not in movement_cols:
            db.execute("ALTER TABLE movements ADD COLUMN reference TEXT DEFAULT ''")


def create_manager(username: str, display_name: str, password: str) -> None:
    if len(username) < 3 or len(password) < 12 or not display_name.strip():
        raise ValueError("اسم المستخدم 3 أحرف على الأقل، وكلمة المرور 12 حرفًا على الأقل.")
    with connect() as db:
        if db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            raise ValueError("يوجد مستخدم بالفعل. أعد تعيين الحساب من داخل النظام.")
        db.execute("INSERT INTO users(username,display_name,password_hash,role,permissions) VALUES(?,?,?,'manager','{}')",
                   (username.strip(), display_name.strip(), password_hash(password)))


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class AppHandler(BaseHTTPRequestHandler):
    server_version = "Rakham/2.0"

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"{self.log_date_time_string()} {self.address_string()} {fmt % args}")

    def send_json(self, payload: object, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; script-src 'self' 'unsafe-inline'; img-src 'self' data:")
        self.end_headers()
        self.wfile.write(body)

    def send_static(self, path: str) -> None:
        file = ROOT / ("index.html" if path in ("/", "/index.html") else path.lstrip("/"))
        if not file.is_file() or ROOT.resolve() not in file.resolve().parents:
            self.send_error(404); return
        body = file.read_bytes()
        kind = {".html": "text/html", ".css": "text/css", ".js": "text/javascript", ".jpg": "image/jpeg"}.get(file.suffix, "application/octet-stream")
        self.send_response(200)
        self.send_header("Content-Type", kind + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers(); self.wfile.write(body)

    def body(self) -> dict:
        size = int(self.headers.get("Content-Length", "0"))
        if size > 100_000: raise ValueError("البيانات أكبر من الحد المسموح")
        raw = self.rfile.read(size)
        parsed = json.loads(raw or b"{}")
        if not isinstance(parsed, dict): raise ValueError("صيغة البيانات غير صالحة")
        return parsed

    def client_ip(self) -> str:
        return self.client_address[0]

    def current_user(self) -> sqlite3.Row | None:
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        morsel = cookie.get("rm_session")
        if not morsel: return None
        with connect() as db:
            return db.execute("""SELECT u.id,u.username,u.display_name,u.role,u.permissions
                FROM sessions s JOIN users u ON u.id=s.user_id
                WHERE s.token_hash=? AND s.expires_at>? AND u.active=1""",
                (token_digest(morsel.value), int(time.time()))).fetchone()

    def require_user(self) -> sqlite3.Row | None:
        user = self.current_user()
        if not user: self.send_json({"error": "سجل الدخول أولًا"}, 401)
        return user

    def require_manager(self) -> sqlite3.Row | None:
        user = self.require_user()
        if user and user["role"] != "manager":
            self.send_json({"error": "الصلاحية دي للمدير العام فقط"}, 403); return None
        return user

    def allowed(self, user: sqlite3.Row, permission: str) -> bool:
        return user["role"] == "manager" or bool(json.loads(user["permissions"] or "{}").get(permission))

    def audit(self, db: sqlite3.Connection, user: sqlite3.Row | None, action: str,
              entity: str, entity_id: object = "", details: dict | None = None) -> None:
        db.execute("INSERT INTO audit_log(user_id,username,action,entity,entity_id,details,ip) VALUES(?,?,?,?,?,?,?)",
                   (user["id"] if user else None, user["username"] if user else "", action, entity,
                    str(entity_id), json.dumps(details or {}, ensure_ascii=False), self.client_ip()))

    def csrf_ok(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin: return True  # same-origin clients may omit Origin
        host = self.headers.get("Host", "")
        return origin in (f"http://{host}", f"https://{host}")

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in ("/", "/index.html", "/app.css", "/app.js", "/assets/alqadsia-logo.jpg", "/assets/alqadsia-mark.jpg"):
            self.send_static(path); return
        user = self.require_user()
        if not user: return
        manager = user["role"] == "manager"
        with connect() as db:
            if path == "/api/me":
                self.send_json({"user": {"id": user["id"], "username": user["username"],
                    "display_name": user["display_name"], "role": user["role"],
                    "permissions": json.loads(user["permissions"] or "{}")}}); return
            if path == "/api/dashboard":
                today = date.today().isoformat()
                sales_owner = "" if manager else " AND user_id=?"
                sales_params = (today,) if manager else (today, user["id"])
                stats = db.execute("""SELECT (SELECT COUNT(*) FROM materials) material_count,
                    (SELECT COUNT(*) FROM suppliers WHERE active=1) supplier_count,
                    (SELECT COALESCE(SUM(quantity),0) FROM movements WHERE type='sale' AND date(created_at)=?""" + sales_owner + ") sales_count,\
                    (SELECT COUNT(*) FROM materials WHERE stock<=min_stock) low_stock", sales_params).fetchone()
                own = "" if manager else " WHERE m.user_id=?"
                params = () if manager else (user["id"],)
                moves = db.execute(f"""SELECT m.id,m.type,m.quantity,m.party,m.notes,m.created_at,
                    a.name material_name,a.unit,u.display_name FROM movements m JOIN materials a ON a.id=m.material_id
                    JOIN users u ON u.id=m.user_id {own} ORDER BY m.created_at DESC LIMIT 7""", params).fetchall()
                result = {"stats": dict(stats), "movements": [dict(x) for x in moves]}
                if manager:
                    result["stats"]["today_revenue"] = db.execute("SELECT COALESCE(SUM(quantity*unit_sale),0) FROM movements WHERE type='sale' AND date(created_at)=?", (today,)).fetchone()[0]
                    result["stats"]["today_profit"] = db.execute("SELECT COALESCE(SUM(quantity*(unit_sale-unit_cost)),0) FROM movements WHERE type='sale' AND date(created_at)=?", (today,)).fetchone()[0]
                    result["weekly"] = [dict(x) for x in db.execute("""SELECT date(created_at) day,
                        SUM(CASE WHEN type='sale' THEN quantity*unit_sale ELSE 0 END) revenue,
                        SUM(CASE WHEN type='receipt' THEN quantity*unit_cost ELSE 0 END) purchases
                        FROM movements WHERE created_at>=date('now','-6 days') GROUP BY date(created_at) ORDER BY day""").fetchall()]
                self.send_json(result); return
            if path == "/api/materials":
                if not self.allowed(user, "materials.read"):
                    self.send_json({"error": "لا تملك صلاحية عرض المخزون"}, 403); return
                cols = "a.id,a.name,a.sku,a.category,a.unit,a.stock,a.min_stock,a.purchase_price,s.name supplier,w.name warehouse"
                if manager: cols += ",a.sale_price"
                rows = db.execute(f"SELECT {cols} FROM materials a LEFT JOIN suppliers s ON s.id=a.supplier_id LEFT JOIN warehouses w ON w.id=a.warehouse_id ORDER BY a.name").fetchall()
                self.send_json({"materials": [dict(x) for x in rows]}); return
            if path.startswith("/api/materials/"):
                if not self.allowed(user, "materials.read"):
                    self.send_json({"error": "لا تملك صلاحية عرض المخزون"}, 403); return
                try: material_id = int(path.rsplit("/", 1)[1])
                except ValueError:
                    self.send_json({"error": "رقم الخامة غير صالح"}, 400); return
                cols = "a.id,a.name,a.sku,a.category,a.unit,a.stock,a.min_stock,a.purchase_price,a.updated_at,"
                cols += "s.id supplier_id,s.name supplier,s.contact supplier_contact,s.phone supplier_phone,s.email supplier_email,s.address supplier_address,s.country supplier_country,s.category supplier_category,w.name warehouse"
                if manager: cols += ",a.sale_price,s.notes supplier_notes"
                material = db.execute(f"SELECT {cols} FROM materials a LEFT JOIN suppliers s ON s.id=a.supplier_id LEFT JOIN warehouses w ON w.id=a.warehouse_id WHERE a.id=?", (material_id,)).fetchone()
                if not material:
                    self.send_json({"error": "الخامة غير موجودة"}, 404); return
                all_history = manager or self.allowed(user, "movements.read_all")
                where = "WHERE m.material_id=?" if all_history else "WHERE m.material_id=? AND m.user_id=?"
                params = (material_id,) if all_history else (material_id,user["id"])
                history_cols = "m.id,m.type,m.quantity,m.party,m.notes,m.reference,m.unit_cost,m.created_at,u.display_name"
                if manager: history_cols += ",m.unit_sale"
                history = db.execute(f"SELECT {history_cols} FROM movements m JOIN users u ON u.id=m.user_id {where} ORDER BY m.created_at DESC LIMIT 200", params).fetchall()
                recent = [dict(x) for x in history]
                supplies = []
                for row in recent:
                    if row["type"] == "receipt":
                        supplies.append({"supplier":row["party"],"quantity":row["quantity"],"unit_cost":row["unit_cost"],"notes":row["notes"],"reference":row["reference"],"created_at":row["created_at"]})
                self.send_json({"material":dict(material),"history":recent,"supply_history":supplies}); return
            if path == "/api/suppliers":
                cols = "id,name,contact,phone,category" + (",email,address,country,notes,active" if manager else "")
                rows = db.execute(f"SELECT {cols} FROM suppliers WHERE active=1 ORDER BY name").fetchall()
                self.send_json({"suppliers": [dict(x) for x in rows]}); return
            if path == "/api/customers":
                if not manager:
                    self.send_json({"error": "الصلاحية دي للمدير العام فقط"}, 403); return
                self.send_json({"customers": [dict(x) for x in db.execute("SELECT * FROM customers WHERE active=1 ORDER BY name").fetchall()]}); return
            if path == "/api/warehouses":
                self.send_json({"warehouses": [dict(x) for x in db.execute("SELECT id,name,location FROM warehouses WHERE active=1 ORDER BY id").fetchall()]}); return
            if path == "/api/movements":
                if not manager and not self.allowed(user, "movements.read_all"):
                    where, params = "WHERE m.user_id=?", (user["id"],)
                else: where, params = "", ()
                cols = "m.id,m.type,m.quantity,m.party,m.notes,m.created_at,a.name material_name,a.unit,u.display_name,m.unit_cost"
                if manager: cols += ",m.unit_sale"
                rows = db.execute(f"""SELECT {cols} FROM movements m JOIN materials a ON a.id=m.material_id
                    JOIN users u ON u.id=m.user_id {where} ORDER BY m.created_at DESC LIMIT 500""", params).fetchall()
                self.send_json({"movements": [dict(x) for x in rows]}); return
            if path == "/api/users":
                if not self.require_manager(): return
                self.send_json({"users": [dict(x) for x in db.execute("SELECT id,username,display_name,role,permissions,active,created_at FROM users ORDER BY id").fetchall()]}); return
            if path == "/api/audit":
                if not self.require_manager(): return
                rows = db.execute("SELECT id,username,action,entity,entity_id,details,ip,created_at FROM audit_log ORDER BY id DESC LIMIT 500").fetchall()
                self.send_json({"events": [dict(x) for x in rows]}); return
            if path == "/api/reports":
                if not self.require_manager(): return
                start = self.headers.get("X-Date-From", date.today().replace(day=1).isoformat())
                end = self.headers.get("X-Date-To", date.today().isoformat())
                rows = db.execute("""SELECT m.id,m.type,m.quantity,m.party,m.notes,m.created_at,a.name material_name,a.unit,
                    u.display_name,m.unit_cost,m.unit_sale FROM movements m JOIN materials a ON a.id=m.material_id
                    JOIN users u ON u.id=m.user_id WHERE date(m.created_at) BETWEEN ? AND ? ORDER BY m.created_at DESC""", (start, end)).fetchall()
                self.send_json({"movements": [dict(x) for x in rows], "date_from": start, "date_to": end}); return
        self.send_json({"error": "المسار غير موجود"}, 404)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try: data = self.body()
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            self.send_json({"error": "البيانات المرسلة غير صالحة"}, 400); return
        if not self.csrf_ok():
            self.send_json({"error": "تم رفض الطلب"}, 403); return
        if path == "/api/login":
            username, password = str(data.get("username", "")).strip(), str(data.get("password", ""))
            ip = self.client_ip()
            with connect() as db:
                recent = db.execute("SELECT COUNT(*) FROM login_attempts WHERE ip=? AND success=0 AND created_at>?", (ip, int(time.time())-900)).fetchone()[0]
                account = db.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
                valid = bool(account and check_password(password, account["password_hash"]))
                db.execute("INSERT INTO login_attempts(username,ip,success,created_at) VALUES(?,?,?,?)", (username, ip, int(valid), int(time.time())))
                if valid:
                    token = secrets.token_urlsafe(32)
                    db.execute("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)", (token_digest(token), account["id"], int(time.time())+SESSION_TTL))
                    self.audit(db, account, "login", "session")
                else:
                    self.audit(db, None, "login_failed", "session", details={"username": username})
            if recent >= 10 or not valid:
                self.send_json({"error": "اسم المستخدم أو كلمة المرور غير صحيحة"}, 429 if recent >= 10 else 401); return
            secure = "; Secure" if self.headers.get("X-Forwarded-Proto") == "https" else ""
            self.send_response(200); self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Set-Cookie", f"rm_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_TTL}" + secure)
            self.send_header("Cache-Control", "no-store"); self.end_headers()
            self.wfile.write(json.dumps({"user": {"id": account["id"], "username": account["username"], "display_name": account["display_name"], "role": account["role"]}}, ensure_ascii=False).encode()); return
        if path == "/api/logout":
            cookie = SimpleCookie(self.headers.get("Cookie", "")); morsel = cookie.get("rm_session")
            if morsel:
                with connect() as db:
                    user = self.current_user(); self.audit(db, user, "logout", "session")
                    db.execute("DELETE FROM sessions WHERE token_hash=?", (token_digest(morsel.value),))
            self.send_response(200); self.send_header("Set-Cookie", "rm_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
            self.send_header("Content-Type", "application/json; charset=utf-8"); self.end_headers(); self.wfile.write(b'{"ok":true}'); return
        user = self.require_user()
        if not user: return
        try:
            with connect() as db:
                if path == "/api/suppliers":
                    if not self.require_manager(): return
                    name = str(data.get("name", "")).strip()
                    if not name: self.send_json({"error": "اكتب اسم المورد"}, 400); return
                    cur = db.execute("INSERT INTO suppliers(name,contact,phone,email,address,country,category,notes) VALUES(?,?,?,?,?,?,?,?)",
                        tuple(str(data.get(k, "")).strip() for k in ("name","contact","phone","email","address","country","category","notes")))
                    self.audit(db,user,"create","supplier",cur.lastrowid,{"name":name})
                    db.commit()
                    self.send_json({"ok": True, "id": cur.lastrowid}, 201); return
                if path == "/api/customers":
                    if not self.require_manager(): return
                    name = str(data.get("name", "")).strip()
                    if not name: self.send_json({"error": "اكتب اسم العميل"},400); return
                    cur=db.execute("INSERT INTO customers(name,contact,phone,email,address,notes) VALUES(?,?,?,?,?,?)", tuple(str(data.get(k,"")).strip() for k in ("name","contact","phone","email","address","notes")))
                    self.audit(db,user,"create","customer",cur.lastrowid,{"name":name})
                    db.commit()
                    self.send_json({"ok":True,"id":cur.lastrowid},201); return
                if path == "/api/materials":
                    if not self.require_manager(): return
                    name, sku = str(data.get("name", "")).strip(), str(data.get("sku", "")).strip().upper()
                    if not name or not sku: self.send_json({"error": "اسم المادة وكودها مطلوبان"}, 400); return
                    stock=max(0,float(data.get("stock",0))); cost=max(0,float(data.get("purchase_price",0)))
                    cur=db.execute("""INSERT INTO materials(name,sku,category,unit,stock,min_stock,purchase_price,sale_price,supplier_id,warehouse_id)
                        VALUES(?,?,?,?,?,?,?,?,?,?)""", (name,sku,str(data.get("category","")).strip(),str(data.get("unit","طن")).strip(),stock,max(0,float(data.get("min_stock",0))),cost,max(0,float(data.get("sale_price",0))),int(data["supplier_id"]) if data.get("supplier_id") else None,int(data.get("warehouse_id",1))))
                    if stock:
                        db.execute("INSERT INTO movements(type,material_id,quantity,party,user_id,unit_cost,notes,reference) VALUES('receipt',?,?,?, ?,?,?,?)",(cur.lastrowid,stock,"رصيد افتتاحي",user["id"],cost,"رصيد افتتاحي موثق","OPENING"))
                    self.audit(db,user,"create","material",cur.lastrowid,{"sku":sku,"opening_stock":stock})
                    db.commit()
                    self.send_json({"ok":True,"id":cur.lastrowid},201); return
                if path == "/api/users":
                    if not self.require_manager(): return
                    username, display_name, password = str(data.get("username","")).strip(),str(data.get("display_name","")).strip(),str(data.get("password",""))
                    if len(username)<3 or not display_name or len(password)<12:
                        self.send_json({"error":"اسم المستخدم 3 أحرف وكلمة المرور 12 حرفًا على الأقل"},400); return
                    perms={k:bool(v) for k,v in data.get("permissions",DEFAULT_PERMISSIONS).items() if k in ("materials.read","purchases.create","sales.create","movements.read_all","movements.read_own")}
                    cur=db.execute("INSERT INTO users(username,display_name,password_hash,role,permissions) VALUES(?,?,?,'employee',?)",(username,display_name,password_hash(password),json.dumps(perms)))
                    self.audit(db,user,"create","user",cur.lastrowid,{"username":username,"permissions":perms})
                    db.commit()
                    self.send_json({"ok":True,"id":cur.lastrowid},201); return
                if path == "/api/movements":
                    typ=str(data.get("type","")); qty=float(data.get("quantity",0)); mid=int(data.get("material_id",0))
                    if typ not in ("receipt","sale") or qty<=0 or qty>1e9:
                        self.send_json({"error":"راجع نوع الحركة والكمية"},400); return
                    permission="purchases.create" if typ=="receipt" else "sales.create"
                    if not self.allowed(user,permission):
                        self.send_json({"error":"لا تملك صلاحية تسجيل هذه الحركة"},403); return
                    idem_key=str(self.headers.get("Idempotency-Key") or data.get("idempotency_key", "")).strip()
                    if len(idem_key)<16 or len(idem_key)>128:
                        self.send_json({"error":"مفتاح منع التكرار مطلوب وصيغته غير صالحة"},400); return
                    normalized=json.dumps({"type":typ,"quantity":qty,"material_id":mid,"party":str(data.get("party","")).strip(),"notes":str(data.get("notes","")).strip()},sort_keys=True,ensure_ascii=False)
                    req_hash=hashlib.sha256(normalized.encode()).hexdigest()
                    db.execute("BEGIN IMMEDIATE")
                    prior=db.execute("SELECT user_id,request_hash,movement_id FROM operation_keys WHERE key=?",(idem_key,)).fetchone()
                    if prior:
                        if prior["user_id"]!=user["id"] or prior["request_hash"]!=req_hash:
                            self.send_json({"error":"تم استخدام مفتاح العملية لطلب مختلف"},409); return
                        self.send_json({"ok":True,"id":prior["movement_id"],"duplicate":True},200); return
                    material=db.execute("SELECT * FROM materials WHERE id=?",(mid,)).fetchone()
                    if not material: self.send_json({"error":"الخامة غير موجودة"},404); return
                    party=str(data.get("party","")).strip()
                    if typ=="receipt":
                        cost=float(data.get("unit_cost",material["purchase_price"]))
                        if cost<0: self.send_json({"error":"سعر الشراء غير صالح"},400); return
                        new_stock=material["stock"]+qty
                        avg_cost=((material["stock"]*material["purchase_price"])+(qty*cost))/new_stock
                        db.execute("UPDATE materials SET stock=?,purchase_price=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(new_stock,avg_cost,mid))
                        unit_cost,unit_sale=cost,0
                    else:
                        cur=db.execute("UPDATE materials SET stock=stock-?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND stock>=?",(qty,mid,qty))
                        if cur.rowcount!=1:
                            self.send_json({"error":"الكمية المطلوبة أكبر من المخزون المتاح"},400); return
                        unit_cost,unit_sale=material["purchase_price"],material["sale_price"]
                    cur=db.execute("INSERT INTO movements(type,material_id,quantity,party,user_id,unit_cost,unit_sale,notes,reference) VALUES(?,?,?,?,?,?,?,?,?)",
                        (typ,mid,qty,party,user["id"],unit_cost,unit_sale,str(data.get("notes","")).strip(),str(data.get("reference","")).strip()))
                    db.execute("INSERT INTO operation_keys(key,user_id,request_hash,movement_id) VALUES(?,?,?,?)",(idem_key,user["id"],req_hash,cur.lastrowid))
                    self.audit(db,user,"create", "purchase" if typ=="receipt" else "sale",cur.lastrowid,{"material_id":mid,"quantity":qty,"party":party})
                    db.commit()
                    self.send_json({"ok":True,"id":cur.lastrowid},201); return
                if path == "/api/backups":
                    if not self.require_manager(): return
                    BACKUP_DIR.mkdir(parents=True,exist_ok=True)
                    target=BACKUP_DIR / f"raw_materials-{datetime.now().strftime('%Y%m%d-%H%M%S')}.db"
                    with connect() as source, sqlite3.connect(target) as dest: source.backup(dest)
                    self.audit(db,user,"backup","database",target.name)
                    db.commit()
                    self.send_json({"ok":True,"file":target.name},201); return
        except sqlite3.IntegrityError as exc:
            message="اسم المستخدم أو كود الصنف مستخدم بالفعل" if "UNIQUE" in str(exc) else "تعذر حفظ البيانات بسبب ارتباط غير صالح"
            self.send_json({"error":message},409); return
        except (ValueError,TypeError,OverflowError):
            self.send_json({"error":"تأكد من كتابة بيانات وأرقام صحيحة"},400); return
        self.send_json({"error":"المسار غير موجود"},404)


def main() -> None:
    parser=argparse.ArgumentParser(description="نظام رخام لإدارة المواد الخام")
    parser.add_argument("--create-admin",action="store_true",help="إنشاء حساب المدير الأول تفاعليًا")
    args=parser.parse_args(); initialize()
    if args.create_admin:
        import getpass
        try:
            create_manager(input("اسم المستخدم: "),input("الاسم الظاهر: "),getpass.getpass("كلمة المرور (12 حرفًا على الأقل): "))
            print("تم إنشاء المدير. شغّل python server.py لبدء النظام.")
        except ValueError as exc: print(str(exc)); raise SystemExit(1)
        return
    host,port=os.environ.get("HOST","127.0.0.1"),int(os.environ.get("PORT","8000"))
    print(f"Raw Materials Pro is ready at http://{host}:{port}")
    ThreadingHTTPServer((host,port),AppHandler).serve_forever()


if __name__=="__main__":
    main()
