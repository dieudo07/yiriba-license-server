"""
Yiriba License Server — Backend API
"""

import os
import json
import hmac
import hashlib
import sqlite3
import secrets
import tempfile
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, g
from flask_cors import CORS


# ═══ RATE LIMITER ═══
import time as _time
_rate_store = {}

def _check_rate(key, limit=30):
    now = _time.time()
    if key not in _rate_store:
        _rate_store[key] = []
    _rate_store[key] = [t for t in _rate_store[key] if now - t < 60]
    if len(_rate_store[key]) >= limit:
        return False
    _rate_store[key].append(now)
    return True

# ═══ ADMIN AUTH ═══
import time as _time
_admin_password = os.environ.get("YIRIBA_ADMIN_PASSWORD", "Yr@2026!S3cur3P@ss#BF")
_admin_sessions = {}

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "").replace("Bearer ", "")
        if auth in _admin_sessions:
            expired = [t for t, s in _admin_sessions.items() if _time.time() - s["created"] > 86400]
            for t in expired: del _admin_sessions[t]
            if auth in _admin_sessions:
                return f(*args, **kwargs)
        if auth == ADMIN_TOKEN:
            return f(*args, **kwargs)
        return jsonify({"error": "Non autorisé"}), 401
    return decorated



import time
_rate_limits = {}
def rate_limit(max_per_minute=30):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            ip = request.remote_addr
            now = time.time()
            key = f"{ip}:{f.__name__}"
            if key in _rate_limits:
                timestamps = [t for t in _rate_limits[key] if now - t < 60]
                _rate_limits[key] = timestamps
                if len(timestamps) >= max_per_minute:
                    return jsonify({"error": "Trop de requêtes. Réessayez dans 1 minute."}), 429
            else:
                _rate_limits[key] = []
            _rate_limits[key].append(now)
            return f(*args, **kwargs)
        return decorated
    return decorator



# ═══ CONFIG ═══
SECRET_KEY = os.environ.get("YIRIBA_SECRET", "SM-Licence-HMAC-2026-BurkinaFaso-SecretKey!@#$%")
ADMIN_TOKEN = os.environ.get("YIRIBA_ADMIN_TOKEN", "")
if not ADMIN_TOKEN:
    import sys; print("WARNING: YIRIBA_ADMIN_TOKEN not set!"); sys.exit(1)
DB_PATH = os.environ.get("YIRIBA_DB", "") or os.path.join(tempfile.gettempdir(), "yiriba_licenses.db")
MAX_ACTIVATIONS = int(os.environ.get("YIRIBA_MAX_ACTIVATIONS", "5"))

PACKS = {
    "DEMO": {"max_eleves": 150, "max_pc": 1, "duree_jours": 365, "prix": 0},
    "ECOLE": {"max_eleves": -1, "max_pc": 1, "duree_jours": -1, "prix": 250000},
    "RESEAU_PRO": {"max_eleves": -1, "max_pc": 5, "duree_jours": -1, "prix": 450000},
}

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": ["https://schoolmanager-bf.github.io"]}})

_db_initialized = False


def get_db():
    global _db_initialized
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        if not _db_initialized:
            g.db.executescript("""
                CREATE TABLE IF NOT EXISTS licenses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    school_name TEXT NOT NULL,
                    pack TEXT NOT NULL DEFAULT 'DEMO',
                    hardware_id TEXT NOT NULL,
                    license_key TEXT UNIQUE NOT NULL,
                    date_activation TEXT NOT NULL,
                    date_expiration TEXT DEFAULT '',
                    max_eleves INTEGER DEFAULT 150,
                    max_pc INTEGER DEFAULT 1,
                    version TEXT DEFAULT '2.0',
                    signature TEXT NOT NULL,
                    is_revoked INTEGER DEFAULT 0,
                    revoked_at TEXT DEFAULT '',
                    created_at TEXT DEFAULT (datetime('now')),
                    last_verified TEXT DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS activations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    license_key TEXT NOT NULL,
                    hardware_id TEXT NOT NULL,
                    activated_at TEXT DEFAULT (datetime('now')),
                    ip_address TEXT DEFAULT '',
                    UNIQUE(license_key, hardware_id)
                );
            """)
            _db_initialized = True
            print(f"[INIT] Database ready: {DB_PATH}")
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.errorhandler(Exception)
def handle_exception(e):
    import traceback
    traceback.print_exc()
    return jsonify({"error": str(e), "type": type(e).__name__}), 500


def compute_hmac(content: str) -> str:
    return hmac.new(SECRET_KEY.encode(), content.encode(), hashlib.sha256).hexdigest()


# ═══ PUBLIC ENDPOINTS ═══

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "Yiriba License Server", "version": "2.0.0", "timestamp": datetime.utcnow().isoformat()})


@app.route("/api/license/verify", methods=["POST"])
def verify_license():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"valid": False, "error": "JSON body requis"}), 400

    license_key = data.get("license_key", "").strip()
    hw_id = data.get("hardware_id", "").strip()
    if not license_key or not hw_id:
        return jsonify({"valid": False, "error": "license_key et hardware_id requis"}), 400

    db = get_db()
    lic = db.execute("SELECT * FROM licenses WHERE license_key = ?", (license_key,)).fetchone()
    if not lic:
        return jsonify({"valid": False, "error": "Licence inconnue", "status": "UNKNOWN"})
    if lic["is_revoked"]:
        return jsonify({"valid": False, "error": "Licence révoquée", "status": "REVOKED"})
    if lic["date_expiration"]:
        try:
            if datetime.now() > datetime.strptime(lic["date_expiration"], "%Y-%m-%d"):
                return jsonify({"valid": False, "error": "Licence expirée", "status": "EXPIRED"})
        except ValueError:
            pass

    remaining = -1
    if lic["date_expiration"]:
        try:
            remaining = max(0, (datetime.strptime(lic["date_expiration"], "%Y-%m-%d") - datetime.now()).days)
        except ValueError:
            pass

    db.execute("UPDATE licenses SET last_verified = datetime('now') WHERE id = ?", (lic["id"],))
    db.commit()

    return jsonify({
        "valid": True, "status": "ACTIVE",
        "school_name": lic["school_name"], "pack": lic["pack"],
        "max_eleves": lic["max_eleves"], "max_pc": lic["max_pc"],
        "date_activation": lic["date_activation"],
        "date_expiration": lic["date_expiration"] or "À vie",
        "remaining_days": remaining, "version": lic["version"]
    })


@app.route("/api/license/activate", methods=["POST"])
def activate_license():
    if not _check_rate("activate:" + request.remote_addr, 10):
        return jsonify({"error": "Trop de requêtes. Réessayez dans 1 minute."}), 429
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "error": "JSON requis"}), 400

    license_key = data.get("license_key", "").strip()
    hw_id = data.get("hardware_id", "").strip()
    if not license_key or not hw_id:
        return jsonify({"success": False, "error": "license_key et hardware_id requis"}), 400

    db = get_db()
    lic = db.execute("SELECT * FROM licenses WHERE license_key = ?", (license_key,)).fetchone()
    if not lic:
        # Auto-enregistrer la licence si elle n'existe pas
        pack = data.get("pack", "DEMO").strip().upper()
        school = data.get("school_name", "").strip()
        date_act = data.get("date_activation", datetime.now().strftime("%Y-%m-%d"))
        pack_info = PACKS.get(pack, PACKS["DEMO"])
        date_exp = ""
        if pack_info["duree_jours"] > 0:
            date_exp = (datetime.strptime(date_act, "%Y-%m-%d") + timedelta(days=pack_info["duree_jours"])).strftime("%Y-%m-%d")
        try:
            db.execute(
                "INSERT INTO licenses (school_name, pack, hardware_id, license_key, date_activation, date_expiration, max_eleves, max_pc, version, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?, '2.1', 'auto')",
                (school, pack, hw_id, license_key, date_act, date_exp, pack_info["max_eleves"], data.get("nb_pc", 1))
            )
            db.commit()
            lic = db.execute("SELECT * FROM licenses WHERE license_key = ?", (license_key,)).fetchone()
            print(f"[AUTO-REGISTER] Licence '{school}' enregistrée automatiquement")
        except Exception as e:
            return jsonify({"success": False, "error": f"Erreur enregistrement: {e}"})
    if lic["is_revoked"]:
        return jsonify({"success": False, "error": "Licence révoquée"})

    existing = db.execute("SELECT 1 FROM activations WHERE license_key = ? AND hardware_id = ?", (license_key, hw_id)).fetchone()
    if existing:
        return jsonify({"success": True, "message": "Déjà activé sur ce PC"})

    count = db.execute("SELECT COUNT(DISTINCT hardware_id) as c FROM activations WHERE license_key = ?", (license_key,)).fetchone()["c"]
    if count >= lic["max_pc"]:
        return jsonify({"success": False, "error": f"Max {lic['max_pc']} PC atteint"})

    db.execute("INSERT OR IGNORE INTO activations (license_key, hardware_id, ip_address) VALUES (?, ?, ?)",
               (license_key, hw_id, request.remote_addr or ""))
    db.commit()
    return jsonify({"success": True, "message": f"Activé sur PC #{count + 1}/{lic['max_pc']}"})


@app.route("/api/license/status", methods=["GET"])
def license_status():
    license_key = request.args.get("key", "").strip()
    if not license_key:
        return jsonify({"error": "key requis"}), 400

    db = get_db()
    lic = db.execute("SELECT * FROM licenses WHERE license_key = ?", (license_key,)).fetchone()
    if not lic:
        return jsonify({"status": "UNKNOWN", "valid": False})
    if lic["is_revoked"]:
        return jsonify({"status": "REVOKED", "valid": False})
    if lic["date_expiration"]:
        try:
            if datetime.now() > datetime.strptime(lic["date_expiration"], "%Y-%m-%d"):
                return jsonify({"status": "EXPIRED", "valid": False})
        except ValueError:
            pass
    return jsonify({"status": "ACTIVE", "valid": True, "pack": lic["pack"], "school": lic["school_name"]})


# ═══ ADMIN ENDPOINTS ═══

@app.route("/api/admin/create", methods=["POST"])
@require_admin
def admin_create():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON requis"}), 400

    school = data.get("school_name", "").strip()
    pack = data.get("pack", "DEMO").strip().upper()
    hw_id = data.get("hardware_id", "").strip()
    date_act = data.get("date_activation", datetime.now().strftime("%Y-%m-%d"))
    max_pc = data.get("max_pc", PACKS.get(pack, PACKS["DEMO"])["max_pc"])

    if not school or not hw_id:
        return jsonify({"error": "school_name et hardware_id requis"}), 400
    if pack not in PACKS:
        return jsonify({"error": f"Pack inconnu: {pack}"}), 400

    pack_info = PACKS[pack]
    date_exp = ""
    if pack_info["duree_jours"] > 0:
        date_exp = (datetime.strptime(date_act, "%Y-%m-%d") + timedelta(days=pack_info["duree_jours"])).strftime("%Y-%m-%d")

    license_key = secrets.token_hex(16)
    signature = compute_hmac(f"{school}|{pack}|{hw_id}|{date_act}|{max_pc}")

    db = get_db()
    try:
        db.execute(
            "INSERT INTO licenses (school_name, pack, hardware_id, license_key, date_activation, date_expiration, max_eleves, max_pc, version, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?, '2.1', ?)",
            (school, pack, hw_id, license_key, date_act, date_exp, pack_info["max_eleves"], max_pc, signature)
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Clé déjà existante"}), 400

    return jsonify({
        "success": True, "license_key": license_key, "school_name": school,
        "pack": pack, "date_activation": date_act, "date_expiration": date_exp or "À vie",
        "max_pc": max_pc, "signature": signature
    })


@app.route("/api/admin/list", methods=["GET"])
@require_admin
def admin_list():
    db = get_db()
    rows = db.execute("SELECT * FROM licenses ORDER BY created_at DESC").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/admin/stats", methods=["GET"])
@require_admin
def admin_stats():
    db = get_db()
    total = db.execute("SELECT COUNT(*) as c FROM licenses").fetchone()["c"]
    active = db.execute("SELECT COUNT(*) as c FROM licenses WHERE is_revoked = 0").fetchone()["c"]
    revoked = db.execute("SELECT COUNT(*) as c FROM licenses WHERE is_revoked = 1").fetchone()["c"]
    by_pack = db.execute("SELECT pack, COUNT(*) as c FROM licenses GROUP BY pack").fetchall()
    return jsonify({"total": total, "active": active, "revoked": revoked, "by_pack": {r["pack"]: r["c"] for r in by_pack}})


@app.route("/api/admin/revoke-quick", methods=["POST"])
@require_admin
def admin_revoke_quick():
    """Révoque une licence par nom d'école — protégé par un code simple."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON requis"}), 400
    school = data.get("school_name", "").strip()
    code = data.get("code", "").strip()
    if code != "yiriba-revoke-2026":
        return jsonify({"error": "Code invalide"}), 403
    if not school:
        return jsonify({"error": "school_name requis"}), 400
    db = get_db()
    lic = db.execute("SELECT * FROM licenses WHERE school_name = ?", (school,)).fetchone()
    if not lic:
        return jsonify({"error": f'Aucune licence pour "{school}"'})
    db.execute("UPDATE licenses SET is_revoked = 1, revoked_at = datetime('now') WHERE school_name = ?", (school,))
    db.commit()
    return jsonify({"success": True, "message": f"Licence '{school}' révoquée"})


@app.route("/api/admin/reactivate-quick", methods=["POST"])
@require_admin
def admin_reactivate_quick():
    """Réactive une licence par nom d'école."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON requis"}), 400
    school = data.get("school_name", "").strip()
    code = data.get("code", "").strip()
    if code != "yiriba-revoke-2026":
        return jsonify({"error": "Code invalide"}), 403
    if not school:
        return jsonify({"error": "school_name requis"}), 400
    db = get_db()
    lic = db.execute("SELECT * FROM licenses WHERE school_name = ?", (school,)).fetchone()
    if not lic:
        return jsonify({"error": f'Aucune licence pour "{school}"'})
    db.execute("UPDATE licenses SET is_revoked = 0, revoked_at = '' WHERE school_name = ?", (school,))
    db.commit()
    return jsonify({"success": True, "message": f"Licence '{school}' réactivée"})


@app.route("/api/admin/revoke", methods=["POST"])
@require_admin
def admin_revoke():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON requis"}), 400
    license_key = data.get("license_key", "").strip()
    if not license_key:
        return jsonify({"error": "license_key requis"}), 400
    db = get_db()
    lic = db.execute("SELECT * FROM licenses WHERE license_key = ?", (license_key,)).fetchone()
    if not lic:
        return jsonify({"error": "Licence inconnue"})
    db.execute("UPDATE licenses SET is_revoked = 1, revoked_at = datetime('now') WHERE license_key = ?", (license_key,))
    db.commit()
    return jsonify({"success": True, "message": f"Licence '{lic['school_name']}' révoquée"})



# ═══ ADMIN: ACTION LOGS ═══
@app.route("/api/admin/logs", methods=["GET"])
@require_admin
def admin_logs():
    db = get_db()
    try:
        logs = db.execute("SELECT * FROM admin_logs ORDER BY id DESC LIMIT 200").fetchall()
    except:
        db.execute("""CREATE TABLE IF NOT EXISTS admin_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, target TEXT, details TEXT, ip TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        db.commit()
        logs = []
    return jsonify([dict(l) for l in logs])

@app.route("/api/admin/logs", methods=["POST"])
@require_admin
def admin_log_action():
    data = request.get_json(silent=True) or {}
    db = get_db()
    try:
        db.execute("INSERT INTO admin_logs (action, target, details, ip) VALUES (?, ?, ?, ?)",
                   (data.get("action", ""), data.get("target", ""), data.get("details", ""), data.get("ip", "")))
        db.commit()
    except: pass
    return jsonify({"success": True})

# ═══ ADMIN: ANALYTICS ═══
@app.route("/api/admin/analytics", methods=["GET"])
@require_admin
def admin_analytics():
    db = get_db()
    for t in [
        "CREATE TABLE IF NOT EXISTS activations (id INTEGER PRIMARY KEY AUTOINCREMENT, license_key TEXT NOT NULL, hardware_id TEXT NOT NULL, ip_address TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(license_key, hardware_id))",
        "CREATE TABLE IF NOT EXISTS admin_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, target TEXT, details TEXT, ip TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
    ]:
        try: db.execute(t)
        except: pass
    db.commit()
    total = db.execute("SELECT COUNT(*) as c FROM licenses").fetchone()["c"]
    active = db.execute("SELECT COUNT(*) as c FROM licenses WHERE is_revoked = 0").fetchone()["c"]
    revoked = db.execute("SELECT COUNT(*) as c FROM licenses WHERE is_revoked = 1").fetchone()["c"]
    by_pack = db.execute("SELECT pack, COUNT(*) as c FROM licenses GROUP BY pack").fetchall()
    try:
        daily = db.execute("SELECT date(created_at) as day, COUNT(*) as count FROM activations WHERE created_at >= datetime('now', '-30 days') GROUP BY day ORDER BY day").fetchall()
    except: daily = []
    prices = {"DEMO": 0, "ECOLE": 250000, "RESEAU_PRO": 450000}
    rev = db.execute("SELECT pack, COUNT(*) as c FROM licenses WHERE pack != 'DEMO' GROUP BY pack").fetchall()
    total_rev = sum(prices.get(r["pack"], 0) * r["c"] for r in rev)
    try:
        recent = db.execute("SELECT a.*, l.school_name, l.pack FROM activations a LEFT JOIN licenses l ON a.license_key = l.license_key ORDER BY a.id DESC LIMIT 10").fetchall()
    except: recent = []
    return jsonify({"total": total, "active": active, "revoked": revoked,
        "by_pack": {r["pack"]: r["c"] for r in by_pack},
        "daily_activations": [{"day": r["day"], "count": r["count"]} for r in daily],
        "total_revenue": total_rev,
        "recent_activations": [dict(r) for r in recent]})

# ═══ ADMIN: NOTIFICATIONS ═══
@app.route("/api/admin/notifications", methods=["GET"])
@require_admin
def admin_get_notifications():
    db = get_db()
    try:
        notifs = db.execute("SELECT * FROM notifications ORDER BY id DESC LIMIT 50").fetchall()
    except:
        db.execute("CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, message TEXT NOT NULL, type TEXT DEFAULT 'info', is_active INTEGER DEFAULT 1, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
        db.commit()
        notifs = []
    return jsonify([dict(n) for n in notifs])

@app.route("/api/admin/notifications", methods=["POST"])
@require_admin
def admin_create_notification():
    data = request.get_json(silent=True)
    if not data: return jsonify({"error": "JSON requis"}), 400
    title = data.get("title", "").strip()
    message = data.get("message", "").strip()
    ntype = data.get("type", "info")
    if not title or not message: return jsonify({"error": "title et message requis"}), 400
    db = get_db()
    try:
        db.execute("INSERT INTO notifications (title, message, type) VALUES (?, ?, ?)", (title, message, ntype))
        db.commit()
    except: return jsonify({"error": "Erreur DB"}), 500
    return jsonify({"success": True})

@app.route("/api/admin/notifications/<int:notif_id>", methods=["DELETE"])
@require_admin
def admin_delete_notification(notif_id):
    db = get_db()
    db.execute("DELETE FROM notifications WHERE id = ?", (notif_id,))
    db.commit()
    return jsonify({"success": True})

@app.route("/api/notifications", methods=["GET"])
def public_notifications():
    db = get_db()
    try: notifs = db.execute("SELECT id, title, message, type, created_at FROM notifications WHERE is_active = 1 ORDER BY id DESC LIMIT 5").fetchall()
    except: notifs = []
    return jsonify([dict(n) for n in notifs])

# ═══ ADMIN: PACKS CONFIG ═══
@app.route("/api/admin/packs", methods=["GET"])
@require_admin
def admin_get_packs():
    db = get_db()
    try: packs = db.execute("SELECT * FROM pack_config ORDER BY id").fetchall()
    except:
        db.execute("CREATE TABLE IF NOT EXISTS pack_config (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, max_eleves INTEGER DEFAULT -1, max_pc INTEGER DEFAULT 1, duree_jours INTEGER DEFAULT 365, prix INTEGER DEFAULT 0, features TEXT DEFAULT '')")
        db.commit()
        for p in [("DEMO", 150, 1, 365, 0, "Base,Watermark"), ("ECOLE", -1, 1, -1, 250000, "Tout,QR local"), ("RESEAU_PRO", -1, 5, -1, 450000, "Tout,QR verifiable,Reseau")]:
            try: db.execute("INSERT OR IGNORE INTO pack_config (name, max_eleves, max_pc, duree_jours, prix, features) VALUES (?, ?, ?, ?, ?, ?)", p)
            except: pass
        db.commit()
        packs = db.execute("SELECT * FROM pack_config ORDER BY id").fetchall()
    return jsonify([dict(p) for p in packs])

@app.route("/api/admin/packs", methods=["PUT"])
@require_admin
def admin_update_packs():
    data = request.get_json(silent=True)
    if not data or "packs" not in data: return jsonify({"error": "packs requis"}), 400
    db = get_db()
    for p in data["packs"]:
        db.execute("UPDATE pack_config SET max_eleves=?, max_pc=?, duree_jours=?, prix=?, features=? WHERE name=?",
                   (p["max_eleves"], p["max_pc"], p["duree_jours"], p["prix"], p.get("features", ""), p["name"]))
    db.commit()
    return jsonify({"success": True})

# ═══ ADMIN: ABUSE ═══
@app.route("/api/admin/abuse", methods=["GET"])
@require_admin
def admin_abuse_check():
    db = get_db()
    try:
        abuse = db.execute("SELECT l.school_name, l.license_key, l.pack, l.max_pc, COUNT(DISTINCT a.hardware_id) as pc_count, GROUP_CONCAT(DISTINCT a.hardware_id) as hw_ids FROM licenses l JOIN activations a ON l.license_key = a.license_key GROUP BY l.license_key HAVING pc_count > l.max_pc AND l.max_pc > 0").fetchall()
    except: abuse = []
    return jsonify([dict(a) for a in abuse])

# ═══ ADMIN: EXPORT CSV ═══
@app.route("/api/admin/export", methods=["GET"])
@require_admin
def admin_export():
    db = get_db()
    licenses = db.execute("SELECT * FROM licenses ORDER BY id").fetchall()
    csv_lines = ["Id,SchoolName,Pack,HardwareId,ActivationDate,Expiration,MaxEleves,MaxPC,IsRevoked"]
    for l in licenses:
        csv_lines.append(f"{l['id']},{l['school_name']},{l['pack']},{l.get('hardware_id','')},{l.get('date_activation','')},{l.get('date_expiration','')},{l.get('max_eleves',0)},{l.get('max_pc',1)},{l.get('is_revoked',0)}")
    from flask import Response
    return Response("\n".join(csv_lines), mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=yiriba_licenses.csv"})




@app.route("/api/packs", methods=["GET"])
def public_packs():
    db = get_db()
    try:
        packs = db.execute("SELECT name, max_eleves, max_pc, duree_jours, prix, features FROM pack_config ORDER BY id").fetchall()
    except:
        packs = []
    return jsonify([dict(p) for p in packs])





@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON requis"}), 400
    password = data.get("password", "")
    if password != _admin_password:
        return jsonify({"error": "Mot de passe incorrect"}), 401
    token = secrets.token_hex(32)
    _admin_sessions[token] = {"created": _time.time(), "ip": request.remote_addr}
    return jsonify({"success": True, "token": token})


if __name__ == "__main__":
    print(f"\n  YIRIBA LICENSE SERVER v1.0 — {DB_PATH}\n")
    app.run(host="0.0.0.0", port=5000, debug=False)

# redeploy Sat Aug 29 11:45:10     2026
# Sat Aug 29 14:38:35     2026
# Sat Aug 29 14:41:16     2026
