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

# ═══ CONFIG ═══
SECRET_KEY = os.environ.get("YIRIBA_SECRET", "SM-Licence-HMAC-2026-BurkinaFaso-SecretKey!@#$%")
ADMIN_TOKEN = os.environ.get("YIRIBA_ADMIN_TOKEN", secrets.token_hex(32))
DB_PATH = os.environ.get("YIRIBA_DB", "") or os.path.join(tempfile.gettempdir(), "yiriba_licenses.db")
MAX_ACTIVATIONS = int(os.environ.get("YIRIBA_MAX_ACTIVATIONS", "5"))

PACKS = {
    "DEMO": {"max_eleves": 150, "max_pc": 1, "duree_jours": 365, "prix": 0},
    "ECOLE": {"max_eleves": -1, "max_pc": 1, "duree_jours": -1, "prix": 250000},
    "RESEAU_PRO": {"max_eleves": -1, "max_pc": 5, "duree_jours": -1, "prix": 450000},
}

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

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


def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if token != ADMIN_TOKEN:
            return jsonify({"error": "Token admin invalide"}), 401
        return f(*args, **kwargs)
    return decorated


# ═══ PUBLIC ENDPOINTS ═══

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "Yiriba License Server", "version": "1.0.0", "timestamp": datetime.utcnow().isoformat()})


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


if __name__ == "__main__":
    print(f"\n  YIRIBA LICENSE SERVER v1.0 — {DB_PATH}\n")
    app.run(host="0.0.0.0", port=5000, debug=False)

# redeploy Sat Aug 29 11:45:10     2026
