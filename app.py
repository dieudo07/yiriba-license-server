"""
Yiriba License Server — Backend API
Vérification de licences en ligne pour l'app Yiriba.

Endpoints:
  POST /api/license/verify    — Vérifier une licence
  POST /api/license/activate  — Activer une licence (enregistrer HWID)
  POST /api/license/revoke    — Révoquer une licence
  GET  /api/license/status    — Statut d'une licence
  GET  /api/health            — Health check
  POST /api/admin/create      — Créer une licence (admin)
  GET  /api/admin/list        — Lister toutes les licences (admin)
"""

import os
import json
import hmac
import hashlib
import sqlite3
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, g
from flask_cors import CORS

# ═══ CONFIG ═══
SECRET_KEY = os.environ.get("YIRIBA_SECRET", "SM-Licence-HMAC-2026-BurkinaFaso-SecretKey!@#$%")
ADMIN_TOKEN = os.environ.get("YIRIBA_ADMIN_TOKEN", secrets.token_hex(32))
DB_PATH = os.environ.get("YIRIBA_DB", "licenses.db")
HOST = os.environ.get("YIRIBA_HOST", "0.0.0.0")
PORT = int(os.environ.get("YIRIBA_PORT", "5000"))
MAX_ACTIVATIONS_PER_LICENSE = int(os.environ.get("YIRIBA_MAX_ACTIVATIONS", "5"))
ONLINE_CHECK_INTERVAL_HOURS = 24

# ═══ PACKS ═══
PACKS = {
    "DEMO": {"max_eleves": 150, "max_pc": 1, "duree_jours": 365, "support_mois": 0, "prix": 0},
    "ECOLE": {"max_eleves": -1, "max_pc": 1, "duree_jours": -1, "support_mois": 6, "prix": 250_000},
    "RESEAU_PRO": {"max_eleves": -1, "max_pc": 5, "duree_jours": -1, "support_mois": 12, "prix": 450_000},
}

# ═══ APP ═══
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})


# ═══ DATABASE ═══
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create tables if they don't exist."""
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
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
        
        CREATE INDEX IF NOT EXISTS idx_license_key ON licenses(license_key);
        CREATE INDEX IF NOT EXISTS idx_hardware_id ON licenses(hardware_id);
        CREATE INDEX IF NOT EXISTS idx_school_name ON licenses(school_name);
    """)
    conn.close()
    print(f"[INIT] Database ready: {DB_PATH}")


# ═══ HMAC ═══
def compute_hmac(content: str) -> str:
    return hmac.new(SECRET_KEY.encode(), content.encode(), hashlib.sha256).hexdigest()


def verify_hmac(license_key: str, hw_id: str, school: str, pack: str, date_act: str, nb_pc: int, signature: str) -> bool:
    payload = f"{school}|{pack}|{hw_id}|{date_act}|{nb_pc}"
    expected = compute_hmac(payload)
    return hmac.compare_digest(signature, expected)


# ═══ AUTH ═══
def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if token != ADMIN_TOKEN:
            return jsonify({"error": "Unauthorized", "message": "Token admin invalide"}), 401
        return f(*args, **kwargs)
    return decorated


# ═══ ENDPOINTS PUBLICS ═══

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "Yiriba License Server",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat()
    })


@app.route("/api/license/verify", methods=["POST"])
def verify_license():
    """
    Vérifie une licence.
    Body: { "license_key": "...", "hardware_id": "...", "school_name": "...", "pack": "...", "date_activation": "...", "nb_pc": 1, "signature": "..." }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"valid": False, "error": "JSON body requis"}), 400

    license_key = data.get("license_key", "").strip()
    hw_id = data.get("hardware_id", "").strip()
    school = data.get("school_name", "").strip()
    pack = data.get("pack", "DEMO").strip().upper()
    date_act = data.get("date_activation", "").strip()
    nb_pc = data.get("nb_pc", 1)
    signature = data.get("signature", "").strip()

    if not license_key or not hw_id:
        return jsonify({"valid": False, "error": "license_key et hardware_id requis"}), 400

    db = get_db()

    # Chercher la licence
    lic = db.execute("SELECT * FROM licenses WHERE license_key = ?", (license_key,)).fetchone()

    if not lic:
        return jsonify({
            "valid": False,
            "error": "Licence inconnue",
            "status": "UNKNOWN"
        }), 200

    # Vérifier si révoquée
    if lic["is_revoked"]:
        return jsonify({
            "valid": False,
            "error": "Licence révoquée",
            "status": "REVOKED",
            "revoked_at": lic["revoked_at"]
        }), 200

    # Vérifier HMAC
    expected_sig = compute_hmac(f"{lic['school_name']}|{lic['pack']}|{lic['hardware_id']}|{lic['date_activation']}|{lic['max_pc']}")
    if not hmac.compare_digest(signature, expected_sig) and signature:
        return jsonify({
            "valid": False,
            "error": "Signature invalide",
            "status": "INVALID_SIGNATURE"
        }), 200

    # Vérifier hardware ID (licite = même PC ou autorisé)
    activations = db.execute(
        "SELECT COUNT(DISTINCT hardware_id) as count FROM activations WHERE license_key = ?",
        (license_key,)
    ).fetchone()

    is_known_hw = db.execute(
        "SELECT 1 FROM activations WHERE license_key = ? AND hardware_id = ?",
        (license_key, hw_id)
    ).fetchone()

    if not is_known_hw and activations["count"] >= lic["max_pc"]:
        return jsonify({
            "valid": False,
            "error": f"Nombre maximum de PC atteint ({lic['max_pc']})",
            "status": "MAX_PC_REACHED"
        }), 200

    # Vérifier expiration
    if lic["date_expiration"]:
        try:
            exp_date = datetime.strptime(lic["date_expiration"], "%Y-%m-%d")
            if datetime.now() > exp_date:
                return jsonify({
                    "valid": False,
                    "error": "Licence expirée",
                    "status": "EXPIRED",
                    "expired_at": lic["date_expiration"]
                }), 200
        except ValueError:
            pass

    # Calculer jours restants
    remaining_days = -1  # -1 = à vie
    if lic["date_expiration"]:
        try:
            exp_date = datetime.strptime(lic["date_expiration"], "%Y-%m-%d")
            remaining_days = max(0, (exp_date - datetime.now()).days)
        except ValueError:
            pass

    # Enregistrer la vérification
    db.execute("UPDATE licenses SET last_verified = datetime('now') WHERE id = ?", (lic["id"],))
    db.commit()

    pack_info = PACKS.get(lic["pack"], PACKS["DEMO"])

    return jsonify({
        "valid": True,
        "status": "ACTIVE",
        "school_name": lic["school_name"],
        "pack": lic["pack"],
        "max_eleves": lic["max_eleves"],
        "max_pc": lic["max_pc"],
        "date_activation": lic["date_activation"],
        "date_expiration": lic["date_expiration"] or "À vie",
        "remaining_days": remaining_days,
        "version": lic["version"],
        "last_verified": datetime.utcnow().isoformat()
    })


@app.route("/api/license/activate", methods=["POST"])
def activate_license():
    """
    Active une licence sur un nouveau PC.
    Body: { "license_key": "...", "hardware_id": "...", "ip_address": "..." }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "error": "JSON body requis"}), 400

    license_key = data.get("license_key", "").strip()
    hw_id = data.get("hardware_id", "").strip()
    ip_addr = request.remote_addr or ""

    if not license_key or not hw_id:
        return jsonify({"success": False, "error": "license_key et hardware_id requis"}), 400

    db = get_db()

    # Chercher la licence
    lic = db.execute("SELECT * FROM licenses WHERE license_key = ?", (license_key,)).fetchone()
    if not lic:
        return jsonify({"success": False, "error": "Licence inconnue"}), 200

    if lic["is_revoked"]:
        return jsonify({"success": False, "error": "Licence révoquée"}), 200

    # Vérifier si déjà activé sur ce PC
    existing = db.execute(
        "SELECT 1 FROM activations WHERE license_key = ? AND hardware_id = ?",
        (license_key, hw_id)
    ).fetchone()

    if existing:
        return jsonify({"success": True, "message": "Déjà activé sur ce PC"})

    # Vérifier le nombre de PC
    count = db.execute(
        "SELECT COUNT(DISTINCT hardware_id) as count FROM activations WHERE license_key = ?",
        (license_key,)
    ).fetchone()

    if count["count"] >= lic["max_pc"]:
        return jsonify({
            "success": False,
            "error": f"Maximum {lic['max_pc']} PC autorisé(s). Contactez l'admin pour activer sur un nouveau PC."
        }), 200

    # Activer
    db.execute(
        "INSERT OR IGNORE INTO activations (license_key, hardware_id, ip_address) VALUES (?, ?, ?)",
        (license_key, hw_id, ip_addr)
    )
    db.commit()

    return jsonify({
        "success": True,
        "message": f"Activé sur PC #{count['count'] + 1}/{lic['max_pc']}",
        "activations_remaining": lic["max_pc"] - count["count"] - 1
    })


@app.route("/api/license/status", methods=["GET"])
def license_status():
    """Statut rapide d'une licence (GET avec query params)."""
    license_key = request.args.get("key", "").strip()
    hw_id = request.args.get("hw", "").strip()

    if not license_key:
        return jsonify({"error": "key requis"}), 400

    db = get_db()
    lic = db.execute("SELECT * FROM licenses WHERE license_key = ?", (license_key,)).fetchone()

    if not lic:
        return jsonify({"status": "UNKNOWN", "valid": False})

    if lic["is_revoked"]:
        return jsonify({"status": "REVOKED", "valid": False})

    # Vérifier expiration
    if lic["date_expiration"]:
        try:
            exp_date = datetime.strptime(lic["date_expiration"], "%Y-%m-%d")
            if datetime.now() > exp_date:
                return jsonify({"status": "EXPIRED", "valid": False})
        except ValueError:
            pass

    return jsonify({
        "status": "ACTIVE",
        "valid": True,
        "pack": lic["pack"],
        "school": lic["school_name"],
        "remaining_days": lic["date_expiration"] and max(0, (datetime.strptime(lic["date_expiration"], "%Y-%m-%d") - datetime.now()).days) or -1
    })


@app.route("/api/license/revoke", methods=["POST"])
def revoke_license():
    """Révoquer une licence."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON requis"}), 400

    license_key = data.get("license_key", "").strip()
    if not license_key:
        return jsonify({"error": "license_key requis"}), 400

    db = get_db()
    lic = db.execute("SELECT * FROM licenses WHERE license_key = ?", (license_key,)).fetchone()
    if not lic:
        return jsonify({"error": "Licence inconnue"}), 200

    db.execute(
        "UPDATE licenses SET is_revoked = 1, revoked_at = datetime('now') WHERE license_key = ?",
        (license_key,)
    )
    db.commit()

    return jsonify({"success": True, "message": f"Licence '{lic['school_name']}' révoquée"})


# ═══ ENDPOINTS ADMIN ═══

@app.route("/api/admin/create", methods=["POST"])
@require_admin
def admin_create_license():
    """Créer une licence (admin only)."""
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
        return jsonify({"error": f"Pack inconnu: {pack}. Valid: {list(PACKS.keys())}"}), 400

    pack_info = PACKS[pack]
    date_exp = ""
    if pack_info["duree_jours"] > 0:
        date_exp = (datetime.strptime(date_act, "%Y-%m-%d") + timedelta(days=pack_info["duree_jours"])).strftime("%Y-%m-%d")

    license_key = secrets.token_hex(16)
    signature = compute_hmac(f"{school}|{pack}|{hw_id}|{date_act}|{max_pc}")

    db = get_db()
    try:
        db.execute("""
            INSERT INTO licenses (school_name, pack, hardware_id, license_key, date_activation, date_expiration, max_eleves, max_pc, version, signature)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, '2.0', ?)
        """, (school, pack, hw_id, license_key, date_act, date_exp, pack_info["max_eleves"], max_pc, signature))
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Clé de licence déjà existante"}), 400

    return jsonify({
        "success": True,
        "license_key": license_key,
        "school_name": school,
        "pack": pack,
        "date_activation": date_act,
        "date_expiration": date_exp or "À vie",
        "max_pc": max_pc,
        "signature": signature
    })


@app.route("/api/admin/list", methods=["GET"])
@require_admin
def admin_list_licenses():
    """Lister toutes les licences (admin only)."""
    db = get_db()
    rows = db.execute("SELECT * FROM licenses ORDER BY created_at DESC").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/admin/revoke", methods=["POST"])
@require_admin
def admin_revoke():
    """Révoquer une licence (admin with token)."""
    return revoke_license()


@app.route("/api/admin/stats", methods=["GET"])
@require_admin
def admin_stats():
    """Statistiques (admin only)."""
    db = get_db()
    total = db.execute("SELECT COUNT(*) as c FROM licenses").fetchone()["c"]
    active = db.execute("SELECT COUNT(*) as c FROM licenses WHERE is_revoked = 0").fetchone()["c"]
    revoked = db.execute("SELECT COUNT(*) as c FROM licenses WHERE is_revoked = 1").fetchone()["c"]
    by_pack = db.execute("SELECT pack, COUNT(*) as c FROM licenses GROUP BY pack").fetchall()
    total_activations = db.execute("SELECT COUNT(*) as c FROM activations").fetchone()["c"]

    return jsonify({
        "total_licenses": total,
        "active": active,
        "revoked": revoked,
        "total_activations": total_activations,
        "by_pack": {r["pack"]: r["c"] for r in by_pack}
    })


# ═══ MAIN ═══
if __name__ == "__main__":
    init_db()
    print(f"\n{'='*50}")
    print(f"  YIRIBA LICENSE SERVER v1.0")
    print(f"  http://{HOST}:{PORT}")
    print(f"  Admin token: {ADMIN_TOKEN[:8]}...")
    print(f"  Database: {DB_PATH}")
    print(f"{'='*50}\n")
    app.run(host=HOST, port=PORT, debug=False)
