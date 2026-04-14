import os
import hashlib
import zipfile
import tempfile
import uuid
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)


MAX_UPLOAD_MB = 100

# ── Risk rules ────────────────────────────────────────────────────────────────

# Strings we search for inside the binary AndroidManifest.xml
DANGEROUS_PERMS = [
    b"SEND_SMS", b"READ_SMS", b"RECEIVE_SMS",
    b"SYSTEM_ALERT_WINDOW", b"DEVICE_ADMIN",
    b"BIND_DEVICE_ADMIN", b"GET_ACCOUNTS",
    b"AUTHENTICATE_ACCOUNTS", b"RECORD_AUDIO",
]

def _check_apk(path: str) -> dict:
    """
    Rule-based APK analysis using only the standard library.
    Returns a result dict with is_safe, risk_level, score, and flags.
    """
    score = 0
    flags = []

    # ── ZIP integrity ─────────────────────────────────────────────────────────
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        return {"is_safe": False, "risk_level": "high", "score": 100,
                "flags": ["File is not a valid APK/ZIP"]}

    with zf:
        names = zf.namelist()

        # Missing manifest = definitely bad
        if "AndroidManifest.xml" not in names:
            score += 50
            flags.append("AndroidManifest.xml missing")

        # Extra DEX = possible code injection
        extra_dex = [n for n in names if n.endswith(".dex") and n != "classes.dex"]
        if extra_dex:
            score += 30
            flags.append(f"Extra DEX files: {', '.join(extra_dex)}")

        # Scan raw manifest bytes for dangerous permission strings
        if "AndroidManifest.xml" in names:
            manifest_bytes = zf.read("AndroidManifest.xml")
            found = [p.decode() for p in DANGEROUS_PERMS if p in manifest_bytes]
            if found:
                score += min(len(found) * 8, 40)
                flags.append(f"Dangerous permissions: {', '.join(found)}")

        # Excessive native libs
        native = [n for n in names if n.endswith(".so")]
        if len(native) > 8:
            score += 10
            flags.append(f"{len(native)} native libraries (high count)")

    # ── File-level checks ─────────────────────────────────────────────────────
    size_mb = os.path.getsize(path) / (1024 * 1024)
    if size_mb < 0.1:
        score += 20
        flags.append("Suspiciously small file size")

    score = min(score, 100)

    if score < 30:
        risk = "low"
    elif score < 60:
        risk = "medium"
    else:
        risk = "high"

    return {
        "is_safe":    risk != "high",
        "risk_level": risk,
        "score":      score,
        "size_mb":    round(size_mb, 2),
        "flags":      flags,
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/analyze", methods=["POST"])
def analyze():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    f = request.files["file"]
    if not f.filename or not f.filename.endswith(".apk"):
        return jsonify({"error": "Upload must be a .apk file"}), 400

    # Size guard
    f.seek(0, 2)
    if f.tell() > MAX_UPLOAD_MB * 1024 * 1024:
        return jsonify({"error": f"File exceeds {MAX_UPLOAD_MB} MB limit"}), 413
    f.seek(0)

    tmp = os.path.join(tempfile.gettempdir(), f"apk_{uuid.uuid4().hex}.apk")
    try:
        f.save(tmp)
        result = _check_apk(tmp)
        result["sha256"] = hashlib.sha256(open(tmp, "rb").read()).hexdigest()
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass

    result["filename"] = f.filename
    return jsonify(result)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
