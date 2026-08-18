import os
import io
import json
import zipfile
import hashlib
import base64
import datetime

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200_000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def create_backup(db_path, backup_dir, btype="manual", password=None):
    os.makedirs(backup_dir, exist_ok=True)
    ts = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    with open(db_path, "rb") as f:
        raw = f.read()
    checksum = hashlib.sha256(raw).hexdigest()
    manifest = json.dumps({"created_at": ts, "checksum_sha256": checksum, "type": btype}).encode()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("novadns.sqlite", raw)
        zf.writestr("manifest.json", manifest)
    payload = buf.getvalue()

    encrypted = bool(password)
    ext = "ndnsbak"
    if encrypted:
        salt = os.urandom(16)
        key = _derive_key(password, salt)
        token = Fernet(key).encrypt(payload)
        payload = salt + token

    filename = f"novadns-{btype}-{ts}.{ext}{'.enc' if encrypted else ''}"
    path = os.path.join(backup_dir, filename)
    with open(path, "wb") as f:
        f.write(payload)
    return {"filename": filename, "size_bytes": len(payload), "encrypted": encrypted, "checksum": checksum}


def restore_backup(path, db_path, password=None):
    with open(path, "rb") as f:
        payload = f.read()
    if path.endswith(".enc"):
        if not password:
            raise ValueError("This backup is encrypted — a password is required.")
        salt, token = payload[:16], payload[16:]
        key = _derive_key(password, salt)
        payload = Fernet(key).decrypt(token)

    buf = io.BytesIO(payload)
    with zipfile.ZipFile(buf, "r") as zf:
        manifest = json.loads(zf.read("manifest.json"))
        db_bytes = zf.read("novadns.sqlite")
        checksum = hashlib.sha256(db_bytes).hexdigest()
        if checksum != manifest.get("checksum_sha256"):
            raise ValueError("Backup integrity check failed — checksum mismatch.")
    with open(db_path, "wb") as f:
        f.write(db_bytes)
    return manifest
