import datetime
import ipaddress
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_self_signed_cert(cert_path, key_path, common_name="novadns.local", extra_names=None):
    """Generates a 2-year self-signed RSA-2048 certificate for the admin
    web UI. This is meant for LAN access or evaluation over HTTPS --
    browsers will show a trust warning since nothing signed it. For a
    publicly-trusted certificate, put NovaDNS behind a reverse proxy
    (Caddy/nginx) with a real ACME-issued cert instead."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    san_entries = [x509.DNSName(common_name), x509.DNSName("localhost")]
    for name in (extra_names or []):
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            san_entries.append(x509.DNSName(name))

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=730))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    os.makedirs(os.path.dirname(cert_path), exist_ok=True)
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return {"cert_path": cert_path, "key_path": key_path, "expires": cert.not_valid_after_utc.isoformat()}


def cert_expiry_days(cert_path):
    if not os.path.exists(cert_path):
        return None
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    delta = cert.not_valid_after_utc - datetime.datetime.now(datetime.timezone.utc)
    return delta.days
