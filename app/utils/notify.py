"""Real outbound notification delivery for the channels configured under
Settings -> Notifications. Uses stdlib only (urllib for webhooks,
smtplib for email) -- no third-party HTTP client needed."""
import json
import smtplib
import urllib.request
import urllib.error
from email.mime.text import MIMEText

TIMEOUT = 6.0


def _post_json(url, payload):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST", headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return resp.status < 400


def send_webhook(url, message):
    return _post_json(url, {"text": message, "content": message, "message": message})


def send_discord(url, message):
    return _post_json(url, {"content": message[:2000]})


def send_slack(url, message):
    return _post_json(url, {"text": message})


def send_telegram(bot_token, chat_id, message):
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    return _post_json(url, {"chat_id": chat_id, "text": message})


def send_email(smtp_config, subject, body):
    """smtp_config: {host, port, username, password, from_addr, to_addr, use_tls}"""
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = smtp_config.get("from_addr", smtp_config.get("username", "novadns@localhost"))
    msg["To"] = smtp_config["to_addr"]

    host = smtp_config["host"]
    port = int(smtp_config.get("port", 587))
    with smtplib.SMTP(host, port, timeout=TIMEOUT) as server:
        if smtp_config.get("use_tls", True):
            server.starttls()
        if smtp_config.get("username"):
            server.login(smtp_config["username"], smtp_config.get("password", ""))
        server.sendmail(msg["From"], [smtp_config["to_addr"]], msg.as_string())
    return True


def dispatch(channel, config, message, subject="NovaDNS alert"):
    """Best-effort send; returns (ok, error_or_None). Never raises."""
    try:
        if channel == "webhook":
            return send_webhook(config["value"], message), None
        if channel == "discord":
            return send_discord(config["value"], message), None
        if channel == "slack":
            return send_slack(config["value"], message), None
        if channel == "telegram":
            bot_token, _, chat_id = config["value"].partition(":")
            return send_telegram(bot_token, chat_id, message), None
        if channel == "email":
            return send_email(config, subject, message), None
        return False, f"unknown channel {channel}"
    except (urllib.error.URLError, smtplib.SMTPException, OSError, KeyError, IndexError) as e:
        return False, str(e)
