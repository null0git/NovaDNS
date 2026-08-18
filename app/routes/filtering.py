import json
from flask import Blueprint, render_template, request, jsonify
from .. import db as dbmod
from ..auth import login_required, audit
from .. import get_dns_server
from ..utils import blocklist_updater
from ..utils.blocklist_seeds import SEED_LISTS, SECURITY_FEED_URLS, CATEGORY_LABELS

bp = Blueprint("filtering", __name__, url_prefix="/filtering")

FAMILY_CATEGORIES = [(k, v) for k, v in CATEGORY_LABELS.items()]


def _bust_cache():
    srv = get_dns_server()
    if srv:
        srv.resolver.cache.clear()


@bp.route("/")
@login_required
def index():
    db = dbmod.get_db()
    blocklists = dbmod.query(db, "SELECT * FROM blocklists ORDER BY category")
    custom = dbmod.query(db, "SELECT * FROM block_entries WHERE blocklist_id IS NULL ORDER BY created_at DESC")
    enabled_cats = {b["category"] for b in blocklists if b["enabled"]}
    top_blocked = dbmod.query(db, """SELECT qname, COUNT(*) c FROM query_log WHERE source='blocked'
                                      AND ts >= datetime('now','-1 day') GROUP BY qname ORDER BY c DESC LIMIT 10""")
    blocked_today = dbmod.query(db, "SELECT COUNT(*) c FROM query_log WHERE source='blocked' AND ts >= datetime('now','-1 day')", one=True)["c"]
    return render_template("filtering.html", blocklists=blocklists, custom=custom,
                           categories=FAMILY_CATEGORIES, enabled_cats=enabled_cats,
                           has_seed=set(SEED_LISTS.keys()), has_feed=set(SECURITY_FEED_URLS.keys()),
                           top_blocked=top_blocked, blocked_today=blocked_today)


@bp.route("/blocklists/add", methods=["POST"])
@login_required
def add_blocklist():
    db = dbmod.get_db()
    body = request.get_json(force=True)
    name = body.get("name", "").strip()
    url = body.get("source_url", "").strip()
    if not name or not url:
        return jsonify({"error": "Name and source URL are required"}), 400
    bid = dbmod.execute(db, "INSERT INTO blocklists (name, category, source_url, enabled) VALUES (?,?,?,1)",
                         (name, body.get("category", "custom"), url))
    audit(f"Added blocklist '{name}' from {url}", "filtering")
    return jsonify({"ok": True, "id": bid})


@bp.route("/blocklists/upload", methods=["POST"])
@login_required
def upload_blocklist():
    """Import a blocklist from an uploaded text file (hosts-format or
    plain domain list) -- works fully offline, no source URL needed."""
    db = dbmod.get_db()
    name = request.form.get("name", "").strip()
    category = request.form.get("category", "custom").strip()
    file = request.files.get("file")
    if not name or not file:
        return jsonify({"error": "Name and file are required"}), 400
    text = file.read().decode("utf-8", errors="ignore")
    domains = blocklist_updater.parse_blocklist_text(text)
    bid = dbmod.execute(db, "INSERT INTO blocklists (name, category, enabled, entry_count, last_updated) VALUES (?,?,1,?,datetime('now'))",
                         (name, category, len(domains)))
    for d in domains:
        dbmod.execute(db, "INSERT INTO block_entries (blocklist_id, domain, list_type) VALUES (?,?,'block')", (bid, d))
    audit(f"Imported blocklist '{name}' from file: {len(domains)} entries", "filtering")
    _bust_cache()
    return jsonify({"ok": True, "count": len(domains)})


@bp.route("/blocklists/<int:bid>/sync", methods=["POST"])
@login_required
def sync_blocklist(bid):
    db = dbmod.get_db()
    bl = dbmod.query(db, "SELECT * FROM blocklists WHERE id=?", (bid,), one=True)
    if not bl or not bl["source_url"]:
        return jsonify({"error": "This blocklist has no source URL to sync from"}), 400
    try:
        count = blocklist_updater.fetch_and_sync(db, bid, bl["source_url"])
        audit(f"Synced blocklist '{bl['name']}': {count} entries", "filtering")
        _bust_cache()
        return jsonify({"ok": True, "count": count})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 502


@bp.route("/blocklists/<int:bid>/delete", methods=["POST"])
@login_required
def delete_blocklist(bid):
    db = dbmod.get_db()
    dbmod.execute(db, "DELETE FROM blocklists WHERE id=?", (bid,))
    audit(f"Deleted blocklist #{bid}", "filtering")
    _bust_cache()
    return jsonify({"ok": True})


@bp.route("/category/<cat>/toggle", methods=["POST"])
@login_required
def toggle_category(cat):
    db = dbmod.get_db()
    existing = dbmod.query(db, "SELECT * FROM blocklists WHERE category=?", (cat,), one=True)

    if existing:
        new_state = 0 if existing["enabled"] else 1
        dbmod.execute(db, "UPDATE blocklists SET enabled=? WHERE id=?", (new_state, existing["id"]))
        state = bool(new_state)
        audit(f"Toggled filter category '{cat}' -> {'on' if state else 'off'}", "filtering")
        _bust_cache()
        return jsonify({"ok": True, "enabled": state, "seeded": 0})

    label = CATEGORY_LABELS.get(cat, cat)
    seeded = 0
    if cat in SEED_LISTS:
        # Real, bundled, well-known domains -- blocks immediately, no
        # internet access required.
        bid = dbmod.execute(db, "INSERT INTO blocklists (name, category, enabled, entry_count, last_updated) VALUES (?,?,1,?,datetime('now'))",
                             (label, cat, len(SEED_LISTS[cat])))
        for domain in SEED_LISTS[cat]:
            dbmod.execute(db, "INSERT INTO block_entries (blocklist_id, domain, list_type) VALUES (?,?,'block')", (bid, domain))
        seeded = len(SEED_LISTS[cat])
    elif cat in SECURITY_FEED_URLS:
        # Security-critical: subscribe to a real, actively-maintained
        # public threat feed instead of a static (and quickly stale) list.
        url = SECURITY_FEED_URLS[cat]
        bid = dbmod.execute(db, "INSERT INTO blocklists (name, category, source_url, enabled) VALUES (?,?,?,1)",
                             (label, cat, url))
        try:
            seeded = blocklist_updater.fetch_and_sync(db, bid, url)
        except Exception:
            pass  # scheduled updater (or a manual "Sync now") will pick it up once internet is reachable
    else:
        dbmod.execute(db, "INSERT INTO blocklists (name, category, enabled) VALUES (?,?,1)", (label, cat))

    audit(f"Enabled filter category '{cat}' ({seeded} domain(s) loaded)", "filtering")
    _bust_cache()
    return jsonify({"ok": True, "enabled": True, "seeded": seeded})


@bp.route("/custom/add", methods=["POST"])
@login_required
def add_custom():
    db = dbmod.get_db()
    body = request.get_json(force=True)
    eid = dbmod.execute(db, """INSERT INTO block_entries (blocklist_id, domain, list_type, is_regex, client_match)
                                VALUES (NULL,?,?,?,?)""",
                         (body["domain"].strip(), body.get("list_type", "block"),
                          1 if body.get("is_regex") else 0, body.get("client_match") or None))
    audit(f"Added {body.get('list_type', 'block')} entry '{body['domain']}'", "filtering")
    _bust_cache()
    return jsonify({"ok": True, "id": eid})


@bp.route("/custom/<int:eid>", methods=["DELETE"])
@login_required
def remove_custom(eid):
    db = dbmod.get_db()
    dbmod.execute(db, "DELETE FROM block_entries WHERE id=?", (eid,))
    _bust_cache()
    return jsonify({"ok": True})


@bp.route("/category/<cat>/domains")
@login_required
def category_domains(cat):
    db = dbmod.get_db()
    bl = dbmod.query(db, "SELECT * FROM blocklists WHERE category=?", (cat,), one=True)
    if not bl:
        return jsonify({"domains": []})
    entries = dbmod.query(db, "SELECT domain FROM block_entries WHERE blocklist_id=? ORDER BY domain", (bl["id"],))
    return jsonify({"domains": [e["domain"] for e in entries], "count": len(entries),
                     "last_updated": bl["last_updated"], "source_url": bl["source_url"]})
