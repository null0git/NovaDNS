-- NovaDNS core schema (SQLite)

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin',
    theme TEXT NOT NULL DEFAULT 'system',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_login TEXT
);

CREATE TABLE IF NOT EXISTS zones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    ztype TEXT NOT NULL DEFAULT 'authoritative', -- authoritative | forward
    default_ttl INTEGER NOT NULL DEFAULT 3600,
    soa_mname TEXT,
    soa_rname TEXT,
    soa_serial INTEGER DEFAULT 1,
    soa_refresh INTEGER DEFAULT 3600,
    soa_retry INTEGER DEFAULT 900,
    soa_expire INTEGER DEFAULT 604800,
    soa_minimum INTEGER DEFAULT 300,
    dnssec_enabled INTEGER NOT NULL DEFAULT 0,
    nsec3_enabled INTEGER NOT NULL DEFAULT 0,
    nsec3_salt TEXT NOT NULL DEFAULT '',
    nsec3_iterations INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    zone_id INTEGER NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
    name TEXT NOT NULL,          -- relative or '@' for apex
    rtype TEXT NOT NULL,
    ttl INTEGER,
    data_json TEXT NOT NULL,     -- JSON blob matching wire.py value dict for rtype
    client_match TEXT,           -- optional CIDR/IP/group -- Split DNS: this record only
                                  -- answers matching clients; NULL = answers everyone
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_records_zone ON records(zone_id, name, rtype);

CREATE TABLE IF NOT EXISTS forwarders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 53,
    protocol TEXT NOT NULL DEFAULT 'udp', -- udp | tcp | doh | dot | doq
    label TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL DEFAULT 100,
    condition_domain TEXT,       -- NULL = default/global forwarder, else conditional forwarding suffix
    last_latency_ms REAL,
    last_check TEXT,
    healthy INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS rewrite_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    match_type TEXT NOT NULL DEFAULT 'exact', -- exact | wildcard | regex
    pattern TEXT NOT NULL,
    rtype TEXT NOT NULL DEFAULT 'A',
    rewrite_value TEXT NOT NULL,   -- JSON dict, shape depends on rtype
    client_match TEXT,             -- CIDR or exact IP, NULL = all clients
    time_start TEXT,               -- 'HH:MM' or NULL
    time_end TEXT,
    priority INTEGER NOT NULL DEFAULT 100,
    enabled INTEGER NOT NULL DEFAULT 1,
    hits INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS blocklists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'custom',
    source_url TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_updated TEXT,
    entry_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS block_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    blocklist_id INTEGER REFERENCES blocklists(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,
    list_type TEXT NOT NULL DEFAULT 'block', -- block | allow
    is_regex INTEGER NOT NULL DEFAULT 0,
    client_match TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_block_domain ON block_entries(domain);

CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE NOT NULL,
    hostname TEXT,
    group_name TEXT,
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen TEXT NOT NULL DEFAULT (datetime('now')),
    query_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS query_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL DEFAULT (datetime('now')),
    client_ip TEXT,
    qname TEXT,
    qtype TEXT,
    rcode INTEGER,
    source TEXT,       -- cache | authoritative | forward | blocked | rewritten
    latency_ms REAL
);
CREATE INDEX IF NOT EXISTS idx_qlog_ts ON query_log(ts);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL DEFAULT (datetime('now')),
    username TEXT,
    action TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'general',
    details TEXT,
    ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);

CREATE TABLE IF NOT EXISTS backups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    btype TEXT NOT NULL DEFAULT 'manual', -- manual | scheduled | pre_upgrade
    size_bytes INTEGER,
    encrypted INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS notification_channels (
    channel TEXT PRIMARY KEY, -- email | discord | slack | telegram | webhook
    config_json TEXT NOT NULL DEFAULT '{}',
    enabled INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL DEFAULT (datetime('now')),
    severity TEXT NOT NULL DEFAULT 'info', -- info | warning | critical
    message TEXT NOT NULL,
    resolved INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS maintenance (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 0,
    message TEXT,
    starts_at TEXT,
    ends_at TEXT
);

CREATE TABLE IF NOT EXISTS dnssec_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    zone_id INTEGER NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
    algorithm INTEGER NOT NULL DEFAULT 13,   -- 13 = ECDSAP256SHA256
    key_tag INTEGER NOT NULL,
    flags INTEGER NOT NULL DEFAULT 257,      -- 257 = KSK+ZSK (SEP+ZONE), 256 = ZSK only
    private_key_pem TEXT NOT NULL,
    public_key_hex TEXT NOT NULL,
    ds_digest_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS benchmarks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_at TEXT NOT NULL DEFAULT (datetime('now')),
    queries INTEGER NOT NULL,
    duration_sec REAL NOT NULL,
    qps REAL NOT NULL,
    avg_latency_ms REAL NOT NULL,
    p95_latency_ms REAL NOT NULL,
    p99_latency_ms REAL NOT NULL,
    cache_hit_ratio REAL,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS client_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS client_group_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL REFERENCES client_groups(id) ON DELETE CASCADE,
    cidr_or_ip TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS zone_templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    records_json TEXT NOT NULL DEFAULT '[]',  -- list of {name, rtype, fields}, {IP} placeholder supported
    builtin INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS dyndns_hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT UNIQUE NOT NULL,
    zone_id INTEGER REFERENCES zones(id) ON DELETE CASCADE,
    token TEXT NOT NULL,
    last_ip TEXT,
    last_ipv6 TEXT,
    last_update TEXT
);
