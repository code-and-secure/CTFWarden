#!/usr/bin/env python3
"""
ctfmon - lightweight monitor for Docker-based CTF infrastructure (single file).

Watches
  * every container: state, uptime, CPU, memory, PIDs, net/disk I/O, writable-layer size, risky config
  * docker events: create/start/die/OOM/crash loops, and anyone running docker exec / attach / cp / commit / export
  * who connects to which container (kernel conntrack: client IP -> container), plus
    container -> container and container -> internet flows (pivots, reverse shells)
  * web access logs (nginx container stdout and/or log files): per-IP stats + attack / abuse detection
  * SSH logins, SSH brute force and sudo commands on the host (auth.log)
  * host nginx in front of the challenges, strictly read-only: reads its config (public port ->
    container, which access_log belongs to which server) and its existing access logs, so the real
    player IP is known for every challenge instance without touching nginx
Serves a password-protected dashboard + JSON/CSV API, keeps history in SQLite and
pushes HIGH alerts to a Discord/Slack webhook if one is configured.

Dependency:  pip install "docker>=7"
"""
import csv
import hmac
import io
import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import sqlite3
import subprocess
import threading
import time
import urllib.request
from collections import Counter, defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

try:
    import docker
except ImportError:  # allows offline testing of the parsers
    docker = None

logging.basicConfig(level=os.environ.get("CTFMON_LOGLEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ctfmon")


# =================================================================== config
def env(k, d=""):
    return os.environ.get("CTFMON_" + k, d)


def env_list(k, d=""):
    return [x.strip() for x in env(k, d).split(",") if x.strip()]


def nets(items):
    out = []
    for x in items:
        try:
            out.append(ipaddress.ip_network(x, strict=False))
        except ValueError:
            log.warning("ignoring bad network %r", x)
    return out


LISTEN = env("LISTEN", "127.0.0.1")
PORT = int(env("PORT", "9999"))
USER = env("USER", "admin")
PASSWORD = env("PASSWORD")
GENERATED_PW = not PASSWORD
if GENERATED_PW:
    PASSWORD = secrets.token_urlsafe(12)
DB_PATH = env("DB", "/data/ctfmon.db")
STATS_EVERY = int(env("STATS_EVERY", "10"))        # seconds between container stat sweeps
SIZE_EVERY = int(env("SIZE_EVERY", "300"))         # seconds between disk-size sweeps (expensive)
CONN_EVERY = int(env("CONN_EVERY", "5"))           # seconds between conntrack snapshots
LOG_CONTAINERS = env_list("LOG_CONTAINERS")   # optional: containers whose stdout is an access log
LOG_FILES = env_list("LOG_FILES")                  # extra log files; nginx access logs are auto-discovered
NGINX_CONF = env("NGINX_CONF", "/host/etc/nginx")  # host nginx config dir (maps public ports -> containers)
FILE_ROLE = env("FILE_ROLE", "challenge")          # what un-attributed requests in LOG_FILES are aimed at
PUBLIC_IPS = set(env_list("PUBLIC_IP"))            # the VM's public IP(s), e.g. the Azure public IP
CONN_PER_MIN = int(env("CONN_PER_MIN", "120"))     # TCP sessions/min from one IP (nc / pwn challenges)
CTFD_CONTAINER = env("CTFD_CONTAINER", "ctfd-v388-ctfd-1")
AUTH_LOG = env("AUTH_LOG")                         # auto-detected if empty
PLATFORM = set(env_list("PLATFORM", ",".join([
    "ctfd-v388-nginx-1", "ctfd-v388-ctfd-1", "ctfd-v388-db-1", "ctfd-v388-cache-1",
    "ctfd-v388-permissions-1", "scoreboard-ui", "container-dynamic-flag-validator-flagvalidator-1", "ctfmon"])))
TRUSTED = nets(env_list("TRUSTED", "127.0.0.0/8,::1/128"))   # admin IPs: never flagged
TRUST_XFF = env("TRUST_XFF", "0") == "1"           # use X-Forwarded-For (only behind your own LB/CDN)
EGRESS_ALLOW = nets(env_list("EGRESS_ALLOW"))      # internet ranges challenges may legitimately reach
LINK_ALLOW = set(env_list("LINK_ALLOW"))           # container names / ip:port / :port challenges may reach
EXEC_IGNORE = re.compile(env("EXEC_IGNORE", r"^$"))  # regex of docker exec commands from your own automation
WEBHOOK = env("WEBHOOK")
SUSPICIOUS = int(env("SUSPICIOUS", "15"))          # IP score threshold
RATE_PER_MIN = int(env("RATE_PER_MIN", "600"))     # requests/min from one IP
LOGIN_FAILS = int(env("LOGIN_FAILS", "15"))        # failed CTFd logins per 10 min
NOTFOUND_5MIN = int(env("NOTFOUND_5MIN", "150"))   # 404s per 5 min
SSH_FAILS = int(env("SSH_FAILS", "10"))            # failed SSH logins per 10 min
DISK_MB = int(env("DISK_MB", "500"))               # container writable layer alert
CPU_PCT = float(env("CPU_PCT", "90"))
MEM_PCT = float(env("MEM_PCT", "90"))
PIDS_MAX = int(env("PIDS_MAX", "300"))
MAX_IPS = int(env("MAX_IPS", "60000"))             # IPs kept in memory (rest stay in SQLite)

SEVW = {"info": 0, "low": 0, "medium": 3, "high": 10}   # low = recorded, not scored (normal CTF solving)
SEVR = {"": -1, "info": 0, "low": 1, "medium": 2, "high": 3}

# =================================================================== state
LOCK = threading.RLock()
CONTAINERS = {}                     # name -> info
IP2CT, PORT2CT, GATEWAYS = {}, {}, set()
PREV_CPU, SIZES, RISKS, HEALTH = {}, {}, {}, {}
DF, HOST = {}, {}
IPS = {}                            # client ip -> stats
CT_ACCESS = defaultdict(dict)       # container -> ip -> {first,last,flows,via}
LINKS = {}                          # (src, dst, port/proto) -> {first,last,flows}
ALERTS = deque(maxlen=1000)
EVENTS = deque(maxlen=2000)
SOURCES = {}
DIRTY_IPS, DIRTY_ACC, DIRTY_LINKS = set(), set(), set()
HIT_Q = []
LAST_HIT, ALERT_COOL = {}, {}
COUNTERS = Counter()
REQ_MIN = {"m": 0, "cur": 0, "prev": 0}
STARTED = time.time()
DB = None
NGX_MAP, NGX_REV, LOCAL_IPS = {}, {}, set()   # nginx listen port -> [(host, port)], container -> [ports]
LOCALISH = ("host/proxy", "localhost")
RECENT_CT = defaultdict(dict)       # client ip -> {container: last connection ts}  (from conntrack)
NGX_LOGS = {}                       # discovered access_log path -> {"ports": set, "global": bool}
TAILING = set()
CTFD_PATHS = re.compile(r"^/(api/v1/|challenges|scoreboard|login|logout|register|admin|themes/|plugins/|"
                        r"users|teams|team\b|user\b|notifications|settings|reset_password|confirm|setup|"
                        r"events|healthcheck|static/|files/)", re.I)


# =================================================================== helpers
def human(n):
    try:
        n = float(n or 0)
    except (TypeError, ValueError):
        return str(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f}{u}" if u == "B" else f"{n:.1f}{u}"
        n /= 1024
    return f"{n:.1f}PB"


def ip_obj(s):
    try:
        o = ipaddress.ip_address(s)
    except ValueError:
        return None
    if o.version == 6 and o.ipv4_mapped:
        return o.ipv4_mapped
    return o


def norm_ip(s):
    o = ip_obj(s.strip().strip("[]"))
    return str(o) if o else s.strip()


def in_nets(ip, nl):
    o = ip_obj(ip)
    return bool(o) and any(o in n for n in nl)


def is_trusted(ip):
    return in_nets(ip, TRUSTED)


def role(name):
    return "platform" if name in PLATFORM else "challenge"


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).isoformat() if t else ""


def win(st, key, now, span, cap):
    """sliding-window counter stored on a stats dict"""
    dq = st.get(key)
    if dq is None:
        dq = st[key] = deque(maxlen=cap)
    dq.append(now)
    while dq and now - dq[0] > span:
        dq.popleft()
    return len(dq)


def mkcli(timeout=60):
    return docker.from_env(timeout=timeout, max_pool_size=32)


# =================================================================== storage
SCHEMA = """
CREATE TABLE IF NOT EXISTS events(ts REAL, sev TEXT, action TEXT, container TEXT, image TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS ev_ct ON events(container);
CREATE TABLE IF NOT EXISTS alerts(ts REAL, sev TEXT, kind TEXT, target TEXT, ttype TEXT, msg TEXT);
CREATE TABLE IF NOT EXISTS hits(ts REAL, ip TEXT, sev TEXT, rule TEXT, target TEXT, req TEXT, ua TEXT);
CREATE INDEX IF NOT EXISTS hits_ip ON hits(ip);
CREATE INDEX IF NOT EXISTS hits_tg ON hits(target);
CREATE TABLE IF NOT EXISTS ip_stats(ip TEXT PRIMARY KEY, data TEXT);
CREATE TABLE IF NOT EXISTS access(container TEXT, ip TEXT, first REAL, last REAL, flows INTEGER, via TEXT,
                                  PRIMARY KEY(container, ip));
CREATE TABLE IF NOT EXISTS links(src TEXT, dst TEXT, port TEXT, first REAL, last REAL, flows INTEGER,
                                 PRIMARY KEY(src, dst, port));
CREATE TABLE IF NOT EXISTS ip_intel(ip TEXT PRIMARY KEY, ts REAL, data TEXT);
"""


class Store:
    def __init__(self, path):
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        self.c = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.c.execute("PRAGMA journal_mode=WAL")
        self.c.execute("PRAGMA synchronous=NORMAL")
        self.c.executescript(SCHEMA)
        self.lock = threading.Lock()

    def x(self, sql, args=()):
        with self.lock:
            return self.c.execute(sql, args).fetchall()

    def many(self, sql, rows):
        if not rows:
            return
        with self.lock:
            self.c.execute("BEGIN")
            try:
                self.c.executemany(sql, rows)
                self.c.execute("COMMIT")
            except Exception:
                self.c.execute("ROLLBACK")
                raise


def ip_public(st):
    return {k: v for k, v in st.items() if not k.startswith(("w_", "_"))}


def load_state():
    n = 0
    for ip, data in DB.x("SELECT ip, data FROM ip_stats"):
        try:
            d = json.loads(data)
        except ValueError:
            continue
        d["reasons"] = Counter(d.get("reasons") or {})
        d["containers"] = Counter(d.get("containers") or {})
        d.setdefault("uas", [])
        d.setdefault("conns", 0)
        d["_min"], d["_mc"] = 0, 0
        d["trusted"] = is_trusted(ip)
        IPS[ip] = d
        n += 1
    for ct, ip, first, last, flows, via in DB.x("SELECT * FROM access"):
        CT_ACCESS[ct][ip] = {"first": first, "last": last, "flows": flows, "via": via}
    for src, dst, port, first, last, flows in DB.x("SELECT * FROM links"):
        LINKS[(src, dst, port)] = {"first": first, "last": last, "flows": flows}
    for r in DB.x("SELECT ts,sev,kind,target,ttype,msg FROM alerts ORDER BY rowid DESC LIMIT 1000"):
        ALERTS.append(dict(zip(("ts", "sev", "kind", "target", "ttype", "msg"), r)))
    for r in DB.x("SELECT ts,sev,action,container,image,detail FROM events ORDER BY rowid DESC LIMIT 2000"):
        EVENTS.append(dict(zip(("ts", "sev", "action", "container", "image", "detail"), r)))
    log.info("loaded %d IPs, %d alerts, %d events from %s", n, len(ALERTS), len(EVENTS), DB_PATH)


def flush():
    now = time.time()
    with LOCK:
        ips = [(ip, json.dumps(ip_public(IPS[ip]))) for ip in DIRTY_IPS if ip in IPS]
        DIRTY_IPS.clear()
        acc = []
        for ct, ip in DIRTY_ACC:
            a = CT_ACCESS.get(ct, {}).get(ip)
            if a:
                acc.append((ct, ip, a["first"], a["last"], a["flows"], a["via"]))
        DIRTY_ACC.clear()
        lk = [(k[0], k[1], k[2], LINKS[k]["first"], LINKS[k]["last"], LINKS[k]["flows"])
              for k in DIRTY_LINKS if k in LINKS]
        DIRTY_LINKS.clear()
        hits = HIT_Q[:]
        HIT_Q.clear()
        for k in [k for k, t in LAST_HIT.items() if now - t > 120]:
            LAST_HIT.pop(k, None)
        for k in [k for k, t in LAST_SSH_FAIL.items() if now - t > 60]:
            LAST_SSH_FAIL.pop(k, None)
        for ip in list(RECENT_CT):
            d = {c: t for c, t in RECENT_CT[ip].items() if now - t < 300}
            if d:
                RECENT_CT[ip] = d
            else:
                RECENT_CT.pop(ip, None)
        if len(IPS) > MAX_IPS:   # evict quiet, harmless IPs from memory (they stay in SQLite)
            for ip in sorted((i for i, s in IPS.items() if s["score"] == 0), key=lambda i: IPS[i]["last"])[:len(IPS) - MAX_IPS]:
                IPS.pop(ip, None)
    DB.many("INSERT OR REPLACE INTO ip_stats VALUES(?,?)", ips)
    DB.many("INSERT OR REPLACE INTO access VALUES(?,?,?,?,?,?)", acc)
    DB.many("INSERT OR REPLACE INTO links VALUES(?,?,?,?,?,?)", lk)
    DB.many("INSERT INTO hits VALUES(?,?,?,?,?,?,?)", hits)


def flush_loop():
    last_trim = 0
    while True:
        time.sleep(10)
        try:
            flush()
            if time.time() - last_trim > 3600:
                DB.x("DELETE FROM hits WHERE rowid < (SELECT MAX(rowid) - 300000 FROM hits)")
                DB.x("DELETE FROM events WHERE rowid < (SELECT MAX(rowid) - 200000 FROM events)")
                last_trim = time.time()
        except Exception as e:
            log.warning("flush failed: %s", e)


# =================================================================== alerts
_wh_times = deque(maxlen=20)


def post_webhook(a):
    now = time.time()
    if len(_wh_times) == _wh_times.maxlen and now - _wh_times[0] < 60:
        return                                    # max 20 webhook posts / minute
    _wh_times.append(now)
    text = f"[ctfmon {a['sev'].upper()}] {a['kind']} | {a['target']} | {a['msg']}"[:1900]
    if "discord" in WEBHOOK:
        body = {"content": text, "allowed_mentions": {"parse": []}}   # attacker text can't @everyone
    elif "slack" in WEBHOOK:
        body = {"text": text}
    else:
        body = {"text": text, "content": text, "alert": a}
    req = urllib.request.Request(WEBHOOK, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", "User-Agent": "ctfmon"})
    try:
        urllib.request.urlopen(req, timeout=10).read()
    except Exception as e:
        log.warning("webhook failed: %s", e)


def alert(sev, kind, target, msg, ttype=""):
    now = time.time()
    with LOCK:
        key = (kind, target)
        if now - ALERT_COOL.get(key, 0) < 300:   # same alert at most every 5 min
            return
        ALERT_COOL[key] = now
        a = {"ts": now, "sev": sev, "kind": kind, "target": target, "ttype": ttype, "msg": msg[:600]}
        ALERTS.appendleft(a)
    try:
        DB.x("INSERT INTO alerts VALUES(?,?,?,?,?,?)", (now, sev, kind, target, ttype, a["msg"]))
    except Exception as e:
        log.warning("alert store failed: %s", e)
    (log.warning if sev == "high" else log.info)("ALERT %s %s %s: %s", sev, kind, target, msg)
    if WEBHOOK and sev == "high":
        threading.Thread(target=post_webhook, args=(a,), daemon=True).start()


def rec_event(sev, action, container, image="", detail="", ts=None):
    e = {"ts": ts or time.time(), "sev": sev, "action": action, "container": container,
         "image": image, "detail": (detail or "")[:600]}
    with LOCK:
        EVENTS.appendleft(e)
    try:
        DB.x("INSERT INTO events VALUES(?,?,?,?,?,?)", tuple(e.values()))
    except Exception as ex:
        log.warning("event store failed: %s", ex)


# =================================================================== per-IP state + detection
def get_ip(ip, now):
    st = IPS.get(ip)
    if st is None:
        st = IPS[ip] = {"ip": ip, "first": now, "last": now, "total": 0, "s4xx": 0, "s5xx": 0, "s404": 0,
                        "peak": 0, "conns": 0, "score": 0, "maxsev": "", "reasons": Counter(), "uas": [],
                        "containers": Counter(), "last_req": "", "trusted": is_trusted(ip), "_min": 0, "_mc": 0}
        if INTEL_SCOPE == "all":
            intel_want(ip)
    if now > st["last"]:
        st["last"] = now
    DIRTY_IPS.add(ip)
    return st


def flag(st, sev, rule, target, req, ua, now):
    key = (st["ip"], rule, target)
    if now - LAST_HIT.get(key, 0) < 60:     # one incident per ip/rule/target per minute
        return
    LAST_HIT[key] = now
    before = st["score"]
    st["score"] += SEVW[sev]
    st["reasons"][rule] += 1
    if SEVR[sev] > SEVR.get(st["maxsev"], -1):
        st["maxsev"] = sev
    HIT_Q.append((now, st["ip"], sev, rule, target, (req or "")[:500], (ua or "")[:300]))
    if SEVW[sev]:
        intel_want(st["ip"], deep=True)          # attacker -> full lookup (location, VPN, reputation)
    if sev == "high":
        alert("high", rule, st["ip"], f"{st['ip']}{intel_tag(st['ip'])} -> {target}: {rule} | {(req or '')[:150]}", "ip")
    elif before < SUSPICIOUS <= st["score"]:
        top = ", ".join(f"{r}x{n}" for r, n in st["reasons"].most_common(4))
        alert("medium", "suspicious-ip", st["ip"], f"{st['ip']}{intel_tag(st['ip'])} reached score {st['score']} ({top})", "ip")


SCANNER_RE = re.compile(r"sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|\bdirb\b|ffuf|wfuzz|feroxbuster|"
                        r"nuclei|hydra|acunetix|nessus|openvas|wpscan|whatweb|arachni|skipfish|w3af|"
                        r"commix|xsstrike|burp collaborator|netsparker|zaproxy|jaeles|dalfox", re.I)
ATTACKS = [(n, re.compile(p, re.I)) for n, p in [
    ("log4shell", r"\$\{jndi:"),
    ("path-traversal", r"\.\./|\.\.\\|/etc/(passwd|shadow|hosts)|/proc/self/|c:\\windows"),
    ("sqli", r"union(\s|/\*.*?\*/|\+)+(all\s+)?select|\bor\s+\d+=\d+|sleep\(\s*\d|benchmark\(|"
             r"information_schema|pg_sleep|waitfor\s+delay|'\s*or\s*'|extractvalue\(|updatexml\("),
    ("xss", r"<script|javascript:|onerror\s*=|onload\s*=|<svg|<img[^>]+src|alert\(|document\.cookie"),
    ("ssti", r"\{\{.*\}\}|\{%.*%\}|\$\{.*\}|<%.*%>|__class__|__globals__"),
    ("cmd-injection", r"[;|&]\s*(cat|id|whoami|uname|wget|curl|nc|ncat|bash|sh|python3?|perl)\b|`[^`]+`|"
                      r"\$\([^)]+\)|/bin/(ba)?sh"),
    ("sensitive-file", r"/\.git(/|$)|/\.env\b|/\.ssh/|/\.htaccess|/\.ds_store|/config\.php|/web\.config|"
                       r"/server-status|/\.aws/|/\.docker|/docker-compose|/backup\.(zip|sql|tar)"),
    ("cms-probe", r"/wp-(admin|login|content|includes)|/phpmyadmin|/xmlrpc\.php|/cgi-bin/|/vendor/phpunit|"
                  r"/actuator|/boaform|/hnap1|/\.well-known/security|/solr/|/owa/"),
]]

LOG_RE = re.compile(r'^(?P<ip>[0-9a-fA-F:.\[\]]+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
                    r'"(?P<req>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) (?P<bytes>\S+)'
                    r'(?: "(?P<ref>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?(?P<rest>.*)$')
KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')


def parse_access(line):
    # docker may prefix lines with an RFC3339 timestamp if timestamps are enabled; strip it
    m = LOG_RE.match(line.strip())
    if not m:
        return None
    d = m.groupdict()
    kv = {k: (a or b) for k, a, b in KV_RE.findall(d.get("rest") or "")}
    return d, kv


def resolve_upstream(up):
    if not up or up == "-":
        return None
    first = up.split(",")[0].split(" : ")[0].strip()
    if first.startswith("unix:"):
        return None
    host, _, port = first.rpartition(":")
    host = host.strip("[]")
    with LOCK:
        if host in IP2CT:
            return IP2CT[host]
        try:
            return PORT2CT.get(int(port))
        except ValueError:
            return None


def guess_target(ip, path, now):
    """attribute a log line that names no upstream: use which containers this IP just connected to"""
    with LOCK:
        rec = {c: t for c, t in RECENT_CT.get(ip, {}).items() if now - t < 180 and c in CONTAINERS}
    ctfd_path = bool(CTFD_PATHS.match(path or ""))
    if ctfd_path and (CTFD_CONTAINER in rec or not rec) and CTFD_CONTAINER in CONTAINERS:
        return CTFD_CONTAINER
    chal = sorted(((t, c) for c, t in rec.items() if role(c) == "challenge"), reverse=True)
    if chal:
        return chal[0][1]
    if rec:
        return max(rec, key=rec.get)
    return None


def process_access_line(line, source, default_target, default_role="platform", hint_ports=None):
    p = parse_access(line)
    if not p:
        COUNTERS["unparsed_lines"] += 1
        return
    d, kv = p
    ip = norm_ip(d["ip"])
    xff = kv.get("xff", "")
    if TRUST_XFF and xff and xff != "-":
        ip = norm_ip(xff.split(",")[0])
    parts = d["req"].split(" ")
    method, path = (parts[0], parts[1]) if len(parts) >= 2 else ("-", d["req"])
    status = int(d["status"])
    ua = d.get("ua") or ""
    now = time.time()
    target = resolve_upstream(kv.get("up"))
    if not target and (kv.get("port") or "").isdigit():
        target = ngx_port_ct(int(kv["port"]))            # public port -> container via nginx config
    if not target and hint_ports:                        # log file belongs to one server{} block
        cts = {c for c in (ngx_port_ct(p) for p in hint_ports) if c}
        if len(cts) == 1:
            target = cts.pop()
    sure = bool(target)
    if not target:
        target = guess_target(ip, path, now)
    target = target or default_target
    with LOCK:
        if target in CONTAINERS:
            is_plat = CONTAINERS[target].get("role") == "platform"
        else:
            is_plat = default_role == "platform"
        COUNTERS["requests"] += 1
        m = int(now // 60)
        if REQ_MIN["m"] != m:
            REQ_MIN.update(prev=REQ_MIN["cur"] if REQ_MIN["m"] == m - 1 else 0, cur=0, m=m)
        REQ_MIN["cur"] += 1
        st = get_ip(ip, now)
        st["total"] += 1
        if 400 <= status < 500:
            st["s4xx"] += 1
        elif status >= 500:
            st["s5xx"] += 1
        if status == 404:
            st["s404"] += 1
        st["last_req"] = f"{method} {path[:300]} -> {status}"
        if ua and ua != "-" and ua not in st["uas"] and len(st["uas"]) < 10:
            st["uas"].append(ua[:300])
        st["containers"][target] += 1
        if sure and target in CONTAINERS:
            record_access(target, ip, now, True, (), via="nginx log" if source.startswith("file:") else "web log",
                          count_ip=False)
        if st["_min"] != m:
            st["_min"], st["_mc"] = m, 0
        st["_mc"] += 1
        st["peak"] = max(st["peak"], st["_mc"])
        if st["trusted"]:
            return
        detect(st, method, path, status, ua, target, is_plat, now)


def detect(st, method, path, status, ua, target, is_plat, now):
    req = f"{method} {path}"
    dec = unquote(unquote(path)).lower()
    attack_sev = "high" if is_plat else "low"   # attacking challenges is the game; attacking CTFd is not
    if SCANNER_RE.search(ua):
        flag(st, attack_sev, "scanner-ua", target, req, ua, now)
    for name, rx in ATTACKS:
        if rx.search(dec):
            flag(st, attack_sev, name, target, req, ua, now)
            break
    if is_plat:
        if dec.startswith("/admin"):
            flag(st, "medium", "admin-probe", target, req, ua, now)
        if method == "POST" and dec.startswith("/login") and status == 200:   # CTFd: 200 = failed, 302 = ok
            if win(st, "w_login", now, 600, LOGIN_FAILS * 2) >= LOGIN_FAILS:
                flag(st, "high", "login-bruteforce", target, req, ua, now)
        if method == "POST" and dec.startswith("/register"):
            if win(st, "w_reg", now, 600, 20) >= 5:
                flag(st, "medium", "mass-registration", target, req, ua, now)
        if "/api/v1/challenges/attempt" in dec:
            if win(st, "w_sub", now, 60, 80) >= 30:
                flag(st, "medium", "flag-bruteforce", target, req, ua, now)
        if method == "POST" and dec.startswith(("/reset_password", "/confirm")):
            if win(st, "w_rst", now, 600, 40) >= 20:
                flag(st, "medium", "reset-spam", target, req, ua, now)
    if status == 404 and win(st, "w_404", now, 300, NOTFOUND_5MIN * 2) >= NOTFOUND_5MIN:
        flag(st, "medium" if is_plat else "low", "dir-bruteforce", target, req, ua, now)
    if status == 429 and win(st, "w_429", now, 300, 120) >= 60:
        flag(st, "medium", "rate-limit-flood", target, req, ua, now)
    if st["_mc"] == RATE_PER_MIN:
        flag(st, "medium", "high-rate", target, f"{RATE_PER_MIN}+ req/min", ua, now)


HOSTPORT_RE = re.compile(r'"?(\[[0-9a-fA-F:]+\]|\d{1,3}(?:\.\d{1,3}){3}|[\w.-]+):(\d{1,5})"?$')


def process_stream_line(line, source, hint_ports=None):
    """nginx stream (TCP) log line: key=value style, or any format starting with the client IP and
    containing the upstream host:port (e.g. the common  $remote_addr [$time_local] ... "$upstream_addr")"""
    kv = {k: (a or b) for k, a, b in KV_RE.findall(line)}
    if "remote" in kv:
        ip, port, up = norm_ip(kv.get("remote", "")), kv.get("port") or "", kv.get("up")
    else:
        toks = line.split()
        ip = norm_ip(toks[0]) if toks else ""
        up = next((t.strip('"') for t in reversed(toks[1:]) if HOSTPORT_RE.match(t)), None)
        port = ""
    if not ip_obj(ip):
        COUNTERS["unparsed_lines"] += 1
        return
    target = resolve_upstream(up) or (ngx_port_ct(int(port)) if port.isdigit() else None)
    if not target and hint_ports:
        cts = {c for c in (ngx_port_ct(p) for p in hint_ports) if c}
        target = cts.pop() if len(cts) == 1 else None
        port = port or ",".join(map(str, sorted(hint_ports)))
    target = target or f"nginx-stream:{port or '?'}"
    now = time.time()
    with LOCK:
        COUNTERS["stream_sessions"] += 1
        st = get_ip(ip, now)
        st["conns"] = st.get("conns", 0) + 1
        st["containers"][target] += 1
        st["last_req"] = (f"TCP :{port} -> {target} status {kv.get('status', '?')}, {kv.get('time', '?')}s, "
                          f"in {human(kv.get('recv'))} / out {human(kv.get('sent'))}")
        if target in CONTAINERS:
            record_access(target, ip, now, True, (), via=f"nginx stream :{port}", count_ip=False)
        if st["trusted"]:
            return
        if win(st, "w_conn", now, 60, CONN_PER_MIN * 2) >= CONN_PER_MIN:
            flag(st, "medium", "conn-flood", target, f"{CONN_PER_MIN}+ TCP sessions/min on :{port}", "", now)


def file_line(line, label, info=None):
    hint = sorted(info["ports"]) if info and info["ports"] and not info["global"] else None
    if line.startswith("stream "):
        return process_stream_line(line, label, hint)
    if LOG_RE.match(line.strip()):
        return process_access_line(line, label, label, FILE_ROLE, hint)
    if info and info.get("stream"):
        return process_stream_line(line, label, hint)
    COUNTERS["unparsed_lines"] += 1


# =================================================================== docker: inventory, stats, sizes
SEVERE_CAPS = {"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "NET_ADMIN", "SYS_RAWIO",
               "ALL", "BPF", "PERFMON", "SYS_BOOT"}
SENSITIVE_MOUNTS = {"/", "/etc", "/root", "/home", "/proc", "/sys", "/dev", "/var/run", "/run",
                    "/var/lib/docker", "/boot", "/var/log"}


def check_risky(cli, cid, name):
    try:
        a = cli.api.inspect_container(cid)
    except Exception:
        return
    hc, cfg = a.get("HostConfig") or {}, a.get("Config") or {}
    risks = []
    if hc.get("Privileged"):
        risks.append(("privileged", "high"))
    for cap in hc.get("CapAdd") or []:
        c = cap.upper().replace("CAP_", "")
        if c in SEVERE_CAPS:
            risks.append((f"cap {c}", "high"))
    for mnt in a.get("Mounts") or []:
        src = mnt.get("Source") or ""
        if src.endswith("docker.sock"):
            risks.append(("docker.sock mounted", "high"))
        elif (src.rstrip("/") or "/") in SENSITIVE_MOUNTS:
            risks.append((f"host mount {src}", "high"))
    for k, label in (("NetworkMode", "host network"), ("PidMode", "host pid"), ("IpcMode", "host ipc")):
        if hc.get(k) == "host":
            risks.append((label, "high"))
    for opt in hc.get("SecurityOpt") or []:
        if "unconfined" in opt:
            risks.append((opt, "medium"))
    if not hc.get("Memory"):
        risks.append(("no memory limit", "low"))
    if not hc.get("PidsLimit") or hc.get("PidsLimit") <= 0:
        risks.append(("no pids limit", "low"))
    if (cfg.get("User") or "root") in ("root", "0", "0:0"):
        risks.append(("runs as root", "low"))
    test = (cfg.get("Healthcheck") or {}).get("Test") or []
    if test and test[0] in ("CMD", "CMD-SHELL"):
        HEALTH[name] = " ".join(test[1:])
    risks = list(dict.fromkeys(risks))
    with LOCK:
        RISKS[name] = risks
        if name in CONTAINERS:
            CONTAINERS[name]["risks"] = risks
    bad = [r for r, s in risks if s == "high"]
    if bad and role(name) == "challenge":
        alert("high", "risky-container", name, f"{name} ({cfg.get('Image')}): {', '.join(bad)}", "container")


def refresh_inventory(cli):
    rows = cli.api.containers(all=True)
    seen, ip2ct, port2ct, gws, new = set(), {}, {}, set(), []
    for r in rows:
        name = r["Names"][0].lstrip("/") if r.get("Names") else r["Id"][:12]
        seen.add(name)
        ports = set()
        for p in r.get("Ports") or []:
            if p.get("PublicPort"):
                port2ct[p["PublicPort"]] = name
                ports.add(f'{p.get("IP", "")}:{p["PublicPort"]}->{p["PrivatePort"]}/{p.get("Type", "tcp")}')
            else:
                ports.add(f'{p["PrivatePort"]}/{p.get("Type", "tcp")}')
        ips = []
        for net in ((r.get("NetworkSettings") or {}).get("Networks") or {}).values():
            if net.get("IPAddress"):
                ips.append(net["IPAddress"])
                ip2ct[net["IPAddress"]] = name
            if net.get("GlobalIPv6Address"):
                ip2ct[net["GlobalIPv6Address"]] = name
            if net.get("Gateway"):
                gws.add(net["Gateway"])
        with LOCK:
            c = CONTAINERS.get(name)
            if c is None or c.get("id") != r["Id"][:12]:
                c = CONTAINERS[name] = {"name": name, "cpu": None, "mem": None, "mem_limit": None,
                                        "mem_pct": None, "pids": None, "net_rx": None, "net_tx": None,
                                        "blk_r": None, "blk_w": None, "hot": 0, "risks": RISKS.get(name, [])}
                new.append((r["Id"], name))
            rw, root = SIZES.get(name, (None, None))
            c.update(id=r["Id"][:12], image=r.get("Image"), state=r.get("State"), status=r.get("Status"),
                     created=r.get("Created"), ports=", ".join(sorted(ports)), ips=ips, role=role(name),
                     size_rw=rw, size_root=root)
            if c["state"] != "running":
                c.update(cpu=None, pids=None)
    with LOCK:
        for n in [n for n in CONTAINERS if n not in seen]:
            CONTAINERS.pop(n, None)
            PREV_CPU.pop(n, None)
        IP2CT.clear()
        IP2CT.update(ip2ct)
        PORT2CT.clear()
        PORT2CT.update(port2ct)
        GATEWAYS.clear()
        GATEWAYS.update(gws)
    rebuild_ngx_rev()
    for cid, name in new:
        check_risky(cli, cid, name)


def get_stats(cli, name, cid):
    try:
        try:
            return name, cli.api.stats(cid, stream=False, one_shot=True)
        except TypeError:
            return name, cli.api.stats(cid, stream=False)
    except Exception:
        return name, None


def apply_stats(name, s):
    c = CONTAINERS.get(name)
    if not c:
        return
    cpu = s.get("cpu_stats") or {}
    usage = cpu.get("cpu_usage") or {}
    tot, sysu = usage.get("total_usage") or 0, cpu.get("system_cpu_usage") or 0
    ncpu = cpu.get("online_cpus") or len(usage.get("percpu_usage") or []) or 1
    prev = PREV_CPU.get(name)
    if prev is None:
        pre = s.get("precpu_stats") or {}
        if pre.get("system_cpu_usage"):
            prev = ((pre.get("cpu_usage") or {}).get("total_usage") or 0, pre["system_cpu_usage"])
    PREV_CPU[name] = (tot, sysu)
    if prev and sysu > prev[1] and tot >= prev[0]:
        c["cpu"] = round((tot - prev[0]) / (sysu - prev[1]) * ncpu * 100, 1)
    m = s.get("memory_stats") or {}
    mst = m.get("stats") or {}
    inactive = mst.get("inactive_file", mst.get("total_inactive_file", mst.get("cache", 0))) or 0
    used, limit = max((m.get("usage") or 0) - inactive, 0), m.get("limit") or 0
    rx = tx = br = bw = 0
    for n in (s.get("networks") or {}).values():
        rx += n.get("rx_bytes", 0)
        tx += n.get("tx_bytes", 0)
    for e in (s.get("blkio_stats") or {}).get("io_service_bytes_recursive") or []:
        op = (e.get("op") or "").lower()
        if op == "read":
            br += e.get("value", 0)
        elif op == "write":
            bw += e.get("value", 0)
    c.update(mem=used, mem_limit=limit, mem_pct=round(used / limit * 100, 1) if limit else None,
             pids=(s.get("pids_stats") or {}).get("current"), net_rx=rx, net_tx=tx, blk_r=br, blk_w=bw)
    if c["cpu"] is not None and c["cpu"] >= CPU_PCT:
        c["hot"] += 1
        if c["hot"] == 3:
            alert("medium", "cpu-hog", name, f"{name} at {c['cpu']}% CPU for {3 * STATS_EVERY}s+", "container")
    else:
        c["hot"] = 0
    if c["mem_pct"] and c["mem_pct"] >= MEM_PCT and limit < (HOST.get("mem_total") or 1 << 62):
        alert("medium", "memory-pressure", name, f"{name} using {c['mem_pct']}% of its {human(limit)} limit",
              "container")
    if c["pids"] and c["pids"] >= PIDS_MAX:
        alert("high", "fork-bomb", name, f"{name} has {c['pids']} processes", "container")


_prev_host = [None]


def host_stats():
    try:
        with open("/proc/stat") as f:
            vals = list(map(int, f.readline().split()[1:9]))
        idle, total = vals[3] + vals[4], sum(vals)
        cpu = None
        if _prev_host[0]:
            dt, di = total - _prev_host[0][0], idle - _prev_host[0][1]
            cpu = round(100 * (dt - di) / dt, 1) if dt > 0 else None
        _prev_host[0] = (total, idle)
        mem = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":", 1)
                mem[k] = int(v.split()[0]) * 1024
        with open("/proc/loadavg") as f:
            load = f.read().split()[:3]
        sv = os.statvfs("/")
        dtot, dfree = sv.f_blocks * sv.f_frsize, sv.f_bavail * sv.f_frsize
        HOST.update(cpu=cpu, load=load, ncpu=os.cpu_count(), mem_total=mem.get("MemTotal"),
                    mem_avail=mem.get("MemAvailable"), disk_total=dtot, disk_free=dfree)
        if dtot and dfree / dtot < 0.10:
            alert("high", "host-disk", "host", f"only {human(dfree)} disk free ({dfree / dtot:.0%})")
        if mem.get("MemTotal") and mem.get("MemAvailable", 0) / mem["MemTotal"] < 0.08:
            alert("high", "host-memory", "host", f"only {human(mem['MemAvailable'])} RAM available")
    except Exception as e:
        log.debug("host stats: %s", e)


def stats_loop(cli):
    pool = ThreadPoolExecutor(max_workers=16)
    while True:
        t0 = time.time()
        try:
            refresh_inventory(cli)
            with LOCK:
                running = [(c["name"], c["id"]) for c in CONTAINERS.values() if c.get("state") == "running"]
            for name, s in pool.map(lambda nc: get_stats(cli, *nc), running):
                if s:
                    with LOCK:
                        apply_stats(name, s)
            host_stats()
            SOURCES["docker"] = f"ok ({len(running)} running)"
        except Exception as e:
            SOURCES["docker"] = f"error: {e}"
            log.warning("stats loop: %s", e)
        time.sleep(max(1.0, STATS_EVERY - (time.time() - t0)))


def size_loop(cli):
    last_df = 0
    while True:
        try:
            rows = cli.api.containers(all=True, size=True)
            with LOCK:
                for r in rows:
                    name = r["Names"][0].lstrip("/") if r.get("Names") else r["Id"][:12]
                    rw, root = r.get("SizeRw") or 0, r.get("SizeRootFs") or 0
                    SIZES[name] = (rw, root)
                    if name in CONTAINERS:
                        CONTAINERS[name].update(size_rw=rw, size_root=root)
                    if rw > DISK_MB * 1024 * 1024:
                        alert("high", "disk-fill", name, f"{name} writable layer is {human(rw)}", "container")
            if time.time() - last_df > 900:
                d = cli.api.df()
                DF.update(images=len(d.get("Images") or []),
                          images_size=sum(i.get("Size", 0) for i in d.get("Images") or []),
                          volumes=len(d.get("Volumes") or []),
                          volumes_size=sum(max((v.get("UsageData") or {}).get("Size", 0), 0)
                                           for v in d.get("Volumes") or []),
                          build_cache=sum(b.get("Size", 0) for b in d.get("BuildCache") or []),
                          containers_rw=sum(c.get("SizeRw", 0) or 0 for c in d.get("Containers") or []))
                last_df = time.time()
        except Exception as e:
            log.warning("size loop: %s", e)
        time.sleep(SIZE_EVERY)


# =================================================================== docker events
START_TIMES = defaultdict(lambda: deque(maxlen=20))


def handle_event(ev, cli):
    actor = ev.get("Actor") or {}
    attrs = actor.get("Attributes") or {}
    cid = actor.get("ID") or ev.get("id") or ""
    name = attrs.get("name") or cid[:12]
    image = attrs.get("image") or ev.get("from") or ""
    ts = (ev.get("timeNano") or 0) / 1e9 or ev.get("time") or time.time()
    base, _, detail = (ev.get("Action") or ev.get("status") or "").partition(":")
    base, detail = base.strip(), detail.strip()
    if base in ("top", "resize", "exec_start", "exec_die", "exec_detach"):
        return
    if base == "health_status":
        if detail == "unhealthy":
            rec_event("low", "unhealthy", name, image, "", ts)
        return
    sev, extra = "info", ""
    if base == "exec_create":
        hc = HEALTH.get(name)
        if (hc and hc in detail) or EXEC_IGNORE.search(detail):
            return
        sev = "high"
        alert("high", "docker-exec", name, f"docker exec into {name} ({image}): {detail}", "container")
    elif base == "oom":
        sev = "high"
        alert("high", "oom", name, f"{name} ({image}) was OOM-killed", "container")
    elif base == "attach":
        sev = "medium"
        alert("medium", "docker-attach", name, f"someone attached to {name}", "container")
    elif base in ("archive-path", "extract-to-dir"):
        sev = "medium"
        alert("medium", "docker-cp", name,
              f"docker cp {'out of' if base == 'archive-path' else 'into'} {name}", "container")
    elif base in ("commit", "export"):
        sev = "medium"
        alert("medium", f"docker-{base}", name, f"{name} was {base}ed (filesystem copied)", "container")
    elif base == "die":
        code = attrs.get("exitCode", "")
        extra = f"exit code {code}"
        if code not in ("0", "137", "143", ""):
            sev = "low"
    elif base == "start":
        dq = START_TIMES[name]
        dq.append(ts)
        recent = sum(1 for t in dq if ts - t < 600)
        if recent >= 5:
            sev = "medium"
            alert("medium", "crash-loop", name, f"{name} started {recent}x in 10 min", "container")
        threading.Thread(target=check_risky, args=(cli, cid, name), daemon=True).start()
    rec_event(sev, base, name, image, detail or extra, ts)


def events_loop():
    since = int(time.time())
    while True:
        try:
            cli = mkcli(timeout=120)
            SOURCES["docker-events"] = "ok"
            for ev in cli.events(decode=True, since=since, filters={"type": "container"}):
                since = int(ev.get("time") or time.time())
                try:
                    handle_event(ev, cli)
                except Exception as e:
                    log.warning("event handling: %s", e)
        except Exception as e:
            SOURCES["docker-events"] = f"error: {e}"
            log.warning("events stream: %s", e)
            time.sleep(5)


# =================================================================== access-log sources
def follow_container_logs(name):
    since = int(time.time())
    src = "log:" + name
    while True:
        try:
            cli = mkcli(timeout=120)
            c = cli.containers.get(name)
            SOURCES[src] = "ok (following stdout/stderr)"
            buf = b""
            for chunk in c.logs(stream=True, follow=True, stdout=True, stderr=True, since=since):
                buf += chunk
                *lines, buf = buf.split(b"\n")
                for ln in lines:
                    try:
                        process_access_line(ln.decode("utf-8", "replace"), src, name)
                    except Exception as e:
                        log.debug("line: %s", e)
                since = int(time.time())
            SOURCES[src] = "stream ended (container stopped?), reconnecting"
            time.sleep(3)
        except Exception as e:
            SOURCES[src] = f"error: {e}"
            time.sleep(10)


def tail_file(path, handler, name):
    f, ino, first = None, None, True
    while True:
        try:
            if f is None:
                f = open(path, "r", errors="replace")
                ino = os.fstat(f.fileno()).st_ino
                if first:
                    f.seek(0, 2)
                first = False
                SOURCES[name] = f"ok ({path})"
            line = f.readline()
            if line:
                if line.endswith("\n"):
                    handler(line.rstrip("\n"))
                else:
                    f.seek(f.tell() - len(line.encode(errors="replace")))
                    time.sleep(0.5)
                continue
            time.sleep(1)
            st = os.stat(path)
            if st.st_ino != ino or st.st_size < f.tell():   # rotated / truncated
                f.close()
                f = None
        except FileNotFoundError:
            SOURCES[name] = f"waiting for {path}"
            if f:
                f.close()
            f = None
            time.sleep(10)
        except Exception as e:
            SOURCES[name] = f"error: {e}"
            if f:
                f.close()
            f = None
            time.sleep(10)


# =================================================================== host auth.log
SSH_OK = re.compile(r"sshd(?:-session)?\[\d+\]: Accepted (\S+) for (\S+) from (\S+) port (\d+)(?: [^\s:]+(?:: (.*))?)?")
# key-only servers: bots trying a real user (root, azureuser...) only leave a "closed ... [preauth]" line
SSH_PRE = re.compile(r"sshd(?:-session)?\[\d+\]: (?:Connection closed|Disconnected) by (?:authenticating|invalid) user "
                     r"(\S*) (\S+) port \d+ \[preauth\]")
SSH_SCAN = re.compile(r"sshd(?:-session)?\[\d+\]: (?:banner exchange: Connection from (\S+) port \d+: (.*)|"
                      r"Did not receive identification string from (\S+)|"
                      r"Unable to negotiate with (\S+) port \d+: (.*))")
SSH_FAIL = re.compile(r"sshd(?:-session)?\[\d+\]: (?:Failed \S+ for (?:invalid user )?(\S+)|"
                      r"Invalid user (\S*)) from (\S+)")
LAST_SSH_FAIL = {}
SUDO = re.compile(r"sudo(?:\[\d+\])?:\s+(\S+) : .*?COMMAND=(.*)$")


def ssh_rec(st, now):
    d = st.get("ssh")
    if not isinstance(d, dict):
        d = st["ssh"] = {"fails": 0, "users": {}, "logins": [], "notes": [], "first": now, "last": now}
    d["last"] = now
    return d


def ssh_fail(ip, user, now):
    with LOCK:
        st = get_ip(ip, now)
        d = ssh_rec(st, now)
        d["fails"] += 1
        if user in d["users"] or len(d["users"]) < 300:
            d["users"][user] = d["users"].get(user, 0) + 1
        if not st["trusted"] and win(st, "w_ssh", now, 600, SSH_FAILS * 2) >= SSH_FAILS:
            flag(st, "medium", "ssh-bruteforce", "host-ssh", f"user {user}", "", now)


def handle_auth(line):
    now = time.time()
    m = SSH_OK.search(line)
    if m:
        method, user, ip, port, key = m.groups()
        ip = norm_ip(ip)
        trusted = is_trusted(ip)
        with LOCK:
            d = ssh_rec(get_ip(ip, now), now)
            d["logins"] = (d["logins"] + [{"ts": now, "user": user, "method": method, "key": key or ""}])[-30:]
        if not trusted:
            try:
                lookup_now(ip)                         # rare + important: know where it came from before alerting
            except Exception as e:
                log.warning("lookup %s failed: %s", ip, e)
        extra = f", key {key}" if key else ""
        rec_event("medium" if not trusted else "info", "ssh-login", "host", "", f"{user} from {ip} ({method}{extra})")
        alert("medium" if trusted else "high", "ssh-login", ip,
              f"SSH login as {user} from {ip}{intel_tag(ip)} ({method}{extra})", "ip")
        return
    m = SSH_FAIL.search(line)
    if m:
        ip = norm_ip(m.group(3))
        user = m.group(1) or m.group(2) or "?"
        LAST_SSH_FAIL[(ip, user)] = now
        ssh_fail(ip, user, now)
        return
    m = SSH_PRE.search(line)
    if m:
        ip = norm_ip(m.group(2))
        user = m.group(1) or "?"
        if now - LAST_SSH_FAIL.pop((ip, user), 0) > 5:   # not already counted by a "Failed/Invalid ..." line
            ssh_fail(ip, user, now)
        return
    m = SSH_SCAN.search(line)
    if m:
        ip = norm_ip(m.group(1) or m.group(3) or m.group(4))
        note = (m.group(2) or m.group(5) or "no SSH banner sent (port scanner)")[:160]
        with LOCK:
            d = ssh_rec(get_ip(ip, now), now)
            if note not in d["notes"]:
                d["notes"] = (d["notes"] + [note])[-10:]
        return
    m = SUDO.search(line)
    if m:
        user, cmd = m.groups()
        risky = "docker" in cmd and re.search(r"\b(exec|cp|attach|commit|export|run)\b", cmd)
        rec_event("medium" if risky else "info", "sudo", "host", "", f"{user}: {cmd}")
        if risky:
            alert("medium", "sudo-docker", user, f"{user} ran: {cmd}", "")


# =================================================================== conntrack: who talks to which container
TCP_STATES = {"ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT", "TIME_WAIT", "CLOSE", "CLOSE_WAIT",
              "LAST_ACK", "LISTEN", "CLOSING"}
SEEN_FLOWS = {}


def read_conntrack():
    try:
        with open("/proc/net/nf_conntrack") as f:
            return f.read().splitlines(), "procfs"
    except OSError:
        pass
    try:
        out = subprocess.run(["conntrack", "-L", "-o", "extended"], capture_output=True, text=True, timeout=30)
        if out.returncode == 0:
            return out.stdout.splitlines(), "conntrack tool"
        return None, out.stderr.strip()[:200] or "conntrack failed"
    except FileNotFoundError:
        return None, "no /proc/net/nf_conntrack and no conntrack binary (apt install conntrack)"
    except Exception as e:
        return None, str(e)


def parse_ct(line):
    toks = line.split()
    proto = next((t for t in toks[:6] if t in ("tcp", "udp", "icmp", "icmpv6", "sctp")), None)
    state = next((t for t in toks if t in TCP_STATES), "")
    o, r, cur = {}, {}, None
    cur = o
    for t in toks:
        if "=" not in t:
            continue
        k, v = t.split("=", 1)
        if k not in ("src", "dst", "sport", "dport"):
            continue
        if k in cur:
            if cur is o:
                cur = r
            else:
                break
        cur[k] = v
    if not proto or "src" not in o:
        return None
    return proto, state, o, r


def record_access(ct, ip, now, new, gws, via=None, count_ip=True):
    o = ip_obj(ip)
    if o is None:
        return
    if ip in gws:
        via = "host/proxy"                       # docker-proxy leg (host -> container)
    elif o.is_loopback or ip in LOCAL_IPS or o.is_link_local:
        via = "localhost"                        # from the VM itself (nginx upstream leg, or someone on the box)
    else:
        via = via or "direct"
    with LOCK:
        a = CT_ACCESS[ct].get(ip)
        if a is None:
            a = CT_ACCESS[ct][ip] = {"first": now, "last": now, "flows": 0, "via": via}
        elif a["via"] in LOCALISH and via not in LOCALISH:
            a["via"] = via
        a["last"] = now
        if new:
            a["flows"] += 1
            if count_ip and via not in LOCALISH:
                get_ip(ip, now)["containers"][ct] += 1
        if via not in LOCALISH:
            RECENT_CT[ip][ct] = now
        DIRTY_ACC.add((ct, ip))


def record_link(src, dst, port, now, new):
    key = (src, dst, port)
    with LOCK:
        lk = LINKS.get(key)
        if lk is None:
            lk = LINKS[key] = {"first": now, "last": now, "flows": 0}
        lk["last"] = now
        if new:
            lk["flows"] += 1
        DIRTY_LINKS.add(key)


def link_allowed(dst_name, dst_ip, dport):
    return bool(LINK_ALLOW & {dst_name or "", f"{dst_ip}:{dport}", f":{dport}"})


def process_flows(lines, now):
    with LOCK:
        ip2ct, gws, port2ct = dict(IP2CT), set(GATEWAYS), dict(PORT2CT)
        local = set(LOCAL_IPS) | PUBLIC_IPS
    n = 0
    for line in lines:
        f = parse_ct(line)
        if not f:
            continue
        proto, state, o, r = f
        if proto not in ("tcp", "udp"):
            continue
        key = (proto, o.get("src"), o.get("sport"), o.get("dst"), o.get("dport"))
        new = key not in SEEN_FLOWS
        SEEN_FLOWS[key] = now
        osrc, odst, dport = o.get("src"), o.get("dst"), o.get("dport")
        rsrc, rsport = r.get("src"), r.get("sport")
        src_ct = ip2ct.get(osrc)
        dst_ct = ip2ct.get(rsrc) or ip2ct.get(odst)
        real_port = rsport if ip2ct.get(rsrc) else dport
        lp = int(dport) if (dport or "").isdigit() else 0
        d = ip_obj(odst)
        to_host = bool(d) and (d.is_loopback or odst in local)
        n += 1
        if dst_ct and not src_ct:                                   # client -> container (published port / DNAT)
            record_access(dst_ct, osrc, now, new, gws)
        elif src_ct and dst_ct and src_ct != dst_ct:                # container -> container
            record_link(src_ct, dst_ct, f"{real_port}/{proto}", now, new)
            if new and role(src_ct) == "challenge" and not link_allowed(dst_ct, odst, dport):
                kind = "pivot-to-platform" if role(dst_ct) == "platform" else "cross-challenge"
                alert("high", kind, src_ct, f"{src_ct} connected to {dst_ct}:{real_port}/{proto}", "container")
        elif not src_ct and not dst_ct and to_host and lp:          # someone -> a port on this VM
            via_ct = ngx_port_ct(lp)
            s = ip_obj(osrc)
            if via_ct and s and not (s.is_loopback or osrc in local):
                record_access(via_ct, osrc, now, new, gws, via=f"nginx :{lp}")     # public IP -> nginx -> container
            elif lp in port2ct:
                record_access(port2ct[lp], osrc, now, new, gws)                  # straight to 127.0.0.1:328xx
        elif src_ct and not dst_ct and role(src_ct) == "challenge":  # challenge -> host / internet
            if d is None:
                continue
            via_ct = ngx_port_ct(lp) if to_host and lp else None
            if via_ct:                                               # another instance through nginx
                record_link(src_ct, via_ct, f"nginx:{lp}/{proto}", now, new)
                if new and via_ct != src_ct and not link_allowed(via_ct, odst, dport):
                    kind = "pivot-to-platform" if role(via_ct) == "platform" else "cross-challenge"
                    alert("high", kind, src_ct, f"{src_ct} connected to {via_ct} through nginx :{lp}", "container")
                continue
            record_link(src_ct, odst, f"{dport}/{proto}", now, new)
            if not new or link_allowed(None, odst, dport):
                continue
            if odst in gws or to_host:
                alert("high", "host-access", src_ct, f"{src_ct} reached host service {odst}:{dport}/{proto}",
                      "container")
            elif d.is_global and not in_nets(odst, EGRESS_ALLOW) and not (dport == "53"):
                alert("medium", "egress", src_ct,
                      f"{src_ct} opened outbound {proto} to {odst}:{dport} (reverse shell / exfil?)", "container")
    for k in [k for k, t in SEEN_FLOWS.items() if now - t > 900]:
        SEEN_FLOWS.pop(k, None)
    return n


def conn_loop():
    while True:
        t0 = time.time()
        lines, mode = read_conntrack()
        if lines is None:
            SOURCES["conntrack"] = "unavailable: " + mode
            time.sleep(60)
            continue
        try:
            n = process_flows(lines, time.time())
            SOURCES["conntrack"] = f"ok ({mode}, {n} flows)"
        except Exception as e:
            SOURCES["conntrack"] = f"error: {e}"
        time.sleep(max(1.0, CONN_EVERY - (time.time() - t0)))


# =================================================================== host nginx config: public port -> container
NGX_TOK = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|[{};]|[^\s{};]+')
NGX_SKIP = {"sites-available", "conf-available", "modules-available", "streams-available", "snippets-available"}
PASS_DIRECTIVES = ("proxy_pass", "grpc_pass", "uwsgi_pass", "scgi_pass", "fastcgi_pass")


def _host_path(p):
    """follow symlinks inside the mounted config dir (sites-enabled -> /etc/nginx/sites-available/...)"""
    for _ in range(10):
        if not os.path.islink(p):
            break
        t = os.readlink(p)
        if not os.path.isabs(t):
            t = os.path.join(os.path.dirname(p), t)
        elif NGINX_CONF != "/etc/nginx" and t.startswith("/etc/nginx"):
            t = NGINX_CONF + t[len("/etc/nginx"):]
        elif not t.startswith("/host/") and os.path.exists("/host" + t):
            t = "/host" + t
        p = t
    return p


def ngx_files(root):
    out = []
    for dp, dns, fns in os.walk(root, followlinks=True):
        dns[:] = [x for x in dns if x not in NGX_SKIP]
        for fn in fns:
            if fn.endswith(("~", ".bak", ".swp", ".dpkg-old", ".dpkg-dist", ".types")) or "params" in fn:
                continue
            out.append(os.path.join(dp, fn))
    return out


def ngx_parse(text):
    text = re.sub(r"(?m)#.*$", "", text)
    root, cur = [], []
    stack = [root]
    for t in NGX_TOK.findall(text):
        if t == ";":
            if cur:
                stack[-1].append((cur[0], cur[1:], None))
            cur = []
        elif t == "{":
            node = (cur[0] if cur else "", cur[1:], [])
            stack[-1].append(node)
            stack.append(node[2])
            cur = []
        elif t == "}":
            if cur:
                stack[-1].append((cur[0], cur[1:], None))
            cur = []
            if len(stack) > 1:
                stack.pop()
        else:
            cur.append(t[1:-1] if t[:1] in "\"'" and len(t) > 1 else t)
    return root


def ngx_walk(nodes, fn):
    for nd in nodes:
        fn(nd)
        if nd[2]:
            ngx_walk(nd[2], fn)


def _listen_port(v):
    if v.startswith("unix:"):
        return None
    p = v.rsplit(":", 1)[-1] if ":" in v else v
    return int(p) if p.isdigit() else None


def _hostport(v):
    host, sep, port = v.rpartition(":")
    if not sep or not port.isdigit():
        return []
    return [(host.strip("[]"), int(port))]


def build_nginx_map(files):
    upstreams, servers = {}, []
    trees = []
    for f in files:
        try:
            with open(_host_path(f), errors="replace") as fh:
                trees.append(ngx_parse(fh.read(2_000_000)))
        except OSError:
            continue

    def visit(nd):
        if nd[0] == "upstream" and nd[2] is not None and nd[1]:
            upstreams[nd[1][0]] = [c[1][0] for c in nd[2] if c[0] == "server" and c[1]]
        elif nd[0] == "server" and nd[2] is not None:
            servers.append(nd[2])

    for t in trees:
        ngx_walk(t, visit)
    out = {}
    for body in servers:
        ports, targets = set(), []

        def v2(nd):
            if nd[0] == "listen" and nd[1]:
                p = _listen_port(nd[1][0])
                if p:
                    ports.add(p)
            elif nd[0] in PASS_DIRECTIVES and nd[1] and "$" not in nd[1][0]:
                hp = re.sub(r"^\w+://", "", nd[1][0]).split("/", 1)[0]
                if hp in upstreams:
                    for u in upstreams[hp]:
                        targets.extend(_hostport(u))
                else:
                    targets.extend(_hostport(hp))

        ngx_walk(body, v2)
        for p in ports:
            lst = out.setdefault(p, [])
            lst.extend(t for t in targets if t not in lst)
    return out


def collect_logs(nodes, ctx, ports, out):
    """find access_log directives and which server{} (listen ports) each belongs to"""
    for name, args, kids in nodes:
        if kids is not None:
            if name in ("http", "stream"):
                collect_logs(kids, name, None, out)
            elif name == "server":
                sp = {_listen_port(c[1][0]) for c in kids if c[0] == "listen" and c[1]} - {None}
                is_stream = ctx == "stream" or (
                    not any(c[0] == "location" for c in kids) and any(c[0] == "proxy_pass" for c in kids))
                collect_logs(kids, "stream" if is_stream else (ctx or "http"), sp, out)
            else:
                collect_logs(kids, ctx, ports, out)
        elif name == "access_log" and args and args[0] != "off":
            path = args[0]
            if path.startswith(("syslog:", "/dev/")) or "$" in path or not path.startswith("/"):
                continue
            e = out.setdefault(path, {"ports": set(), "global": False, "stream": False})
            if ports:
                e["ports"] |= ports
            else:
                e["global"] = True
            if ctx == "stream":
                e["stream"] = True


def discover_logs(files):
    out = {}
    for f in files:
        try:
            with open(_host_path(f), errors="replace") as fh:
                collect_logs(ngx_parse(fh.read(2_000_000)), None, None, out)
        except OSError:
            continue
    out.setdefault("/var/log/nginx/access.log", {"ports": set(), "global": True, "stream": False})
    return out


def host_log_path(p):
    return "/host" + p if os.path.isdir("/host") and not p.startswith("/host/") else p


def ensure_tails():
    """start a tail for every discovered nginx access log + CTFMON_LOG_FILES (read-only)"""
    with LOCK:
        wanted = {host_log_path(p): info for p, info in NGX_LOGS.items()}
    for p in LOG_FILES:
        wanted.setdefault(p, {"ports": set(), "global": True, "stream": "stream" in p})
    for path, info in wanted.items():
        if path in TAILING:
            continue
        TAILING.add(path)
        label = "file:" + os.path.basename(path)

        def handler(ln, label=label, raw=path):
            with LOCK:
                inf = NGX_LOGS.get(raw[5:] if raw.startswith("/host/") else raw)
            file_line(ln, label, inf)

        start(tail_file, path, handler, "log " + path)


def ngx_port_ct(lp):
    """public nginx port -> container name (via the upstream it proxies to)"""
    with LOCK:
        for host, port in NGX_MAP.get(lp, ()):
            if host in IP2CT:
                return IP2CT[host]
            if port in PORT2CT:
                return PORT2CT[port]
    return None


def rebuild_ngx_rev():
    rev = defaultdict(list)
    with LOCK:
        ports = sorted(NGX_MAP)
    for lp in ports:
        ct = ngx_port_ct(lp)
        if ct:
            rev[ct].append(lp)
    with LOCK:
        NGX_REV.clear()
        NGX_REV.update(rev)


def local_ips():
    ips = set()
    try:
        with open("/proc/net/fib_trie") as f:
            lines = f.read().splitlines()
        for i, ln in enumerate(lines):
            if "/32 host LOCAL" in ln and i:
                ips.add(lines[i - 1].split()[-1])
    except OSError:
        pass
    try:
        with open("/proc/net/if_inet6") as f:
            for ln in f:
                ips.add(str(ipaddress.ip_address(int(ln.split()[0], 16))))
    except (OSError, ValueError):
        pass
    return ips


def nginx_loop():
    sig = None
    while True:
        try:
            ips = local_ips()
            with LOCK:
                LOCAL_IPS.clear()
                LOCAL_IPS.update(ips)
            if not os.path.isdir(NGINX_CONF):
                SOURCES["nginx-config"] = f"not found at {NGINX_CONF} (mount /etc/nginx to map public ports)"
                ensure_tails()
            else:
                cur = []
                for f in ngx_files(NGINX_CONF):
                    try:
                        st = os.stat(_host_path(f))
                        cur.append((f, st.st_mtime, st.st_size))
                    except OSError:
                        pass
                cur = tuple(sorted(cur))
                if cur != sig:
                    files = [f for f, _, _ in cur]
                    m, logs = build_nginx_map(files), discover_logs(files)
                    with LOCK:
                        NGX_MAP.clear()
                        NGX_MAP.update(m)
                        NGX_LOGS.clear()
                        NGX_LOGS.update(logs)
                    sig = cur
                ensure_tails()
                rebuild_ngx_rev()
                with LOCK:
                    live = sum(len(v) for v in NGX_REV.values())
                SOURCES["nginx-config"] = f"ok ({len(NGX_MAP)} listen ports, {live} routed to running containers)"
        except Exception as e:
            SOURCES["nginx-config"] = f"error: {e}"
        time.sleep(15)


# =================================================================== IP intelligence: who is this attacker?
# Everything here is passive lookups about an IP address (never touches the attacker's machine):
#   ip-api.com     country / region / city / ISP / org / ASN / reverse DNS / proxy-VPN / hosting / mobile (free, no key)
#   Tor project    official list of Tor exit nodes
#   proxycheck.io  VPN / proxy detection incl. the VPN provider name (keyless 100/day, free key 1000/day)
#   AbuseIPDB      worldwide abuse reputation + report count (optional free key, 1000/day)
INTEL_ON = env("INTEL", "1") == "1"
INTEL_SCOPE = env("INTEL_SCOPE", "all")           # all = geolocate every public IP, flagged = only IPs with score > 0
INTEL_TTL = float(env("INTEL_TTL_DAYS", "7")) * 86400
PROXYCHECK_KEY = env("PROXYCHECK_KEY")
ABUSEIPDB_KEY = env("ABUSEIPDB_KEY")
DEEP_BUDGET = {"proxycheck": 900 if PROXYCHECK_KEY else 90, "abuseipdb": 900}   # lookups per day
INTEL = {}                                        # ip -> dict
INTEL_Q, INTEL_DEEP, INTEL_INFLIGHT = deque(), deque(), set()
INTEL_LOCK = threading.RLock()
DEEP_USED = {"day": "", "proxycheck": 0, "abuseipdb": 0}
TOR_EXITS = set()
IPAPI_FIELDS = ("status,message,query,continent,country,countryCode,regionName,city,zip,lat,lon,timezone,"
                "isp,org,as,asname,reverse,mobile,proxy,hosting")


def is_public(ip):
    o = ip_obj(ip)
    return bool(o) and o.is_global and not is_trusted(ip) and ip not in PUBLIC_IPS


def _http_json(url, data=None, headers=None, timeout=8):
    body = json.dumps(data).encode() if data is not None else None
    h = {"User-Agent": "ctfmon", "Accept": "application/json", **(headers or {})}
    if body is not None:
        h["Content-Type"] = "application/json"
    with urllib.request.urlopen(urllib.request.Request(url, data=body, headers=h), timeout=timeout) as r:
        return json.loads(r.read(4_000_000).decode("utf-8", "replace"))


def _ipapi_rec(r):
    if r.get("status") != "success":
        return {"geo_error": r.get("message") or "lookup failed"}
    return {"continent": r.get("continent"), "country": r.get("country"), "cc": r.get("countryCode"),
            "region": r.get("regionName"), "city": r.get("city"), "zip": r.get("zip"),
            "lat": r.get("lat"), "lon": r.get("lon"), "tz": r.get("timezone"),
            "isp": r.get("isp"), "org": r.get("org"), "asn": r.get("as"), "asname": r.get("asname"),
            "rdns": r.get("reverse"), "mobile": bool(r.get("mobile")), "proxy": bool(r.get("proxy")),
            "hosting": bool(r.get("hosting"))}


def _rdns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def intel_store(ip, upd):
    with INTEL_LOCK:
        d = INTEL.setdefault(ip, {})
        d.update({k: v for k, v in upd.items() if v not in (None, "")})
        d["tor"] = ip in TOR_EXITS
        d["ts"] = time.time()
        data = json.dumps(d)
    try:
        DB.x("INSERT OR REPLACE INTO ip_intel VALUES(?,?,?)", (ip, d["ts"], data))
    except Exception as e:
        log.warning("intel store failed: %s", e)


def intel_want(ip, deep=False):
    """queue an IP for lookup; deep = also VPN-provider + abuse reputation (used for attackers)"""
    if not INTEL_ON or not is_public(ip):
        return
    with INTEL_LOCK:
        d = INTEL.get(ip)
        fresh = d and time.time() - d.get("ts", 0) < INTEL_TTL
        if not (fresh and "cc" in d) and ip not in INTEL_INFLIGHT:
            INTEL_INFLIGHT.add(ip)
            INTEL_Q.append(ip)
        if deep and not (fresh and d.get("deep")) and ip not in INTEL_DEEP:
            INTEL_DEEP.append(ip)


def _budget(name):
    day = time.strftime("%Y-%m-%d")
    if DEEP_USED["day"] != day:
        DEEP_USED.update({"day": day, "proxycheck": 0, "abuseipdb": 0})
    if DEEP_USED[name] >= DEEP_BUDGET[name]:
        return False
    DEEP_USED[name] += 1
    return True


def deep_lookup(ip):
    out = {"deep": True, "rdns_local": _rdns(ip)}
    if _budget("proxycheck"):
        try:
            u = f"https://proxycheck.io/v2/{ip}?vpn=1&asn=1&risk=1&port=1&seen=1&days=30"
            if PROXYCHECK_KEY:
                u += "&key=" + PROXYCHECK_KEY
            r = _http_json(u).get(ip) or {}
            op = r.get("operator") or {}
            out.update({"pc_proxy": r.get("proxy"), "pc_type": r.get("type"), "pc_provider": r.get("provider"),
                        "pc_risk": r.get("risk"), "pc_port": r.get("port"), "pc_seen": r.get("last seen human"),
                        "vpn_name": op.get("name"), "vpn_url": op.get("url"),
                        "vpn_anon": op.get("anonymity"), "vpn_policies": op.get("policies")})
        except Exception as e:
            out["pc_error"] = str(e)[:120]
    if ABUSEIPDB_KEY and _budget("abuseipdb"):
        try:
            r = _http_json(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=365&verbose",
                           headers={"Key": ABUSEIPDB_KEY}).get("data") or {}
            cats = Counter(c for rep in (r.get("reports") or [])[:200] for c in rep.get("categories") or [])
            out.update({"ab_score": r.get("abuseConfidenceScore"), "ab_reports": r.get("totalReports"),
                        "ab_users": r.get("numDistinctUsers"), "ab_last": r.get("lastReportedAt"),
                        "ab_usage": r.get("usageType"), "ab_domain": r.get("domain"),
                        "ab_hostnames": r.get("hostnames"), "ab_tor": r.get("isTor"),
                        "ab_cats": [ABUSE_CATS.get(c, str(c)) for c, _ in cats.most_common(6)]})
        except Exception as e:
            out["ab_error"] = str(e)[:120]
    return out


ABUSE_CATS = {3: "fraud orders", 4: "DDoS", 5: "FTP brute force", 9: "open proxy", 10: "web spam", 11: "email spam",
              13: "VPN IP", 14: "port scan", 15: "hacking", 16: "SQL injection", 18: "brute force",
              19: "bad web bot", 20: "exploited host", 21: "web app attack", 22: "SSH", 23: "IoT targeted"}


def lookup_now(ip):
    """synchronous full lookup (when you open an IP in the dashboard)"""
    if not INTEL_ON or not is_public(ip):
        return
    d = INTEL.get(ip) or {}
    if d.get("cc") and d.get("deep") and time.time() - d.get("ts", 0) < INTEL_TTL:
        return
    upd = {}
    if not d.get("cc"):
        try:
            upd.update(_ipapi_rec(_http_json(f"http://ip-api.com/json/{ip}?fields={IPAPI_FIELDS}")))
        except Exception as e:
            upd["geo_error"] = str(e)[:120]
    if not d.get("deep"):
        upd.update(deep_lookup(ip))
    intel_store(ip, upd)


def refresh_tor():
    try:
        req = urllib.request.Request("https://check.torproject.org/torbulkexitlist", headers={"User-Agent": "ctfmon"})
        with urllib.request.urlopen(req, timeout=20) as r:
            ips = {norm_ip(x) for x in r.read().decode().split() if ip_obj(x)}
        if ips:
            TOR_EXITS.clear()
            TOR_EXITS.update(ips)
            with INTEL_LOCK:
                for ip, d in INTEL.items():
                    d["tor"] = ip in TOR_EXITS
        return True
    except Exception as e:
        log.warning("tor exit list failed: %s", e)
        return False


def intel_loop():
    for ip, ts, data in DB.x("SELECT ip, ts, data FROM ip_intel"):
        try:
            INTEL[ip] = json.loads(data)
        except ValueError:
            pass
    with LOCK:
        for ip, st in IPS.items():
            if INTEL_SCOPE == "all" or st.get("score", 0) > 0:
                intel_want(ip, deep=st.get("score", 0) > 0)
    next_tor = 0
    while True:
        now = time.time()
        if now >= next_tor:
            next_tor = now + (6 * 3600 if refresh_tor() else 1800)
            SOURCES["ip-intel"] = f"ok: {len(INTEL)} IPs looked up, {len(TOR_EXITS)} Tor exits known"
        with INTEL_LOCK:
            batch = [INTEL_Q.popleft() for _ in range(min(100, len(INTEL_Q)))]
        if batch:
            try:
                res = _http_json(f"http://ip-api.com/batch?fields={IPAPI_FIELDS}", data=batch, timeout=15)
                for r in res:
                    ip = norm_ip(r.get("query") or "")
                    intel_store(ip, _ipapi_rec(r))
                with INTEL_LOCK:
                    INTEL_INFLIGHT.difference_update(batch)
                SOURCES["ip-intel"] = f"ok: {len(INTEL)} IPs looked up, {len(TOR_EXITS)} Tor exits known"
            except Exception as e:
                with INTEL_LOCK:
                    INTEL_Q.extendleft(reversed(batch))
                SOURCES["ip-intel"] = f"error: {e}"
                time.sleep(60 if "429" in str(e) else 20)
            time.sleep(4.5)                           # ip-api batch limit: 15 / minute
            continue
        with INTEL_LOCK:
            ip = INTEL_DEEP.popleft() if INTEL_DEEP else None
        if ip:
            try:
                intel_store(ip, deep_lookup(ip))
            except Exception as e:
                log.warning("deep lookup %s failed: %s", ip, e)
            time.sleep(2)
            continue
        time.sleep(2)


def intel_brief(ip):
    d = INTEL.get(ip)
    if not d:
        return None
    tags = intel_tags(d)
    return {"cc": d.get("cc"), "country": d.get("country"), "city": d.get("city"),
            "org": d.get("org") or d.get("isp") or d.get("asname"), "tags": tags}


def intel_tags(d):
    t = []
    if d.get("tor") or d.get("ab_tor"):
        t.append("Tor")
    if d.get("vpn_name") or (d.get("pc_type") or "").upper() == "VPN":
        t.append("VPN" + (f": {d['vpn_name']}" if d.get("vpn_name") else ""))
    elif d.get("proxy") or d.get("pc_proxy") == "yes":
        t.append("proxy/VPN")
    if d.get("hosting"):
        t.append("datacenter")
    if d.get("mobile"):
        t.append("mobile")
    if d.get("ab_score"):
        t.append(f"abuse {d['ab_score']}%")
    return t


def intel_tag(ip):
    """one-line summary for alerts / webhook"""
    d = INTEL.get(ip)
    if not d or not d.get("cc"):
        return ""
    where = ", ".join(x for x in (d.get("city"), d.get("country")) if x)
    net = d.get("org") or d.get("isp") or ""
    tags = intel_tags(d)
    return f" [{where} | {net}{' | ' + ', '.join(tags) if tags else ''}]"


# =================================================================== API payloads
def ip_json(st, full=False):
    d = {k: st.get(k) for k in ("ip", "first", "last", "total", "conns", "s4xx", "s5xx", "s404", "peak", "score",
                                "maxsev", "last_req", "trusted")}
    d["reasons"] = {k: v for k, v in st["reasons"].most_common(20 if full else 6) if v}
    d["containers"] = dict(st["containers"].most_common(100 if full else 6))
    d["uas"] = st["uas"] if full else st["uas"][:2]
    d["geo"] = intel_brief(st["ip"])
    ssh = st.get("ssh")
    if isinstance(ssh, dict):
        d["ssh_fails"] = ssh.get("fails", 0)
        if full:
            d["ssh"] = {**ssh, "users": dict(Counter(ssh.get("users") or {}).most_common(100))}
    return d


def ct_json(c):
    d = {k: c.get(k) for k in ("name", "id", "image", "state", "status", "created", "ports", "ips", "role",
                               "cpu", "mem", "mem_limit", "mem_pct", "pids", "net_rx", "net_tx", "blk_r",
                               "blk_w", "size_rw", "size_root")}
    d["risks"] = [{"r": r, "sev": s} for r, s in c.get("risks") or []]
    acc = CT_ACCESS.get(c["name"], {})
    d["accessors"] = sum(1 for a in acc.values() if a["via"] not in LOCALISH)
    d["proxied"] = sum(a["flows"] for a in acc.values() if a["via"] in LOCALISH)
    d["public_ports"] = NGX_REV.get(c["name"], [])
    d["last_access"] = max((a["last"] for a in acc.values()), default=None)
    return d


def overview():
    now = time.time()
    with LOCK:
        cts = [ct_json(c) for c in CONTAINERS.values()]
        ips = list(IPS.values())
        alerts = list(ALERTS)
        susp = sorted((s for s in ips if s["score"] >= SUSPICIOUS), key=lambda s: -s["score"])
        out = {
            "host": dict(HOST), "df": dict(DF), "threshold": SUSPICIOUS, "uptime": now - STARTED,
            "counts": {
                "total": len(cts), "running": sum(1 for c in cts if c["state"] == "running"),
                "challenges": sum(1 for c in cts if c["role"] == "challenge" and c["state"] == "running"),
                "requests": COUNTERS["requests"], "req_per_min": REQ_MIN["prev"], "sessions": COUNTERS["stream_sessions"],
                "ips": len(ips), "active_ips": sum(1 for s in ips if now - s["last"] < 300),
                "suspicious": len(susp),
                "alerts_1h": sum(1 for a in alerts if now - a["ts"] < 3600),
                "high_1h": sum(1 for a in alerts if now - a["ts"] < 3600 and a["sev"] == "high"),
            },
            "alerts": alerts[:15],
            "top_suspicious": [ip_json(s) for s in susp[:10]],
            "top_cpu": sorted((c for c in cts if c["cpu"] is not None), key=lambda c: -c["cpu"])[:10],
            "sources": [{"name": k, "status": v} for k, v in sorted(SOURCES.items())],
        }
    return out


def container_detail(name):
    with LOCK:
        c = CONTAINERS.get(name)
        info = ct_json(c) if c else {"name": name, "state": "removed", "role": role(name), "risks": []}
        acc = [{"ip": ip, **a, "score": (IPS.get(ip) or {}).get("score", 0)}
               for ip, a in CT_ACCESS.get(name, {}).items()]
        links = [{"src": k[0], "dst": k[1], "port": k[2], **v} for k, v in LINKS.items() if name in (k[0], k[1])]
    ev = [dict(zip(("ts", "sev", "action", "container", "image", "detail"), r)) for r in
          DB.x("SELECT ts,sev,action,container,image,detail FROM events WHERE container=? "
               "ORDER BY rowid DESC LIMIT 300", (name,))]
    hits = [dict(zip(("ts", "ip", "sev", "rule", "target", "req", "ua"), r)) for r in
            DB.x("SELECT * FROM hits WHERE target=? ORDER BY rowid DESC LIMIT 300", (name,))]
    return {"c": info, "access": sorted(acc, key=lambda a: -a["last"]), "links": links, "events": ev, "hits": hits}


def ip_detail(ip):
    try:
        lookup_now(ip)                     # make sure the "who is this" section is filled
    except Exception as e:
        log.warning("lookup %s failed: %s", ip, e)
    with LOCK:
        st = IPS.get(ip)
        if st is None:
            row = DB.x("SELECT data FROM ip_stats WHERE ip=?", (ip,))
            if row:
                d = json.loads(row[0][0])
                st = {**d, "reasons": Counter(d.get("reasons")), "containers": Counter(d.get("containers"))}
        info = ip_json(st, True) if st else {"ip": ip, "score": 0, "reasons": {}, "containers": {}, "uas": []}
        acc = [{"container": ct, **m[ip]} for ct, m in CT_ACCESS.items() if ip in m]
    hits = [dict(zip(("ts", "ip", "sev", "rule", "target", "req", "ua"), r)) for r in
            DB.x("SELECT * FROM hits WHERE ip=? ORDER BY rowid DESC LIMIT 500", (ip,))]
    intel = dict(INTEL.get(ip) or {})
    intel["public"] = is_public(ip)
    intel["intel_on"] = INTEL_ON
    return {"ip": info, "access": sorted(acc, key=lambda a: -a["last"]), "hits": hits, "intel": intel}


def intel_csv(ip):
    d = INTEL.get(ip) or {}
    return [d.get("country", ""), d.get("region", ""), d.get("city", ""), d.get("isp", ""), d.get("org", ""),
            d.get("asn", ""), d.get("rdns") or d.get("rdns_local", ""), "; ".join(intel_tags(d)) if d else ""]


def ssh_csv(s):
    d = s.get("ssh") if isinstance(s.get("ssh"), dict) else {}
    users = Counter(d.get("users") or {}).most_common(30)
    return [d.get("fails", 0), "; ".join(f"{u}={n}" for u, n in users)]


def csv_ips():
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ip", "score", "max_severity", "requests", "4xx", "5xx", "404", "peak_per_min", "first_seen",
                "last_seen", "reasons", "targets", "user_agents", "last_request", "trusted",
                "country", "region", "city", "isp", "org", "asn", "reverse_dns", "tags", "ssh_fails", "ssh_users"])
    with LOCK:
        rows = sorted(IPS.values(), key=lambda s: -s["score"])
        for s in rows:
            w.writerow([s["ip"], s["score"], s["maxsev"], s["total"], s["s4xx"], s["s5xx"], s["s404"], s["peak"],
                        iso(s["first"]), iso(s["last"]),
                        "; ".join(f"{k}={v}" for k, v in s["reasons"].items() if v),
                        "; ".join(f"{k}={v}" for k, v in s["containers"].items()),
                        " | ".join(s["uas"]), s["last_req"], s["trusted"], *intel_csv(s["ip"]),
                        *ssh_csv(s)])
    return buf.getvalue()


def csv_access():
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["container", "ip", "via", "flows", "first_seen", "last_seen"])
    with LOCK:
        for ct, m in CT_ACCESS.items():
            for ip, a in m.items():
                w.writerow([ct, ip, a["via"], a["flows"], iso(a["first"]), iso(a["last"])])
    return buf.getvalue()


def csv_alerts():
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["time", "severity", "kind", "target", "message"])
    for r in DB.x("SELECT ts,sev,kind,target,msg FROM alerts ORDER BY rowid DESC"):
        w.writerow([iso(r[0]), *r[1:]])
    return buf.getvalue()


# =================================================================== HTTP
HERE = os.path.dirname(os.path.abspath(__file__))


def asset(name):
    with open(os.path.join(HERE, "static", name), "rb") as f:
        return f.read()


AUTH_FAILS = defaultdict(lambda: deque(maxlen=30))
SESSIONS = {}                        # session token -> expiry (epoch seconds), kept in memory only
SESS_LOCK = threading.Lock()
SESSION_TTL = int(env("SESSION_TTL", str(8 * 3600)))   # seconds a login stays valid
SESSION_COOKIE = "ctfmon_session"


class Handler(BaseHTTPRequestHandler):
    server_version = "ctfmon"
    sys_version = ""

    def log_message(self, *a):
        pass

    def session_token(self):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == SESSION_COOKIE:
                return v
        return ""

    def authed(self):
        tok = self.session_token()
        with SESS_LOCK:
            exp = SESSIONS.get(tok, 0)
            if exp > time.time():
                return True
            SESSIONS.pop(tok, None)
        return False

    def send(self, code, body, ctype, headers=()):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; "
                                                    "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                                                    "frame-ancestors 'none'")
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, where):
        self.send_response(302)
        self.send_header("Location", where)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        p = urlparse(self.path).path
        if p == "/api/login":
            return self.login()
        if p == "/api/logout":
            with SESS_LOCK:
                SESSIONS.pop(self.session_token(), None)
            return self.send(200, json.dumps({"ok": True}), "application/json",
                             [("Set-Cookie", f"{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")])
        return self.send(404, "not found", "text/plain")

    def login(self):
        peer = self.client_address[0]
        fails = AUTH_FAILS[peer]
        now = time.time()
        if len(fails) >= 20 and now - fails[0] < 600:
            return self.send(429, json.dumps({"error": "too many failed logins, wait 10 minutes"}), "application/json")
        try:
            n = min(int(self.headers.get("Content-Length", "0")), 4096)
            body = json.loads(self.rfile.read(n) or b"{}")
            user, pw = str(body.get("username", "")), str(body.get("password", ""))
        except (ValueError, TypeError, AttributeError):
            return self.send(400, json.dumps({"error": "bad request"}), "application/json")
        if not (hmac.compare_digest(user.encode(), USER.encode()) & hmac.compare_digest(pw.encode(), PASSWORD.encode())):
            fails.append(now)
            return self.send(401, json.dumps({"error": "wrong username or password"}), "application/json")
        tok = secrets.token_urlsafe(32)
        with SESS_LOCK:
            for t in [t for t, e in SESSIONS.items() if e <= now]:
                del SESSIONS[t]
            SESSIONS[tok] = now + SESSION_TTL
        cookie = f"{SESSION_COOKIE}={tok}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}"
        return self.send(200, json.dumps({"ok": True}), "application/json", [("Set-Cookie", cookie)])

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/login":
            if self.authed():
                return self.redirect("/")
            return self.send(200, asset("login.html"), "text/html; charset=utf-8")
        if u.path == "/login.js":
            return self.send(200, asset("login.js"), "application/javascript; charset=utf-8")
        if not self.authed():
            if u.path.startswith(("/api/", "/export/")):
                return self.send(401, json.dumps({"error": "login required"}), "application/json")
            return self.redirect("/login")
        q = parse_qs(u.query)

        def g(k, d=""):
            return q.get(k, [d])[0]

        def lim(d):
            try:
                return max(1, min(int(g("limit", d)), 5000))
            except ValueError:
                return d

        try:
            p = u.path
            if p == "/":
                return self.send(200, asset("index.html"), "text/html; charset=utf-8")
            if p == "/app.js":
                return self.send(200, asset("app.js"), "application/javascript; charset=utf-8")
            if p == "/api/overview":
                return self.json(overview())
            if p == "/api/containers":
                with LOCK:
                    return self.json([ct_json(c) for c in CONTAINERS.values()])
            if p == "/api/container":
                return self.json(container_detail(g("name")))
            if p == "/api/ips":
                with LOCK:
                    rows = list(IPS.values())
                    if g("suspicious") == "1":
                        rows = [s for s in rows if s["score"] >= SUSPICIOUS]
                    rows.sort(key=lambda s: (-s["score"], -s["last"]))
                    return self.json([ip_json(s) for s in rows[:lim(1000)]])
            if p == "/api/ip":
                return self.json(ip_detail(g("ip")))
            if p == "/api/alerts":
                with LOCK:
                    return self.json(list(ALERTS)[:lim(500)])
            if p == "/api/events":
                with LOCK:
                    return self.json(list(EVENTS)[:lim(1000)])
            if p == "/api/hits":
                rows = DB.x("SELECT * FROM hits ORDER BY rowid DESC LIMIT ?", (lim(1000),))
                return self.json([dict(zip(("ts", "ip", "sev", "rule", "target", "req", "ua"), r)) for r in rows])
            if p == "/export/ips.csv":
                return self.send(200, csv_ips(), "text/csv; charset=utf-8")
            if p == "/export/access.csv":
                return self.send(200, csv_access(), "text/csv; charset=utf-8")
            if p == "/export/alerts.csv":
                return self.send(200, csv_alerts(), "text/csv; charset=utf-8")
            return self.send(404, "not found", "text/plain")
        except BrokenPipeError:
            pass
        except Exception as e:
            log.exception("request failed")
            return self.send(500, json.dumps({"error": str(e)}), "application/json")

    def json(self, obj):
        return self.send(200, json.dumps(obj, default=str), "application/json")


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def start(fn, *a):
    t = threading.Thread(target=fn, args=a, daemon=True)
    t.start()
    return t


def with_docker(fn):
    def run():
        while True:
            try:
                cli = mkcli()
                cli.ping()
                fn(cli)
            except Exception as e:
                SOURCES["docker"] = f"error: {e}"
                log.warning("docker unavailable (%s), retrying", e)
                time.sleep(10)
    return run


def main():
    global DB
    if docker is None:
        raise SystemExit("missing dependency: pip install 'docker>=7'")
    DB = Store(DB_PATH)
    load_state()
    start(with_docker(stats_loop))
    start(with_docker(size_loop))
    start(events_loop)
    start(conn_loop)
    start(flush_loop)
    if INTEL_ON:
        start(intel_loop)
    else:
        SOURCES["ip-intel"] = "off (CTFMON_INTEL=0)"
    for n in LOG_CONTAINERS:
        start(follow_container_logs, n)
    start(nginx_loop)          # also discovers + tails the nginx access logs (read-only)
    auth = AUTH_LOG or next((p for p in ("/host/var/log/auth.log", "/var/log/auth.log",
                                          "/host/var/log/secure", "/var/log/secure") if os.path.exists(p)), "")
    if auth:
        start(tail_file, auth, handle_auth, "auth-log")
    else:
        SOURCES["auth-log"] = "not found (mount /var/log or set CTFMON_AUTH_LOG)"
    Server.address_family = socket.AF_INET6 if ":" in LISTEN else socket.AF_INET
    srv = Server((LISTEN, PORT), Handler)
    log.info("ctfmon listening on http://%s:%d  (user: %s)", LISTEN, PORT, USER)
    if GENERATED_PW:
        log.warning("no CTFMON_PASSWORD set - generated one for this run: %s", PASSWORD)
    try:
        srv.serve_forever()
    finally:
        flush()


if __name__ == "__main__":
    main()
