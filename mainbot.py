import asyncio
from collections import deque
import random
import secrets
import threading
import html
import json
import logging
import os
import re
import shutil
import sqlite3
import tempfile
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlencode, quote
from pathlib import Path

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.error import Forbidden, TelegramError
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

# ============================================================
# ProDecryptor - single-file Telegram bot | v1.1.0
# ============================================================

APP_VERSION = "1.1.0"
APP_NAME = "ProDecryptor"

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
ADMIN_ID = 5728292317

DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data"))
DB_PATH = DATA_DIR / "prodecryptor.db"

PANTEGNOS_BIN = os.getenv("PANTEGNOS_BIN", "/opt/pantegnos/pantegnos")

DEFAULT_MAX_FILE_SIZE = 50 * 1024 * 1024
DEFAULT_PROCESS_TIMEOUT = 90
MAX_CONCURRENT_JOBS = max(1, int(os.getenv("MAX_CONCURRENT_JOBS", "4")))
TELEGRAM_CHUNK = 3900
LOG_WINDOW_SECONDS = 300
ENGINE_LOG_PATH = DATA_DIR / "engine.log"

def reset_engine_log():
    """Start every bot process with a fresh engine log on persistent storage."""
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        ENGINE_LOG_PATH.write_text("", encoding="utf-8")
    except Exception:
        pass

# App-format feature registry. These switches control INPUT APP FILES only.
# Output protocols (VLESS/VMess/Trojan/SS/...) are intentionally separate and are
# never used to decide whether an app file such as .npvt or .ehi is accepted.
APP_FORMATS = {
    ".npvt": {"name": "NPVT", "setting": "app_npvt"},
    ".npvs": {"name": "NPVS", "setting": "app_npvs"},
    ".slip": {"name": "SLIP", "setting": "app_slip"},
    ".dark": {"name": "DarkTunnel", "setting": "app_dark"},
    ".ehi": {"name": "HTTP Injector", "setting": "app_ehi"},
    ".hat": {"name": "HA Tunnel Plus", "setting": "app_hat"},
    ".nm": {"name": "NetMod VPN", "setting": "app_nm"},
    ".happ": {"name": "HAPP", "setting": "app_happ"},
}
SUPPORTED_EXTENSIONS = set(APP_FORMATS)

# Output protocols are only for parsing genuine URI outputs.  UUIDs, IPs,
# hostnames, server names and arbitrary text are never promoted to links.
OUTPUT_PROTOCOLS = {
    "vless", "vmess", "trojan", "ss", "socks", "socks5",
    "hysteria", "hysteria2", "hy2", "tuic", "wireguard", "ssh",
}
URI_SCHEMES = tuple(f"{p}://" for p in sorted(OUTPUT_PROTOCOLS, key=len, reverse=True))
URL_RE = re.compile(
    r"(?i)(?:vless|vmess|trojan|ss|socks5?|hysteria2?|hy2|tuic|wireguard|ssh)://[^\s<>\[\]{}\"']+"
)

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    level=logging.INFO,
)
log = logging.getLogger("prodecryptor")

class FiveMinuteHandler(logging.Handler):
    def emit(self, record):
        try:
            item = (time.time(), self.format(record))
            with LOG_LOCK:
                LOG_BUFFER.append(item)
                cutoff = time.time() - LOG_WINDOW_SECONDS
                while LOG_BUFFER and LOG_BUFFER[0][0] < cutoff:
                    LOG_BUFFER.popleft()
        except Exception:
            pass

_log_buffer_handler = FiveMinuteHandler()
_log_buffer_handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s"))
logging.getLogger().addHandler(_log_buffer_handler)

JOB_SEMAPHORE = asyncio.Semaphore(MAX_CONCURRENT_JOBS)
USER_JOBS = {}
ADMIN_STATE = {}
CAPTCHA_PENDING = {}
LOG_BUFFER = deque()
LOG_LOCK = threading.Lock()


# ============================================================
# Database
# ============================================================

class Database:
    def __init__(self, path):
        self.path = path
        self.conn = None

    def open(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.init_schema()
        self.seed()

    def init_schema(self):
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            username TEXT DEFAULT '',
            first_name TEXT DEFAULT '',
            last_name TEXT DEFAULT '',
            is_blocked INTEGER DEFAULT 0,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            total_files INTEGER DEFAULT 0,
            successful_files INTEGER DEFAULT 0,
            failed_files INTEGER DEFAULT 0,
            total_links INTEGER DEFAULT 0,
            captcha_verified INTEGER DEFAULT 0,
            captcha_ops INTEGER DEFAULT 0,
            captcha_failures INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS force_join_channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL DEFAULT '',
            username TEXT DEFAULT '',
            invite_url TEXT DEFAULT '',
            active INTEGER DEFAULT 1,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS daily_usage (
            user_id INTEGER NOT NULL,
            day TEXT NOT NULL,
            count INTEGER DEFAULT 0,
            PRIMARY KEY(user_id, day),
            FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS sponsors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            button_text TEXT NOT NULL,
            style TEXT NOT NULL DEFAULT 'primary',
            active INTEGER DEFAULT 1,
            sort_order INTEGER DEFAULT 0,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            extension TEXT NOT NULL,
            status TEXT NOT NULL,
            links_count INTEGER DEFAULT 0,
            error TEXT DEFAULT '',
            created_at INTEGER NOT NULL,
            finished_at INTEGER DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_users_last_seen ON users(last_seen);
        CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs(created_at);
        """)
        # Safe migrations for databases created by older ProDecryptor versions.
        for col, ddl in (
            ("captcha_verified", "ALTER TABLE users ADD COLUMN captcha_verified INTEGER DEFAULT 0"),
            ("captcha_ops", "ALTER TABLE users ADD COLUMN captcha_ops INTEGER DEFAULT 0"),
            ("captcha_failures", "ALTER TABLE users ADD COLUMN captcha_failures INTEGER DEFAULT 0"),
        ):
            try:
                self.conn.execute(ddl)
            except sqlite3.OperationalError:
                pass
        self.conn.commit()

    def seed(self):
        defaults = {
            "daily_limit": "5",       # 0 = unlimited
            "maintenance": "0",
            "max_file_size": str(DEFAULT_MAX_FILE_SIZE),
            "process_timeout": str(DEFAULT_PROCESS_TIMEOUT),
            "captcha_interval": "10",
            "captcha_max_attempts": "5",
            "app_npvt": "1",
            "app_npvs": "1",
            "app_slip": "1",
            "app_dark": "1",
            "app_ehi": "1",
            "app_hat": "1",
            "app_nm": "1",
            "app_happ": "1",
        }
        for k, v in defaults.items():
            self.conn.execute(
                "INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (k, v)
            )
        self.conn.commit()

    def setting(self, key, default=""):
        row = self.conn.execute(
            "SELECT value FROM settings WHERE key=?", (key,)
        ).fetchone()
        return row["value"] if row else default

    def set_setting(self, key, value):
        self.conn.execute(
            "INSERT INTO settings(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        self.conn.commit()

    def upsert_user(self, user):
        now = int(time.time())
        self.conn.execute(
            """
            INSERT INTO users(user_id,username,first_name,last_name,first_seen,last_seen)
            VALUES(?,?,?,?,?,?)
            ON CONFLICT(user_id) DO UPDATE SET
              username=excluded.username,
              first_name=excluded.first_name,
              last_name=excluded.last_name,
              last_seen=excluded.last_seen
            """,
            (
                user.id, user.username or "", user.first_name or "",
                user.last_name or "", now, now,
            ),
        )
        self.conn.commit()

    def get_user(self, user_id):
        return self.conn.execute(
            "SELECT * FROM users WHERE user_id=?", (user_id,)
        ).fetchone()

    def set_blocked(self, user_id, blocked):
        self.conn.execute(
            "UPDATE users SET is_blocked=? WHERE user_id=?",
            (1 if blocked else 0, user_id),
        )
        self.conn.commit()

    def daily_usage(self, user_id):
        row = self.conn.execute(
            "SELECT count FROM daily_usage WHERE user_id=? AND day=?",
            (user_id, utc_day()),
        ).fetchone()
        return int(row["count"]) if row else 0

    def consume_daily(self, user_id):
        limit = int(self.setting("daily_limit", "5"))
        if limit == 0:
            self.conn.execute(
                "UPDATE users SET total_files=total_files+1 WHERE user_id=?",
                (user_id,),
            )
            self.conn.commit()
            return True

        day = utc_day()
        row = self.conn.execute(
            "SELECT count FROM daily_usage WHERE user_id=? AND day=?",
            (user_id, day),
        ).fetchone()
        current = int(row["count"]) if row else 0
        if current >= limit:
            return False

        if row:
            self.conn.execute(
                "UPDATE daily_usage SET count=count+1 WHERE user_id=? AND day=?",
                (user_id, day),
            )
        else:
            self.conn.execute(
                "INSERT INTO daily_usage(user_id,day,count) VALUES(?,?,1)",
                (user_id, day),
            )

        self.conn.execute(
            "UPDATE users SET total_files=total_files+1 WHERE user_id=?",
            (user_id,),
        )
        self.conn.commit()
        return True

    def refund_daily(self, user_id):
        limit = int(self.setting("daily_limit", "5"))
        if limit == 0:
            self.conn.execute(
                "UPDATE users SET total_files=CASE WHEN total_files>0 THEN total_files-1 ELSE 0 END WHERE user_id=?",
                (user_id,),
            )
            self.conn.commit()
            return

        day = utc_day()
        self.conn.execute(
            "UPDATE daily_usage SET count=CASE WHEN count>0 THEN count-1 ELSE 0 END "
            "WHERE user_id=? AND day=?",
            (user_id, day),
        )
        self.conn.execute(
            "UPDATE users SET total_files=CASE WHEN total_files>0 THEN total_files-1 ELSE 0 END "
            "WHERE user_id=?",
            (user_id,),
        )
        self.conn.commit()

    def record_success(self, user_id, links):
        self.conn.execute(
            "UPDATE users SET successful_files=successful_files+1,total_links=total_links+? WHERE user_id=?",
            (links, user_id),
        )
        self.conn.commit()

    def record_failure(self, user_id):
        self.conn.execute(
            "UPDATE users SET failed_files=failed_files+1 WHERE user_id=?",
            (user_id,),
        )
        self.conn.commit()

    def create_job(self, job_id, user_id, filename, extension):
        self.conn.execute(
            "INSERT INTO jobs(id,user_id,filename,extension,status,created_at) VALUES(?,?,?,?,?,?)",
            (job_id, user_id, filename, extension, "processing", int(time.time())),
        )
        self.conn.commit()

    def finish_job(self, job_id, status, links=0, error=""):
        self.conn.execute(
            "UPDATE jobs SET status=?,links_count=?,error=?,finished_at=? WHERE id=?",
            (status, links, error[:2000], int(time.time()), job_id),
        )
        self.conn.commit()

    def sponsors(self, active_only=True):
        if active_only:
            return self.conn.execute(
                "SELECT * FROM sponsors WHERE active=1 ORDER BY sort_order,id"
            ).fetchall()
        return self.conn.execute(
            "SELECT * FROM sponsors ORDER BY sort_order,id"
        ).fetchall()

    def sponsor(self, sponsor_id):
        return self.conn.execute(
            "SELECT * FROM sponsors WHERE id=?", (sponsor_id,)
        ).fetchone()

    def add_sponsor(self, name, url, button_text, style, active=True):
        now = int(time.time())
        order = self.conn.execute(
            "SELECT COALESCE(MAX(sort_order),0)+1 AS n FROM sponsors"
        ).fetchone()["n"]
        cur = self.conn.execute(
            """
            INSERT INTO sponsors(name,url,button_text,style,active,sort_order,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?,?)
            """,
            (name, url, button_text, style, 1 if active else 0, int(order), now, now),
        )
        self.conn.commit()
        return cur.lastrowid

    def update_sponsor(self, sponsor_id, name, url, button_text, style):
        self.conn.execute(
            """
            UPDATE sponsors
            SET name=?,url=?,button_text=?,style=?,updated_at=?
            WHERE id=?
            """,
            (name, url, button_text, style, int(time.time()), sponsor_id),
        )
        self.conn.commit()

    def set_sponsor_active(self, sponsor_id, active):
        self.conn.execute(
            "UPDATE sponsors SET active=?,updated_at=? WHERE id=?",
            (1 if active else 0, int(time.time()), sponsor_id),
        )
        self.conn.commit()

    def delete_sponsor(self, sponsor_id):
        self.conn.execute("DELETE FROM sponsors WHERE id=?", (sponsor_id,))
        self.conn.commit()

    def stats(self):
        total_users = self.conn.execute(
            "SELECT COUNT(*) n FROM users"
        ).fetchone()["n"]
        active_24h = self.conn.execute(
            "SELECT COUNT(*) n FROM users WHERE last_seen>=?",
            (int(time.time()) - 86400,),
        ).fetchone()["n"]
        blocked = self.conn.execute(
            "SELECT COUNT(*) n FROM users WHERE is_blocked=1"
        ).fetchone()["n"]
        totals = self.conn.execute(
            "SELECT COALESCE(SUM(total_files),0) files,"
            "COALESCE(SUM(successful_files),0) success,"
            "COALESCE(SUM(failed_files),0) failed,"
            "COALESCE(SUM(total_links),0) links FROM users"
        ).fetchone()
        jobs24 = self.conn.execute(
            "SELECT COUNT(*) n FROM jobs WHERE created_at>=?",
            (int(time.time()) - 86400,),
        ).fetchone()["n"]
        return {
            "users": int(total_users),
            "active": int(active_24h),
            "blocked": int(blocked),
            "files": int(totals["files"]),
            "success": int(totals["success"]),
            "failed": int(totals["failed"]),
            "links": int(totals["links"]),
            "jobs24": int(jobs24),
        }

    def users_page(self, page, per_page=8):
        return self.conn.execute(
            "SELECT * FROM users ORDER BY last_seen DESC LIMIT ? OFFSET ?",
            (per_page, page * per_page),
        ).fetchall()

    def user_count(self):
        return int(self.conn.execute("SELECT COUNT(*) n FROM users").fetchone()["n"])

    def recent_jobs(self, limit=15):
        return self.conn.execute(
            "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()

    def set_captcha_verified(self, user_id, verified=True):
        self.conn.execute("UPDATE users SET captcha_verified=?, captcha_ops=0, captcha_failures=0 WHERE user_id=?", (1 if verified else 0, user_id))
        self.conn.commit()

    def captcha_state(self, user_id):
        row = self.get_user(user_id)
        if not row:
            return False, 0, 0
        return bool(row["captcha_verified"]), int(row["captcha_ops"]), int(row["captcha_failures"])

    def captcha_increment_ops(self, user_id):
        self.conn.execute("UPDATE users SET captcha_ops=captcha_ops+1 WHERE user_id=?", (user_id,))
        self.conn.commit()

    def captcha_fail(self, user_id):
        self.conn.execute("UPDATE users SET captcha_failures=captcha_failures+1 WHERE user_id=?", (user_id,))
        self.conn.commit()
        return int(self.get_user(user_id)["captcha_failures"])

    def reset_captcha_failures(self, user_id):
        self.conn.execute("UPDATE users SET captcha_failures=0 WHERE user_id=?", (user_id,))
        self.conn.commit()

    def channels(self, active_only=True):
        sql = "SELECT * FROM force_join_channels" + (" WHERE active=1" if active_only else "") + " ORDER BY id"
        return self.conn.execute(sql).fetchall()

    def add_channel(self, chat_id, title, username, invite_url):
        cur = self.conn.execute(
            "INSERT OR REPLACE INTO force_join_channels(chat_id,title,username,invite_url,active,created_at) VALUES(?,?,?,?,1,?)",
            (str(chat_id), title or "", username or "", invite_url or "", int(time.time())),
        )
        self.conn.commit()
        return cur.lastrowid

    def channel(self, cid):
        return self.conn.execute("SELECT * FROM force_join_channels WHERE id=?", (cid,)).fetchone()

    def toggle_channel(self, cid):
        self.conn.execute("UPDATE force_join_channels SET active=CASE active WHEN 1 THEN 0 ELSE 1 END WHERE id=?", (cid,))
        self.conn.commit()

    def delete_channel(self, cid):
        self.conn.execute("DELETE FROM force_join_channels WHERE id=?", (cid,))
        self.conn.commit()

    def snapshot(self, destination):
        destination = str(destination)
        dest = sqlite3.connect(destination)
        try:
            with self.conn:
                self.conn.backup(dest)
        finally:
            dest.close()

    def close(self):
        if self.conn:
            self.conn.close()


DB = Database(DB_PATH)


# ============================================================
# Helpers
# ============================================================

def utc_day():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def now_text():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def esc(value):
    return html.escape(str(value or ""), quote=True)


def mdv2(value):
    return re.sub(r"([_*\[\]()~`>#+\-=|{}.!])", r"\\\1", value)


def normalize_link(link):
    value = str(link or "").strip()
    # Do not strip URL-safe closing chars blindly; only remove obvious prose
    # punctuation that cannot be part of these URI outputs.
    return value.rstrip(".,;)]}>'\"")


KEY_LABEL_RE = re.compile(
    r"(?im)^\s*(?:[#>*`\-_/]+\s*)?(?:key|app\s*key|appkey|config\s*key|configkey|access\s*key|accesskey|subscription\s*key|pass\s*key|passkey)\s*[:=\-]\s*([^\r\n`<>]+?)\s*$"
)
JSON_KEY_RE = re.compile(
    r"(?i)[\"'](?:appKey|configKey|accessKey|subscriptionKey|passKey|passkey|key)[\"']\s*[:=]\s*[\"']([^\"']+)[\"']"
)


def app_format_enabled(ext):
    meta = APP_FORMATS.get(str(ext).lower())
    if not meta:
        return False
    return DB.setting(meta["setting"], "1") == "1"


def enabled_app_formats():
    return [ext for ext in APP_FORMATS if app_format_enabled(ext)]


def app_format_label(ext):
    return APP_FORMATS.get(str(ext).lower(), {}).get("name", str(ext).upper().lstrip("."))


def strip_ansi(text):
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text or "")


def iter_json_values(text):
    """Yield complete JSON values embedded in noisy engine stdout/stderr."""
    clean = strip_ansi(text)
    decoder = json.JSONDecoder()
    i, n = 0, len(clean)
    while i < n:
        while i < n and clean[i] not in "[{":
            i += 1
        if i >= n:
            break
        try:
            value, end = decoder.raw_decode(clean[i:])
        except (json.JSONDecodeError, TypeError, ValueError):
            i += 1
            continue
        yield value
        i += max(1, end)


def _boolish(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _first(d, *names):
    for name in names:
        if isinstance(d, dict) and name in d and d[name] not in (None, ""):
            return d[name]
    return None


def build_vless_from_v2ray_profile(profile, remarks=None):
    """Conservative NPVT/NVP compatibility reconstruction only.

    This is deliberately the sole protocol reconstruction in the bot. For all
    other app-specific output, the engine's own generated URI/file/JSON is
    preserved rather than guessed.
    """
    if not isinstance(profile, dict):
        return None
    server = _first(profile, "server", "address", "host")
    port = _first(profile, "serverPort", "port")
    user_id = _first(profile, "uuid", "id", "password")
    if not server or not port or not user_id:
        return None
    try:
        port = int(port)
    except (TypeError, ValueError):
        return None
    query = []
    for key, names in (
        ("encryption", ("method", "encryption")),
        ("type", ("network", "type")),
        ("security", ("security",)),
        ("sni", ("sni", "serverName")),
        ("alpn", ("alpn",)),
        ("fp", ("fingerPrint", "fingerprint", "fp")),
    ):
        value = _first(profile, *names)
        if value is not None:
            query.append((key, str(value)))
    if _boolish(_first(profile, "insecure", "allowInsecure")):
        query.extend((("insecure", "1"), ("allowInsecure", "1")))
    uri = "vless://" + quote(str(user_id), safe="") + "@" + str(server) + ":" + str(port)
    if query:
        uri += "?" + urlencode(query)
    if remarks and str(remarks).strip():
        uri += "#" + quote(str(remarks).strip(), safe="")
    return uri


def extract_structured_uris(text):
    """Extract engine-provided URIs and only the known NPVT structured VLESS profile."""
    found, seen = [], set()

    def add(uri):
        uri = normalize_link(uri)
        if not uri or "://" not in uri:
            return
        proto = uri.split("://", 1)[0].lower()
        if proto not in OUTPUT_PROTOCOLS or not app_output_protocol_enabled(proto):
            return
        if uri not in seen:
            seen.add(uri)
            found.append(uri)

    def walk(value, inherited_remarks=None):
        if isinstance(value, dict):
            remarks = _first(value, "remarks", "remark", "name", "title") or inherited_remarks
            for key, child in value.items():
                if isinstance(child, str) and "://" in child:
                    for uri in URL_RE.findall(child):
                        add(uri)
                if key == "v2rayProfile" and isinstance(child, dict):
                    add(build_vless_from_v2ray_profile(child, remarks))
                    continue
                if isinstance(child, (dict, list)):
                    walk(child, remarks)
            if "server" in value:
                add(build_vless_from_v2ray_profile(value, remarks))
        elif isinstance(value, list):
            for child in value:
                walk(child, inherited_remarks)

    for value in iter_json_values(text):
        walk(value)
    return found


def app_output_protocol_enabled(proto):
    # Output protocol switches are intentionally not app-format switches. Keep
    # all protocols enabled by default and allow optional DB keys for backwards
    # compatibility with databases that already contain them.
    key = f"output_{proto}"
    if DB.conn is None:
        return True
    return DB.setting(key, "1") == "1"


def extract_links(text):
    """Extract only genuine supported URI schemes; never UUID/IP/host text."""
    found, seen = [], set()
    for match in URL_RE.findall(strip_ansi(text or "")):
        value = normalize_link(match)
        if not value or "://" not in value:
            continue
        proto = value.split("://", 1)[0].lower()
        if proto in OUTPUT_PROTOCOLS and app_output_protocol_enabled(proto) and value not in seen:
            seen.add(value)
            found.append(value)
    return found


def extract_labeled_keys(text):
    found, seen = [], set()
    text = text or ""
    for key in KEY_LABEL_RE.findall(text):
        value = str(key).strip().strip('"\'.,;')
        if value and value not in seen:
            seen.add(value); found.append(value)
    for key in JSON_KEY_RE.findall(text):
        value = str(key).strip().strip('"\'.,;')
        if value and value not in seen:
            seen.add(value); found.append(value)
    return found


def json_objects_from_text(text):
    values = []
    for value in iter_json_values(text or ""):
        values.append(value)
    return values


def is_probably_text(path):
    try:
        sample = path.read_bytes()[:4096]
    except Exception:
        return False
    if b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def collect_engine_outputs(output_dir):
    """Collect every generated file without assuming it is a TXT/URI output."""
    items = []
    for path in sorted(p for p in output_dir.rglob("*") if p.is_file()):
        rel = path.relative_to(output_dir).as_posix()
        size = path.stat().st_size
        item = {"path": path, "name": rel, "size": size, "text": None, "binary": False}
        if is_probably_text(path) and size <= 5 * 1024 * 1024:
            item["text"] = path.read_text(encoding="utf-8", errors="replace")
        else:
            item["binary"] = True
        items.append(item)
    return items


def analyze_engine_output(output_dir, stdout, stderr, input_filename):
    """Build a lossless-ish result model from ALL engine outputs.

    Priority:
      1) real URIs emitted by engine files/stdout
      2) structured JSON URIs / NPVT compatibility reconstruction
      3) explicit keys kept separate
      4) every generated engine file exposed for download
      5) raw text preserved verbatim for client-specific formats
    """
    files = collect_engine_outputs(output_dir)
    text_parts = []
    for item in files:
        if item["text"] is not None:
            text_parts.append(f"===== {item['name']} =====\n{item['text']}\n")
    raw = "\n".join(text_parts)
    combined = "\n".join(x for x in (stdout, raw) if x)
    links = extract_links(combined)
    for uri in extract_structured_uris(combined):
        if uri not in links:
            links.append(uri)
    keys = extract_labeled_keys(combined)
    json_values = json_objects_from_text(combined)
    return {
        "input_filename": input_filename,
        "links": links,
        "keys": keys,
        "raw": raw,
        "stdout": stdout or "",
        "stderr": stderr or "",
        "files": files,
        "json_values": json_values,
        "protocol_counts": protocol_counts(links),
    }


def links_codeblock(links):
    # Keep every item on its own line and preserve the code-block/copy affordance.
    return "```\n" + "\n".join(str(x).replace("`", "\u200b`") for x in links) + "\n```"


def split_link_chunks(items, max_chars=TELEGRAM_CHUNK):
    chunks, current = [], []
    size = 8
    for item in items:
        line = str(item)
        if current and size + len(line) + 1 > max_chars:
            chunks.append(current)
            current, size = [], 8
        current.append(line)
        size += len(line) + 1
    if current:
        chunks.append(current)
    return chunks or [[]]


def split_text(text, limit=TELEGRAM_CHUNK):
    if len(text) <= limit:
        return [text]
    return [text[i:i+limit] for i in range(0, len(text), limit)]


def file_size_text(n):
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / 1024 / 1024:.1f} MB"


def protocol_counts(links):
    result = {}
    for link in links:
        p = link.split("://", 1)[0].lower()
        result[p] = result.get(p, 0) + 1
    return result


def cleanup_job(user_id):
    job = USER_JOBS.pop(user_id, None)
    if job and job.get("directory"):
        shutil.rmtree(job["directory"], ignore_errors=True)


def maintenance_on():
    return DB.setting("maintenance", "0") == "1"


def admin_only(user_id):
    return user_id == ADMIN_ID


def sponsor_rows():
    rows = []
    for s in DB.sponsors(True):
        style = s["style"] if s["style"] in {"primary", "success", "danger"} else "primary"
        rows.append([
            InlineKeyboardButton(
                s["button_text"], url=s["url"], style=style
            )
        ])
    return rows


# ============================================================
# Keyboards
# ============================================================

def user_menu():
    rows = [
        [
            InlineKeyboardButton("📤 ارسال فایل", callback_data="menu:upload", style="primary"),
            InlineKeyboardButton("🔗 ارسال لینک", callback_data="menu:link", style="primary"),
        ],
        [
            InlineKeyboardButton("📊 سهمیه من", callback_data="menu:quota", style="success"),
            InlineKeyboardButton("ℹ️ راهنما", callback_data="menu:help", style="primary"),
        ],
    ]
    rows.extend(sponsor_rows())
    return InlineKeyboardMarkup(rows)


def result_menu(user_id):
    job = USER_JOBS.get(user_id, {})
    rows = []
    if job.get("links"):
        rows.append([InlineKeyboardButton("🔗 لینک‌ها", callback_data=f"result:links:{user_id}", style="success")])
    if job.get("json_values") or job.get("raw"):
        rows.append([InlineKeyboardButton("📋 JSON / ساختاریافته", callback_data=f"result:json:{user_id}", style="primary")])
    if job.get("keys"):
        rows.append([InlineKeyboardButton("🔑 کلیدها", callback_data=f"result:keys:{user_id}", style="primary")])
    if job.get("raw"):
        rows.append([InlineKeyboardButton("📄 خروجی متنی", callback_data=f"result:raw:{user_id}", style="primary")])
    if job.get("files"):
        rows.append([InlineKeyboardButton("📦 فایل‌های خروجی موتور", callback_data=f"result:files:{user_id}", style="primary")])
    rows.append([InlineKeyboardButton("🔍 اطلاعات", callback_data=f"result:info:{user_id}", style="primary")])
    rows.append([InlineKeyboardButton("🗑 حذف", callback_data=f"result:delete:{user_id}", style="danger")])
    rows.extend(sponsor_rows())
    return InlineKeyboardMarkup(rows)


def admin_menu():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📊 داشبورد", callback_data="admin:dashboard", style="primary"),
            InlineKeyboardButton("👥 کاربران", callback_data="admin:users:0", style="primary"),
        ],
        [
            InlineKeyboardButton("⚙️ سهمیه و محدودیت", callback_data="admin:limits", style="primary"),
            InlineKeyboardButton("📣 پیام همگانی", callback_data="admin:broadcast", style="primary"),
        ],
        [
            InlineKeyboardButton("🤝 اسپانسرها", callback_data="admin:sponsors", style="primary"),
            InlineKeyboardButton("🧾 فعالیت‌ها", callback_data="admin:jobs", style="primary"),
        ],
        [
            InlineKeyboardButton("🛠 وضعیت سرویس", callback_data="admin:status", style="success"),
            InlineKeyboardButton("⚙️ تنظیمات", callback_data="admin:settings", style="primary"),
        ],
        [
            InlineKeyboardButton("💾 دیتابیس", callback_data="admin:database", style="primary"),
            InlineKeyboardButton("📜 لاگ ۵ دقیقه اخیر", callback_data="admin:logs", style="primary"),
        ],
        [
            InlineKeyboardButton("⚙️ لاگ کامل موتور", callback_data="admin:engine_logs", style="primary"),
        ],
        [InlineKeyboardButton("📦 مدیریت فرمت‌های اپ", callback_data="admin:app_formats", style="primary")],
        [InlineKeyboardButton("🔒 عضویت اجباری", callback_data="admin:channels", style="primary")],
    ])


# ============================================================
# Access / start
# ============================================================

async def check_force_join(context, user_id):
    channels = DB.channels(True)
    missing = []
    for ch in channels:
        try:
            member = await context.bot.get_chat_member(ch["chat_id"], user_id)
            status = getattr(member, "status", "")
            if status not in {"creator", "administrator", "member"} and not (status == "restricted" and getattr(member, "is_member", False)):
                missing.append(ch)
        except Exception as exc:
            log.warning("force-join check failed for %s: %s", ch["chat_id"], exc)
            missing.append(ch)
    return missing

def join_keyboard(channels):
    rows = []
    for ch in channels:
        url = ch["invite_url"] or (f"https://t.me/{ch['username'].lstrip('@')}" if ch["username"] else "")
        if url:
            rows.append([InlineKeyboardButton(f"📢 {ch['title'] or ch['username'] or ch['chat_id']}", url=url, style="primary")])
    rows.append([InlineKeyboardButton("✅ عضو شدم — بررسی", callback_data="access:check_join", style="success")])
    return InlineKeyboardMarkup(rows)

async def require_join(update, context):
    if update.effective_user.id == ADMIN_ID:
        return True
    missing = await check_force_join(context, update.effective_user.id)
    if not missing:
        return True
    target = update.callback_query.message if update.callback_query else update.message
    text = "🔒 <b>برای استفاده از بات باید در کانال‌های زیر عضو باشی.</b>\n\nبعد از عضویت، روی «عضو شدم — بررسی» بزن."
    await target.reply_text(text, parse_mode=ParseMode.HTML, reply_markup=join_keyboard(missing))
    return False

def new_captcha():
    a, b = secrets.randbelow(40) + 1, secrets.randbelow(40) + 1
    return a, b, a + b

async def ask_captcha(update, context, force=False):
    uid = update.effective_user.id
    verified, ops, failures = DB.captcha_state(uid)
    interval = max(1, int(DB.setting("captcha_interval", "10")))
    if not force and verified and ops < interval:
        return True
    a, b, answer = new_captcha()
    msg = update.callback_query.message if update.callback_query else update.message
    sent = await msg.reply_text(f"🤖 <b>برای ادامه، ثابت کن ربات نیستی.</b>\n\n<b>{a} + {b} = ؟</b>\n\nحداکثر ۵ تلاش داری.", parse_mode=ParseMode.HTML)
    CAPTCHA_PENDING[uid] = {"answer": answer, "question_id": sent.message_id}
    return False

async def access_guard(update, context, require_captcha=True):
    if not await guard(update):
        return False
    if not await require_join(update, context):
        return False
    if require_captcha and update.effective_user.id != ADMIN_ID:
        if not await ask_captcha(update, context):
            return False
    return True

async def guard(update):
    user = update.effective_user
    if not user:
        return False

    DB.upsert_user(user)
    row = DB.get_user(user.id)
    if row and row["is_blocked"] and user.id != ADMIN_ID:
        if update.callback_query:
            await update.callback_query.answer("دسترسی شما مسدود است.", show_alert=True)
        elif update.message:
            await update.message.reply_text("⛔ دسترسی شما به بات مسدود شده است.")
        return False
    return True


async def start(update, context):
    if not await guard(update):
        return

    uid = update.effective_user.id
    if uid != ADMIN_ID:
        if not await require_join(update, context):
            return
        if not await ask_captcha(update, context):
            return

    if maintenance_on() and uid != ADMIN_ID:
        await update.message.reply_text("🛠 بات موقتاً در حال بروزرسانی است.")
        return

    limit = int(DB.setting("daily_limit", "5"))
    await update.message.reply_text(
        "✨ <b>ProDecryptor</b>\n\n"
        "فایل کانفیگ یا لینک خودت را ارسال کن.\n\n"
        f"📅 سهمیه امروز: <b>{'∞' if limit == 0 else limit}</b> فایل",
        parse_mode=ParseMode.HTML,
        reply_markup=user_menu(),
    )


async def help_command(update, context):
    if not await guard(update): return
    uid = update.effective_user.id
    if uid != ADMIN_ID:
        if not await require_join(update, context): return
        if not await ask_captcha(update, context): return
    await update.message.reply_text(
        "ℹ️ <b>راهنمای کامل و ساده ProDecryptor</b>\n\n"
        "📤 <b>ارسال فایل</b>\nبرای فایل‌های واقعی کانفیگ استفاده کن: <code>SLIP</code>، <code>EHI</code>، <code>DARK</code>، <code>HAT</code>، <code>NPVT</code>، <code>NPVS</code>، <code>NM</code> و <code>HAPP</code>.\n\n"
        "🔗 <b>ارسال لینک/متن</b>\nبرای وقتی است که لینک یا کلید را به‌صورت متن داری؛ بات موارد قابل شناسایی را جدا می‌کند.\n\n"
        "🌐 <b>موارد قابل شناسایی</b>\nVLESS، VMess، Trojan، Shadowsocks، SOCKS، Hysteria، Hysteria2، TUIC، WireGuard و SSH.\n\n"
        "🔑 <b>کلیدها</b>\nفرمت‌های مختلف کلید مثل <code>Key:</code>، <code>AppKey:</code>، <code>ConfigKey:</code> و کلیدهای مشابه بررسی می‌شوند.\n\n"
        "📋 <b>بعد از پردازش</b>\n«لینک‌ها» فقط موارد قابل استخراج را می‌دهد، «JSON» نتیجه ساختاریافته را می‌دهد، «اطلاعات» خلاصه نتیجه را نشان می‌دهد و «خروجی» فایل کامل پردازش‌شده را می‌فرستد.\n\n"
        "📦 <b>تعداد زیاد</b>\nاگر تعداد لینک‌ها زیاد باشد، خودکار در چند پیام تقسیم می‌شوند و هر پیام جداگانه قابل کپی است.\n\n"
        "🔐 <b>فایل رمزدار</b>\nاگر فایل به رمز خارجی نیاز داشته باشد، بدون کلید یا رمز لازم قابل باز کردن نیست.\n\n"
        "🆘 <b>دستورها</b>\n<code>/start</code> شروع کار\n<code>/help</code> راهنما\n<code>/cancel</code> لغو عملیات جاری",
        parse_mode=ParseMode.HTML, reply_markup=user_menu())


async def cancel(update, context):
    uid = update.effective_user.id
    if uid == ADMIN_ID:
        ADMIN_STATE.pop(ADMIN_ID, None)
    cleanup_job(uid)
    await update.message.reply_text(
        "❎ عملیات لغو شد.",
        reply_markup=admin_menu() if uid == ADMIN_ID else user_menu(),
    )


# ============================================================
# User menu callback
# ============================================================

async def access_callback(update, context):
    q = update.callback_query
    uid = q.from_user.id
    if q.data == "access:check_join":
        await q.answer()
        if not await require_join(update, context):
            return
        await q.message.reply_text("✅ عضویت تأیید شد. حالا می‌توانی از بات استفاده کنی.", reply_markup=user_menu())

async def handle_captcha_answer(update, context):
    uid = update.effective_user.id
    if not await require_join(update, context):
        return
    pending = CAPTCHA_PENDING.pop(uid, None)
    if not pending:
        return
    answer_msg = update.message
    try:
        await context.bot.delete_message(uid, pending["question_id"])
    except Exception:
        pass
    try:
        await answer_msg.delete()
    except Exception:
        pass
    try:
        answer = int((answer_msg.text or "").strip())
    except Exception:
        answer = None
    if answer == pending["answer"]:
        DB.set_captcha_verified(uid, True)
        await context.bot.send_message(uid, "✅ تأیید شد. حالا می‌توانی ادامه بدهی.", reply_markup=user_menu())
        return
    failures = DB.captcha_fail(uid)
    max_attempts = max(1, int(DB.setting("captcha_max_attempts", "5")))
    if failures >= max_attempts:
        DB.set_blocked(uid, True)
        u = DB.get_user(uid)
        name = " ".join(x for x in [u["first_name"], u["last_name"]] if x)
        username = "@" + u["username"] if u["username"] else "ندارد"
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🟢 رفع مسدودیت", callback_data=f"admin:user:unblock:{uid}", style="success")]])
        try:
            await context.bot.send_message(ADMIN_ID, f"⛔ <b>کاربر به‌دلیل ۵ پاسخ اشتباه مسدود شد.</b>\n\n🆔 <code>{uid}</code>\n👤 {esc(name or 'بدون نام')}\n🔹 {esc(username)}", parse_mode=ParseMode.HTML, reply_markup=kb)
        except Exception: pass
        return
    # The previous question and answer have already been deleted. Replace them
    # with one fresh challenge without leaving extra captcha messages behind.
    a,b,ans = new_captcha()
    sent = await context.bot.send_message(uid, f"🤖 <b>{a} + {b} = ؟</b>", parse_mode=ParseMode.HTML)
    CAPTCHA_PENDING[uid] = {"answer": ans, "question_id": sent.message_id}

async def menu_callback(update, context):
    q = update.callback_query
    await q.answer()
    if not await guard(update):
        return
    uid = q.from_user.id
    if uid != ADMIN_ID and not await require_join(update, context):
        return

    if q.data == "menu:upload":
        await q.message.reply_text(
            "📤 فایل را مستقیم ارسال کن.\n\n"
            f"فرمت‌های فعال: {', '.join(app_format_label(x) for x in enabled_app_formats()) or 'هیچ‌کدام'}.",
            reply_markup=back_button("menu:help"),
        )
    elif q.data == "menu:link":
        await q.message.reply_text("🔗 لینک یا متن را همینجا ارسال کن.", reply_markup=back_button("menu:help"))
    elif q.data == "menu:quota":
        limit = int(DB.setting("daily_limit", "5"))
        used = DB.daily_usage(uid)
        text = (
            "📊 <b>سهمیه امروز</b>\n\n"
            f"مصرف‌شده: <b>{used}</b>\n"
            f"سقف: <b>{'∞' if limit == 0 else limit}</b>"
        )
        await q.message.reply_text(
            text, parse_mode=ParseMode.HTML, reply_markup=user_menu()
        )
    elif q.data == "menu:help":
        await q.message.reply_text(
            "ℹ️ <b>راهنما</b>\n\n"
            "• بخش «ارسال فایل»: برای پردازش و رمزگشایی خودکار فایل‌های پشتیبانی‌شده است.\n"
            "• بخش «ارسال لینک»: برای شناسایی و استخراج لینک‌های کانفیگ از متن است.\n"
            "• رمز از کاربر دریافت نمی‌شود؛ پردازش به‌صورت غیرتعاملی انجام می‌شود.\n"
            "• اگر فایل کلید داخلی داشته باشد، خودکار پردازش می‌شود. فایل‌هایی که واقعاً به رمز بیرونی نیاز دارند بدون آن رمز قابل بازشدن نیستند.\n"
            "• بعد از پردازش می‌توانی لینک‌ها، JSON، اطلاعات یا خروجی را بگیری.\n"
            "• در بخش لینک‌ها هر خط فقط یک لینک است.\n"
            f"• فرمت‌های فعال: {', '.join(x.lstrip('.') for x in enabled_app_formats()) or 'هیچ‌کدام'}.",
            parse_mode=ParseMode.HTML,
            reply_markup=user_menu(),
        )


# ============================================================
# Direct text / link
# ============================================================

async def handle_text(update, context):
    if not await guard(update):
        return

    uid = update.effective_user.id

    if uid != ADMIN_ID and uid in CAPTCHA_PENDING:
        await handle_captcha_answer(update, context)
        return

    if not await require_join(update, context):
        return

    if uid == ADMIN_ID and uid in ADMIN_STATE:
        await handle_admin_state(update, context)
        return

    if uid != ADMIN_ID and not await ask_captcha(update, context):
        return

    if maintenance_on() and uid != ADMIN_ID:
        await update.message.reply_text("🛠 بات موقتاً در حال بروزرسانی است.")
        return

    links = extract_links(update.message.text or "")
    if not links:
        links = extract_structured_uris(update.message.text or "")
    if not links:
        await update.message.reply_text(
            "❌ لینک قابل شناسایی پیدا نشد.",
            reply_markup=user_menu(),
        )
        return

    cleanup_job(uid)
    USER_JOBS[uid] = {
        "directory": None,
        "raw": update.message.text,
        "links": links,
        "source_files": ["پیام"],
        "keys": extract_labeled_keys(update.message.text or ""),
        "json_values": json_objects_from_text(update.message.text or ""),
        "files": [],
        "protocol_counts": protocol_counts(links),
    }
    if uid != ADMIN_ID:
        DB.captcha_increment_ops(uid)

    await update.message.reply_text(
        f"✅ <b>{len(links)}</b> لینک شناسایی شد.\n\nانتخاب کن:",
        parse_mode=ParseMode.HTML,
        reply_markup=result_menu(uid),
    )


# ============================================================
# Engine
# ============================================================

async def run_engine(input_dir, output_dir):
    """Run Pantegnos completely non-interactively and wait for its real exit.

    We intentionally do NOT terminate the process as soon as the first output
    file appears: some Pantegnos modules can create one file and then continue
    writing other outputs. Waiting for process completion prevents partial
    results from being presented to the user.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    timeout = max(10, int(DB.setting("process_timeout", str(DEFAULT_PROCESS_TIMEOUT))))
    command = [PANTEGNOS_BIN, "-input", str(input_dir), "-output", str(output_dir)]
    job_stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    log.info("engine start input=%s output=%s interactive_password=%s", input_dir, output_dir, False)
    async with JOB_SEMAPHORE:
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(input_dir.parent),
            )
        except FileNotFoundError as exc:
            log.exception("engine executable not found: %s", PANTEGNOS_BIN)
            raise RuntimeError("موتور پردازش روی سرور در دسترس نیست.") from exc
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError as exc:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                out, err = await proc.communicate()
            except Exception:
                out, err = b"", b""
            log.error("engine timeout after %ss", timeout)
            raise RuntimeError("زمان پردازش فایل تمام شد.") from exc

    stdout = out.decode("utf-8", errors="replace")
    stderr = err.decode("utf-8", errors="replace")
    rc = proc.returncode

    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with ENGINE_LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write("\n" + "=" * 90 + "\n")
            fh.write(f"[{job_stamp}] rc={rc}\n")
            fh.write(f"input={input_dir}\noutput={output_dir}\n")
            fh.write("--- STDOUT ---\n")
            fh.write(stdout if stdout else "<empty>\n")
            fh.write("--- STDERR ---\n")
            fh.write(stderr if stderr else "<empty>\n")
    except Exception:
        log.exception("could not persist engine log")

    log.info("engine finished rc=%s stdout=%d stderr=%d output_exists=%s", rc, len(stdout), len(stderr), output_exists(output_dir))
    if stdout.strip():
        log.info("engine stdout: %s", stdout[-12000:])
    if stderr.strip():
        log.warning("engine stderr: %s", stderr[-12000:])
    return rc, stdout, stderr


def output_text(output_dir):
    parts, names = [], []
    for path in sorted(p for p in output_dir.rglob("*") if p.is_file()):
        if not is_probably_text(path) or path.stat().st_size > 5 * 1024 * 1024:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        names.append(path.relative_to(output_dir).as_posix())
        parts.append(f"===== {path.relative_to(output_dir).as_posix()} =====\n{text}\n")
    return "\n".join(parts), names


def output_exists(output_dir):
    return any(p.is_file() for p in output_dir.rglob("*"))


def password_prompt_detected(stdout, stderr):
    text = (stdout + "\n" + stderr).lower()
    return any(x in text for x in (
        "enter password", "enter passkey", "enter passphrase",
        "password:", "passkey:", "passphrase:",
        "passphrase required to open this config",
        "this config is passphrase-protected",
    ))


def engine_failure_reason(rc, stdout, stderr, ext=""):
    """Return a precise engine-facing reason without asking the Telegram user for a password."""
    text = strip_ansi((stdout or "") + "\n" + (stderr or "")).strip()
    low = text.lower()
    if any(x in low for x in ("incorrect passphrase", "passphrase required", "passphrase-protected", "enter passphrase")):
        for line in reversed(text.splitlines()):
            if any(x in line.lower() for x in ("passphrase", "password", "passkey")):
                return f"🔐 {line.strip()[:900]}"
        return "🔐 این فایل به Passphrase خارجی نیاز دارد و موتور آن را بدون ورودی تعاملی باز نکرد."
    if "bad magic" in low or "invalid format" in low or "no matching module" in low:
        return "ساختار فایل با ماژول‌های فعلی Pantegnos سازگار نیست یا فایل ناقص است."
    if rc != 0 and text:
        for line in reversed(text.splitlines()):
            line = line.strip()
            if line and not line.startswith("["):
                return f"خطای موتور: {line[:900]}"
        return "پردازش فایل توسط موتور با خطا متوقف شد."
    return "فایل خراب، ناقص یا غیرقابل پردازش است."



    files = sorted(p for p in output_dir.rglob("*") if p.is_file())
    parts = []
    names = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        names.append(path.name)
        parts.append(f"===== {path.name} =====\n{text}\n")
    return "\n".join(parts), names


# ============================================================
# File processing
# ============================================================

async def handle_document(update, context):
    if not await guard(update):
        return

    uid = update.effective_user.id

    if uid == ADMIN_ID and ADMIN_STATE.get(ADMIN_ID, {}).get("type") in {"db_replace", "channel"}:
        await handle_admin_state(update, context)
        return

    if uid != ADMIN_ID and uid in CAPTCHA_PENDING:
        await update.message.reply_text("🤖 ابتدا پاسخ سؤال امنیتی را ارسال کن.")
        return

    if not await require_join(update, context):
        return

    if uid != ADMIN_ID and not await ask_captcha(update, context):
        return

    if maintenance_on() and uid != ADMIN_ID:
        await update.message.reply_text("🛠 بات موقتاً در حال بروزرسانی است.")
        return

    doc = update.message.document
    filename = Path(doc.file_name or "config.bin").name
    ext = Path(filename).suffix.lower()
    max_size = int(DB.setting("max_file_size", str(DEFAULT_MAX_FILE_SIZE)))

    if doc.file_size and doc.file_size > max_size:
        await update.message.reply_text(
            f"❌ حجم فایل بیشتر از حد مجاز است.\nحداکثر: {file_size_text(max_size)}"
        )
        return

    # Plain text/JSON config files: extract links without invoking the engine.
    if ext in {".txt", ".json", ".conf", ".log"}:
        path = Path(tempfile.mkstemp(prefix="pd-", suffix=ext)[1])
        try:
            tg = await doc.get_file()
            await tg.download_to_drive(custom_path=str(path))
            content = path.read_text(encoding="utf-8", errors="ignore")
            links = extract_links(content)
            if not links:
                links = extract_structured_uris(content)
            if links:
                cleanup_job(uid)
                USER_JOBS[uid] = {
                    "directory": None,
                    "input_filename": filename,
                    "raw": content,
                    "links": links,
                    "keys": extract_labeled_keys(content),
                    "json_values": json_objects_from_text(content),
                    "files": [],
                    "protocol_counts": protocol_counts(links),
                    "source_files": [filename],
                }
                await update.message.reply_text(
                    f"✅ <b>{len(links)}</b> لینک پیدا شد.\n\nانتخاب کن:",
                    parse_mode=ParseMode.HTML,
                    reply_markup=result_menu(uid),
                )
                return
        finally:
            path.unlink(missing_ok=True)

    if ext not in SUPPORTED_EXTENSIONS:
        await update.message.reply_text("⚠️ این پسوند در موتور فعلی ProDecryptor ثبت نشده است.")
        return
    if not app_format_enabled(ext):
        await update.message.reply_text(f"⛔ فرمت {esc(app_format_label(ext))} فعلاً توسط مدیر غیرفعال شده است.", parse_mode=ParseMode.HTML)
        return

    if not DB.consume_daily(uid):
        limit = int(DB.setting("daily_limit", "5"))
        await update.message.reply_text(
            f"⛔ سهمیه امروزت تمام شده است.\nسقف روزانه: {limit} فایل"
        )
        return

    work_dir = Path(tempfile.mkdtemp(prefix="prodecryptor-"))
    input_dir = work_dir / "configs"
    output_dir = work_dir / "output"
    input_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    input_file = input_dir / filename

    job_id = uuid.uuid4().hex
    DB.create_job(job_id, uid, filename, ext)

    status = await update.message.reply_text(
        "⏳ <b>فایل دریافت شد.</b>\nدر حال آماده‌سازی...",
        parse_mode=ParseMode.HTML,
    )

    try:
        tg = await doc.get_file()
        await tg.download_to_drive(custom_path=str(input_file))

        if input_file.stat().st_size > max_size:
            raise RuntimeError("حجم فایل بیش از حد مجاز است.")

        await status.edit_text(
            "⚙️ <b>در حال پردازش...</b>\nلطفاً صبر کن.",
            parse_mode=ParseMode.HTML,
        )

        rc, stdout, stderr = await run_engine(input_dir, output_dir)

        # A produced output is authoritative even when the process return code is non-zero.
        if not output_exists(output_dir):
            raise RuntimeError(engine_failure_reason(rc, stdout, stderr, ext))

        analysis = analyze_engine_output(output_dir, stdout, stderr, filename)
        if not analysis["raw"].strip() and not analysis["links"] and not analysis["files"]:
            raise RuntimeError("خروجی معتبری از موتور دریافت نشد.")
        log.info("engine analysis: files=%d links=%d json=%d keys=%d", len(analysis["files"]), len(analysis["links"]), len(analysis["json_values"]), len(analysis["keys"]))

        USER_JOBS[uid] = {
            "directory": str(work_dir),
            "input_filename": filename,
            "raw": analysis["raw"],
            "stdout": analysis["stdout"],
            "stderr": analysis["stderr"],
            "links": analysis["links"],
            "keys": analysis["keys"],
            "json_values": analysis["json_values"],
            "files": analysis["files"],
            "source_files": [x["name"] for x in analysis["files"]] or [filename],
            "protocol_counts": analysis["protocol_counts"],
            "job_id": job_id,
        }

        DB.record_success(uid, len(analysis["links"]))
        if uid != ADMIN_ID:
            DB.captcha_increment_ops(uid)
        DB.finish_job(job_id, "success", len(analysis["links"]))

        await status.edit_text(
            "✅ <b>پردازش با موفقیت انجام شد.</b>\n\n"
            f"📄 فایل: <code>{esc(filename)}</code>\n"
            f"🔗 URIهای قابل استخراج: <b>{len(analysis['links'])}</b>\n" f"📦 فایل‌های خروجی موتور: <b>{len(analysis['files'])}</b>\n\n"
            "گزینه موردنظر را انتخاب کن:",
            parse_mode=ParseMode.HTML,
            reply_markup=result_menu(uid),
        )

    except Exception as exc:
        log.exception("file processing failed user=%s file=%s", uid, filename)
        DB.record_failure(uid)
        DB.finish_job(job_id, "failed", 0, str(exc)[:500])
        DB.refund_daily(uid)
        cleanup_job(uid)

        await status.edit_text(
            "❌ <b>پردازش فایل ناموفق بود.</b>\n\n"
            "فایل ممکن است خراب، ناقص، رمز اشتباه یا غیرقابل پردازش باشد.",
            parse_mode=ParseMode.HTML,
        )


async def handle_password(update, context):
    uid = update.effective_user.id
    job = USER_JOBS.get(uid)
    if not job or not job.get("pending_password"):
        return

    password = update.message.text or ""
    if not password:
        await update.message.reply_text("❌ رمز خالی قابل استفاده نیست.")
        return

    status = await update.message.reply_text("🔐 در حال بررسی رمز...")
    output_dir = Path(job["output_dir"])
    input_dir = Path(job["input_dir"])

    try:
        shutil.rmtree(output_dir, ignore_errors=True)
        output_dir.mkdir(parents=True, exist_ok=True)

        rc, stdout, stderr = await run_engine(input_dir, output_dir, password)

        if rc != 0 or not output_exists(output_dir):
            raise RuntimeError("wrong password")

        raw, source_files = output_text(output_dir)
        if not raw.strip():
            raise RuntimeError("empty output")

        links = extract_links(raw)
        for link in extract_structured_uris(stdout):
            if link not in links:
                links.append(link)

        job["pending_password"] = False
        job["raw"] = raw
        job["links"] = links
        job["source_files"] = source_files
        USER_JOBS[uid] = job

        DB.record_success(uid, len(links))
        if uid != ADMIN_ID:
            DB.captcha_increment_ops(uid)
        DB.finish_job(job["job_id"], "success", len(links))

        await status.edit_text(
            "✅ <b>رمز صحیح بود.</b>\n\n"
            f"🔗 لینک‌های قابل استخراج: <b>{len(links)}</b>\n\n"
            "گزینه موردنظر را انتخاب کن:",
            parse_mode=ParseMode.HTML,
            reply_markup=result_menu(uid),
        )
    except Exception:
        DB.record_failure(uid)
        DB.finish_job(job["job_id"], "failed", 0, "wrong password or invalid file")
        DB.refund_daily(uid)
        cleanup_job(uid)
        await status.edit_text(
            "❌ <b>رمز صحیح نیست یا فایل قابل پردازش نیست.</b>",
            parse_mode=ParseMode.HTML,
        )


# ============================================================
# Result callback
# ============================================================

async def result_callback(update, context):
    q = update.callback_query
    await q.answer()
    if not await guard(update):
        return
    if not await require_join(update, context):
        return
    _, action, owner = q.data.split(":")
    owner = int(owner)
    if q.from_user.id != owner:
        await q.answer("این نتیجه متعلق به شما نیست.", show_alert=True)
        return
    job = USER_JOBS.get(owner)
    if not job:
        await q.message.reply_text("⚠️ نتیجه دیگر در دسترس نیست. فایل را دوباره ارسال کن.")
        return

    links = job.get("links", [])
    raw = job.get("raw", "")
    keys = job.get("keys", [])
    files = job.get("files", [])
    json_values = job.get("json_values", [])
    source_files = job.get("source_files", [])

    if action == "links":
        if not links:
            await q.message.reply_text("❌ هیچ URI قابل استخراجی پیدا نشد. اگر اپ خروجی اختصاصی دارد، از «فایل‌های خروجی موتور» استفاده کن.", reply_markup=result_menu(owner))
            return
        for chunk_items in split_link_chunks(links):
            await q.message.reply_text(links_codeblock(chunk_items), parse_mode=ParseMode.MARKDOWN)
        await q.message.reply_text("🔗 پایان فهرست URIها", reply_markup=result_menu(owner))
        return

    if action == "keys":
        if not keys:
            await q.message.reply_text("❌ کلید صریحی در خروجی پیدا نشد.", reply_markup=result_menu(owner))
            return
        for chunk in split_text("\n".join(f"{i+1}. {x}" for i, x in enumerate(keys))):
            await q.message.reply_text(f"<pre>{esc(chunk)}</pre>", parse_mode=ParseMode.HTML)
        await q.message.reply_text("🔑 پایان کلیدها", reply_markup=result_menu(owner))
        return

    if action == "json":
        data = {
            "name": APP_NAME,
            "version": APP_VERSION,
            "input": job.get("input_filename", source_files[0] if source_files else ""),
            "output_files": [
                {"name": x["name"], "size": x["size"], "binary": x["binary"]}
                for x in files
            ],
            "keys": keys,
            "links": [
                {"protocol": x.split("://", 1)[0].lower(), "uri": x}
                for x in links
            ],
            "engine_json": json_values,
            "raw_output": raw,
        }
        content = json.dumps(data, ensure_ascii=False, indent=2)
        if len(content) <= TELEGRAM_CHUNK:
            await q.message.reply_text(f"<pre>{esc(content)}</pre>", parse_mode=ParseMode.HTML, reply_markup=result_menu(owner))
        else:
            path = Path(tempfile.mkstemp(prefix="pd-", suffix=".json")[1])
            try:
                path.write_text(content, encoding="utf-8")
                with path.open("rb") as f:
                    await q.message.reply_document(f, filename="prodecryptor-result.json", caption="📋 JSON کامل نتیجه موتور")
            finally:
                path.unlink(missing_ok=True)
            await q.message.reply_text("📋 JSON ارسال شد.", reply_markup=result_menu(owner))
        return

    if action == "info":
        counts = job.get("protocol_counts", protocol_counts(links))
        lines = [
            "🔍 <b>اطلاعات نتیجه</b>", "",
            f"📄 فایل‌های خروجی: <b>{len(files)}</b>",
            f"🔗 URIهای معتبر: <b>{len(links)}</b>",
            f"🔑 کلیدهای صریح: <b>{len(keys)}</b>",
            f"🧩 JSONهای تشخیص‌داده‌شده: <b>{len(json_values)}</b>",
        ]
        if counts:
            lines += ["", "📡 <b>پروتکل‌های URI:</b>"]
            for p, c in sorted(counts.items()):
                lines.append(f"• <code>{esc(p)}</code>: {c}")
        if files:
            lines += ["", "📦 <b>فایل‌های موتور:</b>"]
            for x in files[:30]:
                kind = "binary" if x["binary"] else "text"
                lines.append(f"• <code>{esc(x['name'])}</code> — {file_size_text(x['size'])} — {kind}")
        await q.message.reply_text("\n".join(lines), parse_mode=ParseMode.HTML, reply_markup=result_menu(owner))
        return

    if action == "raw":
        if not raw:
            await q.message.reply_text("❌ خروجی متنی وجود ندارد.", reply_markup=result_menu(owner))
            return
        path = Path(tempfile.mkstemp(prefix="pd-", suffix=".txt")[1])
        try:
            path.write_text(raw, encoding="utf-8")
            with path.open("rb") as f:
                await q.message.reply_document(f, filename="engine-output.txt", caption="📄 خروجی متنی واقعی موتور")
        finally:
            path.unlink(missing_ok=True)
        return

    if action == "files":
        if not files:
            await q.message.reply_text("❌ فایل خروجی جداگانه‌ای وجود ندارد.", reply_markup=result_menu(owner))
            return
        sent = 0
        skipped = 0
        for item in files:
            path = item["path"]
            try:
                if not path.exists() or path.stat().st_size > 49 * 1024 * 1024:
                    skipped += 1
                    continue
                with path.open("rb") as f:
                    await q.message.reply_document(f, filename=Path(item["name"]).name, caption=f"📦 خروجی موتور: {item['name']}")
                sent += 1
            except Exception as exc:
                skipped += 1
                log.warning("could not send engine output %s: %s", path, exc)
        await q.message.reply_text(f"📦 ارسال فایل‌های خروجی تمام شد. موفق: {sent} | ردشده: {skipped}", reply_markup=result_menu(owner))
        return

    if action == "delete":
        cleanup_job(owner)
        await q.message.reply_text("🗑 نتیجه حذف شد.", reply_markup=user_menu())


# ============================================================
# Admin dashboard
# ============================================================

async def admin_command(update, context):
    if not admin_only(update.effective_user.id):
        return
    DB.upsert_user(update.effective_user)
    await update.message.reply_text(
        "🛡 <b>ProDecryptor Admin</b>",
        parse_mode=ParseMode.HTML,
        reply_markup=admin_menu(),
    )


async def admin_callback(update, context):
    q = update.callback_query
    if not admin_only(q.from_user.id):
        await q.answer("دسترسی ندارید.", show_alert=True)
        return
    await q.answer()

    d = q.data

    if d == "admin:dashboard":
        await admin_dashboard(q)
    elif d == "admin:limits":
        await admin_limits(q)
    elif d == "admin:broadcast":
        ADMIN_STATE[ADMIN_ID] = {"type": "broadcast"}
        await q.message.reply_text(
            "📣 پیام همگانی را ارسال کن.\nبرای لغو /cancel",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("❎ لغو", callback_data="admin:cancel", style="danger")]
            ]),
        )
    elif d == "admin:sponsors":
        await admin_sponsors(q)
    elif d == "admin:sponsor:add":
        ADMIN_STATE[ADMIN_ID] = {"type": "sponsor", "mode": "add", "step": "name", "data": {}}
        await q.message.reply_text(
            "🤝 <b>ساخت اسپانسر</b>\n\nمرحله 1 از 4\nنام اسپانسر را ارسال کن.",
            parse_mode=ParseMode.HTML,
            reply_markup=back_button("admin:sponsors"),
        )
    elif d.startswith("admin:sponsor:edit:"):
        sid = int(d.rsplit(":", 1)[1])
        s = DB.sponsor(sid)
        if not s:
            await admin_sponsors(q)
            return
        ADMIN_STATE[ADMIN_ID] = {
            "type": "sponsor", "mode": "edit", "step": "name",
            "sponsor_id": sid,
            "data": {
                "name": s["name"], "url": s["url"],
                "button_text": s["button_text"], "style": s["style"],
            },
        }
        await q.message.reply_text(
            f"✏️ <b>ویرایش #{sid}</b>\n\n"
            "مرحله 1 از 4\nنام جدید را ارسال کن.\n"
            "اگر می‌خواهی همان نام بماند، همان نام را ارسال کن.",
            parse_mode=ParseMode.HTML,
            reply_markup=back_button("admin:sponsors"),
        )
    elif d.startswith("admin:sponsor:toggle:"):
        sid = int(d.rsplit(":", 1)[1])
        s = DB.sponsor(sid)
        if s:
            DB.set_sponsor_active(sid, not bool(s["active"]))
        await admin_sponsors(q)
    elif d.startswith("admin:sponsor:delete:"):
        sid = int(d.rsplit(":", 1)[1])
        DB.delete_sponsor(sid)
        await admin_sponsors(q)
    elif d == "admin:sponsor:up":
        pass
    elif d == "admin:status":
        await admin_status(q)
    elif d == "admin:jobs":
        await admin_jobs(q)
    elif d == "admin:settings":
        await admin_settings(q)
    elif d == "admin:database":
        await admin_database(q)
    elif d == "admin:database:backup":
        await admin_backup(q)
    elif d == "admin:database:replace":
        ADMIN_STATE[ADMIN_ID] = {"type": "db_replace"}
        await q.message.reply_text("💾 فایل دیتابیس را ارسال کن. نام و پسوند فایل مهم نیست؛ فایل باید یک SQLite database معتبر باشد.\nبرای لغو /cancel", reply_markup=back_button("admin:database"))
    elif d == "admin:logs":
        await admin_logs(q)
    elif d == "admin:engine_logs":
        await admin_engine_logs(q)
    elif d == "admin:channels":
        await admin_channels(q)
    elif d == "admin:app_formats":
        await admin_app_formats(q)
    elif d.startswith("admin:appfmt:toggle:"):
        ext = "." + d.rsplit(":", 1)[1].lower()
        if ext in APP_FORMATS:
            key = APP_FORMATS[ext]["setting"]
            DB.set_setting(key, "0" if app_format_enabled(ext) else "1")
        await admin_app_formats(q)
    elif d == "admin:channel:add":
        ADMIN_STATE[ADMIN_ID] = {"type": "channel", "step": "chat", "data": {}}
        await q.message.reply_text("🔒 مرحله 1 از 2\nشناسه کانال یا @username را ارسال کن. بات باید در آن کانال ادمین باشد.", reply_markup=back_button("admin:channels"))
    elif d.startswith("admin:channel:toggle:"):
        DB.toggle_channel(int(d.rsplit(":",1)[1])); await admin_channels(q)
    elif d.startswith("admin:channel:delete:"):
        DB.delete_channel(int(d.rsplit(":",1)[1])); await admin_channels(q)
    elif d == "admin:captcha":
        await admin_captcha(q)
    elif d == "admin:captcha:custom":
        ADMIN_STATE[ADMIN_ID] = {"type": "captcha_custom"}
        await q.message.reply_text("✏️ تعداد عملیات را از ۱ تا ۱۰۰۰ ارسال کن.", reply_markup=back_button("admin:captcha"))
    elif d.startswith("admin:captcha:set:"):
        DB.set_setting("captcha_interval", d.rsplit(":",1)[1]); await admin_captcha(q)
    elif d == "admin:cancel":
        ADMIN_STATE.pop(ADMIN_ID, None)
        await q.message.reply_text("❎ لغو شد.", reply_markup=admin_menu())
    elif d.startswith("admin:limit:set:"):
        value = d.rsplit(":", 1)[1]
        DB.set_setting("daily_limit", value)
        await admin_limits(q)
    elif d == "admin:maintenance:toggle":
        DB.set_setting("maintenance", "0" if maintenance_on() else "1")
        await admin_limits(q)
    elif d.startswith("admin:maxsize:"):
        value = int(d.rsplit(":", 1)[1])
        DB.set_setting("max_file_size", str(value))
        await admin_settings(q)
    elif d.startswith("admin:timeout:"):
        value = int(d.rsplit(":", 1)[1])
        DB.set_setting("process_timeout", str(value))
        await admin_settings(q)
    elif d.startswith("admin:users:"):
        await admin_users(q, int(d.rsplit(":", 1)[1]))
    elif d.startswith("admin:user:view:"):
        await admin_user_view(q, int(d.rsplit(":", 1)[1]))
    elif d.startswith("admin:user:block:"):
        uid = int(d.rsplit(":", 1)[1])
        if uid != ADMIN_ID:
            DB.set_blocked(uid, True)
        await admin_user_view(q, uid)
    elif d.startswith("admin:user:unblock:"):
        uid = int(d.rsplit(":", 1)[1])
        DB.set_blocked(uid, False)
        await admin_user_view(q, uid)
    elif d.startswith("admin:user:jobs:"):
        await admin_user_jobs(q, int(d.rsplit(":", 1)[1]))


def back_button(callback):
    return InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data=callback, style="primary")]])

async def admin_app_formats(q):
    lines = ["📦 <b>مدیریت فرمت‌های اپ</b>", "", "این بخش فقط فرمت فایل ورودی را کنترل می‌کند؛ با پروتکل‌های خروجی اشتباه نشود.", ""]
    rows = []
    for ext, meta in APP_FORMATS.items():
        enabled = app_format_enabled(ext)
        lines.append(f"{'🟢' if enabled else '⚪'} <b>{esc(meta['name'])}</b> <code>{ext}</code>")
        rows.append([InlineKeyboardButton(
            f"{'🟢 فعال' if enabled else '⚪ غیرفعال'} — {meta['name']}",
            callback_data=f"admin:appfmt:toggle:{ext[1:]}",
            style="success" if enabled else "primary",
        )])
    rows.append([InlineKeyboardButton("🔙 پنل", callback_data="admin:dashboard", style="primary")])
    await q.message.edit_text("\n".join(lines), parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(rows))


async def admin_database(q):
    exists = DB_PATH.exists()
    size = file_size_text(DB_PATH.stat().st_size) if exists else "0 KB"
    await q.message.edit_text("💾 <b>مدیریت دیتابیس</b>\n\n" f"وضعیت: <b>{'آماده' if exists else 'یافت نشد'}</b>\nحجم: <b>{size}</b>", parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬇️ بکاپ کامل", callback_data="admin:database:backup", style="success")],[InlineKeyboardButton("♻️ جایگزینی کامل", callback_data="admin:database:replace", style="danger")],[InlineKeyboardButton("🔙 پنل", callback_data="admin:dashboard", style="primary")]]))

async def admin_backup(q):
    tmp = Path(tempfile.mkstemp(prefix="pd-backup-", suffix=".db")[1])
    try:
        DB.snapshot(tmp)
        with tmp.open("rb") as fh:
            await q.message.reply_document(fh, filename="prodecryptor-backup.db", caption="💾 بکاپ کامل و یکپارچه دیتابیس")
        await q.message.reply_text("💾 بکاپ ارسال شد.", reply_markup=back_button("admin:database"))
    finally:
        tmp.unlink(missing_ok=True)


async def admin_logs(q):
    with LOG_LOCK:
        cutoff = time.time() - LOG_WINDOW_SECONDS
        while LOG_BUFFER and LOG_BUFFER[0][0] < cutoff:
            LOG_BUFFER.popleft()
        lines = [x[1] for x in LOG_BUFFER]
    content = "\n".join(lines) or "در ۵ دقیقه اخیر لاگی ثبت نشده است."
    if len(content) > 45000:
        content = content[-45000:]
    path = Path(tempfile.mkstemp(prefix="pd-logs-", suffix=".txt")[1])
    try:
        path.write_text(content, encoding="utf-8")
        await q.message.reply_document(path.open("rb"), filename="logs-last-5-min.txt", caption="📜 فقط لاگ‌های ۵ دقیقه اخیر")
    finally:
        path.unlink(missing_ok=True)
    await q.message.reply_text("📜 گزارش آماده شد.", reply_markup=back_button("admin:dashboard"))

async def admin_engine_logs(q):
    """Send the complete persisted stdout/stderr produced by the decoder engine."""
    if not ENGINE_LOG_PATH.exists():
        await q.message.reply_text("📜 هنوز لاگ موتور ثبت نشده است.", reply_markup=back_button("admin:dashboard"))
        return
    try:
        size = ENGINE_LOG_PATH.stat().st_size
        if size > 45 * 1024 * 1024:
            # Keep the latest 45 MiB so Telegram can receive it reliably.
            with ENGINE_LOG_PATH.open("rb") as fh:
                fh.seek(max(0, size - 45 * 1024 * 1024))
                data = fh.read()
            tmp = Path(tempfile.mkstemp(prefix="pd-engine-logs-", suffix=".txt")[1])
            tmp.write_bytes("[بخش انتهایی لاگ موتور]\n\n".encode("utf-8") + data)
        else:
            tmp = ENGINE_LOG_PATH
        try:
            with tmp.open("rb") as fh:
                await q.message.reply_document(fh, filename="engine-full.log", caption="⚙️ لاگ کامل موتور: stdout + stderr")
        finally:
            if tmp != ENGINE_LOG_PATH:
                tmp.unlink(missing_ok=True)
    except Exception as exc:
        log.exception("sending engine logs failed")
        await q.message.reply_text(f"❌ ارسال لاگ موتور ناموفق بود: {esc(str(exc)[:500])}", parse_mode=ParseMode.HTML, reply_markup=back_button("admin:dashboard"))
    else:
        await q.message.reply_text("⚙️ لاگ کامل موتور ارسال شد.", reply_markup=back_button("admin:dashboard"))

async def admin_captcha(q):
    interval = int(DB.setting("captcha_interval", "10"))
    await q.message.edit_text("🤖 <b>ضد ربات</b>\n\n" f"اولین ورود: سؤال امنیتی اجباری\nبعد از هر: <b>{interval}</b> عملیات موفق\nحداکثر تلاش: <b>5</b>\n\nعدد موردنظر را انتخاب کن:", parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("5", callback_data="admin:captcha:set:5", style="primary"),InlineKeyboardButton("10", callback_data="admin:captcha:set:10", style="primary"),InlineKeyboardButton("20", callback_data="admin:captcha:set:20", style="primary")],[InlineKeyboardButton("✏️ عدد دلخواه", callback_data="admin:captcha:custom", style="primary")],[InlineKeyboardButton("🔙 تنظیمات", callback_data="admin:settings", style="primary")]]))

async def admin_channels(q):
    channels = DB.channels(False)
    lines = ["🔒 <b>عضویت اجباری</b>", ""]
    rows = []
    for ch in channels:
        lines.append(f"{'🟢' if ch['active'] else '⚪'} {esc(ch['title'] or ch['username'] or ch['chat_id'])}")
        rows.append([InlineKeyboardButton("فعال/غیرفعال", callback_data=f"admin:channel:toggle:{ch['id']}", style="success" if ch['active'] else "primary"), InlineKeyboardButton("🗑", callback_data=f"admin:channel:delete:{ch['id']}", style="danger")])
    if not channels: lines.append("هنوز کانالی ثبت نشده است.")
    rows += [[InlineKeyboardButton("➕ افزودن کانال", callback_data="admin:channel:add", style="success")],[InlineKeyboardButton("🔙 پنل", callback_data="admin:dashboard", style="primary")]]
    await q.message.edit_text("\n".join(lines), parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(rows))

async def admin_dashboard(q):
    s = DB.stats()
    limit = int(DB.setting("daily_limit", "5"))
    await q.message.edit_text(
        "📊 <b>داشبورد مدیریت</b>\n\n"
        f"👥 کاربران: <b>{s['users']}</b>\n"
        f"🟢 فعال 24 ساعت: <b>{s['active']}</b>\n"
        f"⛔ مسدود: <b>{s['blocked']}</b>\n\n"
        f"📁 فایل‌ها: <b>{s['files']}</b>\n"
        f"✅ موفق: <b>{s['success']}</b>\n"
        f"❌ ناموفق: <b>{s['failed']}</b>\n"
        f"🔗 لینک‌ها: <b>{s['links']}</b>\n"
        f"⚡ عملیات 24 ساعت: <b>{s['jobs24']}</b>\n\n"
        f"📅 سهمیه روزانه: <b>{'∞' if limit == 0 else limit}</b>\n"
        f"🛠 تعمیر: <b>{'فعال' if maintenance_on() else 'خاموش'}</b>\n"
        f"🕐 {now_text()}",
        parse_mode=ParseMode.HTML,
        reply_markup=admin_menu(),
    )


async def admin_limits(q):
    limit = int(DB.setting("daily_limit", "5"))
    maintenance = maintenance_on()
    rows = [
        [
            InlineKeyboardButton("1", callback_data="admin:limit:set:1", style="primary"),
            InlineKeyboardButton("3", callback_data="admin:limit:set:3", style="primary"),
            InlineKeyboardButton("5", callback_data="admin:limit:set:5", style="primary"),
            InlineKeyboardButton("10", callback_data="admin:limit:set:10", style="primary"),
        ],
        [
            InlineKeyboardButton("20", callback_data="admin:limit:set:20", style="primary"),
            InlineKeyboardButton("50", callback_data="admin:limit:set:50", style="primary"),
            InlineKeyboardButton("∞", callback_data="admin:limit:set:0", style="success"),
        ],
        [
            InlineKeyboardButton(
                "🛠 روشن" if not maintenance else "🟢 خاموش",
                callback_data="admin:maintenance:toggle",
                style="danger" if not maintenance else "success",
            )
        ],
        [InlineKeyboardButton("🔙 پنل", callback_data="admin:dashboard", style="primary")],
    ]
    await q.message.edit_text(
        "⚙️ <b>سهمیه و محدودیت</b>\n\n"
        f"سقف فعلی هر کاربر: <b>{'∞' if limit == 0 else limit}</b> فایل در روز\n"
        f"حالت تعمیر: <b>{'فعال' if maintenance else 'خاموش'}</b>\n\n"
        "سهمیه با زمان UTC روزانه محاسبه می‌شود.",
        parse_mode=ParseMode.HTML,
        reply_markup=InlineKeyboardMarkup(rows),
    )


async def admin_settings(q):
    size = int(DB.setting("max_file_size", str(DEFAULT_MAX_FILE_SIZE)))
    timeout = int(DB.setting("process_timeout", str(DEFAULT_PROCESS_TIMEOUT)))
    await q.message.edit_text(
        "⚙️ <b>تنظیمات سرویس</b>\n\n"
        f"📦 حجم فعلی: <b>{file_size_text(size)}</b>\n"
        f"⏱ زمان پردازش: <b>{timeout} ثانیه</b>\n"
        f"⚡ پردازش همزمان: <b>{MAX_CONCURRENT_JOBS}</b>",
        parse_mode=ParseMode.HTML,
        reply_markup=InlineKeyboardMarkup([
            [
                InlineKeyboardButton("10MB", callback_data=f"admin:maxsize:{10*1024*1024}", style="primary"),
                InlineKeyboardButton("25MB", callback_data=f"admin:maxsize:{25*1024*1024}", style="primary"),
                InlineKeyboardButton("50MB", callback_data=f"admin:maxsize:{50*1024*1024}", style="primary"),
            ],
            [
                InlineKeyboardButton("100MB", callback_data=f"admin:maxsize:{100*1024*1024}", style="primary"),
                InlineKeyboardButton("30s", callback_data="admin:timeout:30", style="primary"),
                InlineKeyboardButton("60s", callback_data="admin:timeout:60", style="primary"),
                InlineKeyboardButton("120s", callback_data="admin:timeout:120", style="primary"),
            ],
            [InlineKeyboardButton("🤖 ضد ربات", callback_data="admin:captcha", style="primary")],
            [InlineKeyboardButton("🔙 پنل", callback_data="admin:dashboard", style="primary")],
        ]),
    )


async def admin_status(q):
    engine = os.path.isfile(PANTEGNOS_BIN)
    await q.message.edit_text(
        "🛠 <b>وضعیت سرویس</b>\n\n"
        f"🤖 ProDecryptor: <b>فعال</b>\n"
        f"⚙️ موتور پردازش: <b>{'آماده' if engine else 'یافت نشد'}</b>\n"
        f"💾 دیتابیس: <code>{esc(DB_PATH)}</code>\n"
        f"📦 حجم: <b>{file_size_text(int(DB.setting('max_file_size', str(DEFAULT_MAX_FILE_SIZE))) )}</b>\n"
        f"⏱ timeout: <b>{DB.setting('process_timeout', str(DEFAULT_PROCESS_TIMEOUT))}s</b>\n"
        f"⚡ همزمانی: <b>{MAX_CONCURRENT_JOBS}</b>\n"
        f"🕐 {now_text()}",
        parse_mode=ParseMode.HTML,
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔄 بروزرسانی", callback_data="admin:status", style="success")],
            [InlineKeyboardButton("🔙 پنل", callback_data="admin:dashboard", style="primary")],
        ]),
    )


async def admin_jobs(q):
    jobs = DB.recent_jobs()
    lines = ["🧾 <b>آخرین عملیات</b>", ""]
    for j in jobs:
        icon = {
            "success": "✅", "failed": "❌",
            "processing": "⏳", "password_required": "🔐"
        }.get(j["status"], "•")
        dt = datetime.fromtimestamp(j["created_at"], timezone.utc).strftime("%m-%d %H:%M")
        lines.append(
            f"{icon} <code>{esc(j['filename'])}</code> | "
            f"{j['user_id']} | {j['links_count']} لینک | {dt}"
        )
    if len(lines) == 2:
        lines.append("هنوز عملیاتی ثبت نشده است.")
    await q.message.edit_text(
        "\n".join(lines),
        parse_mode=ParseMode.HTML,
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔙 پنل", callback_data="admin:dashboard", style="primary")]
        ]),
    )


async def admin_users(q, page):
    users = DB.users_page(page)
    total = DB.user_count()
    lines = [f"👥 <b>کاربران</b> — صفحه {page+1}", f"کل: <b>{total}</b>", ""]
    rows = []

    for u in users:
        name = u["username"] or u["first_name"] or str(u["user_id"])
        icon = "⛔" if u["is_blocked"] else "🟢"
        lines.append(
            f"{icon} <b>{esc(name)}</b> | <code>{u['user_id']}</code> | "
            f"فایل {u['total_files']} | لینک {u['total_links']}"
        )
        rows.append([
            InlineKeyboardButton(
                f"👤 {u['user_id']}",
                callback_data=f"admin:user:view:{u['user_id']}",
                style="primary",
            )
        ])

    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton("◀️ قبلی", callback_data=f"admin:users:{page-1}", style="primary"))
    if (page + 1) * 8 < total:
        nav.append(InlineKeyboardButton("بعدی ▶️", callback_data=f"admin:users:{page+1}", style="primary"))
    if nav:
        rows.append(nav)
    rows.append([InlineKeyboardButton("🔙 پنل", callback_data="admin:dashboard", style="primary")])

    await q.message.edit_text(
        "\n".join(lines),
        parse_mode=ParseMode.HTML,
        reply_markup=InlineKeyboardMarkup(rows),
    )


async def admin_user_view(q, user_id):
    u = DB.get_user(user_id)
    if not u:
        await q.message.edit_text("کاربر پیدا نشد.", reply_markup=admin_menu())
        return

    name = " ".join(x for x in [u["first_name"], u["last_name"]] if x).strip()
    username = f"@{u['username']}" if u["username"] else "ندارد"
    limit = int(DB.setting("daily_limit", "5"))
    used = DB.daily_usage(user_id)

    await q.message.edit_text(
        "👤 <b>جزئیات کاربر</b>\n\n"
        f"🆔 <code>{u['user_id']}</code>\n"
        f"👤 {esc(name or 'بدون نام')}\n"
        f"🔹 {esc(username)}\n"
        f"📅 امروز: <b>{used} / {'∞' if limit == 0 else limit}</b>\n\n"
        f"📁 کل فایل‌ها: <b>{u['total_files']}</b>\n"
        f"✅ موفق: <b>{u['successful_files']}</b>\n"
        f"❌ ناموفق: <b>{u['failed_files']}</b>\n"
        f"🔗 لینک‌ها: <b>{u['total_links']}</b>\n"
        f"🔒 وضعیت: <b>{'مسدود' if u['is_blocked'] else 'فعال'}</b>",
        parse_mode=ParseMode.HTML,
        reply_markup=InlineKeyboardMarkup([
            [
                InlineKeyboardButton(
                    "🟢 رفع مسدودیت" if u["is_blocked"] else "⛔ مسدود",
                    callback_data=f"admin:user:{'unblock' if u['is_blocked'] else 'block'}:{user_id}",
                    style="success" if u["is_blocked"] else "danger",
                ),
                InlineKeyboardButton(
                    "🧾 عملیات", callback_data=f"admin:user:jobs:{user_id}", style="primary"
                ),
            ],
            [InlineKeyboardButton("🔙 کاربران", callback_data="admin:users:0", style="primary")],
        ]),
    )


async def admin_user_jobs(q, user_id):
    rows = DB.conn.execute(
        "SELECT * FROM jobs WHERE user_id=? ORDER BY created_at DESC LIMIT 20",
        (user_id,),
    ).fetchall()
    lines = [f"🧾 <b>عملیات کاربر {user_id}</b>", ""]
    for j in rows:
        icon = "✅" if j["status"] == "success" else "❌" if j["status"] == "failed" else "🔐"
        lines.append(
            f"{icon} <code>{esc(j['filename'])}</code> | "
            f"{j['links_count']} لینک"
        )
    if len(lines) == 2:
        lines.append("عملیاتی ثبت نشده است.")
    await q.message.edit_text(
        "\n".join(lines),
        parse_mode=ParseMode.HTML,
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔙 کاربر", callback_data=f"admin:user:view:{user_id}", style="primary")]
        ]),
    )


async def admin_sponsors(q):
    sponsors = DB.sponsors(False)
    lines = ["🤝 <b>مدیریت اسپانسرها</b>", ""]
    if not sponsors:
        lines.append("هنوز اسپانسری ثبت نشده است.")

    rows = []
    for s in sponsors:
        state = "🟢" if s["active"] else "⚪"
        lines.append(
            f"{state} <b>{esc(s['button_text'])}</b> | "
            f"{esc(s['style'])} | #{s['id']}"
        )
        rows.append([
            InlineKeyboardButton(
                f"✏️ #{s['id']}",
                callback_data=f"admin:sponsor:edit:{s['id']}",
                style="primary",
            ),
            InlineKeyboardButton(
                "🟢 فعال" if s["active"] else "⚪ غیرفعال",
                callback_data=f"admin:sponsor:toggle:{s['id']}",
                style="success" if s["active"] else "primary",
            ),
            InlineKeyboardButton(
                "🗑",
                callback_data=f"admin:sponsor:delete:{s['id']}",
                style="danger",
            ),
        ])

    rows.append([
        InlineKeyboardButton("➕ ساخت اسپانسر", callback_data="admin:sponsor:add", style="success")
    ])
    rows.append([
        InlineKeyboardButton("🔙 پنل", callback_data="admin:dashboard", style="primary")
    ])

    await q.message.edit_text(
        "\n".join(lines),
        parse_mode=ParseMode.HTML,
        reply_markup=InlineKeyboardMarkup(rows),
    )


# ============================================================
# Admin state: broadcast + sponsor wizard
# ============================================================

async def handle_admin_state(update, context):
    state = ADMIN_STATE.get(ADMIN_ID)
    if not state:
        return

    if state["type"] == "db_replace":
        doc = update.message.document
        work = Path(tempfile.mkstemp(prefix="pd-db-", suffix=".bin")[1])
        old_snapshot = DB_PATH.with_name("prodecryptor-before-replace.db")
        try:
            if not doc:
                raise RuntimeError("فایل دیتابیس ارسال نشده است")
            tg = await doc.get_file()
            await tg.download_to_drive(custom_path=str(work))
            with open(work, "rb") as f:
                header = f.read(16)
            if header != b"SQLite format 3\x00":
                raise RuntimeError("فایل SQLite معتبر نیست")
            test = sqlite3.connect(f"file:{work}?mode=ro", uri=True)
            try:
                ok = test.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            finally:
                test.close()
            if not ok:
                raise RuntimeError("بررسی سلامت دیتابیس ناموفق بود")

            # Make a consistent snapshot first; WAL pages are included.
            DB.snapshot(old_snapshot)
            DB.conn.close()
            DB.conn = None
            for suffix in ("-wal", "-shm"):
                Path(str(DB_PATH) + suffix).unlink(missing_ok=True)
            shutil.copy2(work, DB_PATH)
            try:
                DB.open()
            except Exception:
                # Never leave the bot without its previous working database.
                for suffix in ("-wal", "-shm"):
                    Path(str(DB_PATH) + suffix).unlink(missing_ok=True)
                shutil.copy2(old_snapshot, DB_PATH)
                DB.open()
                raise
            ADMIN_STATE.pop(ADMIN_ID, None)
            log.warning("Database replaced successfully from uploaded SQLite file: %s", doc.file_name)
            await update.message.reply_text("✅ دیتابیس با موفقیت و پس از بررسی سلامت جایگزین شد. نسخه قبلی هم برای بازیابی نگه داشته شد.", reply_markup=admin_menu())
        except Exception as exc:
            log.exception("database replacement failed")
            await update.message.reply_text(f"❌ جایگزینی انجام نشد؛ دیتابیس قبلی حفظ شد.\n{esc(str(exc))}", parse_mode=ParseMode.HTML, reply_markup=back_button("admin:database"))
        finally:
            work.unlink(missing_ok=True)
        return

    if state["type"] == "channel":
        if update.message.document:
            await update.message.reply_text("❌ این مرحله متن می‌خواهد.")
            return
        value = (update.message.text or "").strip()
        if state["step"] == "chat":
            try:
                chat = await context.bot.get_chat(value)
            except Exception as exc:
                await update.message.reply_text(f"❌ کانال پیدا نشد یا بات دسترسی ندارد.\n{esc(str(exc))}", parse_mode=ParseMode.HTML)
                return
            state["data"].update({"chat_id": chat.id, "title": chat.title or "", "username": chat.username or ""})
            state["step"] = "invite"
            await update.message.reply_text("مرحله 2 از 2\nلینک دعوت عمومی/خصوصی کانال را ارسال کن. برای کانال عمومی می‌توانی @username را بفرستی.")
            return
        if state["step"] == "invite":
            invite = value
            if invite.startswith("@"): invite = "https://t.me/" + invite[1:]
            if not invite.startswith(("https://t.me/", "http://t.me/")):
                await update.message.reply_text("❌ لینک باید از نوع t.me باشد.")
                return
            d = state["data"]
            DB.add_channel(d["chat_id"], d["title"], d["username"], invite)
            ADMIN_STATE.pop(ADMIN_ID, None)
            await update.message.reply_text("✅ کانال ثبت شد و از این پس عضویت کاربران بررسی می‌شود.", reply_markup=admin_menu())
            return

    if state["type"] == "captcha_custom":
        try:
            value = int((update.message.text or "").strip())
            if not 1 <= value <= 1000:
                raise ValueError
            DB.set_setting("captcha_interval", str(value))
            ADMIN_STATE.pop(ADMIN_ID, None)
            await update.message.reply_text(f"✅ ضد ربات روی هر {value} عملیات تنظیم شد.", reply_markup=admin_menu())
        except Exception:
            await update.message.reply_text("❌ عدد باید بین ۱ تا ۱۰۰۰ باشد.")
        return

    if state["type"] == "broadcast":
        text = update.message.text or ""
        ADMIN_STATE.pop(ADMIN_ID, None)

        users = DB.conn.execute(
            "SELECT user_id FROM users WHERE is_blocked=0"
        ).fetchall()

        sent = failed = 0
        status = await update.message.reply_text("📣 ارسال همگانی شروع شد...")
        for row in users:
            try:
                await context.bot.send_message(row["user_id"], text)
                sent += 1
            except (Forbidden, TelegramError):
                failed += 1
            await asyncio.sleep(0.03)

        await status.edit_text(
            f"📣 <b>ارسال تمام شد.</b>\n\n"
            f"✅ موفق: <b>{sent}</b>\n"
            f"❌ ناموفق: <b>{failed}</b>",
            parse_mode=ParseMode.HTML,
            reply_markup=admin_menu(),
        )
        return

    if state["type"] != "sponsor":
        return

    value = (update.message.text or "").strip()
    if not value:
        await update.message.reply_text("❌ مقدار خالی است.")
        return

    data = state["data"]
    step = state["step"]

    if step == "name":
        data["name"] = value
        state["step"] = "url"
        await update.message.reply_text(
            "مرحله 2 از 4\nلینک اسپانسر را ارسال کن."
        )
    elif step == "url":
        if not value.startswith(("https://", "http://", "tg://")):
            await update.message.reply_text("❌ لینک نامعتبر است.")
            return
        data["url"] = value
        state["step"] = "button"
        await update.message.reply_text("مرحله 3 از 4\nمتن دکمه را ارسال کن.")
    elif step == "button":
        if len(value) > 64:
            await update.message.reply_text("❌ متن دکمه حداکثر 64 کاراکتر است.")
            return
        data["button_text"] = value
        state["step"] = "style"
        await update.message.reply_text(
            "مرحله 4 از 4\nاستایل را انتخاب کن:",
            reply_markup=InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("🔵 Primary", callback_data="sponsorstyle:primary", style="primary"),
                    InlineKeyboardButton("🟢 Success", callback_data="sponsorstyle:success", style="success"),
                    InlineKeyboardButton("🔴 Danger", callback_data="sponsorstyle:danger", style="danger"),
                ],
                [InlineKeyboardButton("❎ لغو", callback_data="admin:cancel", style="danger")],
            ]),
        )


async def sponsor_style_callback(update, context):
    q = update.callback_query
    if q.from_user.id != ADMIN_ID:
        await q.answer("دسترسی ندارید.", show_alert=True)
        return
    await q.answer()

    state = ADMIN_STATE.get(ADMIN_ID)
    if not state or state.get("type") != "sponsor":
        return

    style = q.data.split(":", 1)[1]
    data = state["data"]

    if state["mode"] == "add":
        sid = DB.add_sponsor(
            data["name"], data["url"], data["button_text"], style, True
        )
        message = f"✅ اسپانسر #{sid} ساخته و فعال شد."
    else:
        DB.update_sponsor(
            state["sponsor_id"],
            data["name"], data["url"], data["button_text"], style
        )
        message = f"✅ اسپانسر #{state['sponsor_id']} بروزرسانی شد."

    ADMIN_STATE.pop(ADMIN_ID, None)

    await q.message.edit_text(
        message,
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🤝 مدیریت اسپانسرها", callback_data="admin:sponsors", style="primary")],
            [InlineKeyboardButton("🔙 پنل", callback_data="admin:dashboard", style="primary")],
        ]),
    )


# ============================================================
# Errors / lifecycle
# ============================================================

async def error_handler(update, context):
    log.exception("Unhandled exception", exc_info=context.error)


async def post_init(application):
    # Persistent storage survives Railway restarts/redeploys, so truncate
    # the engine-only log whenever a new bot process starts.
    reset_engine_log()
    DB.open()
    log.info("Database: %s", DB_PATH)
    log.info("Engine: %s", PANTEGNOS_BIN)


async def post_shutdown(application):
    for uid in list(USER_JOBS):
        cleanup_job(uid)
    DB.close()


def main():
    if not BOT_TOKEN:
        raise RuntimeError("BOT_TOKEN is not set")

    app = (
        Application.builder()
        .token(BOT_TOKEN)
        .post_init(post_init)
        .post_shutdown(post_shutdown)
        .build()
    )

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("admin", admin_command))
    app.add_handler(CommandHandler("cancel", cancel))

    app.add_handler(CallbackQueryHandler(access_callback, pattern=r"^access:"))
    app.add_handler(CallbackQueryHandler(menu_callback, pattern=r"^menu:"))
    app.add_handler(CallbackQueryHandler(result_callback, pattern=r"^result:"))
    app.add_handler(CallbackQueryHandler(admin_callback, pattern=r"^admin:"))
    app.add_handler(CallbackQueryHandler(sponsor_style_callback, pattern=r"^sponsorstyle:"))

    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    app.add_error_handler(error_handler)

    log.info("Starting %s v%s", APP_NAME, APP_VERSION)
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
