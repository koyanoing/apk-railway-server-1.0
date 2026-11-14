import json
import os
import re
import hashlib
import ast
import base64
import hmac
import importlib.machinery
import importlib.util
import secrets
import signal
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
import uuid
from functools import wraps
from pathlib import Path

from flask import Flask, g, jsonify, request

BASE = Path(__file__).parent.resolve()
DATA = BASE / "bots"
DATA.mkdir(exist_ok=True)

# ---- Settings (edit here) ----
PORT = 5000
SERVER_NAME = "my server"          # name shown in the admin Telegram message
LOCAL_API = False                  # True = also serve the HTTP API on HOST:PORT (not needed by the app)
HOST = "127.0.0.1"                 # local API address, only used if LOCAL_API is True
USE_TUNNEL = False                 # True = also open a cloudflared quick tunnel
NTFY = "https://ntfy.sh"           # relay server
API_KEY = ""                       # empty = generated once and saved in api_key.txt
ADMIN_BOT_TOKEN = "8837994471:AAGTMO33uOjJiXoXJ77qRjQ2nHD1y3A5ft8"               # optional: Telegram admin bot token from @BotFather
ADMIN_CHAT_ID = "8690698115"                 # optional: your own chat id from @userinfobot
USER_RAM_MB = 120                  # RAM each user may use, all of their bots together (admin: no limit)
USER_CPU = 0.5                     # CPU cores each user may use, all of their bots together (admin: no limit)
MAX_CODE = 300_000                 # biggest bot.py accepted, in characters

# API key: the one set above, otherwise generated once and saved in api_key.txt
KEY_FILE = BASE / "api_key.txt"
if not API_KEY:
    if KEY_FILE.exists():
        API_KEY = KEY_FILE.read_text().strip()
    else:
        API_KEY = secrets.token_urlsafe(24)
        KEY_FILE.write_text(API_KEY)
        os.chmod(KEY_FILE, 0o600)

# ---- Users: the admin key above, plus one key per user stored in users.json ----
USERS_FILE = BASE / "users.json"
USERS = {}  # user id -> {"name": ..., "key": ...}
users_lock = threading.RLock()


def load_users():
    try:
        USERS.update(json.loads(USERS_FILE.read_text()))
    except FileNotFoundError:
        pass
    except ValueError:
        print("users.json is damaged - ignoring it", flush=True)


def save_users():
    with users_lock:
        tmp = USERS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(USERS))
        os.chmod(tmp, 0o600)
        tmp.replace(USERS_FILE)


load_users()

app = Flask(__name__)
procs = {}      # bot id -> subprocess.Popen
owner_of = {}   # bot id -> id of the user who owns the running bot


def identify(token):
    """Whose key is this? None if nobody's."""
    if hmac.compare_digest(token.encode(), API_KEY.encode()):
        return {"uid": "admin", "name": "Admin", "role": "admin"}
    for uid, u in list(USERS.items()):
        if hmac.compare_digest(token.encode(), u["key"].encode()):
            return {"uid": uid, "name": u["name"], "role": "user"}
    return None


def auth(f):
    @wraps(f)
    def wrapper(*a, **kw):
        got = request.headers.get("Authorization", "")
        me = identify(got[7:]) if got.startswith("Bearer ") else None
        if not me:
            return jsonify(error="unauthorized"), 401
        g.me = me
        return f(*a, **kw)
    return wrapper


def admin_only(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if g.me["role"] != "admin":
            return jsonify(error="forbidden"), 403
        return f(*a, **kw)
    return wrapper


def can_access(meta, me):
    return me["role"] == "admin" or meta.get("owner", "admin") == me["uid"]


def owner_name(uid):
    if uid == "admin":
        return "Admin"
    u = USERS.get(uid)
    return u["name"] if u else "?"


def bot_dir(bid):
    if not re.fullmatch(r"[0-9a-f]{32}", bid):
        return None
    d = DATA / bid
    return d if d.is_dir() else None


def my_bot(bid):
    """The bot's folder, but only if the caller owns it (the admin may open
    any). For anyone else this is None and the route answers 404, so another
    user's bot can't even be told apart from one that doesn't exist."""
    d = bot_dir(bid)
    if not d or not (d / "meta.json").exists():
        return None
    try:
        return d if can_access(read_meta(d), g.me) else None
    except ValueError:
        return None


def read_meta(d):
    return json.loads((d / "meta.json").read_text())


def write_meta(d, meta):
    (d / "meta.json").write_text(json.dumps(meta))


def is_running(bid):
    p = procs.get(bid)
    return p is not None and p.poll() is None


def kill_orphan(d):
    """After a server restart the old bot process may still be alive; stop it
    so two copies never poll Telegram at once."""
    pf = d / "pid.txt"
    try:
        pid = int(pf.read_text().strip())
        cmd = Path(f"/proc/{pid}/cmdline").read_bytes()
        if b"bot.py" in cmd:
            os.kill(pid, 15)
            time.sleep(1)
    except Exception:
        pass
    try:
        pf.unlink()
    except FileNotFoundError:
        pass


# ---- Auto-install of packages a bot's code needs ----
# import name -> pip name, for packages where the two differ
PIP_NAMES = {
    "telegram": "python-telegram-bot",
    "telebot": "pyTelegramBotAPI",
    "PIL": "Pillow",
    "cv2": "opencv-python-headless",
    "yaml": "PyYAML",
    "bs4": "beautifulsoup4",
    "dotenv": "python-dotenv",
    "sklearn": "scikit-learn",
    "dateutil": "python-dateutil",
    "Crypto": "pycryptodome",
    "jwt": "PyJWT",
    "discord": "discord.py",
    "googleapiclient": "google-api-python-client",
    "serial": "pyserial",
    "attr": "attrs",
    "magic": "python-magic",
    "docx": "python-docx",
    "fitz": "PyMuPDF",
    "aiogram": "aiogram",
    "pyrogram": "pyrogram",
    "telethon": "Telethon",
}
STDLIB = getattr(sys, "stdlib_module_names", set())


# ---- Packages that are never installed ----
# import name -> name shown to the user
BLOCKED_MODULES = {"cv2": "opencv-python", "numpy": "numpy", "ddddocr": "ddddocr"}
BLOCKED_PIP = {"opencv-python", "opencv-python-headless", "opencv-contrib-python",
               "opencv-contrib-python-headless", "numpy", "ddddocr"}
BLOCKED_DIRS = {"numpy", "cv2", "opencv", "ddddocr"}  # first word of their folder names


def is_blocked_pip(name):
    base = re.split(r"[<>=!~\[;\s]", name, maxsplit=1)[0]
    return re.sub(r"[-_.]+", "-", base).lower() in BLOCKED_PIP


def imported_names(d):
    """Top-level module names bot.py imports, or None if it can't be parsed."""
    try:
        tree = ast.parse((d / "bot.py").read_text())
    except (SyntaxError, ValueError, OSError):
        return None
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
    return names


_blocked_cache = {}


def blocked_in_code(d):
    """Blocked packages that bot.py imports (cached until the file changes)."""
    f = d / "bot.py"
    try:
        mt = f.stat().st_mtime_ns
    except OSError:
        return []
    hit = _blocked_cache.get(str(f))
    if hit and hit[0] == mt:
        return hit[1]
    res = sorted({BLOCKED_MODULES[n] for n in (imported_names(d) or ()) if n in BLOCKED_MODULES})
    _blocked_cache[str(f)] = (mt, res)
    return res


def purge_blocked(libs, log):
    """Delete blocked packages that arrived as a dependency of something else."""
    removed = []
    try:
        for p in libs.iterdir():
            first = re.split(r"[-.]", p.name.lower().replace("_", "-"))[0]
            if first in BLOCKED_DIRS:
                if p.is_dir():
                    shutil.rmtree(p, ignore_errors=True)
                else:
                    p.unlink()
                removed.append(p.name)
    except Exception:
        return
    if removed:
        log.write(b"--- removed blocked packages that came in as a dependency ---\n")
        log.flush()


def needed_packages(d):
    """Parse bot.py and return pip names for imports that aren't stdlib,
    aren't files in the bot's own folder, and aren't installed yet.
    Blocked packages are never returned."""
    names = imported_names(d)
    if names is None:
        return []  # let the bot itself report the syntax error in its log
    libs = d / "libs"
    missing = []
    for n in sorted(names):
        if n in STDLIB or n == "__future__" or n in BLOCKED_MODULES:
            continue
        if (d / f"{n}.py").exists() or (d / n).is_dir():
            continue  # the bot's own module
        try:
            if importlib.util.find_spec(n) is not None:
                continue  # already available to the server's Python
        except (ImportError, ValueError):
            pass
        if libs.is_dir() and importlib.machinery.PathFinder.find_spec(n, [str(libs)]):
            continue  # installed earlier for this bot
        missing.append(PIP_NAMES.get(n, n))
    return missing


installing = set()   # bot ids whose packages are being installed right now
starting = set()     # bot ids that are installing or launching (not yet running)
cancelled = set()    # bot ids stopped while still starting
started_at = {}      # bot id -> time the process was launched


def pip_install(pkg, libs, log):
    """Install one package into the bot's libs/ folder. Returns True on success."""
    if is_blocked_pip(pkg):
        log.write(f"--- {pkg} is blocked and will never be installed ---\n".encode())
        log.flush()
        return False
    log.write(f"--- installing {pkg} ---\n".encode())
    log.flush()
    try:
        r = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--disable-pip-version-check",
             "--no-input", "--target", str(libs), pkg],
            stdout=log, stderr=subprocess.STDOUT, timeout=300,
        )
        if r.returncode != 0:
            log.write(f"--- could not install {pkg} ---\n".encode())
        log.flush()
        return r.returncode == 0
    except Exception as e:
        log.write(f"--- install of {pkg} failed: {e} ---\n".encode())
        log.flush()
        return False


def install_packages(d, log, bid, extra=()):
    """Install whatever bot.py imports but isn't installed yet (plus any extra
    packages), one at a time so a single failure doesn't block the rest. Goes
    into the bot's own libs/ folder so bots never clash on versions."""
    pkgs = [p for p in dict.fromkeys(list(extra) + needed_packages(d)) if not is_blocked_pip(p)]
    if not pkgs:
        return
    libs = d / "libs"
    libs.mkdir(exist_ok=True)
    installing.add(bid)
    try:
        for pkg in pkgs:
            if bid in cancelled:
                return
            pip_install(pkg, libs, log)
    finally:
        installing.discard(bid)


def launch_bot(bid, d, retries=0, tried=frozenset(), extra=()):
    """Runs in a background thread: install what's missing, then start bot.py.
    Doing this off the request thread keeps the app responsive while pip works."""
    proc = None
    log_pos = 0
    try:
        if not d.is_dir():
            return
        kill_orphan(d)
        meta = read_meta(d)
        env = os.environ.copy()
        env.pop("API_KEY", None)  # don't hand the server key to bot code
        env["BOT_TOKEN"] = meta["token"]
        owner_of[bid] = meta.get("owner", "admin")
        logf = d / "log.txt"
        if logf.exists() and logf.stat().st_size > 1_000_000:
            logf.write_bytes(logf.read_bytes()[-200_000:])
        with open(logf, "ab") as log:
            log.write(b"\n--- starting ---\n")
            log.flush()
            install_packages(d, log, bid, extra)
            if (d / "libs").is_dir():
                purge_blocked(d / "libs", log)
        if bid in cancelled or not d.is_dir():
            return
        libs = d / "libs"
        if libs.is_dir():
            env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(libs), env.get("PYTHONPATH")]))
        log_pos = logf.stat().st_size
        with open(logf, "ab") as log:
            proc = subprocess.Popen(
                [sys.executable, "-u", "bot.py"],
                cwd=d, env=env, stdout=log, stderr=subprocess.STDOUT,
                start_new_session=True,  # own process group: the limiter can pause / kill it as a unit
            )
        procs[bid] = proc
        started_at[bid] = time.time()
        (d / "pid.txt").write_text(str(proc.pid))
    except Exception as e:
        try:
            with open(d / "log.txt", "ab") as log:
                log.write(f"--- could not start: {e} ---\n".encode())
        except Exception:
            pass
        proc = None
    finally:
        starting.discard(bid)
        cancelled.discard(bid)
    if proc is not None:
        threading.Thread(target=watch_bot, args=(bid, d, proc, log_pos, retries, tried),
                         daemon=True).start()


def watch_bot(bid, d, proc, log_pos, retries, tried):
    """If the bot dies because a module is missing (e.g. a dynamic import the
    scan can't see), install that module and start the bot again."""
    proc.wait()
    if procs.get(bid) is not proc:
        return  # stopped by the user, or replaced by a newer start
    if proc.returncode == 0 or retries >= 5 or not d.is_dir():
        return
    try:
        with open(d / "log.txt", "rb") as f:
            f.seek(log_pos)
            tail = f.read().decode("utf-8", "replace")
    except Exception:
        return
    found = re.findall(r"No module named '([\w.\-]+)'", tail)
    if not found:
        return
    mod = found[-1].split(".")[0]
    if mod in BLOCKED_MODULES:
        try:
            with open(d / "log.txt", "ab") as log:
                log.write(f"--- '{mod}' is blocked and is never installed on this server ---\n".encode())
        except Exception:
            pass
        return
    pkg = PIP_NAMES.get(mod, mod)
    if pkg in tried or mod in STDLIB or (d / f"{mod}.py").exists() or (d / mod).is_dir():
        return
    if bid in starting or is_running(bid):
        return
    starting.add(bid)
    try:
        with open(d / "log.txt", "ab") as log:
            log.write(f"--- missing module '{mod}': installing {pkg} and restarting ---\n".encode())
    except Exception:
        pass
    launch_bot(bid, d, retries + 1, frozenset(tried) | {pkg}, extra=(pkg,))


def start_bot(bid, d):
    if is_running(bid) or bid in starting:
        return
    bl = blocked_in_code(d)
    if bl:
        try:
            with open(d / "log.txt", "ab") as log:
                log.write(("--- NOT STARTED: bot.py uses " + ", ".join(bl) + ". These packages are "
                           "never installed on this server. Remove them and upload the file again. ---\n").encode())
        except Exception:
            pass
        return
    cancelled.discard(bid)
    starting.add(bid)
    threading.Thread(target=launch_bot, args=(bid, d), daemon=True).start()


def killgroup(pid, sig):
    try:
        os.killpg(pid, sig)
    except Exception:
        pass


def stop_bot(bid):
    if bid in starting:
        cancelled.add(bid)  # the launch thread notices and gives up
    d = bot_dir(bid)
    p = procs.pop(bid, None)
    started_at.pop(bid, None)
    owner_of.pop(bid, None)
    if p and p.poll() is None:
        killgroup(p.pid, signal.SIGCONT)  # the CPU limiter may have it paused
    if d:
        kill_orphan(d)
    if p and p.poll() is None:
        killgroup(p.pid, signal.SIGTERM)
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            killgroup(p.pid, signal.SIGKILL)
            p.kill()


@app.get("/api/ping")
@auth
def ping():
    return jsonify(ok=True, role=g.me["role"], name=g.me["name"],
                   ram_mb=USER_RAM_MB, cpu=USER_CPU)


def bot_info(d, m):
    bid = d.name
    st = STATS.get("bots", {}).get(bid, {})
    return {"id": bid, "name": m["name"], "owner": owner_name(m.get("owner", "admin")),
            "running": is_running(bid), "starting": bid in starting,
            "installing": bid in installing, "blocked": blocked_in_code(d),
            "cpu": st.get("cpu"), "mem": st.get("mem")}


def visible_bots():
    """(folder, meta) of every bot the caller may see: their own, or all for the admin."""
    out = []
    for d in DATA.iterdir():
        if (d / "meta.json").exists():
            try:
                m = read_meta(d)
            except ValueError:
                continue
            if can_access(m, g.me):
                out.append((d, m))
    return out


@app.get("/api/bots")
@auth
def list_bots():
    out = [bot_info(d, m) for d, m in visible_bots()]
    out.sort(key=lambda b: b["name"].lower())
    return jsonify(out)


@app.post("/api/bots")
@auth
def create_bot():
    body = request.get_json(silent=True) or {}
    bid = uuid.uuid4().hex
    d = DATA / bid
    d.mkdir()
    write_meta(d, {"name": str(body.get("name") or "My bot")[:60],
                   "token": str(body.get("token", "")), "owner": g.me["uid"]})
    (d / "bot.py").write_text("")
    return jsonify(id=bid)


@app.get("/api/bots/<bid>")
@auth
def get_bot(bid):
    d = my_bot(bid)
    if not d:
        return jsonify(error="not found"), 404
    m = read_meta(d)
    return jsonify(name=m["name"], token=m["token"],
                   size=(d / "bot.py").stat().st_size, blocked=blocked_in_code(d))


@app.put("/api/bots/<bid>")
@auth
def update_bot(bid):
    d = my_bot(bid)
    if not d:
        return jsonify(error="not found"), 404
    body = request.get_json(silent=True) or {}
    code = body.get("code")
    if code is not None and (not isinstance(code, str) or len(code) > MAX_CODE):
        return jsonify(error="file too large"), 400
    m = read_meta(d)
    if "name" in body:
        m["name"] = str(body["name"])[:60]
    if "token" in body:
        m["token"] = str(body["token"])
    write_meta(d, m)
    if code is not None:
        (d / "bot.py").write_text(code)
    return jsonify(ok=True, blocked=blocked_in_code(d))


@app.delete("/api/bots/<bid>")
@auth
def delete_bot(bid):
    d = my_bot(bid)
    if not d:
        return jsonify(error="not found"), 404
    stop_bot(bid)
    kill_orphan(d)
    shutil.rmtree(d, ignore_errors=True)
    return jsonify(ok=True)


@app.post("/api/bots/<bid>/<action>")
@auth
def control(bid, action):
    d = my_bot(bid)
    if not d:
        return jsonify(error="not found"), 404
    if action == "start":
        start_bot(bid, d)
    elif action == "stop":
        stop_bot(bid)
    elif action == "restart":
        stop_bot(bid)
        start_bot(bid, d)
    else:
        return jsonify(error="bad action"), 400
    blocked = blocked_in_code(d)
    return jsonify(ok=not blocked or action == "stop",
                   running=is_running(bid) or bid in starting, blocked=blocked)


@app.get("/api/bots/<bid>/logs")
@auth
def logs(bid):
    d = my_bot(bid)
    if not d:
        return jsonify(error="not found"), 404
    f = d / "log.txt"
    text = f.read_bytes()[-20000:].decode("utf-8", "replace") if f.exists() else ""
    st = STATS.get("bots", {}).get(bid, {})
    up = int(time.time() - started_at[bid]) if is_running(bid) and bid in started_at else None
    return jsonify(running=is_running(bid), starting=bid in starting,
                   installing=bid in installing, log=text, blocked=blocked_in_code(d),
                   cpu=st.get("cpu"), mem=st.get("mem"), uptime=up)


@app.get("/api/overview")
@auth
def overview():
    """Everything the home screen needs in one call. The admin gets every bot and
    the server's CPU / RAM / disk; a user gets only their own bots and their own
    quota usage (nothing about the server or other users)."""
    bots = [bot_info(d, m) for d, m in visible_bots()]
    bots.sort(key=lambda b: b["name"].lower())
    if g.me["role"] == "admin":
        stats = {k: v for k, v in STATS.items() if k != "bots"}
    else:
        u = USAGE.get(g.me["uid"]) or {"cpu": 0.0, "ram": 0.0}
        stats = {"cpu": u["cpu"], "cores": USER_CPU, "mem_used": u["ram"],
                 "mem_total": USER_RAM_MB, "disk_used": None, "disk_total": None}
    stats["uptime"] = int(time.time() - START_TS)
    return jsonify(bots=bots, stats=stats)


# ---- Users (admin only) ----
@app.get("/api/users")
@auth
@admin_only
def list_users():
    count = {}
    for d in DATA.iterdir():
        if (d / "meta.json").exists():
            try:
                uid = read_meta(d).get("owner", "admin")
            except ValueError:
                continue
            c = count.setdefault(uid, [0, 0])
            c[0] += 1
            c[1] += 1 if is_running(d.name) else 0
    out = [{"id": uid, "name": u["name"], "key": u["key"],
            "bots": count.get(uid, [0, 0])[0], "running": count.get(uid, [0, 0])[1]}
           for uid, u in list(USERS.items())]
    out.sort(key=lambda u: u["name"].lower())
    return jsonify(users=out, ram_mb=USER_RAM_MB, cpu=USER_CPU)


@app.post("/api/users")
@auth
@admin_only
def create_user():
    name = str((request.get_json(silent=True) or {}).get("name", "")).strip()[:40]
    if not name:
        return jsonify(error="name required"), 400
    uid, key = uuid.uuid4().hex[:12], secrets.token_urlsafe(24)
    with users_lock:
        USERS[uid] = {"name": name, "key": key}
        save_users()
    start_user_relay(key)
    return jsonify(id=uid, key=key)


@app.delete("/api/users/<uid>")
@auth
@admin_only
def delete_user(uid):
    with users_lock:
        u = USERS.pop(uid, None)
        if u:
            save_users()
    if not u:
        return jsonify(error="not found"), 404
    stop_user_relay(u["key"])
    for d in list(DATA.iterdir()):
        if (d / "meta.json").exists():
            try:
                mine = read_meta(d).get("owner", "admin") == uid
            except ValueError:
                continue
            if mine:
                stop_bot(d.name)
                kill_orphan(d)
                shutil.rmtree(d, ignore_errors=True)
    USAGE.pop(uid, None)
    return jsonify(ok=True)


def topic():
    return "bh-" + hashlib.sha256(API_KEY.encode()).hexdigest()[:32]


def publish_url(url):
    """Publish the current tunnel link so the app can find it by itself."""
    try:
        req = urllib.request.Request(f"https://ntfy.sh/{topic()}", data=url.encode(), method="POST")
        urllib.request.urlopen(req, timeout=10).read()
    except Exception as e:
        print("Could not publish link:", e, flush=True)


# ---- Resource monitor (reads /proc and cgroups; no extra packages) ----
START_TS = time.time()
STATS = {"cpu": None, "cores": os.cpu_count() or 1, "mem_used": None, "mem_total": None,
         "disk_used": None, "disk_total": None, "load": None, "bots": {}}


def _read(path):
    try:
        return Path(path).read_text().strip()
    except Exception:
        return None


def cgroup_cpu():
    """(cpu seconds used, cores available) from the container's cgroup, if any."""
    t = _read("/sys/fs/cgroup/cpu.stat")  # cgroup v2
    if t:
        for line in t.splitlines():
            if line.startswith("usage_usec"):
                cores = os.cpu_count() or 1
                mx = _read("/sys/fs/cgroup/cpu.max")
                if mx and mx.split()[0] != "max":
                    cores = int(mx.split()[0]) / int(mx.split()[1])
                return int(line.split()[1]) / 1e6, cores
    u = _read("/sys/fs/cgroup/cpuacct/cpuacct.usage")  # cgroup v1
    if u:
        cores = os.cpu_count() or 1
        q = _read("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
        per = _read("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
        if q and per and int(q) > 0:
            cores = int(q) / int(per)
        return int(u) / 1e9, cores
    return None


def proc_stat_cpu():
    """(busy ticks, total ticks) for the whole machine."""
    line = (_read("/proc/stat") or "").splitlines()[0].split()[1:]
    vals = [int(x) for x in line[:8]]
    return sum(vals) - vals[3] - vals[4], sum(vals)


def mem_info():
    """(used bytes, total bytes) - the container's limit when there is one."""
    cur, mx = _read("/sys/fs/cgroup/memory.current"), _read("/sys/fs/cgroup/memory.max")
    if cur and mx and mx != "max":
        used = int(cur)
        for line in (_read("/sys/fs/cgroup/memory.stat") or "").splitlines():
            if line.startswith("inactive_file "):
                used -= int(line.split()[1])  # reclaimable cache isn't "used"
        return max(used, 0), int(mx)
    cur = _read("/sys/fs/cgroup/memory/memory.usage_in_bytes")
    mx = _read("/sys/fs/cgroup/memory/memory.limit_in_bytes")
    if cur and mx and int(mx) < (1 << 50):
        return int(cur), int(mx)
    info = {}
    for line in (_read("/proc/meminfo") or "").splitlines():
        k, _, v = line.partition(":")
        info[k] = int(v.split()[0]) * 1024
    if "MemTotal" in info:
        return info["MemTotal"] - info.get("MemAvailable", info.get("MemFree", 0)), info["MemTotal"]
    return None, None


def bot_usage(pid):
    """(cpu ticks, rss bytes) for one process."""
    data = Path(f"/proc/{pid}/stat").read_text()
    rest = data[data.rindex(")") + 2:].split()
    ticks = int(rest[11]) + int(rest[12])
    rss = int((Path(f"/proc/{pid}/statm").read_text().split())[1]) * os.sysconf("SC_PAGE_SIZE")
    return ticks, rss


def stats_loop():
    global STATS
    try:
        clk = os.sysconf("SC_CLK_TCK")
    except Exception:
        clk = 100
    prev_t = prev_cg = prev_ps = None
    prev_bots = {}
    while True:
        try:
            now = time.time()
            s = {"cores": os.cpu_count() or 1, "cpu": None}
            cg = cgroup_cpu()
            if cg:
                s["cores"] = round(cg[1], 2)
                if prev_cg is not None and now > prev_t:
                    s["cpu"] = (cg[0] - prev_cg) / (now - prev_t) / cg[1] * 100
                prev_cg = cg[0]
            else:
                busy, total = proc_stat_cpu()
                if prev_ps and total > prev_ps[1]:
                    s["cpu"] = (busy - prev_ps[0]) / (total - prev_ps[1]) * 100
                prev_ps = (busy, total)
            if s["cpu"] is not None:
                s["cpu"] = round(max(0.0, min(100.0, s["cpu"])), 1)
            used, total_mem = mem_info()
            s["mem_used"] = round(used / 1048576, 1) if used is not None else None
            s["mem_total"] = round(total_mem / 1048576, 1) if total_mem else None
            try:
                du = shutil.disk_usage(BASE)
                s["disk_used"], s["disk_total"] = round(du.used / 1073741824, 2), round(du.total / 1073741824, 2)
            except Exception:
                s["disk_used"] = s["disk_total"] = None
            try:
                s["load"] = round(os.getloadavg()[0], 2)
            except Exception:
                s["load"] = None
            bots = {}
            for bid, p in list(procs.items()):
                if p.poll() is None:
                    try:
                        ticks, rss = bot_usage(p.pid)
                        cpu = None
                        if bid in prev_bots and now > prev_t:
                            cpu = round(max(0.0, (ticks - prev_bots[bid]) / clk / (now - prev_t) * 100), 1)
                        prev_bots[bid] = ticks
                        bots[bid] = {"cpu": cpu, "mem": round(rss / 1048576, 1)}
                    except Exception:
                        pass
            for bid in list(prev_bots):
                if bid not in bots:
                    del prev_bots[bid]
            s["bots"] = bots
            STATS = s
            prev_t = now
        except Exception as e:
            print("Stats error:", e, flush=True)
        time.sleep(3)


# ---- Per-user limits: RAM and CPU for all of one user's bots together ----
# RAM: if a user's bots use more than USER_RAM_MB, the biggest one is killed.
# CPU: each second a user may burn USER_CPU * 1 s of CPU time; once that is used
#      up their bots are paused (SIGSTOP) until the second is over (SIGCONT).
# The admin's own bots are not limited. Needs Linux (/proc).
USAGE = {}  # user id -> {"cpu": % of their CPU quota, "ram": MB}


def scan_procs():
    """pid -> (session id, cpu ticks, rss pages) for every process."""
    out = {}
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            data = Path(f"/proc/{name}/stat").read_text()
            rest = data[data.rindex(")") + 2:].split()
            out[int(name)] = (int(rest[3]), int(rest[11]) + int(rest[12]), int(rest[21]))
        except Exception:
            continue
    return out


def limiter_loop():
    try:
        clk = os.sysconf("SC_CLK_TCK")
        page = os.sysconf("SC_PAGE_SIZE")
    except Exception:
        clk, page = 100, 4096
    window = 1.0
    last = {}   # pid -> cpu ticks seen last time
    st = {}     # user id -> window state
    while True:
        time.sleep(0.1)
        try:
            groups = {}  # user id -> {bot id: process group id}
            for bid, p in list(procs.items()):
                uid = owner_of.get(bid, "admin")
                if uid != "admin" and p.poll() is None:
                    groups.setdefault(uid, {})[bid] = p.pid
            for uid in [u for u in st if u not in groups]:
                del st[uid]
            if not groups:
                last.clear()
                time.sleep(0.4)
                continue
            snap = scan_procs()
            now = time.time()
            seen = {}
            for uid, bots in groups.items():
                s_ = st.setdefault(uid, {"start": now, "used": 0, "stopped": False})
                by_sid = {pid: bid for bid, pid in bots.items()}
                rss = {bid: 0 for bid in bots}
                for pid, (sid, ticks, pages) in snap.items():
                    bid = by_sid.get(sid)
                    if bid is None:
                        continue
                    seen[pid] = ticks
                    s_["used"] += max(0, ticks - last.get(pid, 0))
                    rss[bid] += pages * page
                ram_mb = sum(rss.values()) / 1048576
                if ram_mb > USER_RAM_MB:
                    big = max(rss, key=rss.get)
                    msg = (f"--- STOPPED: memory limit exceeded ({ram_mb:.0f} MB used, "
                           f"limit {USER_RAM_MB} MB for all your bots together) ---\n")
                    try:
                        with open(DATA / big / "log.txt", "ab") as log:
                            log.write(msg.encode())
                    except Exception:
                        pass
                    killgroup(bots[big], signal.SIGCONT)
                    killgroup(bots[big], signal.SIGKILL)
                if not s_["stopped"] and s_["used"] >= USER_CPU * clk * window:
                    for pid in bots.values():
                        killgroup(pid, signal.SIGSTOP)
                    s_["stopped"] = True
                if now - s_["start"] >= window:
                    cores = s_["used"] / clk / (now - s_["start"])
                    USAGE[uid] = {"cpu": round(min(100.0, cores / USER_CPU * 100), 1),
                                  "ram": round(ram_mb, 1)}
                    if s_["stopped"]:
                        for pid in bots.values():
                            killgroup(pid, signal.SIGCONT)
                        s_["stopped"] = False
                    s_["used"], s_["start"] = 0, now
            last = seen
        except Exception as e:
            print("Limiter error:", e, flush=True)
            time.sleep(1)


# ---- Admin Telegram bot (optional) ----
# Fill ADMIN_BOT_TOKEN and ADMIN_CHAT_ID in the Settings block at the top to
# get a message when the server comes online and to be able to message the
# bot "/key" any time to get the key back. Leave both empty to turn this off.
ADMIN_BOT_TOKEN = ADMIN_BOT_TOKEN or None
ADMIN_CHAT_ID = ADMIN_CHAT_ID or None

current_url = None  # last tunnel link start_tunnel() found, for /key replies


def notify_admin(text):
    """Send a one-off message to the admin's own Telegram chat, e.g. on startup.
    Set ADMIN_BOT_TOKEN (from @BotFather) and ADMIN_CHAT_ID to enable this;
    it's a no-op if either is missing. This never touches ntfy.sh, which keeps
    publishing the tunnel link for the app as before."""
    if not ADMIN_BOT_TOKEN or not ADMIN_CHAT_ID:
        return
    try:
        url = f"https://api.telegram.org/bot{ADMIN_BOT_TOKEN}/sendMessage"
        data = json.dumps({"chat_id": ADMIN_CHAT_ID, "text": text}).encode()
        req = urllib.request.Request(url, data=data, method="POST",
                                      headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10).read()
    except Exception as e:
        print("Could not notify admin bot:", e, flush=True)


def poll_admin_bot():
    """Lets the admin pull the key on demand: message the admin bot /key (or
    /status) in Telegram and it replies with the current key and URL. Only
    replies to ADMIN_CHAT_ID, so someone else messaging the bot gets nothing
    back. No-op if ADMIN_BOT_TOKEN/ADMIN_CHAT_ID aren't set."""
    if not ADMIN_BOT_TOKEN or not ADMIN_CHAT_ID:
        return
    base = f"https://api.telegram.org/bot{ADMIN_BOT_TOKEN}"
    offset = 0
    while True:
        try:
            url = f"{base}/getUpdates?timeout=30&offset={offset}"
            with urllib.request.urlopen(url, timeout=40) as r:
                data = json.loads(r.read())
            for upd in data.get("result", []):
                offset = upd["update_id"] + 1
                msg = upd.get("message") or {}
                chat_id = str((msg.get("chat") or {}).get("id") or "")
                if chat_id != str(ADMIN_CHAT_ID):
                    continue  # ignore anyone who isn't the admin
                text = (msg.get("text") or "").strip().lower()
                if text in ("/key", "/status", "key", "status"):
                    where = current_url or f"no tunnel (listening on port {PORT})"
                    notify_admin(f"Key: {API_KEY}\nURL: {where}")
        except Exception as e:
            print("Admin bot poll error:", e, flush=True)
            time.sleep(5)


def start_tunnel():
    exe = shutil.which("cloudflared")
    if not exe:
        print("cloudflared not found. Install it first.")
        return False
    p = subprocess.Popen(
        [exe, "tunnel", "--url", f"http://127.0.0.1:{PORT}", "--no-autoupdate"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )

    def republish(url):
        while p.poll() is None:
            publish_url(url)
            time.sleep(1800)

    def watch():
        announced = False
        for line in p.stdout:
            m = re.search(r"https://[\w-]+\.trycloudflare\.com", line)
            if m and not announced:
                announced = True
                global current_url
                current_url = m.group(0)
                print("\n=== Enter this key in the app (only once) ===")
                print(API_KEY)
                print("==============================================\n", flush=True)
                name = SERVER_NAME
                notify_admin(f"{name} is online.\nKey: {API_KEY}\nURL: {current_url}")
                threading.Thread(target=republish, args=(current_url,), daemon=True).start()

    threading.Thread(target=watch, daemon=True).start()
    return True


# ---- Relay: control this server through ntfy.sh ----
# No tunnel, domain or open port needed. The server only makes outbound HTTPS
# calls (like a Telegram bot does). The app sends encrypted requests to one
# ntfy topic, the server answers on another. Everything is AES-GCM encrypted
# with a key derived from API_KEY, so ntfy.sh only ever sees ciphertext and
# nobody without the key can send commands.
NTFY = NTFY.rstrip("/")
CHUNK = 3000       # ntfy messages are limited to ~4 KB, so big payloads are split
MAX_AGE = 120      # requests older than this (seconds) are ignored (anti-replay)
_aes = {}          # key -> AESGCM
_seen = {}         # (key, request id) -> time handled
_partial = {}      # (key, request id) -> chunks received so far
relays = {}        # key -> Event that stops that key's listener
# Every key (the admin's and each user's) has its own pair of ntfy topics and its
# own encryption key, so a user can only ever talk to the server as themselves.


def relay_topic(kind, key):
    return "bh" + kind + "-" + hashlib.sha256(f"{kind}:{key}".encode()).hexdigest()[:32]


def get_aes(key):
    if key not in _aes:
        try:
            import cryptography  # noqa: F401
        except ImportError:
            print("Installing 'cryptography' ...", flush=True)
            subprocess.run([sys.executable, "-m", "pip", "install",
                            "--disable-pip-version-check", "cryptography"])
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        k = HKDF(algorithm=hashes.SHA256(), length=32,
                 salt=b"bh-relay-v1", info=b"aes-key").derive(key.encode())
        _aes[key] = AESGCM(k)
    return _aes[key]


def seal(obj, tag, key):
    nonce = os.urandom(12)
    ct = get_aes(key).encrypt(nonce, json.dumps(obj).encode(), tag)
    return base64.urlsafe_b64encode(nonce + ct).decode()


def unseal(text, tag, key):
    raw = base64.urlsafe_b64decode(text.encode())
    return json.loads(get_aes(key).decrypt(raw[:12], raw[12:], tag))


def ntfy_post(topic, text):
    for attempt in range(3):
        try:
            req = urllib.request.Request(f"{NTFY}/{topic}", data=text.encode(), method="POST")
            urllib.request.urlopen(req, timeout=15).read()
            return True
        except Exception as e:
            print("ntfy post failed:", e, flush=True)
            time.sleep(2 * (attempt + 1))
    return False


def send_response(rid, obj, key):
    packet = seal(obj, b"r", key)
    parts = [packet[i:i + CHUNK] for i in range(0, len(packet), CHUNK)] or [""]
    for idx, part in enumerate(parts):
        ntfy_post(relay_topic("r", key),
                  json.dumps({"i": rid, "p": idx, "t": len(parts), "d": part}))
        time.sleep(0.2)


def process_request(rid, req, key):
    """Run an app request through the normal Flask routes, signed with the key it
    arrived on, so the relay and the HTTP API always behave (and check access) the same."""
    try:
        method = str(req.get("method", "GET")).upper()
        path = str(req.get("path", ""))
        if method not in ("GET", "POST", "PUT", "DELETE") or not path.startswith("/api/"):
            out = {"id": rid, "status": 400, "data": {"error": "bad request"}}
        else:
            kw = {"headers": {"Authorization": f"Bearer {key}"}}
            if req.get("body") is not None:
                kw["json"] = req["body"]
            resp = app.test_client().open(path, method=method, **kw)
            out = {"id": rid, "status": resp.status_code, "data": resp.get_json(silent=True)}
    except Exception as e:
        out = {"id": rid, "status": 500, "data": {"error": str(e)}}
    send_response(rid, out, key)


def handle_packet(message, key):
    try:
        m = json.loads(message)
        rid, idx, total, data = str(m["i"]), int(m["p"]), int(m["t"]), m["d"]
    except Exception:
        return
    if not re.fullmatch(r"[A-Za-z0-9_-]{6,64}", rid) or not 1 <= total <= 200 or not 0 <= idx < total:
        return
    now = time.time()
    for k in [k for k, v in _partial.items() if now - v["ts"] > MAX_AGE]:
        del _partial[k]
    for k in [k for k, t in _seen.items() if now - t > MAX_AGE * 2]:
        del _seen[k]
    sk = (key, rid)
    if sk in _seen:
        return
    buf = _partial.setdefault(sk, {"t": total, "parts": {}, "ts": now})
    if buf["t"] != total:
        return
    buf["parts"][idx] = data
    if len(buf["parts"]) < buf["t"]:
        return
    del _partial[sk]
    try:
        req = unseal("".join(buf["parts"][i] for i in range(buf["t"])), b"q", key)
        if abs(now - float(req.get("ts", 0))) > MAX_AGE:
            return  # too old / replayed
    except Exception:
        return  # wrong key, tampered, or garbage: ignore silently
    _seen[sk] = now
    threading.Thread(target=process_request, args=(rid, req, key), daemon=True).start()


def relay_loop(key, stop):
    since = "30s"  # also pick up a command sent just before the server started
    while not stop.is_set():
        try:
            with urllib.request.urlopen(f"{NTFY}/{relay_topic('q', key)}/json?since={since}",
                                        timeout=100) as r:
                for raw in r:
                    if stop.is_set():
                        break
                    try:
                        ev = json.loads(raw)
                    except ValueError:
                        continue
                    if ev.get("event") != "message":
                        continue
                    since = str(ev.get("time", since))
                    handle_packet(ev.get("message", ""), key)
        except Exception as e:
            print("Relay reconnecting:", e, flush=True)
            time.sleep(5)
        else:
            time.sleep(1)


def start_user_relay(key):
    if key in relays:
        return
    stop = threading.Event()
    relays[key] = stop
    threading.Thread(target=relay_loop, args=(key, stop), daemon=True).start()


def stop_user_relay(key):
    stop = relays.pop(key, None)
    if stop:
        stop.set()


def start_relay():
    try:
        get_aes(API_KEY)
    except Exception as e:
        print("Relay disabled (could not load 'cryptography'):", e, flush=True)
        return False
    start_user_relay(API_KEY)
    for u in list(USERS.values()):
        start_user_relay(u["key"])
    return True


if __name__ == "__main__":
    # The relay (ntfy.sh) is the way the app reaches this server: it only needs
    # outbound HTTPS. The local HTTP API is off by default, so a busy port can
    # never stop the server. Set USE_TUNNEL = True to also open a cloudflared
    # quick tunnel (that needs the local API).
    use_local = LOCAL_API or USE_TUNNEL
    tunnel = USE_TUNNEL and start_tunnel()
    threading.Thread(target=stats_loop, daemon=True).start()
    threading.Thread(target=limiter_loop, daemon=True).start()
    relay = start_relay()
    name = SERVER_NAME
    print(f"\n=== Enter this key in the app ===\n{API_KEY}\n=================================")
    print(f"Relay: {'on' if relay else 'OFF'}   Tunnel: {'on' if tunnel else 'off'}   "
          f"Local API: {f'http://{HOST}:{PORT}' if use_local else 'off'}\n", flush=True)
    if not tunnel:
        notify_admin(f"{name} is online (relay {'on' if relay else 'off'}).\nKey: {API_KEY}")
    threading.Thread(target=poll_admin_bot, daemon=True).start()
    if use_local:
        try:
            app.run(host=HOST, port=PORT, threaded=True)
        except (OSError, SystemExit) as e:
            print(f"Local API not started ({e}). The relay keeps running.", flush=True)
    threading.Event().wait()  # keep the relay alive
