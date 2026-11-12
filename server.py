#!/usr/bin/env python3
"""Session Deck: shows live tmux Claude Code sessions as chats and types into them.
Binds 127.0.0.1 (and DECK_SOCKET) only. Needs the token from <DECK_SECRETS>/session-deck.json for every local /api call."""
import html, json, os, re, secrets, shutil, subprocess, sys, threading, time, urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path

HOME = Path.home()
CLAUDE = Path(os.environ.get("CLAUDE_CONFIG_DIR") or HOME / ".claude")
PROJ = CLAUDE / "projects"
HERE = Path(__file__).parent
PORT = int(os.environ.get("DECK_PORT", "8787"))
TS_PORT = int(os.environ.get("DECK_TS_PORT", PORT + 1 if PORT else 0))  # for tailscale serve only: the owner's login is always required here
HOSTS = {"127.0.0.1", "localhost"} | set(filter(None, os.environ.get("DECK_HOSTS", "").split(",")))
SOCK = os.environ.get("DECK_SOCKET")  # a Unix socket for the router: the Tailscale route, like TS_PORT, but no other account can reach it
SECRETS = Path(os.environ.get("DECK_SECRETS") or (HOME / ".secrets" if (HOME / ".secrets").is_dir() else HOME / ".config/session-deck"))
SECRET_FILE = SECRETS / "session-deck.json"  # token, cookie key and VAPID key in one file, easy to keep in a password manager
KEYS = {"Escape", "Enter", "Up", "Down", "Tab", "BTab", "C-c", "C-o", "C-b"} | set("0123456789")
CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; "
       "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'")

def load_secrets():
    """{token, cookie_key, vapid_pem}; missing values come from the old one-per-secret files, else are made, then saved once."""
    if SECRET_FILE.is_symlink() and not SECRET_FILE.exists(): sys.exit("secrets link is dangling; run secrets-mount")  # let launchd retry
    try: d = json.loads(SECRET_FILE.read_text()) if SECRET_FILE.exists() else {}
    except ValueError: sys.exit(f"{SECRET_FILE} is not valid JSON")
    old = lambda n: (SECRETS / n).read_text().strip() if (SECRETS / n).exists() else None
    if not d.get("vapid_pem"):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization as ser
        d["vapid_pem"] = old("session-deck-vapid.pem") or ec.generate_private_key(ec.SECP256R1()).private_bytes(
            ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()).decode()
    new = {k: d.get(k) or (f and old(f)) or secrets.token_urlsafe(24) for k, f in (("token", "session-deck.token"), ("cookie_key", "session-deck-cookie.key"), ("siri_key", None))}
    if new.keys() - d.keys() or not SECRET_FILE.exists(): d.update(new); save_secrets(d)
    return d

def save_secrets(d):
    SECRETS.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Writes through a link (the RAM disk file) rather than replacing it; a new file is made 0600 from the start.
    fd = os.open(SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh: fh.write(json.dumps(d, indent=1) + "\n")

TMUXDIR = Path(os.environ.get("TMUX_TMPDIR") or "/private/tmp") / f"tmux-{os.getuid()}"
_socks = {}  # socket name -> (when checked, has sessions); a new socket is checked at once, so a just-started server shows
def sockets():
    now, out = time.time(), []
    for s in TMUXDIR.iterdir() if TMUXDIR.exists() else ():
        if s.name.endswith("test") and not os.environ.get("DECK_SHOW_TEST"): continue  # throwaway servers used when testing the deck itself (tmux -L <name>test)
        t, ok = _socks.get(s.name, (0, False))
        if now - t > 60: ok = subprocess.run(["tmux", "-L", s.name, "has-session"], capture_output=True).returncode == 0; _socks[s.name] = (now, ok)
        if ok: out.append(s.name)
    return out

RESZ = {}  # pane -> when the phone's terminal view last sized its window (like Termius: the TUI redraws to fit)
def term_size(pane, cols, rows):
    if not (20 <= cols <= 400 and 5 <= rows <= 200): return
    if tm(pane, "display", "-p", "-t", "{P}", "#{window_width}x#{window_height}").strip() != f"{cols}x{rows}":
        tm(pane, "resize-window", "-t", "{P}", "-x", str(cols), "-y", str(rows))
    RESZ[pane] = time.time()

def term_release(pane):
    """Hands sizing back to tmux (window-size latest): the desktop terminal takes over again."""
    if RESZ.pop(pane, None) is not None:
        tm(pane, "resize-window", "-A", "-t", "{P}"); tm(pane, "set-option", "-wu", "-t", "{P}", "window-size")  # resize-window sets manual: unset after

ROOMY = (120, 50)
def roomy():
    """A chat window nobody is attached to keeps the size it last had, often a phone's: questions then wrap and their
    top falls off the screen. Give such windows room (tmux sizes them to a client again once one attaches)."""
    for s in live_sessions():
        p = s["pane"]
        if p in RESZ: continue
        w, h, n = (tm(p, "display", "-p", "-t", "{P}", "#{window_width} #{window_height} #{session_attached}").split() + ["", "", ""])[:3]
        if n == "0" and (w, h) != tuple(map(str, ROOMY)):
            tm(p, "resize-window", "-t", "{P}", "-x", str(ROOMY[0]), "-y", str(ROOMY[1])); tm(p, "set-option", "-wu", "-t", "{P}", "window-size")

def term_reaper():  # a phone that closed or locked mid-view never says goodbye
    while True:
        time.sleep(10)
        try: roomy()
        except Exception: pass
        for p, t in list(RESZ.items()):
            if time.time() - t > 30:
                try: term_release(p)
                except Exception: RESZ.pop(p, None)

def tm(key, *args):
    """Run tmux against the server and pane named by key ("ssh.63"); "{P}" in args becomes the pane target."""
    sock, n = key.rsplit(".", 1)
    return run("tmux", "-L", sock, *[f"%{n}" if a == "{P}" else a for a in args])

PANE_RE = r"[\w-]+\.\d+"

def run(*a, inp=None):
    return subprocess.run(a, capture_output=True, text=True, input=inp, timeout=8).stdout

def proc_table():
    t = {}
    for l in run("ps", "-axo", "pid=,ppid=,command=").splitlines():
        p = l.split(None, 2)
        if len(p) == 3:
            t[int(p[0])] = (int(p[1]), p[2])
    return t

def descendants(table, root):
    out, stack = [], [root]
    while stack:
        cur = stack.pop()
        for pid, (pp, cmd) in table.items():
            if pp == cur:
                out.append((pid, cmd)); stack.append(pid)
    return out

def cwd_of(pid):
    for l in run("lsof", "-a", "-p", str(pid), "-d", "cwd", "-Fn").splitlines():
        if l.startswith("n"):
            return l[1:]

def project_dir(cwd):
    return PROJ / re.sub(r"[/.]", "-", cwd)

def age(pid):
    """Seconds since a process started (ps etime is [[dd-]hh:]mm:ss)."""
    t = run("ps", "-o", "etime=", "-p", str(pid)).strip().replace("-", ":").split(":")
    return sum(int(x) * m for x, m in zip(reversed(t), (1, 60, 3600, 86400))) if all(x.isdigit() for x in t) else 1e9

def newest(d, exclude=()):
    fs = [f for f in d.glob("*.jsonl") if f.stem not in exclude]
    return max(fs, key=lambda f: f.stat().st_mtime, default=None)

def custom_title(f):
    r = subprocess.run(["rg", "-N", "-o", '"customTitle":"((?:[^"\\\\]|\\\\.)*)"', "-r", "$1", str(f)], capture_output=True, text=True).stdout.strip().splitlines()
    return json.loads('"' + r[-1] + '"') if r else None

def title_of(f):
    c = custom_title(f)
    if c: return c
    t = None
    try:
        with open(f, "rb") as fh:
            fh.seek(0, 2); n = fh.tell(); fh.seek(max(0, n - 200000))
            for l in fh.read().decode("utf8", "ignore").splitlines():
                if '"ai-title"' in l:
                    try: t = json.loads(l).get("aiTitle") or t
                    except Exception: pass
    except Exception:
        pass
    return t

def first_prompt(f):
    try:
        with open(f, "rb") as fh:
            for l in fh.read(1500000).decode("utf8", "ignore").splitlines():
                if '"type":"user"' in l and not '"isMeta":true' in l:
                    try: o = json.loads(l)
                    except Exception: continue
                    c = (o.get("message") or {}).get("content")
                    if isinstance(c, list): c = " ".join(b.get("text", "") for b in c if isinstance(b, dict) and b.get("type") == "text")
                    if isinstance(c, str) and c.strip() and not c.lstrip().startswith("<"): return c.strip().replace("\n", " ")[:80]
    except Exception:
        pass

def title_of(f, _t=title_of):
    t = _t(f)
    return t if t and not t.startswith("/") else (first_prompt(f) or t)

_live = [0, None]
def live_sessions():
    if time.time() - _live[0] < 2 and _live[1] is not None: return _live[1]
    _live[1] = _live_sessions(); _live[0] = time.time(); return _live[1]

def parse_menu(plain):
    L = plain.splitlines()
    # a question's key hints; viewers (background shells and agents, the resume list) end "Esc to close" and aren't questions
    # The hints sit on one of the last lines (chat text above can quote them) and start the line.
    tail = [i for i, l in enumerate(L) if l.strip()][-3:]
    F = max((i for i in tail if re.match(r"\s*(Enter to|Esc to|Tab|\u2191|\u2190|Press )", L[i])
             and re.search(r"Enter to (confirm|select|submit)|to navigate|Esc to cancel", L[i])
             and not re.search(r"(?i)esc to close|enter to view", L[i])), default=-1)
    if F < 0:  # "Ready to submit your answers?" has no key hints: a numbered ❯ list at the bottom, under a line ending "?"
        end = max((i for i, l in enumerate(L) if l.strip()), default=-1)
        m1 = next((i for i in range(max(0, end - 12), end + 1) if re.match(r"^\s*\u276f\s+\d+\.\s+\S", L[i])), None)
        if m1 and next((l for l in reversed(L[:m1]) if l.strip()), "").rstrip().endswith("?"): F = end + 1; L = L + [""]
    if F >= 0:
        M = max((i for i in range(F) if re.match(r"^\s*\u276f\s+\S", L[i])), default=-1)
        if M >= 0:
            col = L[M].index("\u276f"); tc = col + 1 + len(L[M][col + 1:]) - len(L[M][col + 1:].lstrip())
            is_opt = lambda l: len(l) > tc and l[tc] != " " and l[:tc].strip() in ("", "\u276f")
            is_desc = lambda l: len(l) > tc and l[:tc + 1].strip() == ""
            s = M
            while s - 1 >= 0 and (is_opt(L[s - 1]) or (is_desc(L[s - 1]) and s - 2 >= 0)): s -= 1
            while s < M and not is_opt(L[s]): s += 1
            opts, sel = [], 0
            for i in range(s, F):
                l = L[i]
                if l.strip().lstrip("\u276f").strip() == "Submit":  # a multi-select's Submit row sits indented, without a number
                    if l.lstrip().startswith("\u276f"): sel = len(opts)
                    opts.append({"label": "Submit", "desc": ""})
                elif is_opt(l):
                    if l[:tc].strip() == "\u276f": sel = len(opts)
                    opts.append({"label": re.sub(r"^\d+\.\s+", "", l[tc:].strip()), "desc": ""})
                elif opts and is_desc(l) and l.strip():
                    opts[-1]["desc"] = (opts[-1]["desc"] + " " + l.strip()).strip()
            j = s - 1
            while j >= 0 and not L[j].strip(): j -= 1
            ql = []
            while j >= 0 and L[j].strip() and not set(L[j].strip()) <= set("\u2500\u2501\u254c-") and not L[j].lstrip().startswith("\u2190") and len(ql) < 12:
                ql.insert(0, re.sub(r"^[\u2502\u2503|]\s?", "", L[j].strip())); j -= 1  # a question is drawn with a bar down its left
            q = " ".join(ql)
            amend = "Tab to amend" in L[F]
            if len(opts) >= 2: return {"question": q, "options": opts, "selected": sel, "mode": "arrows", "amend": amend,
                                       "detail": amend and perm_detail(L, j)}

def perm_detail(L, j):
    """What a permission prompt asks to do (the tool, the command or diff), drawn between the dialog's top rule and the
    question: "Bash command", what it does, then the command between dashed rules. Tips and rules are left out."""
    top = next((i for i in range(j, max(-1, j - 60), -1) if L[i].strip() and set(L[i].strip()) <= set("─━")), None)
    if top is None: return None
    d = [re.sub(r"^ ?(?:[│┃] ?)?", "", l.rstrip()) for l in L[top + 1:j + 1]]  # keeps a command's indents
    d = [l for l in d if not set(l.strip()) <= set("╌┄┈-") and not l.startswith("Tip:")] or [""]
    return "\n".join(d[:40]).strip() or None
    for i, l in enumerate(L):
        found = re.findall(r"(\d): (\w+)", l)
        if len(found) >= 3 and i and "?" in L[i - 1]:
            return {"question": L[i - 1].strip().lstrip("\u25cf ").strip(), "options": [{"label": b, "key": a, "desc": ""} for a, b in found], "mode": "keys"}

def input_box(key, wait=0):
    """What sits in Claude's input box (the ❯ line between the last two rules), "" when empty, None when no box shows.
    With wait, polls up to that many seconds for the box to appear (a chat that is still starting up)."""
    end = time.time() + wait
    while True:
        L = tm(key, "capture-pane", "-p", "-t", "{P}").splitlines()
        r = [i for i, l in enumerate(L) if len(l.strip()) >= 20 and l.strip().count("─") > 0.8 * len(l.strip())]
        if len(r) >= 2 and r[-1] - r[-2] >= 2 and L[r[-2] + 1].lstrip().startswith("❯"):
            return "\n".join(L[r[-2] + 1:r[-1]]).strip().lstrip("❯").strip()
        if time.time() >= end: return None
        time.sleep(0.25)

def deliver(pane, text, imgs=()):
    """Types a message into a chat and sends it."""
    input_box(pane, 15)  # a chat that is still starting: wait for its input box, or the paste lands nowhere
    if imgs:  # pasted on their own, the paths become [Image #N]; the text must be a separate paste after them
        tm(pane, "set-buffer", "-b", "deck", " ".join(f'"{f}"' for f in imgs))
        tm(pane, "paste-buffer", "-p", "-d", "-b", "deck", "-t", "{P}"); time.sleep(0.4)
    if text or not imgs:
        tm(pane, "set-buffer", "-b", "deck", (" " if imgs else "") + text)
        tm(pane, "paste-buffer", "-p", "-d", "-b", "deck", "-t", "{P}")
    for i in range(5):  # Claude drops an Enter that comes while it is still starting up: press it again until the box empties
        time.sleep(0.15 if i == 0 else 0.8); tm(pane, "send-keys", "-t", "{P}", "Enter"); time.sleep(0.4)
        if not input_box(pane): break

def pane_screen(key):
    scr = tm(key, "capture-pane", "-e", "-p", "-t", "{P}")
    sug = [x for x in re.findall("\u276f\u00a0\x1b\\[2m(.+?)\x1b\\[0m", scr)
           if "\x1b" not in x and not re.match(r"(Press |Try |Tip:|esc )", x)]
    plain = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\]8;[^\x1b]*\x1b\\", "", scr).replace("\u00a0", " ")
    st = re.findall(r"^\S\s+[A-Z][\w-]*(?: [\w-]+){0,3}\u2026(?:\s*\(.*)?$", plain, re.M)
    model = re.search(r"Model:\s*(.+?)\s*(\||$)", plain, re.M)
    ctx = re.search(r"Ctx:\s*([\d.]+%)\s*\(([^)]+)\)", plain)
    pm = re.search(r"^\s*(?:\u23f5\u23f5|\u23f8)\s*(.+?)(?:\s+on)?(?:\s*\(|\s+\u00b7|$)", plain, re.M)
    menu = parse_menu(plain)
    if menu:  # several questions at once: a tab row "←  ☐ Topic  ☐ Topic  ✔ Submit  →", the current one on a coloured background
        row = next((l for l in scr.splitlines() if "\u2190" in l and "\u2192" in l and "Submit" in l), None)
        if row:
            parts = re.split("([\u2610\u2612\u2714])", row)
            tabs = [{"label": re.sub(r"\x1b\[[0-9;]*m", "", parts[i + 1]).strip(" \u2192"), "done": parts[i] != "\u2610",
                     "current": bool(re.search(r"\x1b\[48;[0-9;]*m", parts[i - 1]))} for i in range(1, len(parts) - 1, 2)]
            menu["tabs"] = [t for t in tabs if t["label"] != "Submit"]
    return {"menu": menu, "working": "esc to interrupt" in plain or bool(st), "status": st[-1].strip() if st else None,
            "suggestion": sug[-1] if sug else None, "model": model.group(1).strip() if model else None,
            "ctx": f"{ctx.group(1)} ({ctx.group(2)})" if ctx else None,
            "perm": pm.group(1).strip() if pm else "default (asks before acting)"}

_dev = [0, None]
def device():
    if time.time() - _dev[0] < 5 and _dev[1]: return _dev[1]
    n = os.cpu_count() or 1
    cpu = sum(float(x) for x in run("ps", "-A", "-o", "%cpu=").split() if x.replace(".", "").isdigit()) / n
    mp = re.search(r"(\d+)%", run("memory_pressure", "-Q"))
    sv = os.statvfs(str(HOME)); disk = 100 - sv.f_bavail * 100 / sv.f_blocks
    _dev[1] = {"cpu": round(min(cpu, 100)), "mem": 100 - int(mp.group(1)) if mp else None, "disk": round(disk),
               "load": " ".join(f"{x:.1f}" for x in os.getloadavg()), "cores": n}
    _dev[0] = time.time(); return _dev[1]

_acc = [0, None]
def accounts():
    if time.time() - _acc[0] < 30 and _acc[1] is not None: return _acc[1]
    rows, exe = [], "rotate" in ENGINES and engine_exe("rotate")
    for l in (run(exe, "status") if exe else "").splitlines()[1:]:
        c = re.split(r"\s{2,}", l.strip())
        if len(c) >= 6 and c[0].isdigit():
            rows.append({"name": c[1], "status": c[2], "h5": c[3], "week": c[4], "until": c[5] if c[5] != "-" else None})
    _acc[1] = rows; _acc[0] = time.time(); return rows

_mod = [0, None]
def account_models():
    """rclaude's account -> the model ids it can use, newest first (`rclaude models`, which caches Anthropic's list)."""
    if time.time() - _mod[0] < 300 and _mod[1] is not None: return _mod[1]
    exe = "rotate" in ENGINES and engine_exe("rotate")
    try: d = json.loads(run(exe, "models", "--json") or "{}") if exe else {}
    except ValueError: d = {}
    _mod[1] = d if isinstance(d, dict) else {}; _mod[0] = time.time(); return _mod[1]

SESSDIR = CLAUDE / "sessions"
def pid_sessions():
    """Claude Code's own <pid>.json per running chat: sessionId (updated in place by /clear and /resume), cwd, status."""
    out = {}
    for j in SESSDIR.glob("*.json"):
        try: d = json.loads(j.read_text())
        except Exception: continue
        if isinstance(d, dict) and isinstance(d.get("pid"), int) and d.get("sessionId"): out[d["pid"]] = d
    return out

RSTATE = Path(os.environ.get("RCLAUDE_STATE_DIR") or "~/.local/state/claude-rotate").expanduser() / "state.json"
def launchers():
    """rclaude launcher pid -> its entry: the plan its chat runs on now ("account"; a switch relaunches claude under the same
    launcher and records it there) and "pinned" for `rclaude --account`."""
    try: return {int(k): v for k, v in json.loads(RSTATE.read_text()).get("launchers", {}).items() if k.isdigit() and isinstance(v, dict)}
    except Exception: return {}

_engine = {}  # pid -> engine; a process's environment can't change, so ps -E runs once per chat
def _live_sessions():
    table = proc_table()
    by_pid = pid_sessions()
    panes = []
    for sock in sockets():
        for l in run("tmux", "-L", sock, "list-panes", "-a", "-F", "#{pane_id}\t#{session_name}:#{window_index}\t#{window_name}\t#{pane_pid}").splitlines():
            if l.startswith("%"): panes.append(f"{sock}.{l[1:]}")
    out, claimed, fallback, lau = [], set(), [], None
    for l in panes:
        pid_, loc, wname, ppid = l.split("\t")
        if not ppid.isdigit(): continue  # a pane that is still starting has no pid yet
        ds = descendants(table, int(ppid)) + [(int(ppid), table.get(int(ppid), (0, ''))[1])]
        claude = [(p, c) for p, c in ds if re.search(r"(^|/)claude( |$)", c) and "bg-pty" not in c and "daemon" not in c and "remote-control" not in c]
        if not claude:
            continue
        cp = {p for p, _ in claude}  # the chat is the outermost claude; inner ones are e.g. a `claude -p` it ran
        p, cmd = next(((p, c) for p, c in claude if table.get(p, (0,))[0] not in cp), claude[-1])
        sf = by_pid.get(p)
        rotate = any("rclaude" in c for _, c in ds)
        if p not in _engine:
            env = run("ps", "-E", "-o", "command=", "-p", str(p))
            _engine[p] = "local" if "ANTHROPIC_BASE_URL=http://localhost:11434" in env else ("rotate" if rotate else "claude")
        plan, pinned, x = None, False, table.get(p, (0,))[0]
        if _engine[p] == "rotate":
            lau = launchers() if lau is None else lau
            for _ in range(6):  # the launcher is the chat's parent, or a little further up
                if x in lau: plan, pinned = lau[x].get("account"), bool(lau[x].get("pinned")); break
                x = table.get(x, (0,))[0]
        if sf:
            cwd, sid = sf.get("cwd") or "", sf["sessionId"]
            f = project_dir(cwd) / f"{sid}.jsonl"
            f = f if f.exists() else find_file(sid)  # None until the chat's first message is saved
            claimed.add(sid)
        else:
            cwd, f = cwd_of(p) or "", None
            fallback.append((len(out), p))
        out.append({"pane": pid_, "where": loc, "name": wname, "cwd": cwd, "engine": _engine[p], "plan": plan, "pinned": pinned, "file": f, "cmd": cmd,
                    "state": sf.get("status") if sf else None, **pane_screen(pid_)})
    for i, p in fallback:  # no <pid>.json: guess from --resume, else the newest transcript in the folder that no other chat has,
        s = out[i]; d = project_dir(s["cwd"]); m = re.search(r"--resume (\S{36})", s["cmd"])  # written since this chat started
        f = (d / f"{m.group(1)}.jsonl") if m and (d / f"{m.group(1)}.jsonl").exists() else newest(d, claimed)
        if f and not m and f.stat().st_mtime < time.time() - age(p) - 5: f = None  # a chat that has just started: an earlier chat's
        if f: claimed.add(f.stem)
        s["file"] = f
    for k in [k for k in _engine if k not in table]: del _engine[k]
    for s in out:
        f = s.pop("file"); s.pop("cmd")
        s.update(session=f.stem if f else None, title=title_of(f) if f else None, mtime=f.stat().st_mtime if f else 0)
    return out

_cache = {}
def cached(f, fn):
    k = (fn.__name__, str(f), f.stat().st_mtime)
    if k not in _cache:
        for o in [o for o in _cache if o[:2] == k[:2]]: del _cache[o]  # drop the stale copy of a file that changed
        _cache[k] = fn(f)
    return _cache[k]

def file_cwd(f):
    try:
        with open(f, "rb") as fh:
            m = re.search(rb'"cwd":"([^"]+)"', fh.read(120000))
        return m.group(1).decode() if m else None
    except Exception:
        return None

def session_files():
    fs = [f for f in PROJ.glob("*/*.jsonl") if "tmp-claude" not in f.parent.name]
    return sorted(fs, key=lambda f: f.stat().st_mtime, reverse=True)

def history(limit=250, skip=()):
    out = []
    for f in session_files():
        if f.stem in skip: continue
        out.append({"session": f.stem, "cwd": cached(f, file_cwd) or f.parent.name, "title": cached(f, title_of), "mtime": f.stat().st_mtime})
        if len(out) >= limit: break
    return out

def text_snippet(line, rx, n=160):
    """Snippet around the first match in a user or assistant text block of one transcript line, else None."""
    try: o = json.loads(line)
    except Exception: return None
    if o.get("type") not in ("user", "assistant") or o.get("isMeta"): return None
    c = (o.get("message") or {}).get("content")
    for t in [c] if isinstance(c, str) else [b.get("text") or "" for b in c or [] if isinstance(b, dict) and b.get("type") == "text"]:
        m = rx.search(t)
        if m:
            s = max(0, m.start() - 60)
            return ("…" if s else "") + re.sub(r"\s+", " ", t[s:s + n]).strip() + ("…" if s + n < len(t) else "")

def search(q, limit=40):
    pats = sum((["-e", p] for p in {q, json.dumps(q, ensure_ascii=False)[1:-1]}), [])  # as typed, and as escaped inside JSON
    r = subprocess.run(["rg", "-l", "-i", "-F", "--max-depth", "2", "--glob", "*.jsonl", "--glob", "!*tmp-claude*", *pats, str(PROJ)],
                       capture_output=True, text=True, timeout=25).stdout
    fs = sorted((f for f in map(Path, r.splitlines()) if f.exists()), key=lambda f: f.stat().st_mtime, reverse=True)
    rx, out = re.compile(re.escape(q), re.I), []
    for i in range(0, len(fs), limit):  # newest first, a batch at a time, until enough files match in message text
        batch = fs[i:i + limit]
        r = subprocess.run(["rg", "-i", "-F", "-N", "-0", "--with-filename", "-m", "20", "--max-columns", "600000", *pats, *map(str, batch)],
                           capture_output=True, text=True, timeout=25).stdout
        hit = {}
        for l in r.splitlines():
            p, _, line = l.partition("\0")
            if not hit.get(p): hit[p] = text_snippet(line, rx)
        for f in batch:
            if hit.get(str(f)):
                out.append({"session": f.stem, "cwd": cached(f, file_cwd) or f.parent.name, "title": cached(f, title_of),
                            "mtime": f.stat().st_mtime, "snippet": hit[str(f)]})
        if len(out) >= limit: break
    return out[:limit]

FOLDERS = Path(os.environ.get("DECK_FOLDERS") or (HOME / "projects" if (HOME / "projects").is_dir() else HOME))  # where new chats start
def folders():
    return sorted(str(d) for d in FOLDERS.iterdir() if d.is_dir() and not d.name.startswith("."))

# DECK_ENGINES: id[=command],... in the order the new-chat sheet shows them. Commands are looked up in ~/.local/bin, then PATH.
ENGINE_INFO = {"rotate": ("rclaude", "Claude Rotate", "your cloud plans"), "local": ("claude-local", "Local model", "Ollama on this Mac"),
               "claude": ("claude", "Claude", "your Claude plan")}
ENGINES = {}
for _e in filter(None, os.environ.get("DECK_ENGINES", "claude,rotate,local").replace(" ", "").split(",")):
    _k, _, _c = _e.partition("="); _d = ENGINE_INFO.get(_k, (_k, _k, ""))
    ENGINES[_k] = (_c or _d[0], *_d[1:])
def engine_exe(e):
    return shutil.which(os.path.expanduser(ENGINES[e][0]), path=f"{HOME}/.local/bin:{os.environ.get('PATH', '')}:/usr/local/bin:/opt/homebrew/bin")
TMUX_SOCKS = [s for s in os.environ.get("DECK_TMUX_SOCKET", "ssh,default").replace(" ", "").split(",") if s] or ["default"]

PERMS = {"bypass": ["--dangerously-skip-permissions"], **{m: ["--permission-mode", m] for m in ("default", "acceptEdits", "plan", "auto")}}
MODELS, EFFORTS = {"opus", "sonnet", "haiku"}, {"low", "medium", "high", "xhigh", "max"}

def is_git(cwd):
    return subprocess.run(["git", "-C", cwd, "rev-parse", "--is-inside-work-tree"], capture_output=True).returncode == 0

def start(cwd, engine, resume, fork=False, perm="bypass", model=None, effort=None, name=None, worktree=False, account=None, system=None):
    import shlex
    cwd = os.path.realpath(cwd)
    if not os.path.isdir(cwd) or not cwd.startswith(str(HOME) + "/"): return None
    if resume and not re.fullmatch(r"[0-9a-f-]{36}", resume): return None
    perm, model, effort = str(perm), str(model or ""), str(effort or "")
    if perm not in PERMS or not (model in MODELS | {""} or re.fullmatch(r"claude-[a-z0-9-]{1,60}", model)) or effort not in EFFORTS | {""}: return None
    name = re.sub(r"[^\w .,'()&+-]", "", re.sub(r"\s+", " ", str(name or ""))).strip(" -")[:60]
    exe = engine in ENGINES and engine_exe(engine)
    if not exe: return None  # only this deck's engines: a guest's deck must never start the owner's rclaude
    account = str(account or "")  # rclaude --account pins the chat to one plan; only a name `rclaude status` lists
    if account and (engine != "rotate" or account not in {a["name"] for a in accounts()}): return None
    cmd = [exe] + (["--account", account] if account else []) + [*PERMS[perm]] + (["--resume", resume] if resume else []) + (["--fork-session"] if fork and resume else [])
    if model and engine != "local": cmd.append("--model=" + model)  # claude-local sets its own model
    if effort: cmd.append("--effort=" + effort)
    if name: cmd.append("--name=" + name)
    if worktree and not resume and is_git(cwd): cmd.append("--worktree")
    if system: cmd += ["--append-system-prompt", system]
    if os.environ.get("DECK_DRYRUN"): cmd = ["bash", "-c", "exec -a claude cat"]
    full = ["zsh", "-lc", shlex.join(cmd)]
    name = name or os.path.basename(cwd) + (" (local)" if engine == "local" else "")
    sock = next((s for s in TMUX_SOCKS if s in sockets()), TMUX_SOCKS[-1])  # the first running server; a new one only if none is
    target = os.environ.get("DECK_TMUX_SESSION", "work")  # new chats become windows in this session
    if subprocess.run(["tmux", "-L", sock, "has-session", "-t", f"={target}"], capture_output=True).returncode:
        r = run("tmux", "-L", sock, "new-session", "-d", "-P", "-F", "#{pane_id}", "-s", target, "-c", cwd, "-n", name, *full)
    else:
        r = run("tmux", "-L", sock, "new-window", "-d", "-P", "-F", "#{pane_id}", "-t", f"={target}:", "-c", cwd, "-n", name, *full)
    _live[0] = 0; _socks.pop(sock, None)  # the chat may have started a new tmux server
    return f"{sock}.{r.strip()[1:]}" if r.strip().startswith("%") else None

def find_file(session):
    if not re.fullmatch(r"[0-9a-f-]{36}", session): return None
    for f in PROJ.glob(f"*/{session}.jsonl"): return f

def agent_map(f, side=False):  # subagent transcripts (nested ones too) all sit flat in <session>/subagents
    m = {}
    for meta in (f.parent if side else f.parent / f.stem / "subagents").glob("*.meta.json"):
        try: d = json.loads(meta.read_text()); m[d.get("toolUseId")] = (meta.name[6:-10], d.get("description"))
        except Exception: pass
    return m

def images_in(blocks):
    return [i for i, x in enumerate(blocks or []) if isinstance(x, dict) and x.get("type") == "image"]

DIFF_TOOLS = {"Edit", "MultiEdit", "Write", "NotebookEdit"}
def tool_diff(name, inp):
    """Diff lines for a file-editing tool call, each starting with ' ', '+', '-' or '@' (a note or a gap)."""
    import difflib, itertools
    if name == "MultiEdit": pairs = [(e.get("old_string"), e.get("new_string")) for e in inp.get("edits") or [] if isinstance(e, dict)]
    elif name == "Edit": pairs = [(inp.get("old_string"), inp.get("new_string"))]
    else: pairs = [("", inp.get("content") if name == "Write" else inp.get("new_source"))]
    out = [f"@cell {inp.get('cell_id') or 'new'} ({inp.get('edit_mode') or 'replace'})"] if name == "NotebookEdit" else []
    for i, (a, b) in enumerate(pairs):
        if len(pairs) > 1: out.append(f"@edit {i + 1} of {len(pairs)}")
        a, b = str(a or "").splitlines(), str(b or "").splitlines()
        first = True
        for l in itertools.islice(difflib.unified_diff(a, b, lineterm=""), 2, None) if a else ["+" + x for x in b]:
            if l.startswith("@@"):  # an Edit has no line numbers, so a hunk header only marks a gap
                if not first: out.append("@")
                first = False
            else: out.append(l)
    return out

def patch_diff(r, path):
    """Diff lines from a tool result's structuredPatch (or a created file), with "@@ -a,b +c,d @@" hunk headers that let
    the page number the lines; None when the result has neither or is for another file."""
    if not isinstance(r, dict) or str(r.get("filePath"))[:300] != str(path)[:300]: return None  # a chat item keeps 300 characters
    p = r.get("structuredPatch")
    if r.get("type") == "create" and isinstance(r.get("content"), str):
        b = r["content"].splitlines(); p = [{"oldStart": 0, "oldLines": 0, "newStart": 1, "newLines": len(b), "lines": ["+" + x for x in b]}]
    if not p or not isinstance(p, list): return None
    out = []
    for h in p:
        out.append(f"@@@ -{h['oldStart']},{h['oldLines']} +{h['newStart']},{h['newLines']} @@"); out += [str(x) for x in h["lines"]]
    return out

def clip(lines, n=60, chars=6000, width=300):
    """Joined diff text kept to n lines and about `chars` characters; second value is True if anything was cut."""
    out, size = [], 0
    for l in lines[:n]:
        l = l if len(l) <= width else l[:width] + "…"
        size += len(l) + 1
        if size > chars and out: break
        out.append(l)
    return "\n".join(out), len(out) < len(lines) or any(len(l) > width for l in lines[:len(out)])

def diff_fields(lines):
    d, cut = clip(lines)
    return {"diff": d, "add": sum(l[:1] == "+" for l in lines), "del": sum(l[:1] == "-" for l in lines), **({"more": len(lines)} if cut else {})}

def full_tool_diff(f, tid):
    """The call's diff from its result's patch when there is one, else from its input."""
    r = subprocess.run(["rg", "-F", "-N", "-m", "6", "-e", f'"id":"{tid}"', "-e", f'"tool_use_id":"{tid}"', str(f)], capture_output=True, text=True, timeout=10).stdout
    b = pd = None
    for l in r.splitlines():
        try: o = json.loads(l); c = o["message"]["content"]
        except Exception: continue
        for x in c if isinstance(c, list) else []:
            if not isinstance(x, dict): continue
            if not b and x.get("type") == "tool_use" and x.get("id") == tid and x.get("name") in DIFF_TOOLS: b = x
            if b and x.get("type") == "tool_result" and x.get("tool_use_id") == tid and not x.get("is_error"): pd = pd or patch_diff(o.get("toolUseResult"), (b.get("input") or {}).get("file_path"))
    return clip(pd or tool_diff(b["name"], b.get("input") or {}), 5000, 1_500_000, 5000)[0] if b else None
def ptext(c):
    """A prompt's text, saved as a string or (when it has images) as blocks; "[Image #N]" goes, as the image shows on its own."""
    if isinstance(c, list): c = "\n".join(b.get("text", "") for b in c if isinstance(b, dict) and b.get("type") == "text")
    return re.sub(r"</?pasted_content[^>]*>|\[Image #\d+\]", "", c).strip() if isinstance(c, str) else ""

def user_item(tx, ts):  # a message from the user, or a background task's "finished" notice shown as a small note
    tx = ptext(tx)
    tn = re.match(r"<task-notification>.*?(?:<summary>(.*?)</summary>|$)", tx, re.S)
    if tn:  # the summary comes XML-escaped; the page escapes again, so unescape here. Commands in it can be long: cut them
        t = html.unescape(tn.group(1) or "Background task update").strip()
        t = re.sub(r'^(Background command )"(.{70}).*?"( (?:completed|failed|was stopped|exited).*)$', r'\1"\2…"\3', t, flags=re.S)
        return {"role": "assistant", "kind": "note", "text": t[:300], "ts": ts}
    return {"role": "user", "kind": "text", "text": tx[:6000], "ts": ts}

_msgs, _msgs_lock = {}, threading.Lock()
def messages(f, limit=60, side=False):
    """Chat items for a transcript. The parse is kept per file and later calls only parse appended lines."""
    now = time.time()
    with _msgs_lock:
        for k in [k for k, s in _msgs.items() if now - s["used"] > 600]: del _msgs[k]
        st = _msgs.setdefault((str(f), side), {"lock": threading.Lock()}); st["used"] = now
    with st["lock"]:
        s = f.stat()
        if st.get("ino") != (s.st_dev, s.st_ino) or s.st_size < st["off"]:  # new, replaced or truncated: start again
            st.update(ino=(s.st_dev, s.st_ino), off=0, n=0, items=[], delivered=set())
        if s.st_size > st["off"]:
            with open(f, "rb") as fh:
                fh.seek(st["off"]); buf = b""
                for blk in iter(lambda: fh.read(1 << 25), b""):  # 32 MB at a time keeps a huge first parse's memory down
                    buf += blk; cut = buf.rfind(b"\n") + 1  # a half-written last line waits for the next call
                    if not cut: continue
                    lines = buf[:cut].decode("utf8", "ignore").splitlines()
                    try: parse_lines(lines, st["n"], st["items"], st["delivered"], side)
                    except Exception: st.pop("ino", None); raise  # half-applied: rebuild next time
                    st["off"] += cut; st["n"] += len(lines); buf = buf[cut:]
        agents, delivered, items, out = agent_map(f, side), st["delivered"], st["items"], []
        for it in reversed(items):  # copies, so a later parse can't change a reply that is still being sent
            if len(out) >= (limit if limit > 0 else len(items)): break
            if "_d" in it:  # a queued prompt shows only until it is delivered, which may be recorded later in the file
                if it["_d"] in delivered: continue
                it = {k: v for k, v in it.items() if k != "_d"}
            elif it["kind"] == "tool" and it["id"] in agents:
                it = {**it, "agent": agents[it["id"]][0], "summary": agents[it["id"]][1] or it["summary"]}
            else: it = dict(it)
            out.append(it)
        return out[::-1][-limit:]

def parse_lines(lines, n0, items, delivered, side):
    for l in lines:
        if '"type":"user"' in l and '"promptId"' in l:
            try:
                d = re.sub(r"</?bash-input>", "", ptext(json.loads(l)["message"]["content"])).strip()  # a queued ! command comes back as <bash-input>
                if d: delivered.add(d)
            except Exception: pass
        elif '"queued_command"' in l or '"operation":"remove"' in l:  # mid-turn delivery, or taken back out of the queue
            try:
                o = json.loads(l); a = o.get("attachment") or {}
                d = ptext(a.get("prompt") if a.get("type") == "queued_command" else o.get("content") if o.get("operation") == "remove" else None)
                if d: delivered.add(d)
            except Exception: pass
    for n, l in enumerate(lines, n0):
        try: o = json.loads(l)
        except Exception: continue
        t, msg = o.get("type"), o.get("message") or {}
        if t == "queue-operation" and o.get("operation") == "enqueue":
            d = ptext(o.get("content"))
            if d: items.append({**user_item(d, o.get("timestamp")), "queued": True, "_d": d})
            continue
        if t == "attachment" and (o.get("attachment") or {}).get("type") == "queued_command" and not (o.get("isSidechain") and not side):
            p = o["attachment"].get("prompt")  # blocks when it has images: text first, then the images
            if ptext(p): items.append(user_item(p, o.get("timestamp")))
            for bi in images_in(p if isinstance(p, list) else []): items.append({"role": "user", "kind": "image", "img": [f"{n}/{bi}/-1"], "ts": o.get("timestamp")})
            continue
        if t not in ("user", "assistant") or (o.get("isSidechain") and not side): continue
        if o.get("isCompactSummary"):
            c = msg.get("content")
            if isinstance(c, list): c = "\n".join(x.get("text", "") for x in c if isinstance(x, dict))
            items.append({"role": "assistant", "kind": "compact", "text": str(c or "")[:20000], "ts": o.get("timestamp")}); continue
        c = msg.get("content")
        if isinstance(c, str): c = [{"type": "text", "text": c}]
        for bi, b in enumerate(c or []):
            k = b.get("type")
            if k == "image":
                items.append({"role": t, "kind": "image", "img": [f"{n}/{bi}/-1"], "ts": o.get("timestamp")}); continue
            if k == "text" and b["text"].strip():
                tx = b["text"]
                if t == "user" and re.match(r"\s*<command-(name|message)>", tx):
                    m = re.search(r"<command-name>(.*?)</command-name>.*?<command-args>(.*?)</command-args>", tx, re.S)
                    if m: items.append({"role": "user", "kind": "cmd", "text": (m.group(1) + " " + m.group(2)).strip(), "ts": o.get("timestamp")})
                    continue
                if t == "user" and "<local-command-stdout>" in tx:
                    out = re.sub(r"\x1b\[[0-9;]*m", "", re.sub(r"</?local-command-std(out|err)>", "", tx)).strip()
                    if out: items.append({"role": "assistant", "kind": "cmdout", "text": out[:3000], "ts": o.get("timestamp")})
                    continue
                if t == "user":
                    tx = ptext(tx)  # pasted text arrives wrapped in blank lines
                    if not tx: continue
                    if tx.startswith("<task-notification>"): items.append(user_item(tx, o.get("timestamp"))); continue
                    bi_ = re.search(r"<bash-input>(.*?)</bash-input>", tx, re.S)
                    if bi_: items.append({"role": "user", "kind": "cmd", "text": "! " + bi_.group(1).strip(), "ts": o.get("timestamp")}); continue
                    bo = re.search(r"<bash-stdout>(.*?)</bash-stdout>(?:<bash-stderr>(.*?)</bash-stderr>)?", tx, re.S)
                    if bo:
                        bt = "\n".join(filter(None, (bo.group(1).strip(), (bo.group(2) or "").strip())))
                        if bt: items.append({"role": "assistant", "kind": "cmdout", "text": bt[:3000], "ts": o.get("timestamp")})
                        continue
                    if tx.lstrip().startswith("<") or o.get("isMeta"): continue
                items.append({"role": t, "kind": "text", "text": tx[:6000], "ts": o.get("timestamp")})
            elif k == "tool_use":
                inp = b.get("input", {})
                summ = inp.get("command") or inp.get("file_path") or inp.get("pattern") or inp.get("description") or ""
                items.append({"role": "assistant", "kind": "tool", "name": b.get("name"), "summary": str(summ)[:160],
                              "detail": json.dumps(inp, indent=1)[:2500], "id": b.get("id"), "ts": o.get("timestamp")})
                if b.get("name") in DIFF_TOOLS and isinstance(inp, dict):
                    it = items[-1]; del it["detail"]
                    it.update(summary=str(inp.get("file_path") or inp.get("notebook_path") or "")[:300], **diff_fields(tool_diff(b["name"], inp)))
            elif k == "tool_result":
                r = b.get("content"); imgs = images_in(r) if isinstance(r, list) else []
                if isinstance(r, list): r = "\n".join(x.get("text", "") for x in r if isinstance(x, dict))
                for it in reversed(items):
                    if it.get("id") == b.get("tool_use_id") and "_d" not in it:
                        it["result"] = str(r)[:2500] if "diff" not in it or b.get("is_error") else ""  # an edit's result only matters if it failed
                        pd = "diff" in it and not b.get("is_error") and patch_diff(o.get("toolUseResult"), it["summary"])
                        if pd: it.pop("more", None); it.update(diff_fields(pd))
                        if imgs: it["img"] = [f"{n}/{bi}/{i}" for i in imgs[:4]]
                        break

CTRL_C = {}  # pane -> when the deck last sent Ctrl-C
SENT = {}  # session -> [(text, time)] sent from the deck; Claude Code doesn't save text queued during /compact
SENT_IDS = {}  # the page's id for each message -> the reply, so a request repeated after a dropped connection isn't sent twice

def tail(f, size=3_000_000):
    with open(f, "rb") as h:
        h.seek(max(0, f.stat().st_size - size)); return h.read().decode("utf8", "ignore")

def with_sent(sid, items, f=None):
    import datetime
    def when(x):
        try: return datetime.datetime.fromisoformat(x["ts"].replace("Z", "+00:00")).timestamp()
        except Exception: return 0
    keep, end = [], None
    for t, at in SENT.get(sid, []):
        if time.time() - at > 900: continue
        if any(x.get("role") == "user" and (x.get("text") or "").strip() == t and when(x) >= at - 5 for x in items): continue
        if f and end is None: end = tail(f)  # read once per call, not once per message
        if f and '"content":' + json.dumps(t, ensure_ascii=False) in end: continue
        keep.append((t, at))
    SENT[sid] = keep
    return items + [{"role": "user", "kind": "text", "text": t, "queued": True} for t, _ in keep]

def image(f, n, bi, ii):
    import base64
    for k, l in enumerate(open(f, encoding="utf8", errors="ignore")):
        if k == n:
            o = json.loads(l); b = ((o.get("message") or {}).get("content") or (o.get("attachment") or {}).get("prompt"))[bi]  # a queued prompt's are in its attachment
            if ii >= 0: b = b["content"][ii]
            s = b["source"]; return s.get("media_type", "image/png"), base64.b64decode(s["data"])

def info(f):
    first = last = branch = version = model = None; users = asst = tools = 0
    for l in open(f, encoding="utf8", errors="ignore"):
        if '"timestamp"' not in l: continue
        try: o = json.loads(l)
        except Exception: continue
        ts = o.get("timestamp"); first = first or ts; last = ts or last
        branch = o.get("gitBranch") or branch; version = o.get("version") or version
        if o.get("type") == "user" and not o.get("isSidechain") and not o.get("isMeta"):
            c = (o.get("message") or {}).get("content")
            txt = c if isinstance(c, str) else " ".join(b.get("text", "") for b in c or [] if isinstance(b, dict) and b.get("type") == "text")
            if txt.strip() and not re.sub(r"</?pasted_content[^>]*>", "", txt).lstrip().startswith("<"): users += 1
        if o.get("type") == "assistant" and not o.get("isSidechain"):
            m = o.get("message") or {}; model = m.get("model") or model
            asst += sum(1 for b in m.get("content") or [] if isinstance(b, dict) and b.get("type") == "text" and b.get("text", "").strip())
            tools += sum(1 for b in m.get("content") or [] if isinstance(b, dict) and b.get("type") == "tool_use")
    sub = f.parent / f.stem / "subagents"
    return {"session": f.stem, "file": str(f).replace(str(HOME), "~"), "bytes": f.stat().st_size, "cwd": file_cwd(f),
            "first": first, "last": last, "branch": branch, "version": version, "model": model,
            "prompts": users, "replies": asst, "tools": tools, "subagents": len(list(sub.glob("*.jsonl"))) if sub.exists() else 0}

def agent_stats(a):
    first = last = model = None; tools = out = ctx = lo = 0; seen = set()
    for l in open(a, encoding="utf8", errors="ignore"):
        if '"timestamp"' not in l: continue
        try: o = json.loads(l)
        except Exception: continue
        if o.get("type") not in ("user", "assistant"): continue
        ts = o.get("timestamp"); first = first or ts; last = ts or last
        if o["type"] != "assistant": continue
        m = o.get("message") or {}; model = m.get("model") or model; u = m.get("usage") or {}
        tools += sum(1 for b in m.get("content") or [] if isinstance(b, dict) and b.get("type") == "tool_use")
        if u and m.get("id") not in seen:  # one API reply is split over several lines with the same usage
            seen.add(m.get("id")); lo = u.get("output_tokens", 0); out += lo
            ctx = u.get("input_tokens", 0) + u.get("cache_read_input_tokens", 0) + u.get("cache_creation_input_tokens", 0)
    return {"first": first, "last": last, "model": model, "tools": tools, "out": out, "ctx": ctx, "total": ctx + lo}  # total = what Claude Code reports

def agents(f):
    d = f.parent / f.stem / "subagents"; res = []
    for meta in d.glob("*.meta.json") if d.exists() else []:
        try: m = json.loads(meta.read_text())
        except Exception: continue
        aid = meta.name[6:-10]; j = d / f"agent-{aid}.jsonl"
        if not j.exists(): continue
        res.append({"id": aid, "desc": m.get("description"), "type": m.get("agentType"), "parent": m.get("parentAgentId"),
                    "depth": m.get("spawnDepth", 1), "running": not m.get("finished") and time.time() - j.stat().st_mtime < 600,
                    **cached(j, agent_stats)})
    by = {a["id"]: a for a in res}  # an agent waiting on a running subagent of its own is still running
    for a in [a for a in res if a["running"]]:
        p = by.get(a["parent"])
        while p and not p["running"]: p["running"] = True; p = by.get(p["parent"])
    return sorted(res, key=lambda x: x["first"] or "", reverse=True)

def pane_elapsed(key):
    s = next((x for x in live_sessions() if x["pane"] == key), None)
    if not s: return None
    sock, n = key.rsplit(".", 1)
    pid = run("tmux", "-L", sock, "display", "-p", "-t", f"%{n}", "#{pane_pid}").strip()
    kids = [p for p, (pp, c) in proc_table().items() if pp == int(pid or 0)] if pid else []
    return run("ps", "-o", "etime=", "-p", str(kids[0] if kids else pid)).strip() or None

# --- background processes per chat: what its Bash tool started, kept apart from Claude's own helpers (MCP servers, LSP) ---
SNAP = "/shell-snapshots/snapshot-"  # every Bash tool call runs as zsh -c "source <snapshot> ... && eval '<cmd>'"
is_claude = lambda c: bool(re.search(r"(^|/)claude( |$)", c)) and not any(x in c for x in ("bg-pty", "daemon", "remote-control"))
_pst = [0, {}]
def ps_table(age=5):
    """pid -> [ppid, uid, seconds running, cpu %, rss KB, command, start time]: one ps for every pane, reused for `age` seconds."""
    if time.time() - _pst[0] >= age:
        t = {}
        for l in run("ps", "-axo", "pid=,ppid=,uid=,etime=,%cpu=,rss=,lstart=,command=").splitlines():
            p = l.split(None, 11)
            if len(p) == 12 and p[0].isdigit():
                e = [0, 0, 0, 0] + [int(x) for x in re.split(r"[-:]", p[3])]  # [[dd-]hh:]mm:ss
                t[int(p[0])] = [int(p[1]), int(p[2]), ((e[-4] * 24 + e[-3]) * 60 + e[-2]) * 60 + e[-1], float(p[4]), int(p[5]), p[11], " ".join(p[6:11])]
        _pst[:] = [time.time(), t]
    return _pst[1]

def kids_of(t):
    k = {}
    for p, v in t.items(): k.setdefault(v[0], []).append(p)
    return k

def subtree(k, root):
    out, st = [], [root]
    while st:
        for c in k.get(st.pop(), []): out.append(c); st.append(c)
    return out

def chat_pid(t, k, root):
    """A pane's chat: the outermost claude under the pane's shell, the same rule as _live_sessions."""
    cl = [p for p in [root] + subtree(k, root) if p in t and is_claude(t[p][5])]
    return next((p for p in cl if t[p][0] not in cl), None)

def pane_roots():
    out = {}
    for sock in sockets():
        for l in run("tmux", "-L", sock, "list-panes", "-a", "-F", "#{pane_id} #{pane_pid}").splitlines():
            a, _, b = l.partition(" ")
            if a.startswith("%") and b.isdigit(): out[f"{sock}.{a[1:]}"] = int(b)
    return out

def shell_cmd(c):
    m = re.search(r"&& eval '((?:[^']|'\"'\"'|'\\'')*)'", c)  # the command Claude asked for, out of the Bash tool's wrapper
    return (m.group(1).replace("'\"'\"'", "'").replace("'\\''", "'") if m else c).replace("\\012", "\n").strip()

_seen, _envc = {}, {}  # (pid, start time) -> chat pid: seen under a chat's shell command / named by its CLAUDE_PID (0: none)
def detached(t, k, chats):
    """chat pid -> its processes that launchd has adopted (nohup ... &, disown, setsid): seen under the chat before with the
    same start time, or with the chat's CLAUDE_PID in its own or a child's environment. Both, as ps -E can't read Apple's
    own binaries (sleep, bash) and a process started and orphaned between two looks is never seen attached."""
    for d in (_seen, _envc):
        for x in [x for x in list(d) if x[0] not in t or t[x[0]][6] != x[1]]: d.pop(x, None)
    if not chats: return {}
    me, age = os.getuid(), max(t[c][2] for c in chats)
    roots = [p for p, v in t.items() if v[0] == 1 and v[1] == me and v[2] <= age]  # no older than the oldest chat
    new = [p for r in roots for p in [r] + k.get(r, []) if (p, t[p][6]) not in _envc]
    if new:  # a process's environment never changes, so each is read once
        env = {}
        for l in run("ps", "-ww", "-E", "-o", "pid=,command=", "-p", ",".join(map(str, new))).splitlines():
            a, _, rest = l.strip().partition(" "); m = re.findall(r" CLAUDE_PID=(\d+)", rest); ag = re.findall(r" AI_AGENT=(\S+)", rest)
            if a.isdigit() and m and not (ag and ag[-1].endswith("_harness")): env[int(a)] = int(m[-1])  # the last: env follows the command
        for p in new: _envc[(p, t[p][6])] = env.get(p, 0)
    out = {}
    for r in roots:
        c = _seen.get((r, t[r][6])) or next((_envc[(x, t[x][6])] for x in [r] + k.get(r, []) if _envc.get((x, t[x][6]))), 0)
        if c in chats and t[c][2] >= t[r][2]: out.setdefault(c, []).append(r)  # a chat younger than the process is a reused pid
    return out

def chat_procs(t, k, c, det=()):
    """(shell commands, helpers) started by the claude process c, each with its whole tree's CPU and memory; det: its detached ones."""
    sh, hl = [], []
    for p in k.get(c, []) + list(det):
        sub = subtree(k, p); v = t[p]
        r = {"pid": p, "secs": v[2], "cpu": round(sum(t[x][3] for x in [p] + sub), 1), "mem": sum(t[x][4] for x in [p] + sub)}
        if p in det or SNAP in v[5]:
            for x in [p] + sub if p not in det else (): _seen[(x, t[x][6])] = c
            r.update(cmd=shell_cmd(v[5])[:4000], kids=[{"pid": x, "secs": t[x][2], "cpu": t[x][3], "cmd": t[x][5][:300].replace("\\012", " ")} for x in sub if SNAP not in t[x][5]][:30],
                     **({"detached": True} if p in det else {}))
            sh.append(r)
        else: hl.append({**r, "cmd": v[5][:300].strip(), "n": len(sub)})
    return sorted(sh, key=lambda r: -r["secs"]), hl

_psum = [0, {}]
def proc_summary():
    """pane -> {procs, longest, cpu} for the chat list: one ps and one tmux list per socket, every 5 s at most."""
    if time.time() - _psum[0] >= 5:
        t, out = ps_table(), {}; k = kids_of(t)
        cs = {pane: c for pane, root in pane_roots().items() if (c := chat_pid(t, k, root))}
        det = detached(t, k, set(cs.values()))
        for pane, c in cs.items():
            sh = chat_procs(t, k, c, det.get(c, []))[0]
            if sh: out[pane] = {"procs": len(sh), "longest": sh[0]["secs"], "cpu": round(sum(r["cpu"] for r in sh))}
        _psum[:] = [time.time(), out]
    return _psum[1]

def procs_view(pane):
    t = ps_table(1); k = kids_of(t); root = tm(pane, "display", "-p", "-t", "{P}", "#{pane_pid}").strip()
    c = chat_pid(t, k, int(root)) if root.isdigit() else None
    sh, hl = chat_procs(t, k, c, detached(t, k, {c}).get(c, [])) if c else ([], [])
    s = next((x for x in live_sessions() if x["pane"] == pane), {}); f = s.get("session") and find_file(s["session"])
    foot = tm(pane, "capture-pane", "-p", "-t", "{P}").split("─" * 20)[-1]  # below the input box: "· 2 shells"
    n = re.search(r"(\d+) shells?\b", foot)
    return {"pid": c, "procs": sh, "helpers": hl, "shells": int(n.group(1)) if n else 0, "state": s.get("state"),
            "agents": [{"id": a["id"], "desc": a["desc"], "first": a["first"]} for a in (agents(f) if f else []) if a["running"]]}

def stop_proc(pane, pid):
    """SIGTERM a chat's background process and everything under it, then SIGKILL what is left after 3 s.
    The pid must be under that pane's claude process right now, or in a tree launchd adopted from it whose root still has the
    remembered start time (checked here, not taken from the list), and be this user's."""
    import signal
    t = ps_table(0); k = kids_of(t); root = tm(pane, "display", "-p", "-t", "{P}", "#{pane_pid}").strip()
    c = chat_pid(t, k, int(root)) if root.isdigit() else None
    ok = subtree(k, c) + [x for r in detached(t, k, {c}).get(c, []) for x in [r] + subtree(k, r)] if c else []
    if pid not in ok or t[pid][1] != os.getuid():
        return {"error": "That isn't one of this chat's processes."}
    tree = {x: t[x][5].strip() for x in [pid] + subtree(k, pid) if t[x][1] == os.getuid()}
    def left():  # still running under the same command, so a reused pid is never hit
        return [int(p) for p, _, cm in (l.strip().partition(" ") for l in run("ps", "-o", "pid=,command=", "-p", ",".join(map(str, tree))).splitlines())
                if p.isdigit() and tree.get(int(p)) == cm.strip()]
    for x in reversed(list(tree)):
        try: os.kill(x, signal.SIGTERM)
        except OSError: pass
    for _ in range(12):
        time.sleep(0.25); rest = left()
        if not rest: break
    for x in rest:
        try: os.kill(x, signal.SIGKILL)
        except OSError: pass
    _psum[0] = 0
    return {"ok": True, "pid": pid, "stopped": len(tree), "forced": len(rest), "gone": not left()}

_files = {}  # cwd -> (when, paths): typing @abc asks once per keystroke pause
def files(cwd, q, limit=30):
    """Paths under cwd matching q for @ autocomplete: rg --files (respects .gitignore), cut off after 2 s on huge folders."""
    if time.time() - _files.get(cwd, (0,))[0] > 20:
        try: out = subprocess.run(["rg", "--files", "--max-depth", "12"], cwd=cwd, capture_output=True, text=True, timeout=2).stdout
        except subprocess.TimeoutExpired as e: out = e.stdout or ""
        out = out.decode("utf8", "ignore") if isinstance(out, bytes) else out
        _files.clear(); _files[cwd] = (time.time(), out.splitlines()[:200000])
    ps = _files[cwd][1]; ql = q.lower()
    hit = [p for p in ps if ql in p.lower()]
    hit += [d for d in sorted({p[:i + 1] for p in hit for i, ch in enumerate(p) if ch == "/"}) if ql in d.lower()]
    base = lambda p: p.rstrip("/").rsplit("/", 1)[-1].lower()
    return sorted(hit, key=lambda p: (not base(p).startswith(ql), ql not in base(p), len(p)))[:limit]

def valid_pane(p):
    return p in {s["pane"] for s in live_sessions()}

def chat_cwd(key):
    """Folder of a live pane or a saved chat. Git only ever runs in one of these, never in a path the client names."""
    if re.fullmatch(PANE_RE, key): c = next((s["cwd"] for s in live_sessions() if s["pane"] == key), None)
    else: f = find_file(key); c = f and cached(f, file_cwd)
    return c if c and os.path.isdir(c) else None

def git(cwd, *a, cap=1_000_000):
    """Read-only git: (returncode, text). Killed after 5 s, or once the output passes cap (then the text is cut)."""
    p = subprocess.Popen(["git", "--no-optional-locks", "-c", "core.quotepath=off", "-c", "core.fsmonitor=false", "-C", cwd, *a],
                         stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    t = threading.Timer(5, p.kill); t.start()
    out = p.stdout.read(cap + 1)
    if len(out) > cap: p.kill()
    rc = p.wait(); t.cancel(); p.stdout.close()
    return (0 if len(out) > cap else rc), out[:cap].decode("utf8", "replace")

def changes(cwd, limit=300):
    rc, top = git(cwd, "rev-parse", "--show-toplevel")
    if rc: return {"error": "This folder isn't in a git repository."}
    top = top.strip()
    rc, st = git(top, "status", "--porcelain=v1", "-z", "-b", "-uall")
    if rc: return {"error": "git status didn't finish."}
    head = [] if git(top, "rev-parse", "-q", "--verify", "HEAD")[0] else ["HEAD"]  # a repo with no commits yet has no HEAD
    t, nums, i = git(top, "diff", "--numstat", "-z", "--no-ext-diff", "--no-textconv", *head)[1].split("\0"), {}, 0
    while i < len(t) - 1:  # "add\tdel\tpath", or "add\tdel\t" then old and new paths for a rename
        a, d, p = (t[i].split("\t") + ["", ""])[:3]
        if not p: p = t[i + 2] if i + 2 < len(t) else ""; i += 2
        nums[p] = (a, d); i += 1
    e, files, branch, i = st.split("\0"), [], None, 0
    while i < len(e):
        x = e[i]; i += 1
        if x.startswith("## "): branch = x[3:]; continue
        if len(x) < 4: continue
        old = e[i] if x[0] in "RC" and i < len(e) else None  # the old path follows a rename or copy
        if old is not None: i += 1
        p, a, d = x[3:], *nums.get(x[3:], (None, None))
        if x[:2] == "??" and len(files) < limit:
            try: b = Path(top, p).read_bytes()[:200_000] if not Path(top, p).is_symlink() else b""
            except Exception: b = b""
            a, d = (None, None) if b"\0" in b else (b.count(b"\n") + (1 if b and not b.endswith(b"\n") else 0), 0)
        files.append({"path": p, "st": x[:2], **({"from": old} if old else {}), "add": int(a) if str(a).isdigit() else None, "del": int(d) if str(d).isdigit() else None})
    return {"root": top, "branch": branch, "files": files[:limit], "more": max(0, len(files) - limit), "head": bool(head)}

def change_diff(cwd, path):
    c = changes(cwd)
    if c.get("error"): return c
    f = next((x for x in c["files"] if x["path"] == path), None)  # only a path git itself reported, so no traversal
    if not f: return {"error": "This file has no uncommitted changes now."}
    p = Path(c["root"], path)
    if f["st"] == "??":
        if p.is_symlink(): lines = ["@symlink to " + os.readlink(p)]
        else:
            try: b = p.read_bytes()[:400_000]
            except Exception: return {"error": "Can't read this file."}
            lines = ["@binary file"] if b"\0" in b else ["+" + l for l in b.decode("utf8", "replace").splitlines()]
    else:
        lines, body = ["@renamed from " + f["from"]] if f.get("from") else [], False
        for l in git(c["root"], "diff", "-M", "--no-ext-diff", "--no-textconv", "--no-color", *(["HEAD"] if c["head"] else []), "--", *([f["from"]] if f.get("from") else []), path)[1].split("\n"):
            if l.startswith("@@"): body = True; lines.append("@" + l)
            elif l.startswith("Binary files"): lines.append("@binary file changed")
            elif body and l and l[0] in "+- ": lines.append(l)
            elif l.startswith("diff --git"): body = False
    d, cut = clip(lines, 5000, 1_500_000, 5000)
    return {"path": path, "diff": d, "cut": cut, "add": f["add"], "del": f["del"]}
# --- Web Push (RFC 8291 aes128gcm + RFC 8292 VAPID) and the attention watcher ---
import base64, hashlib, hmac, struct, urllib.request, urllib.error
PUSH_FILE = HOME / "Library/Application Support/session-deck/push.json"
VAPID_SUB = os.environ.get("DECK_VAPID_SUB", "mailto:deck@example.com")
PUSH_HOSTS = {"web.push.apple.com", "fcm.googleapis.com", "push.services.mozilla.com"} | set(filter(None, os.environ.get("DECK_PUSH_HOSTS", "").split(",")))
PWA = {"/manifest.webmanifest": "application/manifest+json", "/sw.js": "text/javascript; charset=utf-8", **{f"/icons/{n}.png": "image/png" for n in ("180", "192", "512", "maskable-512")}}
SEEN, WATCH, _push_lock = {}, {}, threading.Lock()  # pane -> last /api/status poll; pane -> watcher state
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
unb64u = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
_hm = lambda k, m: hmac.new(k, m, hashlib.sha256).digest()

def _ec():
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization as ser
    return ec, ser

_vapid = []
def vapid():
    """(private key, public key bytes), from the deck's secrets file."""
    if not _vapid:
        ec, ser = _ec()
        k = ser.load_pem_private_key(SEC["vapid_pem"].encode(), None)
        _vapid.append((k, k.public_key().public_bytes(ser.Encoding.X962, ser.PublicFormat.UncompressedPoint)))
    return _vapid[0]

def encrypt(p256dh, auth, data, salt=None, sk=None):
    ec, ser = _ec()
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    sk, salt, ua = sk or ec.generate_private_key(ec.SECP256R1()), salt or os.urandom(16), unb64u(p256dh)
    asp = sk.public_key().public_bytes(ser.Encoding.X962, ser.PublicFormat.UncompressedPoint)
    ikm = _hm(_hm(unb64u(auth), sk.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua))), b"WebPush: info\0" + ua + asp + b"\1")
    prk = _hm(salt, ikm)
    cek, nonce = _hm(prk, b"Content-Encoding: aes128gcm\0\1")[:16], _hm(prk, b"Content-Encoding: nonce\0\1")[:12]
    return salt + struct.pack(">IB", 4096, len(asp)) + asp + AESGCM(cek).encrypt(nonce, data + b"\2", None)

def vapid_header(endpoint):
    ec, _ = _ec()
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    k, pub = vapid(); u = urllib.parse.urlsplit(endpoint)
    seg = lambda o: b64u(json.dumps(o, separators=(",", ":")).encode())
    msg = seg({"typ": "JWT", "alg": "ES256"}) + "." + seg({"aud": f"{u.scheme}://{u.netloc}", "exp": int(time.time()) + 43200, "sub": VAPID_SUB})
    r, s = decode_dss_signature(k.sign(msg.encode(), ec.ECDSA(hashes.SHA256())))
    return f"vapid t={msg}.{b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}, k={b64u(pub)}"

def push_ok(endpoint):  # only known push services, so a subscription can't make this Mac post anywhere else
    u = urllib.parse.urlsplit(str(endpoint)); h = u.hostname or ""
    return any(h == x or h.endswith("." + x) for x in PUSH_HOSTS) and (u.scheme == "https" or h == "127.0.0.1")

def push_subs():
    try: return json.loads(PUSH_FILE.read_text()).get("subs", [])
    except Exception: return []

def save_subs(subs):
    PUSH_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = PUSH_FILE.with_suffix(".tmp"); tmp.write_text(json.dumps({"subs": subs}, indent=1)); tmp.replace(PUSH_FILE)

def push_one(sub, msg):
    if not push_ok(sub.get("endpoint")) or not vapid(): return 0
    body = encrypt(sub["keys"]["p256dh"], sub["keys"]["auth"], json.dumps(msg).encode())
    req = urllib.request.Request(sub["endpoint"], data=body, method="POST", headers={
        "TTL": "3600", "Urgency": "high", "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream",
        "Authorization": vapid_header(sub["endpoint"])})
    try:
        with urllib.request.urlopen(req, timeout=10) as r: return r.status
    except urllib.error.HTTPError as e:
        print("push:", e.code, e.read(300).decode("utf8", "replace"), flush=True); return e.code
    except Exception as e:
        print("push:", e, flush=True); return 0

VIEW = {}  # (pane, device id) -> when that device last had the chat open and in focus
DEV_RE = re.compile(r"[\w-]{8,40}")
def push_all(msg, skip=()):
    """Sends to every device with notifications on, except those in skip (device ids). [(sub, code or None if skipped)]"""
    with _push_lock:
        subs = push_subs(); res = [(s, None if s.get("dev") in skip else push_one(s, msg)) for s in subs]
        if any(c in (404, 410) for _, c in res): save_subs([s for s, c in res if c not in (404, 410)])
    return res

def attn(s):
    if s["state"] == "waiting" or s["menu"]: return "needs"
    return "done" if WATCH.get(s["pane"], {}).get("fin", 0) > SEEN.get(s["pane"], 0) else None

def last_reply(sid):
    f = sid and find_file(sid)
    for it in reversed(messages(f, 30) if f else []):
        if it["role"] == "assistant" and it["kind"] == "text":
            t = re.sub(r"\s+", " ", re.sub(r"[#*_`>|]+", "", it["text"])).strip()
            return t if len(t) <= 140 else t[:139] + "…"

def watch_once():
    now, live = time.time(), live_sessions()
    for s in live:
        p, st = s["pane"], s["state"]
        busy = st in ("busy", "waiting") if st else s["working"]
        a = attn(s); w = WATCH.get(p)
        if w is None:  # first sight (or a restart): no notice for what was already on screen
            WATCH[p] = {"busy": now if busy else None, "need": a == "needs", "fin": 0, "sent": {}}; continue
        msg = None
        if a == "needs" and not w["need"]:
            q = (s["menu"] or {}).get("question") or "Claude is waiting for your answer."
            msg = {"kind": "needs", "body": "Needs you: " + (q if len(q) <= 128 else q[:127] + "…")}
        elif w["busy"] and not busy and a != "needs":
            w["fin"] = now
            if now - w["busy"] >= 20: msg = {"kind": "done", "body": last_reply(s["session"]) or "Finished."}
        if busy and not w["busy"]: w["fin"] = 0  # a new turn: the old reply is no longer the news
        w["need"], w["busy"] = a == "needs", (w["busy"] or now) if busy else None
        if not msg: continue
        viewers = {d for (vp, d), t in VIEW.items() if vp == p and now - t < 8}  # only the device looking at it is spared
        dup = now - w["sent"].get(msg["body"], 0) < 60
        print(f"push {msg['kind']} {p} {s['title'] or s['name']!r}: {msg['body'][:80]!r}" + (" (skipped: repeat)" if dup else ""), flush=True)
        if dup: continue
        w["sent"] = {k: v for k, v in w["sent"].items() if now - v < 60} | {msg["body"]: now}
        n = sum(attn(x) is not None for x in live)
        if push_subs(): print("  ->", [(x.get("name") or "?", c) for x, c in push_all({"title": s["title"] or s["name"], "body": msg["body"], "pane": p, "n": n}, viewers)], flush=True)
    for p in [p for p in WATCH if p not in {s["pane"] for s in live}]: del WATCH[p]

def end_chat(pane):
    """/exit in the pane, after clearing a question or a draft. Claude may still ask something first."""
    s = pane_screen(pane)
    if s["menu"] or s["working"]: tm(pane, "send-keys", "-t", "{P}", "Escape"); time.sleep(0.8)
    tm(pane, "send-keys", "-t", "{P}", "C-c"); time.sleep(0.3)  # clears a draft (or a prompt Escape put back) so /exit is typed alone
    tm(pane, "set-buffer", "-b", "deck", "/exit"); tm(pane, "paste-buffer", "-p", "-d", "-b", "deck", "-t", "{P}")
    time.sleep(0.15); tm(pane, "send-keys", "-t", "{P}", "Enter")

SIRI, SIRI_LOCK = {}, threading.Lock()  # "pane": the Siri chat
def siri_name():  # what the user calls it: "Hey Siri, Ask <name>"; also the chat's name
    try: n = json.loads((PREFS.with_name("siri.json")).read_text()).get("name")
    except Exception: n = None
    return n if isinstance(n, str) and re.fullmatch(r"[\w' -]{1,30}", n) else "Deck"
def siri_prompt(name):
    return (f"You are {name}. The user is speaking to you through Siri on their phone, and your last message of each turn is read aloud "
            "to them. Do what they ask, then end with one to three short sentences of plain spoken text: no markdown, lists, code, "
            "file paths or links. Ask one short question if you must. Long jobs are fine: they get a notification when you finish.")

def siri_pane():
    """The Siri chat's pane: a live chat with the Siri name (the one this deck started first), else a new one in the folders root."""
    live, name = live_sessions(), siri_name()
    s = next((x for x in live if x["pane"] == SIRI.get("pane") and x["name"] == name), None) or next((x for x in live if x["name"] == name), None)
    if s: SIRI["pane"] = s["pane"]; return s["pane"]
    eng = next((k for k in ENGINES if engine_exe(k)), None)
    p = eng and start(str(FOLDERS), eng, None, name=name, system=siri_prompt(name))
    if not p: return None
    SIRI["pane"] = p
    for _ in range(40):  # until Claude is running in it
        _live[0] = 0
        if any(x["pane"] == p for x in live_sessions()): break
        time.sleep(0.5)
    return p

def spoken(t, n=600):
    """Claude's reply as something Siri can read out: no markdown, code or links, cut at a sentence."""
    t = re.sub(r"```.*?```", " ", t, flags=re.S)
    t = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", t)
    t = re.sub(r"https?://\S+", "a link", t)
    t = re.sub(r"^\s*(?:#+|[-*+]|\d+\.)\s+", "", t, flags=re.M)
    t = re.sub(r"\s+", " ", re.sub(r"[`*_#>|]+", "", t)).strip()
    return t if len(t) <= n else t[:n].rsplit(". ", 1)[0].rstrip(".") + ". The rest is in Session Deck."

def siri_ask(text, wait):
    """Sends text to the Siri chat and waits up to wait seconds for the turn to end. Returns what Siri should say."""
    with SIRI_LOCK: pane = siri_pane()
    if not pane: return "I couldn't start a chat on the Mac."
    if pane_screen(pane)["menu"]: return "Claude is waiting for you to answer a question in Session Deck."
    deliver(pane, text); end, idle = time.time() + wait, 0
    while time.time() < end:
        time.sleep(1)
        sc = pane_screen(pane)
        if sc["menu"]: return "Claude needs you to answer a question in Session Deck: " + spoken(sc["menu"].get("question") or "", 200)
        sid = next((x["session"] for x in live_sessions() if x["pane"] == pane), None); f = sid and find_file(sid)
        items = messages(f, 40) if f else []
        i = next((i for i in range(len(items) - 1, -1, -1) if items[i]["role"] == "user" and not items[i].get("queued") and items[i]["text"].strip() == text.strip()), None)
        said = [x["text"] for x in items[i + 1:] if x["role"] == "assistant" and x["kind"] == "text"] if i is not None else []
        idle = idle + 1 if said and not sc["working"] else 0
        if idle >= 2: return spoken(said[-1])  # idle twice in a row: the turn is over
    return f"{siri_name()} is working on it. You'll get a notification when it's done."

IDLE_END = float(os.environ.get("DECK_IDLE_END_DAYS", "3")) * 86400  # 0 turns it off
def idle_sweep():
    """Ends chats with no activity (nothing written to the transcript) for IDLE_END. Leaves pinned chats, ones that are
    working, and ones with background shells or subagents still running. They stay in History to resume."""
    if not IDLE_END: return
    pins = {x.get("id") for x in prefs()["pins"] if x.get("type") == "chat"}
    for s in live_sessions():
        if not s.get("session") or s["session"] in pins or s["working"] or time.time() - (s.get("mtime") or time.time()) < IDLE_END: continue
        pv = procs_view(s["pane"])
        if pv["procs"] or pv["shells"] or pv["agents"]: continue
        print(f"idle-end {s['pane']} {s['title'] or s['name']!r}: no activity for {(time.time() - s['mtime']) / 86400:.1f} days", flush=True)
        end_chat(s["pane"]); _live[0] = 0

def idler():
    while True:
        time.sleep(600)
        try: idle_sweep()
        except Exception as e: print("idle-end:", e, flush=True)

def watcher():
    while True:
        time.sleep(2)
        try: watch_once(); proc_summary()  # the summary also remembers each chat's processes, for when launchd adopts them
        except Exception as e: print("watcher:", e, flush=True)
UPL = HOME / "Library" / "Caches" / "session-deck" / "uploads"
UP_MAX, NAMES = 1 << 30, {}  # NAMES: saved path -> the file's name on the phone, for the "Attached:" line
IMG = {"png", "jpg", "gif", "webp"}  # what Claude Code turns into an [Image #N] when its path is pasted
TXT = {"txt", "csv", "tsv", "json", "md", "log", "xml", "html", "yaml", "yml", "py", "js", "ts", "sql", "sh", "swift"}

def sniff(b, name):
    """Extension for an upload from its first bytes; the name only picks between text types. None = not allowed."""
    if b.startswith(b"\x89PNG\r\n\x1a\n"): return "png"
    if b.startswith(b"\xff\xd8\xff"): return "jpg"
    if b[:6] in (b"GIF87a", b"GIF89a"): return "gif"
    if b[:4] == b"RIFF" and b[8:12] == b"WEBP": return "webp"
    if b[4:8] == b"ftyp" and b[8:12] in (b"heic", b"heix", b"hevc", b"heim", b"heis", b"mif1", b"msf1"): return "heic"
    if b.startswith(b"%PDF-"): return "pdf"
    if b[:4] in (b"PK\x03\x04", b"PK\x05\x06"): return "zip"  # docx, xlsx and pptx are told apart once saved
    if b"\0" in b: return None
    import codecs
    try: codecs.getincrementaldecoder("utf8")().decode(b)  # a character cut at the end of the chunk is fine
    except UnicodeDecodeError: return None
    ext = name.rsplit(".", 1)[-1].lower()
    return ext if ext in TXT else "txt"

def office(p):
    import zipfile
    try: n = zipfile.ZipFile(p).namelist()
    except Exception: return "zip"
    return next((e for d, e in (("word/", "docx"), ("xl/", "xlsx"), ("ppt/", "pptx")) if any(x.startswith(d) for x in n)), "zip")

def attached(fs):
    """Uploaded files named in a send, or None if any is not a file in the uploads folder."""
    if not isinstance(fs, list) or len(fs) > 20: return None
    out = [Path(str(x)).resolve() for x in fs]
    return out if all(UPL.resolve() in p.parents and p.is_file() for p in out) else None

def human(n):
    return f"{n / 1048576:.1f} MB" if n >= 1048576 else f"{max(1, round(n / 1024))} KB"

def tidy_uploads():
    """Uploads go after 14 days, and the oldest go first while the folder is over 10 GB."""
    fs = sorted((f for f in UPL.rglob("*") if f.is_file()), key=lambda f: f.stat().st_mtime) if UPL.exists() else []
    total = sum(f.stat().st_size for f in fs)
    for f in fs:
        if time.time() - f.stat().st_mtime > 14 * 86400 or total > 10 << 30:
            total -= f.stat().st_size; f.unlink(missing_ok=True); NAMES.pop(str(f), None)
    for d in UPL.glob("*"):
        if d.is_dir() and d.name != time.strftime("%Y-%m-%d") and not any(d.iterdir()): d.rmdir()

def tidy_loop():
    while True:
        try: tidy_uploads()
        except Exception: pass
        time.sleep(3600)
# --- Schedule page: this account's launchd jobs, the Mac's own (LaunchDaemons, admins only, read-only), and the loops (CronCreate) inside live chats ---
import plistlib, datetime, grp, pwd
AGENTS, DOM = HOME / "Library/LaunchAgents", f"gui/{os.getuid()}"
DAEMONS = Path("/Library/LaunchDaemons")
def is_admin():
    try: return pwd.getpwuid(os.getuid()).pw_name in grp.getgrnam("admin").gr_mem
    except KeyError: return False
ADMIN = is_admin()  # only an admin's deck lists the Mac's own jobs; other accounts' decks never see them
DDIR = HOME / "Library/Application Support/session-deck"
JOB_INFO = DDIR / "jobs.json"  # the owner's own names and one-line descriptions, {label: {"name", "about"}}; kept out of the repo
RUNS_FILE = DDIR / "job-runs.json"  # {label: [launchd's run count, when the deck saw it go up]}, kept by run_watch
def _rd(f):
    try: d = json.loads(f.read_text()); return d if isinstance(d, dict) else {}
    except (OSError, ValueError): return {}
RUNS = _rd(RUNS_FILE)
VENDOR = ("com.apple.", "com.google.", "com.microsoft.", "com.adobe.", "homebrew.", "us.zoom.")  # other apps' agents: not yours to run
SELF = "local.session-deck"  # the deck's own job is never run or paused from the deck
WD, MON = ["Sundays", "Mondays", "Tuesdays", "Wednesdays", "Thursdays", "Fridays", "Saturdays"], "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
ordn = lambda n: f"{n}{'th' if 10 <= n % 100 <= 20 else {1: 'st', 2: 'nd', 3: 'rd'}.get(n % 10, 'th')}"
cal = lambda s: [d for d in (s if isinstance(s, list) else [s]) if isinstance(d, dict)]
both = lambda a: ", ".join(a[:-1]) + " and " + a[-1] if len(a) > 1 else a[0]

def every(s):
    for n, u in ((86400, "day"), (3600, "hour"), (60, "minute"), (1, "second")):
        if s >= n and s % n == 0: return f"Every {u}" if s == n else f"Every {s // n} {u}s"
    return "Every few seconds"

def cal_words(sci):
    """StartCalendarInterval in words: "Daily at 07:30 and 19:00", "Mondays at 07:00", "3rd of each month at 07:00"."""
    by = {}
    for d in cal(sci):
        h, m, dd, wd, mo = (d.get(k) for k in ("Hour", "Minute", "Day", "Weekday", "Month"))
        day = ((f"{dd} {MON[mo - 1]}", " each year") if mo and dd else (f"Every day in {MON[mo - 1]}", "") if mo else
               (f"{ordn(dd)} of each month or {WD[wd % 7]}", "") if dd and wd is not None else (ordn(dd), " of each month") if dd else
               (WD[wd % 7], "") if wd is not None else ("Hourly" if h is None and m is not None else "Daily", ""))
        by.setdefault(day, set()).add(f"{h:02}:{m or 0:02}" if h is not None else f":{m:02}" if m is not None else "every minute")
    merged = {}
    for (head, tail), ts in by.items(): merged.setdefault((tail, tuple(sorted(ts))), []).append(head)
    return "; ".join(f"{both(hs)}{tail} at {both(list(ts))}".replace("Daily at every minute", "Every minute").replace(" at every minute", ", every minute")
                     for (tail, ts), hs in merged.items()) or "Every minute"

def next_run(sci):
    now, best = datetime.datetime.now().replace(second=0, microsecond=0), None
    for d in cal(sci):
        g = lambda k: d.get(k) if isinstance(d.get(k), int) else None
        for i in range(400):
            day = now.date() + datetime.timedelta(days=i)
            dd, wd = g("Day"), g("Weekday")
            od, ow = dd is None or day.day == dd, wd is None or day.isoweekday() % 7 == wd % 7
            if (g("Month") and day.month != g("Month")) or not ((od or ow) if dd is not None and wd is not None else od and ow): continue
            t = next((x for h in ([g("Hour")] if g("Hour") is not None else range(24)) for m in ([g("Minute")] if g("Minute") is not None else range(60))
                      if (x := datetime.datetime.combine(day, datetime.time(h % 24, m % 60))) > now), None)
            if t: best = min(best or t, t); break
    return best.timestamp() if best else None

def lc(*a):
    r = subprocess.run(["launchctl", *a], capture_output=True, text=True, timeout=10)
    return r.returncode, (r.stdout + r.stderr).strip()

def short_cmd(argv):
    a = [x.replace(str(HOME), "~") for x in argv]
    if len(a) > 1 and os.path.basename(a[0]) in {"bash", "sh", "zsh", "env", "python", "python3", "node", "perl", "ruby", "osascript", "uv"}:
        a = a[1:]  # bash run.sh: the script is what it runs
        while len(a) > 1 and a[0].startswith("-"): a.pop(0)
    s = " ".join([os.path.basename(a[0]) if "/" in a[0] and " " not in a[0] else a[0], *a[1:]]) if a else ""
    return s if len(s) <= 90 else s[:89] + "…"

_jobs = [0, None]
def jobs(fresh=False):
    """This account's LaunchAgents with launchd's state for each. A deck running for an account that isn't logged in at the
    Mac has no gui domain: its jobs show as not loaded."""
    if not fresh and _jobs[1] is not None and time.time() - _jobs[0] < 8: return _jobs[1]
    off = set(re.findall(r'"([^"]+)" => (?:disabled|true)', lc("print-disabled", DOM)[1]))
    out, info = [], _rd(JOB_INFO)
    for p, dom in [*((p, DOM) for p in sorted(AGENTS.glob("*.plist"))), *((p, "system") for p in (sorted(DAEMONS.glob("*.plist")) if ADMIN else []))]:
        try: d = plistlib.loads(p.read_bytes())
        except Exception: continue
        label = d.get("Label") if isinstance(d, dict) else None
        if not isinstance(label, str) or not re.fullmatch(r"[\w.@-]{1,200}", label) or label.startswith(VENDOR): continue
        argv = d.get("ProgramArguments") or [d.get("Program")]
        argv = [str(x) for x in argv if x is not None] if isinstance(argv, list) else []
        logs = list(dict.fromkeys(os.path.expanduser(x) for x in (d.get("StandardOutPath"), d.get("StandardErrorPath")) if isinstance(x, str)))
        rc, pr = lc("print", f"{dom}/{label}")
        g = lambda k: (re.search(rf"^\t{k} = (.+)$", pr, re.M) or [None, None])[1] if not rc else None
        ex = re.match(r"-?\d+", g("last exit code") or ""); sci, si = d.get("StartCalendarInterval"), d.get("StartInterval")
        trig = [w for k, w in (("KeepAlive", "Kept running"), ("RunAtLoad", "At startup" if dom == "system" else "At login"), ("WatchPaths", "When files change"),
                               ("QueueDirectories", "When files arrive"), ("StartOnMount", "When a disk mounts")) if d.get(k)]
        keep = bool(d.get("KeepAlive"))  # kept running (StartInterval then only restarts it): a service, not a schedule
        when = cal_words(sci) if cal(sci) else every(si) if isinstance(si, int) and si > 0 and not keep else " · ".join(trig) or "Only when started"
        if (cal(sci) or si and not keep) and d.get("RunAtLoad"): when += ", and at startup" if dom == "system" else ", and at login"
        inf = info.get(label) if isinstance(info.get(label), dict) else {}
        seen = (RUNS.get(label) or [0, None])[1]
        out.append({"label": label, "name": str(inf.get("name") or "")[:80] or (d.get("Comment") if isinstance(d.get("Comment"), str) else
                    re.sub(r"^(sh\.brew|homebrew\.mxcl|local|com|org|net|io|dev|app|uk|me)\.", "", label).replace(".", " ").replace("-", " ").replace("_", " ").capitalize()),
                    "about": str(inf.get("about") or "")[:300] or None,
                    "kind": "sched" if (cal(sci) or si) and not keep else "service", "cal": bool(cal(sci)), "when": when, "next": next_run(sci) if cal(sci) else None,
                    "cmd": short_cmd(argv), "argv": " ".join(x.replace(str(HOME), "~") for x in argv)[:2000], "plist": str(p).replace(str(HOME), "~"),
                    "last": max([os.stat(x).st_mtime for x in logs if os.path.isfile(x)] + [seen] * isinstance(seen, (int, float)), default=None), "loaded": not rc,
                    "running": (g("pid") or "").isdigit(), "runs": int(g("runs")) if (g("runs") or "").isdigit() else None,
                    "exit": int(ex.group()) if ex else None, "paused": dom == DOM and label in off, "self": label.startswith(SELF), "system": dom == "system",
                    "_plist": str(p), "_logs": logs})
    _jobs[:] = [time.time(), out]; return out

def run_watch():
    """launchd keeps no start time, only a run count, so once a minute the deck notes when each job's count went up.
    A log's time alone misleads: many jobs only write when they find something to do."""
    while True:
        try:
            ch = False
            for j in jobs(True):
                n, prev = j["runs"], RUNS.get(j["label"])
                if not isinstance(n, int) or (prev and prev[0] == n): continue
                RUNS[j["label"]] = [n, time.time() if prev and n > prev[0] else (prev or [0, None])[1]]; ch = True  # first sight or a reload: no time
            if ch:
                DDIR.mkdir(parents=True, exist_ok=True); t = RUNS_FILE.with_suffix(".tmp"); t.write_text(json.dumps(RUNS)); t.replace(RUNS_FILE)
        except Exception as e: print("run-watch:", e, flush=True)
        time.sleep(60)

def job(label):
    return next((j for j in jobs(True) if j["label"] == label), None) if isinstance(label, str) else None

def job_log(label, n=80, cap=65536):
    """The last n lines of the job's own log files (from its plist, never from the request), read-only and size-capped."""
    j = job(label)
    if not j: return None
    out = []
    for p in j["_logs"]:
        try:
            if not os.path.isfile(p): raise OSError
            with open(p, "rb") as fh:
                size = fh.seek(0, 2); fh.seek(max(0, size - cap)); ls = fh.read().decode("utf8", "replace").splitlines()[1 if size > cap else 0:]
            out.append({"path": p.replace(str(HOME), "~"), "text": re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", "\n".join(ls[-n:]))})
        except OSError: out.append({"path": p.replace(str(HOME), "~"), "text": None})
    return {"label": label, "logs": out}

def job_action(label, action):
    j = job(label)
    if not j: return {"error": "That job isn't in the list."}
    if j["self"]: return {"error": "The deck's own job can't be run or paused from here."}
    if j["system"]: return {"error": "The Mac's own jobs run as root, so they can't be run or paused from here."}
    t = f"{DOM}/{label}"
    steps = {"run": [("kickstart", t)], "pause": [("disable", t)] + ([("bootout", t)] if j["loaded"] else []),
             "resume": [("enable", t)] + ([] if j["loaded"] else [("bootstrap", DOM, j["_plist"])])}.get(action)
    if not steps: return {"error": "Unknown action."}
    for s in steps:
        rc, msg = lc(*s)
        if rc: _jobs[0] = 0; return {"error": f"launchctl {s[0]} failed: {msg[:200] or rc}"}
    _jobs[0] = 0
    return {"ok": True}

def cron_words(c, recurring, nxt):
    if not recurring: return "Once, " + time.strftime("%a %-d %b at %H:%M", time.localtime(nxt / 1000)) if isinstance(nxt, (int, float)) else "Once"
    f, st = str(c).split(), r"(?:\*|\d+-\d+)/(\d+)"
    if len(f) != 5: return str(c)
    mi, h, dom, mon, dow = f
    if (m := re.fullmatch(st, mi)) and h == dom == mon == dow == "*": return every(int(m.group(1)) * 60)
    if mi.isdigit() and (m := re.fullmatch(st, h)) and dom == mon == dow == "*": return every(int(m.group(1)) * 3600)
    if mi.isdigit() and h == dom == mon == dow == "*": return f"Hourly at :{int(mi):02}"
    if mi.isdigit() and h.isdigit() and dom == mon == "*" and (dow == "*" or dow.isdigit()):
        return f"{'Daily' if dow == '*' else WD[int(dow) % 7]} at {int(h):02}:{int(mi):02}"
    return "Cron " + str(c)

def loops_in(f):
    """CronCreate jobs a transcript made and didn't delete: (made at, durable, item)."""
    r = subprocess.run(["rg", "-N", "-e", '"name":"Cron(Create|Delete)"', "-e", '"humanSchedule"', str(f)], capture_output=True, text=True, timeout=10).stdout
    made, gone, out = {}, set(), []
    for l in r.splitlines():
        try: o = json.loads(l); c = o["message"]["content"]
        except Exception: continue
        for b in c if isinstance(c, list) else []:
            if not isinstance(b, dict): continue
            if b.get("type") == "tool_use" and b.get("name") == "CronDelete": gone.add(str((b.get("input") or {}).get("id")))
            elif b.get("type") == "tool_use" and b.get("name") == "CronCreate": made[b.get("id")] = (b.get("input") or {}, o.get("timestamp"))
            elif b.get("type") == "tool_result" and b.get("tool_use_id") in made and not b.get("is_error") and isinstance(o.get("toolUseResult"), dict):
                inp, ts = made[b["tool_use_id"]]; tr = o["toolUseResult"]
                try: at = datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
                except ValueError: at = 0
                out.append((at, bool(tr.get("durable")), {"id": str(tr.get("id")), "prompt": re.sub(r"\s+", " ", str(inp.get("prompt") or ""))[:300],
                            "when": cron_words(inp.get("cron") or tr.get("humanSchedule"), tr.get("recurring", True), tr.get("nextFireAt")),
                            "recurring": tr.get("recurring", True), "next": tr.get("nextFireAt")}))
    return [x for x in out if x[2]["id"] not in gone]

def loops():
    """Loops in live chats. Session-only ones die with the process, so any made before this claude started are gone;
    recurring ones expire after 7 days and one-shots once they have fired."""
    t = ps_table(); k = kids_of(t); now = time.time(); roots = pane_roots(); out = []
    for s in live_sessions():
        f = s["session"] and find_file(s["session"])
        if not f: continue
        c = chat_pid(t, k, roots.get(s["pane"], 0)); born = now - t[c][2] - 60 if c else 0
        L = [x for at, dur, x in cached(f, loops_in) if (dur or at >= born) and (now - at < 7 * 86400 if x["recurring"] else (x["next"] or 0) / 1000 > now)]
        if L: out.append({"pane": s["pane"], "session": s["session"], "title": s["title"] or s["name"], "cwd": s["cwd"], "loops": L})
    return out

def scheduled():
    return {"jobs": [{k: v for k, v in j.items() if k[0] != "_"} for j in jobs()], "loops": loops(), "domain": not lc("print", DOM)[0]}
# --- Artifacts page: what this Mac's Claude sessions published (Artifact tool results), plus rclaude's ledger ---
LEDGER = RSTATE.parent / "artifacts.jsonl"  # rclaude: {"event":"publish",url,id,title,account,main,share?,session,cwd,t} and {"event":"shared",url,t}
ART_URL = re.compile(r"https://claude\.ai/(?:code/)?artifact/[A-Za-z0-9_-]+")
ART_RES = r'"type":"tool_result","content":(?:"|\[\{"type":"text","text":")(?:Published |Updated the Artifact |Created a new Artifact )'
_arts = {}  # transcript -> ((mtime, size), [publishes]): only new or grown files are searched again

def art_lines(fs):
    """Artifact publishes in transcripts fs, found with rg, as {file: [record]}."""
    hits = {f: [] for f in fs}
    for i in range(0, len(fs), 400):
        r = subprocess.run(["rg", "-N", "-0", "--with-filename", "--max-columns", "0", "-e", '"type":"tool_use","id":"[^"]+","name":"Artifact"', "-e", ART_RES, *fs[i:i + 400]],
                           capture_output=True, text=True, timeout=60).stdout
        calls = {}
        for l in r.splitlines():
            f, _, line = l.partition("\0")
            try: o = json.loads(line); c = o["message"]["content"]
            except Exception: continue
            for b in c if isinstance(c, list) else []:
                if not isinstance(b, dict): continue
                if b.get("type") == "tool_use" and b.get("name") == "Artifact": calls[b.get("id")] = b.get("input") if isinstance(b.get("input"), dict) else {}
                elif b.get("type") == "tool_result" and b.get("tool_use_id") in calls and not b.get("is_error"):
                    inp, tr = calls[b["tool_use_id"]], o.get("toolUseResult") if isinstance(o.get("toolUseResult"), dict) else {}
                    if inp.get("action", "publish") != "publish" or inp.get("asset"): continue
                    tx = b.get("content") if isinstance(b.get("content"), str) else json.dumps(b.get("content"))
                    u = ART_URL.match(str(tr.get("url") or "")) or ART_URL.search(tx)
                    if not u: continue
                    try: at = datetime.datetime.fromisoformat(str(o.get("timestamp")).replace("Z", "+00:00")).timestamp()
                    except ValueError: at = 0
                    p = Path(f); sid = o.get("sessionId") or (p.parent.parent.name if p.parent.name == "subagents" else p.stem)
                    hits.setdefault(f, []).append({"url": u.group(), "t": at, "title": str(tr.get("title") or inp.get("title") or Path(str(inp.get("file_path") or "")).stem or "")[:200],
                                                   "icon": str(tr.get("icon") or inp.get("icon") or "")[:40], "typed": bool(tr.get("type") or inp.get("type_url")),
                                                   "session": sid if re.fullmatch(r"[0-9a-f-]{36}", str(sid)) else None, "cwd": o.get("cwd")})
    return hits

def artifacts():
    fs = {}
    for f in [*PROJ.glob("*/*.jsonl"), *PROJ.glob("*/*/subagents/*.jsonl")]:
        try: s = f.stat(); fs[str(f)] = (s.st_mtime, s.st_size)
        except OSError: pass
    for k in [k for k in _arts if k not in fs]: del _arts[k]
    new = [f for f, k in fs.items() if _arts.get(f, (None,))[0] != k]
    for f, recs in art_lines(new).items(): _arts[f] = (fs[f], recs)
    by = {}
    for r in sorted((r for _, recs in _arts.values() for r in recs), key=lambda r: r["t"]): by[r["url"]] = {**by.get(r["url"], {}), **r}  # latest wins
    shared = set()
    try: lines = LEDGER.read_text(errors="ignore").splitlines()
    except OSError: lines = []
    for l in lines:
        try: e = json.loads(l); u = ART_URL.match(e["url"]).group()
        except Exception: continue
        if e.get("event") == "shared": shared.add(u)
        elif e.get("event") == "publish":
            a, t = by.get(u, {"url": u, "t": 0, "icon": "", "typed": False}), e.get("t") if isinstance(e.get("t"), (int, float)) else 0
            fill = {k: e.get(k) for k in ("title", "session", "cwd") if isinstance(e.get(k), str) and (t >= a["t"] or not a.get(k))}
            by[u] = {**a, **fill, "t": max(t, a["t"]), "account": str(e.get("account") or "")[:60] or None, "main": e.get("main") is not False, "share": e.get("share") is not False}
    out = sorted(by.values(), key=lambda a: -a["t"])
    for a in out:
        f = a.get("session") and find_file(a["session"])
        a.update(chat=cached(f, title_of) if f else None, shared=a["url"] in shared)
        a["unshared"] = a.get("main") is False and a.get("share") is not False and not a["shared"]  # share false: an account kept out of sharing
    return out

def mark_shared(url):
    u = ART_URL.fullmatch(str(url or ""))
    if not u or url not in {a["url"] for a in artifacts()}: return {"error": "That artifact isn't in the list."}
    LEDGER.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with os.fdopen(os.open(LEDGER, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600), "a") as fh:
        fh.write(json.dumps({"t": int(time.time()), "event": "shared", "url": url}) + "\n")
    return {"ok": True}

def pages_api(h, path, body=None):
    """/api/scheduled and /api/artifacts for GET (body None) and POST; False when the path is another route's."""
    q = urllib.parse.parse_qs(urllib.parse.urlparse(h.path).query)
    if body is None and path == "/api/scheduled": return h.send(200, scheduled()) or True
    if body is None and path == "/api/scheduled/log":
        r = job_log(q.get("label", [""])[0]); return h.send(200 if r else 404, r or {"error": "That job isn't in the list."}) or True
    if body is None and path == "/api/artifacts": return h.send(200, {"artifacts": artifacts(), "ledger": LEDGER.exists()}) or True
    if body is not None and path in ("/api/scheduled", "/api/artifacts"):
        r = job_action(body.get("label"), body.get("action")) if path == "/api/scheduled" else mark_shared(body.get("url")) if body.get("shared") is True else {"error": "bad"}
        return h.send(409 if "error" in r else 200, r) or True
    return False
# Passkeys (WebAuthn, Face ID) for the Tailscale route; direct local requests keep the token.
import base64, hashlib, hmac
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
def _ts():
    """`tailscale status` for this Mac: its HTTPS name (the default passkey domain) and the login it's signed in with."""
    try:
        d = json.loads(subprocess.run([shutil.which("tailscale", path=f"{os.environ.get('PATH', '')}:/opt/homebrew/bin:/usr/local/bin") or "tailscale",
                                       "status", "--json"], capture_output=True, timeout=5).stdout)
        return d["Self"]["DNSName"].rstrip("."), d["User"][str(d["Self"]["UserID"])]["LoginName"]
    except Exception: return "localhost", ""
TS_NAME, TS_LOGIN = _ts() if not (os.environ.get("DECK_RP_ID") and os.environ.get("DECK_TS_USER")) else ("", "")
RP_ID = os.environ.get("DECK_RP_ID") or TS_NAME
HOSTS |= {RP_ID, RP_ID.split(".")[0]}  # the https name, and the short name that redirects to it
ORIGIN = os.environ.get("DECK_ORIGIN", "https://" + RP_ID)
CK, CK_PATH = "__Secure-deck", os.environ.get("DECK_COOKIE_PATH", "/deck")  # the browser sees the deck under /deck
TTL = int(os.environ.get("DECK_SESSION_TTL", 30 * 86400))  # sliding: refreshed when a session is used
TS_USERS = {u.strip().lower() for u in (os.environ.get("DECK_TS_USER") or TS_LOGIN).split(",") if u.strip()}  # default: the Mac's own login
STORE = Path(os.environ.get("DECK_STORE", HOME / "Library/Application Support/session-deck/passkeys.json"))
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
ub64 = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
LOCK, CHAL, HITS = threading.RLock(), {}, {}
DB = json.loads(STORE.read_text()) if STORE.exists() else {}  # {login: {uid, creds: [...], sessions: {sid: {...}}}}

CODES = STORE.parent / "setup-codes.json"  # one-time Face ID setup codes: sha256 -> expiry (made with: server.py --setup-code)
def setup_code_ok(c):
    try: d = json.loads(CODES.read_text())
    except Exception: return False
    h = hashlib.sha256(c.strip().upper().replace("-", "").encode()).hexdigest()
    return any(secrets.compare_digest(h, k) and t > time.time() for k, t in d.items())

def save():
    STORE.parent.mkdir(parents=True, exist_ok=True); t = STORE.with_suffix(".tmp")
    t.write_text(json.dumps(DB, indent=1)); t.replace(STORE)

def user(login):
    return DB.setdefault(login, {"uid": b64u(secrets.token_bytes(16)), "creds": [], "sessions": {}})

# Pins and archived chats, kept here so every device sees the same. One deck runs per macOS account, so this file is per person.
PREFS = Path(os.environ.get("DECK_PREFS") or STORE.parent / "prefs.json")
PIN_TYPES, PREF_KEYS, _prefs_lock = {"chat", "project", "job", "artifact"}, ("pins", "archived", "archivedProjects"), threading.Lock()
SID_RE = r"[0-9a-f-]{36}"

def prefs():
    try: d = json.loads(PREFS.read_text())
    except Exception: d = {}
    return {k: d[k] if isinstance(d.get(k), list) else [] for k in PREF_KEYS}

def short(v, n=200):  # a non-empty single-line string, or None
    return v if isinstance(v, str) and 0 < len(v) <= n and not re.search(r"[\x00-\x1f\x7f]", v) else None

def pin_item(x):
    """A pin as a page sent it, or None: a known type, an id, and up to 12 short scalar fields (title, cwd, what a page needs to open it)."""
    x = {k: v for k, v in x.items() if v is not None} if isinstance(x, dict) else None
    if not x or x.get("type") not in PIN_TYPES or not short(x.get("id")) or len(x) > 12: return None
    if not all(isinstance(k, str) and re.fullmatch(r"[A-Za-z]{1,20}", k) for k in x): return None
    if not all(isinstance(v, (bool, int, float)) or isinstance(v, str) and len(v) <= 500 for v in x.values()): return None
    return {k: re.sub(r"[\x00-\x1f\x7f]", " ", v) if isinstance(v, str) else v for k, v in x.items()}

def prefs_change(b):
    """Applies one change from POST /api/prefs: (new prefs, None) or (None, error)."""
    with _prefs_lock:
        d = prefs(); P, A, AP = d["pins"], d["archived"], d["archivedProjects"]
        if "pin" in b:
            x = pin_item(b["pin"])
            if not x: return None, "That can't be pinned."
            i = next((i for i, p in enumerate(P) if (p.get("type"), p.get("id")) == (x["type"], x["id"])), None)
            if i is None and len(P) >= 100: return None, "That's 100 pins already. Unpin something first."
            if i is None: P.append(x)
            else: P[i] = x  # pinned again: newer details, same place
        elif "unpin" in b:
            u = b["unpin"] if isinstance(b["unpin"], dict) else {}
            d["pins"] = [p for p in P if (p.get("type"), p.get("id")) != (u.get("type"), u.get("id"))]
        elif "archive" in b or "unarchive" in b:
            s = b.get("archive", b.get("unarchive"))
            if not isinstance(s, str) or not re.fullmatch(SID_RE, s): return None, "Not a chat."
            d["archived"] = ([x for x in A if x != s] + ([s] if "archive" in b else []))[-5000:]
        elif "archiveProject" in b or "unarchiveProject" in b:
            p = short(b.get("archiveProject", b.get("unarchiveProject")))
            if not p: return None, "Not a project."
            d["archivedProjects"] = ([x for x in AP if x != p] + ([p] if "archiveProject" in b else []))[-500:]
        else: return None, "Nothing to change."
        PREFS.parent.mkdir(parents=True, exist_ok=True); t = PREFS.with_name(PREFS.name + ".tmp")
        fd = os.open(t, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600); os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as fh: json.dump(d, fh)
        os.replace(t, PREFS)
        return d, None

def cbor(b, i=0):
    """Minimal CBOR decoder (ints, bytes, text, arrays, maps, bools): enough for attestationObject and COSE keys."""
    mt, ai = b[i] >> 5, b[i] & 31; i += 1
    if ai >= 28: raise ValueError("cbor")
    if ai >= 24: k = 1 << (ai - 24); n = int.from_bytes(b[i:i + k], "big"); i += k
    else: n = ai
    if mt == 0: return n, i
    if mt == 1: return -1 - n, i
    if mt in (2, 3):
        if i + n > len(b): raise ValueError("cbor")
        return (bytes(b[i:i + n]) if mt == 2 else b[i:i + n].decode()), i + n
    if mt in (4, 5):
        out = []
        for _ in range(n * (mt - 3)): v, i = cbor(b, i); out.append(v)
        return (out if mt == 4 else dict(zip(out[::2], out[1::2]))), i
    if mt == 7 and n in (20, 21): return n == 21, i
    raise ValueError("cbor")

def cose_key(m):
    if m.get(1) == 2 and m.get(3) == -7 and m.get(-1) == 1 and len(m[-2]) == len(m[-3]) == 32:  # EC2 P-256, ES256
        return ec.EllipticCurvePublicNumbers(int.from_bytes(m[-2], "big"), int.from_bytes(m[-3], "big"), ec.SECP256R1()).public_key()
    if m.get(1) == 3 and m.get(3) == -257:  # RSA, RS256
        return rsa.RSAPublicNumbers(int.from_bytes(m[-2], "big"), int.from_bytes(m[-1], "big")).public_key()
    raise ValueError("alg")

def client_data(raw, kind):
    """Checks clientDataJSON and returns its challenge, which the caller must still match."""
    c = json.loads(raw)
    if c.get("type") != kind or c.get("origin") != ORIGIN or c.get("crossOrigin"): raise ValueError("clientData")
    return c["challenge"]

def auth_data(a, attested=False):
    """Checks rpIdHash and the user-present + user-verified flags; returns the sign count (and credential id + COSE key)."""
    if len(a) < 37 or not hmac.compare_digest(a[:32], hashlib.sha256(RP_ID.encode()).digest()) or a[32] & 5 != 5: raise ValueError("authData")
    n = int.from_bytes(a[33:37], "big")
    if not attested: return n
    if not a[32] & 0x40: raise ValueError("authData")
    ln = int.from_bytes(a[53:55], "big"); cid = a[55:55 + ln]
    if len(cid) != ln or not ln: raise ValueError("authData")
    return n, cid, cbor(a, 55 + ln)[0]

def verify_reg(att):
    """attestationObject -> (credential id, SPKI public key, alg, sign count). Attestation statements are not checked ("none")."""
    n, cid, key = auth_data(cbor(att)[0]["authData"], True)
    spki = cose_key(key).public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return b64u(cid), b64u(spki), key[3], n

def verify_get(c, cdj, ad, sig):
    """Checks an assertion's signature and counter against stored credential c; returns the new sign count."""
    n = auth_data(ad); pub = serialization.load_der_public_key(ub64(c["pk"])); data = ad + hashlib.sha256(cdj).digest()
    pub.verify(sig, data, ec.ECDSA(hashes.SHA256())) if c["alg"] == -7 else pub.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
    if (n or c["count"]) and n <= c["count"]: raise ValueError("counter")  # Apple passkeys always send 0
    return n

def challenge(login, kind):
    now = time.time()
    for k, v in list(CHAL.items()):
        if v[2] < now: CHAL.pop(k, None)
    c = b64u(secrets.token_bytes(32)); CHAL[c] = (login, kind, now + 120); return c

def take(c, login, kind):  # single use: gone whether or not the rest of the check passes
    v = CHAL.pop(c, None)
    if not v or v[:2] != (login, kind) or v[2] < time.time(): raise ValueError("challenge")

def limited(key, n, win):
    now = time.time(); h = [t for t in HITS.get(key, ()) if now - t < win] + [now]; HITS[key] = h
    return len(h) > n

def sign(v): return b64u(hmac.new(KEY, v.encode(), hashlib.sha256).digest())
def cookie(login=None, sid=None):
    v = b64u(login.encode()) + "." + sid if login else ""
    return f"{CK}={v + '.' + sign(v) if v else ''}; Max-Age={TTL if v else 0}; Path={CK_PATH}; HttpOnly; Secure; SameSite=Strict"

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send(self, code, body, ctype="application/json", csp=None):
        b = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code); self.send_header("Content-Type", ctype)
        if csp: self.send_header("Content-Security-Policy", csp)
        ck = self.__dict__.pop("_ck", None)  # a session cookie set or slid during this request
        if ck: self.send_header("Set-Cookie", ck)
        self.send_header("Content-Length", str(len(b))); self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(b)
    def authed(self):
        host = (self.headers.get("Host") or "").split(":")[0]
        if host not in HOSTS: return False
        # The Host header is chosen by the client, so it decides nothing. Anything on the Tailscale port, or carrying a proxy's
        # headers, needs the owner's login (tailscale serve sets Tailscale-User-Login itself and drops any copy the client sends)
        # plus a passkey session cookie bound to that login. Only direct local requests use the token.
        if self.via_ts(): return bool(self.session())
        return secrets.compare_digest(self.headers.get("X-Deck-Token", "").encode("utf8", "replace"), TOK.encode())
    def via_ts(self):
        return getattr(self.server, "ts", False) or any(k.lower() == "x-forwarded-for" or k.lower().startswith("tailscale-") for k in self.headers)
    def login(self):
        l = self.headers.get("Tailscale-User-Login", "").lower()
        return l if l in TS_USERS and (self.headers.get("Host") or "").split(":")[0] in HOSTS else None
    def session(self):
        """(login, sid) when the cookie is validly signed, bound to this request's Tailscale login and not revoked or expired."""
        login = self.login()
        ck = dict(p.strip().split("=", 1) for p in (self.headers.get("Cookie") or "").split(";") if "=" in p).get(CK, "")
        lb, _, rest = ck.partition("."); sid, _, mac = rest.partition(".")
        if not login or not mac or not hmac.compare_digest(mac.encode(), sign(lb + "." + sid).encode()) \
                or not hmac.compare_digest(lb.encode(), b64u(login.encode()).encode()): return None
        with LOCK:
            s, now = DB.get(login, {}).get("sessions", {}).get(sid), time.time()
            if not s or s["exp"] < now: return None
            if now - s["seen"] > TTL / 30: s.update(seen=now, exp=now + TTL); save(); self._ck = cookie(login, sid)
        return login, sid
    def new_session(self, login, cred):
        now, sid, ss = time.time(), b64u(secrets.token_bytes(18)), user(login)["sessions"]
        for k in [k for k, s in ss.items() if s["exp"] < now]: del ss[k]
        ss[sid] = {"cred": cred, "exp": now + TTL, "seen": now}; self._ck = cookie(login, sid)
    def auth(self, path, post=False):
        """/api/auth/*: passkey sign-in, enrolment and management. Public apart from the Tailscale login check."""
        if not self.via_ts(): return self.send(200 if path == "/api/auth/state" else 404, {"ts": False})
        login = self.login()
        if not login: return self.send(403, {"error": "This Tailscale login is not allowed here."})
        se, u = self.session(), user(login)
        if path == "/api/auth/state": return self.send(200, {"ts": True, "login": login, "signedIn": bool(se), "passkeys": len(u["creds"])})
        if path == "/api/auth/passkeys" and se:
            sc = u["sessions"][se[1]]["cred"]
            return self.send(200, {"passkeys": [{"id": c["id"], "name": c["name"], "made": c["made"], "used": c.get("used"), "current": c["id"] == sc} for c in u["creds"]]})
        if not post: return self.send(401, {"error": "Sign in first."})
        if self.headers.get("Origin") != ORIGIN: return self.send(403, {"error": "Wrong origin."})
        n = int(self.headers.get("Content-Length") or 0)
        if n > 65536: self.close_connection = True; return self.send(413, {"error": "Too big."})
        if limited(login, 40, 300): return self.send(429, {"error": "Too many tries. Wait a few minutes."})
        try:
            b, now = json.loads(self.rfile.read(n) or b"{}"), time.time()
            if path == "/api/auth/login/begin":
                if not u["creds"]: return self.send(404, {"error": "No passkeys yet. Set one up first."})
                return self.send(200, {"challenge": challenge(login, "get"), "rpId": RP_ID,
                                       "allow": [{"id": c["id"], **({"transports": c["tr"]} if c.get("tr") else {})} for c in u["creds"]]})
            if path == "/api/auth/login/finish":
                cdj = ub64(b["clientDataJSON"]); take(client_data(cdj, "webauthn.get"), login, "get")
                c = next(c for c in u["creds"] if c["id"] == b["id"])
                cnt = verify_get(c, cdj, ub64(b["authenticatorData"]), ub64(b["signature"]))
                with LOCK: c.update(count=cnt, used=now); self.new_session(login, c["id"]); save()
                return self.send(200, {"ok": True})
            if path == "/api/auth/register/begin":
                # The first passkey for a login needs the deck token (once): the Tailscale login alone only proves a device is on
                # the owner's tailnet. Later ones can be added from a signed-in session.
                tok = str(b.get("token") or "")
                if not se:
                    if limited(("tok", login), 5, 900): return self.send(429, {"error": "Too many tries. Wait 15 minutes."})
                    if not tok or not (secrets.compare_digest(tok.encode(), TOK.encode()) or setup_code_ok(tok)): return self.send(403, {"error": "That token or setup code is not right."})
                return self.send(200, {"challenge": challenge(login, "create"), "rp": {"id": RP_ID, "name": "Session Deck"},
                                       "user": {"id": u["uid"], "name": login, "displayName": login}, "exclude": [c["id"] for c in u["creds"]]})
            if path == "/api/auth/register/finish":
                cdj = ub64(b["clientDataJSON"]); take(client_data(cdj, "webauthn.create"), login, "create")
                cid, pk, alg, cnt = verify_reg(ub64(b["attestationObject"]))
                with LOCK:
                    if any(c["id"] == cid for v in DB.values() for c in v["creds"]): return self.send(409, {"error": "That passkey is already set up."})
                    u["creds"].append({"id": cid, "pk": pk, "alg": alg, "count": cnt, "made": now, "name": re.sub(r"\s+", " ", str(b.get("name") or "Passkey")).strip()[:40] or "Passkey",
                                       "tr": [t for t in b.get("transports") or [] if isinstance(t, str)][:6]})
                    if not se: self.new_session(login, cid)
                    save(); CODES.unlink(missing_ok=True)  # a setup code is spent once a passkey exists
                return self.send(200, {"ok": True})
            if not se: return self.send(401, {"error": "Sign in first."})
            if path == "/api/auth/passkeys/delete":  # revokes every session signed in with it
                with LOCK:
                    u["creds"] = [c for c in u["creds"] if c["id"] != b.get("id")]
                    u["sessions"] = {k: s for k, s in u["sessions"].items() if s["cred"] != b.get("id")}; save()
                if se[1] not in u["sessions"]: self._ck = cookie()
                return self.send(200, {"ok": True})
            if path == "/api/auth/logout":
                with LOCK: u["sessions"].pop(se[1], None); save()
                self._ck = cookie(); return self.send(200, {"ok": True})
        except Exception:
            return self.send(400, {"error": "The passkey check failed."})
        self.send(404, {"error": "nf"})
    def do_GET(self):
        path = self.path.split("?")[0]
        h = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or ""  # tailscale serve rewrites Host when it proxies to a Unix socket
        if self.via_ts() and h != urllib.parse.urlsplit(ORIGIN).netloc and h.split(":")[0] in HOSTS - {"127.0.0.1", "localhost"}:  # http://<mac>/deck, :8080: passkeys need the https name
            self.send_response(301); self.send_header("Location", ORIGIN + "/deck" + self.path); self.send_header("Content-Length", "0"); self.end_headers(); return
        if path == "/":
            return self.send(200, (HERE / "index.html").read_bytes(), "text/html; charset=utf-8", CSP)
        if path in ("/vendor/marked.min.js", "/vendor/purify.min.js"):
            return self.send(200, (HERE / path[1:]).read_bytes(), "text/javascript; charset=utf-8")
        if path in PWA:
            return self.send(200, (HERE / path[1:]).read_bytes(), PWA[path])
        if path.startswith("/api/auth/"): return self.auth(path)
        if not self.authed(): return self.send(401, {"error": "token"})
        if pages_api(self, path): return
        if path == "/api/siri":
            return self.send(200, {"url": ORIGIN + CK_PATH + "/api/siri/" + SEC["siri_key"], "name": siri_name()})
        if path == "/api/push/key":
            v = vapid(); return self.send(200, {"key": b64u(v[1]) if v else None})
        if path == "/api/sessions":
            ps_ = proc_summary(); live = [{**s, "attn": attn(s), "procs": ps_.get(s["pane"])} for s in live_sessions()]
            return self.send(200, {"live": live, "history": history(skip={s["session"] for s in live})})
        if path == "/api/search":
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("q", [""])[0].strip()
            return self.send(200, {"results": search(q) if len(q) >= 3 else []})
        if path == "/api/folders": return self.send(200, {"folders": folders()})
        if path == "/api/prefs": return self.send(200, prefs())
        if path == "/api/config":
            return self.send(200, {"home": str(HOME), "root": str(FOLDERS), "engines": [{"id": k, "label": v[1], "sub": v[2]} for k, v in ENGINES.items() if engine_exe(k)]})  # only what this user has installed
        if path == "/api/git":
            c = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("cwd", [""])[0]
            return self.send(200, {"git": os.path.isdir(c) and is_git(c)})
        m = re.fullmatch(r"/api/agent/([0-9a-f-]{36})/([0-9a-z]+)", path)
        if m:
            f = find_file(m.group(1)); a = f and f.parent / f.stem / "subagents" / f"agent-{m.group(2)}.jsonl"
            return self.send(200, {"items": messages(a, 200, side=True)}) if a and a.exists() else self.send(404, {"error": "none"})
        m = re.fullmatch(r"/api/img/([0-9a-f-]{36})(?:/([0-9a-z]+))?/(\d+)/(\d+)/(-?\d+)", path)
        if m:
            f = find_file(m.group(1))
            if f and m.group(2): f = f.parent / f.stem / "subagents" / f"agent-{m.group(2)}.jsonl"
            try: ct, data = image(f, int(m.group(3)), int(m.group(4)), int(m.group(5)))
            except Exception: return self.send(404, {"error": "img"})
            return self.send(200, data, ct)
        m = re.fullmatch(r"/api/session/([0-9a-f-]{36})", path)
        if m:
            f = find_file(m.group(1))
            n = int((urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("n") or ["60"])[0])
            return self.send(200, {"items": with_sent(m.group(1), messages(f, min(n, 2000)), f)}) if f else self.send(404, {"error": "none"})
        m = re.fullmatch(r"/api/info/([0-9a-f-]{36})", path)
        if m:
            f = find_file(m.group(1))
            if not f: return self.send(404, {"error": "none"})
            d = cached(f, info); q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("pane", [""])[0]
            d = {**d, "agents": agents(f)}
            if re.fullmatch(PANE_RE, q): d = {**d, "running": pane_elapsed(q), "pane": q}
            return self.send(200, d)
        m = re.fullmatch(r"/api/diff/([0-9a-f-]{36})(?:/([0-9a-z]+))?/([\w-]{6,100})", path)
        if m:
            f = find_file(m.group(1))
            if f and m.group(2): f = f.parent / f.stem / "subagents" / f"agent-{m.group(2)}.jsonl"
            return self.send(200, {"diff": full_tool_diff(f, m.group(3)) if f and f.exists() else None})
        m = re.fullmatch(r"/api/changes/([\w.-]+)", path)
        if m:
            cwd = chat_cwd(m.group(1)); fq = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("file")
            if not cwd: return self.send(200, {"error": "This chat's folder isn't known."})
            return self.send(200, change_diff(cwd, fq[0]) if fq else changes(cwd))
        m = re.fullmatch(r"/api/status/(" + PANE_RE + ")", path)
        if m and valid_pane(m.group(1)):
            SEEN[m.group(1)] = time.time(); q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            if q.get("f") == ["1"] and DEV_RE.fullmatch((q.get("d") or [""])[0]): VIEW[(m.group(1), q["d"][0])] = time.time()
            s = next((s for s in live_sessions() if s["pane"] == m.group(1)), {})
            return self.send(200, {**pane_screen(m.group(1)), "device": device(), "accounts": accounts(), "plan": s.get("plan"), "pinned": s.get("pinned")})
        if path == "/api/accounts": return self.send(200, {"accounts": accounts(), "models": account_models()})  # rclaude's plans, for the Account choice
        m = re.fullmatch(r"/api/procs/(" + PANE_RE + ")", path)
        if m and valid_pane(m.group(1)): return self.send(200, procs_view(m.group(1)))
        if path == "/api/files":
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            s = next((x for x in live_sessions() if x["pane"] == qs.get("pane", [""])[0]), None)  # cwd comes from the live chat, never the client
            if not s or not os.path.isdir(s["cwd"] or ""): return self.send(404, {"error": "pane"})
            return self.send(200, {"files": files(s["cwd"], qs.get("q", [""])[0][:100])})
        m = re.fullmatch(r"/api/screen/(" + PANE_RE + ")", path)
        if m and valid_pane(m.group(1)):
            SEEN[m.group(1)] = time.time(); q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            if q.get("release"): term_release(m.group(1)); return self.send(200, {"ok": True})
            if q.get("cols") and q.get("rows"):
                try: term_size(m.group(1), int(q["cols"][0]), int(q["rows"][0]))
                except ValueError: pass
            return self.send(200, {"screen": tm(m.group(1), "capture-pane", "-p", "-t", "{P}", "-S", "-40")})
        self.send(404, {"error": "nf"})
    def upload(self):
        """Raw file body, streamed to the uploads folder under a name the server picks."""
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        pane = q.get("pane", [""])[0]
        if not re.fullmatch(PANE_RE, pane) or not valid_pane(pane): return self.send(400, {"error": "This chat isn't running any more."})
        try: n = int(self.headers["Content-Length"])
        except Exception: return self.send(411, {"error": "The upload had no size."})
        if n > UP_MAX: return self.send(413, {"error": "Files over 1 GB can't be attached. Move them with Syncthing instead."})
        name = re.sub(r"[\x00-\x1f()/\\]", "", q.get("name", [""])[0]).strip()[:120] or "file"
        d = UPL / time.strftime("%Y-%m-%d"); d.mkdir(parents=True, exist_ok=True)
        sv = os.statvfs(d)
        if sv.f_bavail * sv.f_frsize < n + (2 << 30): return self.send(507, {"error": "The Mac is low on disk space."})
        self.connection.settimeout(120)  # a phone that drops off mid-upload mustn't hold a thread for ever
        head = self.rfile.read(min(n, 1 << 20)); ext = sniff(head, name)
        if not ext: return self.send(415, {"error": f"{name}: that type of file can't be attached."})
        tmp, left = d / f"{secrets.token_hex(8)}.part", n - len(head)
        try:
            with open(tmp, "wb") as fh:
                fh.write(head)
                while left > 0:
                    b = self.rfile.read(min(left, 1 << 20))
                    if not b: raise OSError("cut off")
                    fh.write(b); left -= len(b)
            if ext == "zip": ext = office(tmp)
            p = tmp.with_suffix(".jpg" if ext == "heic" else "." + ext)
            if ext == "heic":
                subprocess.run(["sips", "-s", "format", "jpeg", str(tmp), "--out", str(p)], capture_output=True, timeout=120)
                if not p.exists(): raise OSError("sips")
                tmp.unlink(); ext = "jpg"
            else: tmp.rename(p)
        except Exception:
            tmp.unlink(missing_ok=True); return self.send(400, {"error": f"{name}: the upload failed."})
        NAMES[str(p)] = name
        return self.send(200, {"path": str(p), "kind": "image" if ext in IMG else "file", "name": name, "size": p.stat().st_size})
    def siri(self):
        """POST /api/siri/<key> from the iPhone Shortcut, the text as the body (Request Body: File) or as {"text"}: the Tailscale login plus the Siri key (in the path, so the shortcut
        needs just one address; or X-Siri-Key), as a Shortcut can't use a passkey. Or the usual sign-in. Answers in plain text, so
        the Shortcut reads out errors too."""
        say = lambda code, t: self.send(code, t.encode(), "text/plain; charset=utf-8")
        bad, now = ("siri-bad",), time.time()
        if sum(now - t < 600 for t in HITS.get(bad, ())) >= 10: return say(429, "Too many wrong Siri keys. Try again in ten minutes.")
        given = self.path.split("?")[0][len("/api/siri/"):] or self.headers.get("X-Siri-Key", "")
        key = secrets.compare_digest(given.encode("utf8", "replace"), SEC["siri_key"].encode())
        if not (self.authed() or key and (self.login() if self.via_ts() else (self.headers.get("Host") or "").split(":")[0] in HOSTS)):
            limited(bad, 0, 600); return say(401, "Session Deck didn't accept the Siri key. Copy it again from Settings.")
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():  # in case Shortcuts streams the body
            raw = b""
            while len(raw) < 20000 and (n := int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)):
                raw += self.rfile.read(n); self.rfile.readline()
        else: raw = self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 20000))
        raw = raw.decode("utf8", "replace")
        m = re.search(r"\r?\n\r?\n(.*?)\r?\n--", raw, re.S) if "multipart/" in self.headers.get("Content-Type", "") else None
        try: text = json.loads(raw).get("text", "")
        except Exception: text = m.group(1) if m else raw
        text = re.sub(r"\s+", " ", str(text)).strip()
        if not text: return say(200, "I didn't catch anything to send.")
        w = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get("wait", ["25"])[0]
        return say(200, siri_ask(text, max(0, min(int(w) if w.isdigit() else 25, 55))))
    def do_POST(self):
        if self.path.startswith("/api/auth/"): return self.auth(self.path.split("?")[0], post=True)
        if re.fullmatch(r"/api/siri(/[\w-]{20,})?", self.path.split("?")[0]): return self.siri()
        if not self.authed(): return self.send(401, {"error": "token"})
        if self.path.startswith("/api/upload?"): return self.upload()
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        if self.path == "/api/rename":
            name = re.sub(r"\s+", " ", str(body.get("name", ""))).strip()[:80]
            f = find_file(str(body.get("session", "")))
            pane = body.get("pane") or ""
            live = re.fullmatch(PANE_RE, pane) and valid_pane(pane)
            if not name: return self.send(400, {"error": "name"})
            done = []
            if body.get("claude") and (f or live):
                if live:
                    tm(pane, "set-buffer", "-b", "deck", "/rename " + name); tm(pane, "paste-buffer", "-p", "-d", "-b", "deck", "-t", "{P}")
                    time.sleep(0.15); tm(pane, "send-keys", "-t", "{P}", "Enter")
                else:
                    with open(f, "a", encoding="utf8") as fh:
                        fh.write(json.dumps({"type": "custom-title", "customTitle": name, "sessionId": f.stem}, separators=(",", ":")) + "\n")
                done.append("claude")
            if body.get("tmux") and live:
                tm(pane, "rename-window", "-t", "{P}", name); done.append("tmux")
            _live[0] = 0
            return self.send(200, {"done": done})
        if self.path == "/api/new":
            p = start(str(body.get("cwd", "")), body.get("engine"), body.get("resume"), bool(body.get("fork")), body.get("perm") or "bypass",
                      body.get("model"), body.get("effort"), body.get("name"), bool(body.get("worktree")), body.get("account"))
            return self.send(200, {"pane": p}) if p else self.send(400, {"error": "bad"})
        if self.path == "/api/end":  # /exit, or with kill the pane itself; only ever a pane that is running Claude right now
            pane = str(body.get("pane", "")); _live[0] = 0
            if not re.fullmatch(PANE_RE, pane) or not valid_pane(pane): return self.send(200, {"gone": True})
            if body.get("kill"): tm(pane, "kill-pane", "-t", "{P}")
            else: end_chat(pane)
            _live[0] = 0; return self.send(200, {"ok": True})  # straight away: the pane may already be gone
        if pages_api(self, self.path, body): return
        if self.path == "/api/siri/key":  # a new key; the old one stops working at once
            SEC["siri_key"] = secrets.token_urlsafe(24); save_secrets(SEC); return self.send(200, {"url": ORIGIN + CK_PATH + "/api/siri/" + SEC["siri_key"]})
        if self.path == "/api/siri/name":
            n = re.sub(r"\s+", " ", str(body.get("name", ""))).strip()
            if not re.fullmatch(r"[\w' -]{1,30}", n): return self.send(400, {"error": "Use up to 30 letters, numbers or spaces."})
            f = PREFS.with_name("siri.json"); f.parent.mkdir(parents=True, exist_ok=True); f.write_text(json.dumps({"name": n}))
            return self.send(200, {"name": n})
        if self.path == "/api/push/subscribe":
            sub = body.get("sub") or {}; keys = sub.get("keys") or {}
            if not (push_ok(sub.get("endpoint")) and isinstance(keys.get("p256dh"), str) and isinstance(keys.get("auth"), str)):
                return self.send(400, {"error": "Not a push service this deck knows."})
            dev = body.get("dev") if isinstance(body.get("dev"), str) and DEV_RE.fullmatch(body["dev"]) else None
            name = re.sub(r"[^\w ()./-]", "", str(body.get("name") or ""))[:60] or "A device"
            sub = {"endpoint": sub["endpoint"], "keys": {"p256dh": keys["p256dh"], "auth": keys["auth"]}, "added": time.time(), "dev": dev, "name": name}
            with _push_lock:
                old = push_subs(); subs = [x for x in old if x["endpoint"] != sub["endpoint"] and not (dev and x.get("dev") == dev)]
                code = None if body.get("quiet") else push_one(sub, {"title": "Session Deck", "body": "Notifications are on.", "pane": ""})
                if code not in (404, 410): subs.append({**next((x for x in old if x["endpoint"] == sub["endpoint"]), {}), **sub})
                save_subs(subs)  # one entry per device: a new subscription from the same device replaces the old one
            return self.send(200, {"ok": True, "test": code})
        if self.path == "/api/push/test":  # every device with notifications on, each with what its push service said
            res = push_all({"title": "Session Deck", "body": "Test notification.", "pane": ""})
            return self.send(200, {"devices": [{"name": x.get("name") or "A device", "dev": x.get("dev"), "code": c} for x, c in res]})
        if self.path == "/api/push/unsubscribe":  # this device (endpoint), or another one by its device id
            with _push_lock: save_subs([s for s in push_subs() if s["endpoint"] != body.get("endpoint") and not (body.get("dev") and s.get("dev") == body.get("dev"))])
            return self.send(200, {"ok": True})
        if self.path == "/api/prefs":
            d, err = prefs_change(body) if isinstance(body, dict) else (None, "bad")
            return self.send(400, {"error": err}) if err else self.send(200, d)
        pane = body.get("pane", "")
        if not re.fullmatch(PANE_RE, pane) or not valid_pane(pane): return self.send(400, {"error": "pane"})
        if self.path == "/api/procs/kill":
            pid = body.get("pid")
            r = stop_proc(pane, pid) if isinstance(pid, int) and not isinstance(pid, bool) and pid > 1 else {"error": "pid"}
            return self.send(409 if "error" in r else 200, r)  # 409 carries the reason to the page
        if self.path == "/api/send":
            if pane_screen(pane)["menu"]: return self.send(409, {"error": "Claude is asking a question. Answer it first."})
            text = str(body.get("text", ""))[:20000]
            if body.get("id") and SENT_IDS.get(body["id"]): return self.send(200, SENT_IDS[body["id"]])  # a retried request: sent already
            files = attached(body.get("files", []))
            if files is None: return self.send(400, {"error": "files"})
            imgs = [f for f in files if f.suffix[1:] in IMG]
            if len(imgs) < len(files):  # Claude opens other files itself when it sees the path
                text = (text.rstrip() + "\n\n" + "\n".join(f"Attached: {f} ({NAMES.get(str(f), f.name)}, {human(f.stat().st_size)})" for f in files if f not in imgs)).strip()
            deliver(pane, text, imgs)
            sid = next((x.get("session") for x in live_sessions() if x["pane"] == pane), None)
            if sid and text.strip() and not text.startswith("!"): SENT.setdefault(sid, []).append((text.strip(), time.time()))
            r = {"ok": True, "text": text}
            if body.get("id"): SENT_IDS[str(body["id"])[:40]] = r; [SENT_IDS.pop(k) for k in list(SENT_IDS)[:-50]]
            return self.send(200, r)
        if self.path == "/api/choose":
            m = pane_screen(pane)["menu"]  # same parse as /api/status, so it compares equal to what the page drew
            if not m: return self.send(409, {"error": "That question has gone."})
            if body.get("question") != m["question"] or body.get("labels") != [o["label"] for o in m["options"]]:
                return self.send(409, {"error": "The question changed. Check it and pick again."})
            idx, text = body.get("index"), body.get("text")
            amend = None
            if text is not None:
                idx = next((i for i, o in enumerate(m["options"]) if re.search(r"\b(type something|other|custom|tell claude)\b", o["label"], re.I)), None)
                if idx is None and m.get("amend"):  # permission prompt: Tab on Yes or No adds a note for Claude (Send means No)
                    ok = [i for i, o in enumerate(m["options"]) if o["label"] in ("Yes", "No")]
                    amend = body.get("index") if body.get("index") in ok else next((i for i in ok if m["options"][i]["label"] == "No"), None)
                    idx = amend; text = " ".join(str(text).split())[:2000]
                if idx is None or m["mode"] == "keys": return self.send(409, {"error": "This question has no place for a typed answer. Pick an option."})
            elif not isinstance(idx, int) or not 0 <= idx < len(m["options"]): return self.send(400, {"error": "index"})
            if m["mode"] == "keys":
                tm(pane, "send-keys", "-t", "{P}", m["options"][idx]["key"]); _live[0] = 0; return self.send(200, {"ok": True})
            if idx is not None:
                d = int(idx) - m["selected"]
                for _ in range(abs(d)): tm(pane, "send-keys", "-t", "{P}", "Down" if d > 0 else "Up"); time.sleep(0.05)
            if amend is not None:
                time.sleep(0.15); tm(pane, "send-keys", "-t", "{P}", "Tab"); time.sleep(0.3)
                a = pane_screen(pane)["menu"]
                if not a or a["options"][idx:idx + 1] == m["options"][idx:idx + 1]:  # Tab didn't open the note: send nothing
                    _live[0] = 0; return self.send(409, {"error": "Couldn't add a note to that option. Check the question and try again."})
            if text is not None:
                time.sleep(0.15); tm(pane, "set-buffer", "-b", "deck", text); tm(pane, "paste-buffer", "-p", "-d", "-b", "deck", "-t", "{P}")
            time.sleep(0.15); tm(pane, "send-keys", "-t", "{P}", "Enter"); _live[0] = 0
            return self.send(200, {"ok": True})
        if self.path == "/api/key" and body.get("key") == "SendNow":  # Claude Code's chat:sendNow (ctrl+x ctrl+s)
            tm(pane, "send-keys", "-t", "{P}", "C-x"); time.sleep(0.05); tm(pane, "send-keys", "-t", "{P}", "C-s"); return self.send(200, {"ok": True})
        if self.path == "/api/key" and body.get("key") == "C-c":  # a second Ctrl-C soon after the first exits Claude Code
            if time.time() - CTRL_C.get(pane, 0) < 3: return self.send(409, {"error": "Ctrl-C was just sent. Wait a moment: a quick second one exits Claude."})
            CTRL_C[pane] = time.time()
        if self.path == "/api/key" and body.get("key") in KEYS:
            tm(pane, "send-keys", "-t", "{P}", body["key"]); return self.send(200, {"ok": True})
        self.send(400, {"error": "bad"})

SEC = load_secrets()
TOK, KEY = SEC["token"], SEC["cookie_key"].encode()
if __name__ == "__main__" and "--setup-code" in sys.argv:  # prints a one-time Face ID setup code, valid for 10 minutes
    c = "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(10))
    CODES.parent.mkdir(parents=True, exist_ok=True); CODES.write_text(json.dumps({hashlib.sha256(c.encode()).hexdigest(): time.time() + int(os.environ.get("DECK_CODE_TTL", 600))}))
    os.chmod(CODES, 0o600); print(c[:5] + "-" + c[5:]); sys.exit()
if __name__ == "__main__":
    import threading
    import socketserver
    srvs = [ThreadingHTTPServer(("127.0.0.1", p), H) for p in (PORT, TS_PORT) if p]  # 0 turns a port off
    if TS_PORT: srvs[-1].ts = True
    if SOCK:
        Path(SOCK).unlink(missing_ok=True)
        u = socketserver.ThreadingUnixStreamServer(SOCK, H); u.daemon_threads = u.ts = True
        os.chmod(SOCK, 0o660)  # the folder's group (the router's) may connect; the folder itself keeps everyone else out
        srvs.append(u)
    print(f"Session Deck on {', '.join(str(x.server_address) for x in srvs)}  (token: {SECRET_FILE})", flush=True)
    threading.Thread(target=watcher, daemon=True).start()
    threading.Thread(target=tidy_loop, daemon=True).start()
    threading.Thread(target=term_reaper, daemon=True).start(); threading.Thread(target=idler, daemon=True).start(); threading.Thread(target=run_watch, daemon=True).start()
    for x in srvs[1:]: threading.Thread(target=x.serve_forever, daemon=True).start()
    srvs[0].serve_forever()
