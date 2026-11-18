"""Remote chats: a server's transcript mirrored under RMIR, with fake_ssh_run.sh as ssh: the "server" is this Mac with HOME at a temp folder."""
import http.client, json, os, subprocess, sys, tempfile, threading, time, unittest, uuid
from pathlib import Path

TMP = tempfile.mkdtemp()
os.environ.update(DECK_SECRETS=TMP, DECK_STORE=f"{TMP}/passkeys.json", DECK_PREFS=f"{TMP}/prefs.json", DECK_RP_ID="localhost", DECK_TS_USER="me@example.com",
                  DECK_SSH_HOSTS=f"{TMP}/ssh-hosts.json", DECK_TMUX_SOCKET="decktest", DECK_SHOW_TEST="1", DECK_SSH_CM=f"{TMP}/cm",
                  DECK_SSH_BIN=str(Path(__file__).resolve().parent / "fake_ssh_run.sh"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import server
# another test module may have imported server first, with its own settings: never let these tests reach the real tmux servers, ssh or ~/.claude
PINS = dict(TMUX_SOCKS=["decktest"], SSH_BIN=os.environ["DECK_SSH_BIN"], SSH_CM=Path(os.environ["DECK_SSH_CM"]), SSH_HOSTS=Path(os.environ["DECK_SSH_HOSTS"]),
            RMIR=Path(TMP) / "remote", PROJ=Path(TMP) / "projects", UPL=Path(TMP) / "uploads")
for k, v in PINS.items(): setattr(server, k, v)

def guard():  # a real check, not assert (python -O drops those): never run against the real tmux servers or ssh
    if server.TMUX_SOCKS != ["decktest"] or not server.SSH_BIN.endswith(("/fake_ssh.sh", "/fake_ssh_run.sh")): raise RuntimeError("tests would reach the real tmux or ssh")

def line(role, text, cwd="/root"):
    return json.dumps({"type": role, "cwd": cwd, "timestamp": "2026-11-18T10:00:00Z", "message": {"role": role, "content": [{"type": "text", "text": text}]}}) + "\n"


class Mirror(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old = {k: getattr(server, k) for k in PINS}, os.environ.get("CLAUDE_CONFIG_DIR")
        for k, v in PINS.items(): setattr(server, k, v)
        guard()
        os.environ.pop("CLAUDE_CONFIG_DIR", None)  # the fake server's Claude folder must be its own $HOME/.claude
    @classmethod
    def tearDownClass(cls):
        for k, v in cls.old[0].items(): setattr(server, k, v)
        if cls.old[1] is not None: os.environ["CLAUDE_CONFIG_DIR"] = cls.old[1]

    def setUp(self):
        self.home = Path(tempfile.mkdtemp()); os.environ["FAKE_SSH_HOME"] = str(self.home)
        server.ssh_hosts_write([]); server._SYNC.clear()
        self.h, _ = server.ssh_host_save({"addr": "pi@10.0.0.5", "auth": "key", "name": "Pi"}); self.hid = self.h["id"]
        self.sid = str(uuid.uuid4())
        self.sf = self.home / ".claude/projects/-root" / f"{self.sid}.jsonl"
        (self.sf.parent / self.sid / "subagents").mkdir(parents=True)
        self.sf.write_text(line("user", "hi") + line("assistant", "hello"))
        self.sub = self.sf.parent / self.sid / "subagents"
        (self.sub / "agent-a1.jsonl").write_text(line("user", "sub task"))
        (self.sub / "agent-a1.meta.json").write_text(json.dumps({"toolUseId": "t1", "description": "look"}))
        self.mir = server.RMIR / self.hid / f"{self.sid}.jsonl"

    def sync(self):
        server._SYNC.clear(); return server.ssh_sync(self.h, self.sid)

    def spy(self):  # the stdout sizes of ssh_run calls
        sizes, real = [], server.ssh_run
        def run(*a, **k):
            r = real(*a, **k); sizes.append(len(r.stdout)); return r
        server.ssh_run = run; self.addCleanup(setattr, server, "ssh_run", real)
        return sizes

    def test_first_sync(self):
        self.assertEqual(server.ssh_sync(self.h, self.sid), self.mir)
        self.assertEqual(self.mir.read_bytes(), self.sf.read_bytes())
        for n in ("agent-a1.jsonl", "agent-a1.meta.json"):
            self.assertEqual((self.mir.parent / self.sid / "subagents" / n).read_bytes(), (self.sub / n).read_bytes(), n)
        self.assertEqual(server.remote_of(self.mir), self.hid)
        self.assertIsNone(server.remote_of(self.sf))
        self.assertEqual(os.stat(server.RMIR).st_mode & 0o777, 0o700)

    def test_throttle_and_down(self):
        self.assertEqual(self.sync(), self.mir)
        with open(self.sf, "a") as fh: fh.write(line("user", "more"))
        self.assertEqual(server.ssh_sync(self.h, self.sid), self.mir)  # within 1.5 s: no run, the mirror as it was
        self.assertNotEqual(self.mir.read_bytes(), self.sf.read_bytes())
        down = Path(TMP) / "down"; down.touch(); os.environ["FAKE_SSH_DOWN"] = str(down); self.addCleanup(down.unlink)
        before = self.mir.read_bytes()
        self.assertEqual(self.sync(), self.mir)  # exit 255: the mirror stays
        self.assertEqual(self.mir.read_bytes(), before)
        def slow(*a, **k): raise subprocess.TimeoutExpired("ssh", 30)
        real = server.ssh_run; server.ssh_run = slow; self.addCleanup(setattr, server, "ssh_run", real)
        self.assertEqual(self.sync(), self.mir)  # a slow server: the same
        self.assertEqual(self.mir.read_bytes(), before)

    def test_append_only_new_bytes(self):
        self.sync(); sizes = self.spy()
        new = line("assistant", "x" * 5000)
        with open(self.sf, "a") as fh: fh.write(new)
        ino = self.mir.stat().st_ino
        self.assertEqual(self.sync(), self.mir)
        self.assertEqual(self.mir.read_bytes(), self.sf.read_bytes())
        self.assertEqual(self.mir.stat().st_ino, ino)
        self.assertLess(sizes[-1], len(new) + 200)
        self.sync(); self.assertLess(sizes[-1], 200)  # nothing new: a header only

    def test_shrunk_file_rewritten(self):
        self.sync()
        self.assertEqual([i["text"] for i in server.messages(self.mir)], ["hi", "hello"])
        self.sf.write_text(line("user", "new"))  # shorter than the mirror (a /clear, a compaction rewrite)
        self.assertEqual(self.sync(), self.mir)
        self.assertEqual(self.mir.read_bytes(), self.sf.read_bytes())
        self.assertEqual([i["text"] for i in server.messages(self.mir)], ["new"])
        (self.sub / "agent-a1.meta.json").write_text(json.dumps({"toolUseId": "t1", "description": "looked it up"}))  # rewritten, not appended to: it comes whole
        self.sync()
        self.assertEqual((self.mir.parent / self.sid / "subagents/agent-a1.meta.json").read_bytes(), (self.sub / "agent-a1.meta.json").read_bytes())

    def test_half_line(self):
        last = line("assistant", "the end")
        with open(self.sf, "a") as fh: fh.write(last[:20])
        self.sync()
        self.assertEqual(self.mir.read_bytes(), self.sf.read_bytes())
        self.assertEqual([i["text"] for i in server.messages(self.mir)], ["hi", "hello"])
        with open(self.sf, "a") as fh: fh.write(last[20:])
        self.sync()
        self.assertEqual(self.mir.read_bytes(), self.sf.read_bytes())
        self.assertEqual([i["text"] for i in server.messages(self.mir)], ["hi", "hello", "the end"])

    def test_mirror_out_of_step(self):  # a mirror that isn't the size the server appends from is dropped, then fetched whole
        self.sync()
        with open(self.mir, "ab") as fh: fh.write(b"junk")
        with open(self.sf, "a") as fh: fh.write(line("user", "more"))
        real, n = server.ssh_run, self.mir.stat().st_size
        def stale(h, script, inp, *a, **k): return real(h, script, inp.replace(b" %d\n" % n, b" %d\n" % (n - 4)), *a, **k)  # the server appends from n - 4
        server.ssh_run = stale; self.addCleanup(setattr, server, "ssh_run", real)
        self.sync(); server.ssh_run = real
        self.assertFalse(self.mir.exists())
        self.sync(); self.assertEqual(self.mir.read_bytes(), self.sf.read_bytes())

    def test_bad_names(self):
        real, calls = server.ssh_run, []
        def fake(h, script, *a, **k):
            calls.append(script)
            return subprocess.CompletedProcess([], 0, b"../x.jsonl 0 3\nabc\n/etc/x 0 3\nabc\n%s/../../y.jsonl 0 3\nabc\n%s.jsonl 0 2\nok\n" % (self.sid.encode(), self.sid.encode()), b"")
        server.ssh_run = fake; self.addCleanup(setattr, server, "ssh_run", real)
        before = set(Path(TMP).rglob("*"))
        self.assertEqual(self.sync(), self.mir)
        self.assertEqual(self.mir.read_bytes(), b"ok")
        made = {p for p in set(Path(TMP).rglob("*")) - before if p.is_file()}
        self.assertEqual(made, {self.mir})
        calls.clear()
        self.assertIsNone(server.ssh_sync(self.h, "../../x"))
        self.assertIsNone(server.ssh_sync(self.h, self.sid.upper()))
        self.assertIsNone(server.chat_file("not-a-uuid", self.hid))
        self.assertIsNone(server.chat_file("not-a-uuid"))
        self.assertEqual(calls, [])

    def test_unmirrored_names_not_sent(self):  # a file Python won't mirror must not be sent at all, or it comes whole on every sync
        for n in ("agent-acompact-1a2b.jsonl", "agent-a1.jsonl.bak", "agent-.jsonl", "agent-x.y.jsonl"): (self.sub / n).write_text(line("user", "y" * 4000))
        self.sync(); sizes = self.spy(); self.sync()
        self.assertLess(sizes[-1], 200)
        self.assertEqual(sorted(p.name for p in (self.mir.parent / self.sid / "subagents").iterdir()), ["agent-a1.jsonl", "agent-a1.meta.json"])

    def test_cut_short(self):  # a file that shrank while it was read sends fewer bytes than its header says: nothing of it is written
        self.sync(); before = self.mir.read_bytes()
        real = server.ssh_run
        server.ssh_run = lambda *a, **k: subprocess.CompletedProcess([], 0, b"%s.jsonl 0 30\nshort\n\n%s/subagents/agent-a1.jsonl 0 2\nhi\n" % (self.sid.encode(), self.sid.encode()), b"")
        self.addCleanup(setattr, server, "ssh_run", real)
        self.assertEqual(self.sync(), self.mir)
        self.assertEqual(self.mir.read_bytes(), before)

    def test_no_transcript(self):
        self.assertIsNone(server.ssh_sync(self.h, str(uuid.uuid4())))

    def test_chat_file(self):
        self.assertIsNone(server.find_file(self.sid))
        self.assertIsNone(server.chat_file(self.sid))  # no host and no mirror: nothing to sync from
        self.assertEqual(server.chat_file(self.sid, self.hid), self.mir)
        self.assertEqual(server.find_file(self.sid), self.mir)
        with open(self.sf, "a") as fh: fh.write(line("user", "more"))
        server._SYNC.clear()
        self.assertEqual(server.chat_file(self.sid), self.mir)  # a mirror is enough to know the host
        self.assertEqual(self.mir.read_bytes(), self.sf.read_bytes())
        local = server.PROJ / "-Users-me" / f"{self.sid}.jsonl"; local.parent.mkdir(parents=True, exist_ok=True); local.write_text(line("user", "mac"))
        self.addCleanup(local.unlink)
        self.assertEqual(server.chat_file(self.sid, self.hid), local)  # a local transcript wins

    def test_remote_out_chips(self):
        self.mir.parent.mkdir(parents=True, exist_ok=True)
        self.mir.write_text(line("assistant", "Saved it as report.pdf for you.") + line("assistant", "And a copy in ~/x.pdf too."))
        items = server.messages(self.mir)
        self.assertEqual(items[0]["files"], [{"name": "report.pdf", "rpath": "/root/report.pdf", "host": self.hid}])
        self.assertEqual(items[-1]["files"], [{"name": "x.pdf", "rpath": "~/x.pdf", "host": self.hid}])
        self.assertEqual(server.out_paths("see ~/x.pdf", "/root"), [str(Path.home() / "x.pdf")])  # a local chat's ~ is still the Mac's

    def test_delete_and_tidy(self):
        self.sync()
        old = self.mir.parent / f"{uuid.uuid4()}.jsonl"; old.write_text("x\n"); os.utime(old, (1, 1))
        server.tidy_uploads()
        self.assertFalse(old.exists()); self.assertTrue(self.mir.exists())
        server.ssh_host_delete("../" + server.RMIR.name)  # a tampered id never reaches outside RMIR
        self.assertTrue(server.RMIR.exists())
        server.ssh_host_delete(self.hid)
        self.assertFalse((server.RMIR / self.hid).exists())

def until(fn, secs=5):
    end = time.time() + secs
    while time.time() < end:
        v = fn()
        if v: return v
        time.sleep(0.1)
    return fn()

def T(*a): return subprocess.run(["tmux", "-L", "decktest", *a], capture_output=True, text=True).stdout.strip()


class Chats(unittest.TestCase):
    """Remote chats: SSH terminals (sessions on decktest marked as Stage 1 and Task 3 mark them) matched to Claude's sessions json on the fake server."""
    @classmethod
    def setUpClass(cls):
        cls.old = {k: getattr(server, k) for k in (*PINS, "sockets", "input_box")}, os.environ.get("CLAUDE_CONFIG_DIR")
        for k, v in PINS.items(): setattr(server, k, v)
        guard()
        server.sockets = lambda: ["decktest"]  # tmux options are written here: never on the real servers' sessions
        os.environ.pop("CLAUDE_CONFIG_DIR", None)
        T("kill-server")
        cls.srv = server.ThreadingHTTPServer(("127.0.0.1", 0), server.H); cls.srv.daemon_threads = True
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close()
        T("kill-server")
        for k, v in cls.old[0].items(): setattr(server, k, v)
        if cls.old[1] is not None: os.environ["CLAUDE_CONFIG_DIR"] = cls.old[1]

    def setUp(self):
        self.home = Path(tempfile.mkdtemp()); os.environ["FAKE_SSH_HOME"] = str(self.home)
        (self.home / ".claude/sessions").mkdir(parents=True)
        server.ssh_hosts_write([]); server._SYNC.clear(); server._RSCAN.clear(); server._live[0] = 0
        self.h, _ = server.ssh_host_save({"addr": "pi@10.0.0.5", "auth": "key", "name": "Pi"}); self.hid = self.h["id"]
        server.input_box = lambda key, wait=0: None
        self.n = 0

    def tearDown(self):
        T("kill-server")
        server.input_box = self.old[0]["input_box"]

    def term(self, **opts):  # an SSH connection session on the Mac, as ssh_open makes it, with the remote chat's options
        self.n += 1; s = f"ssh-{self.hid}-{self.n}"
        T("new-session", "-d", "-s", s, "-x", "120", "-y", "40", "-n", "Pi", "cat", ";", "set-option", "-t", f"={s}:", "@deck_ssh", self.hid,
          ";", "set-option", "-w", "-t", f"={s}:", "remain-on-exit", "on", *[x for k, v in opts.items() for x in (";", "set-option", "-t", f"={s}:", f"@deck_{k}", v)])
        return s, "decktest." + T("display", "-p", "-t", f"={s}:", "#{pane_id}")[1:]

    def opt(self, s, k): return T("show-options", "-v", "-t", f"={s}:", f"@deck_{k}")

    def created(self, s): return int(T("display", "-p", "-t", f"={s}:", "#{session_created}"))

    def claude(self, sid, cwd="/root/x", started=None, status="idle"):  # a live Claude on the server: a real pid, and its sessions json
        p = subprocess.Popen(["sleep", "600"]); self.addCleanup(lambda: (p.kill(), p.wait()))
        self.write(p.pid, sid, cwd, started if started is not None else time.time(), status)
        return p

    def write(self, pid, sid, cwd, started, status):
        (self.home / f".claude/sessions/{pid}.json").write_text(json.dumps({"pid": pid, "sessionId": sid, "cwd": cwd, "startedAt": int(started * 1000), "status": status, "kind": "interactive"}))

    def scan(self):  # a fresh scan, waited for (matching runs on every good scan); then the list as /api/sessions sees it
        server._RSCAN.clear(); server.rscan(self.h); return server.remote_chats()

    def get(self, path):
        c = http.client.HTTPConnection("127.0.0.1", self.srv.server_address[1], timeout=15)
        c.request("GET", path, headers={"X-Deck-Token": server.TOK}); r = c.getresponse(); return r.status, json.loads(r.read())

    def post(self, path, body):
        c = http.client.HTTPConnection("127.0.0.1", self.srv.server_address[1], timeout=15)
        c.request("POST", path, json.dumps(body), {"X-Deck-Token": server.TOK, "Content-Type": "application/json"})
        r = c.getresponse(); return r.status, json.loads(r.read())

    def test_deck_chat_listed(self):
        sid = str(uuid.uuid4()); s, pane = self.term(claude=sid, rcwd="/root/x", rkind="plain")
        self.claude(sid, status="busy")
        c = next(x for x in self.scan() if x["pane"] == pane)
        self.assertEqual((c["session"], c["state"], c["remote"], c["host"], c["rkind"], c["dropped"], c["cwd"]), (sid, "busy", True, self.hid, "plain", False, "/root/x"))
        for k in ("pane", "where", "name", "cwd", "engine", "plan", "pinned", "state", "session", "title", "mtime", "menu", "working"): self.assertIn(k, c)
        server._live[0] = 0
        self.assertNotIn(pane, {x["pane"] for x in server.live_sessions()})
        self.assertIn(pane, {x["pane"] for x in server.chats()})
        self.assertTrue(server.valid_pane(pane))
        _, d = self.get("/api/sessions")
        self.assertEqual([x["pane"] for x in d["ssh"]["chats"]], [pane]); self.assertIn("attn", d["ssh"]["chats"][0])
        self.assertNotIn(pane, {t["pane"] for t in d["ssh"]["terms"]})
        self.assertNotIn(pane, {x["pane"] for x in d["live"]})

    def test_clear_follows_pid(self):
        sid, new = str(uuid.uuid4()), str(uuid.uuid4()); s, pane = self.term(claude=sid, rcwd="/root/x", rkind="tmux")
        p = self.claude(sid); self.scan()
        self.assertEqual(self.opt(s, "rpid"), str(p.pid))
        self.write(p.pid, new, "/root/x", time.time(), "idle")  # /clear: the same Claude, a new session id
        self.assertEqual(next(x for x in self.scan() if x["pane"] == pane)["session"], new)
        self.assertEqual(self.opt(s, "claude"), new)

    def test_two_chats_same_folder(self):
        for order in (0, 1):
            T("kill-server")
            for j in (self.home / ".claude/sessions").iterdir(): j.unlink()
            (a, pa), (b, pb) = self.term(rcwd="/root/x", rkind="plain"), self.term(rcwd="/root/x", rkind="plain")
            real = server.ssh_terms  # b opened 3 s after a
            server.ssh_terms = lambda: [{**t, "created": t["created"] + 3 * (t["session"] == b)} for t in real()]
            self.addCleanup(setattr, server, "ssh_terms", real)
            ca = self.created(a); sa, sb = str(uuid.uuid4()), str(uuid.uuid4())
            for sid, at in ([(sa, ca + 1), (sb, ca + 4)], [(sb, ca + 4), (sa, ca + 1)])[order]: self.claude(sid, started=at)
            got = {x["pane"]: x["session"] for x in self.scan()}
            self.assertEqual(got, {pa: sa, pb: sb}, order)
            self.assertEqual((self.opt(a, "claude"), self.opt(b, "claude")), (sa, sb))
            server.ssh_terms = real

    def test_hand_typed(self):
        s, pane = self.term(); c = self.created(s)
        self.claude(str(uuid.uuid4()), started=c - 60)  # started before the terminal opened: never this terminal's
        self.assertEqual(self.scan(), [])  # no input box on screen
        server.input_box = lambda key, wait=0: "" if key == pane else None
        self.assertEqual(self.scan(), [])  # Claude's box shows, but the only Claude started before the terminal
        sid = str(uuid.uuid4()); p = self.claude(sid, started=c + 2)
        ch = self.scan()
        self.assertEqual([(x["pane"], x["session"], x["rkind"]) for x in ch], [(pane, sid, "hand")])
        self.assertEqual((self.opt(s, "rkind"), self.opt(s, "rpid")), ("hand", str(p.pid)))
        p.kill(); p.wait(); server.input_box = lambda key, wait=0: None
        self.assertEqual(self.scan(), [])
        self.assertEqual([self.opt(s, k) for k in ("claude", "rpid", "rkind")], ["", "", ""])
        self.assertIn(pane, {t["pane"] for t in server.ssh_state()["terms"]})

    def test_hand_no_swap(self):  # a terminal showing an older Claude never takes a newer Claude's session, nor a deck fork's
        boxes = set(); server.input_box = lambda key, wait=0: "" if key in boxes else None
        a, pa = self.term(); ca = self.created(a); boxes.add(pa)
        self.claude(str(uuid.uuid4()), started=ca - 60)  # A's own Claude: started before A opened (a tmux attach), so it never fits
        f, pf = self.term(rcwd="/root/f", rkind="plain"); sf = str(uuid.uuid4()); self.claude(sf, cwd="/root/f", started=time.time())  # a fork, found by folder
        got = {x["pane"]: x["session"] for x in self.scan()}
        self.assertEqual(got, {pf: sf})  # folder matches come first: A, the only box, doesn't take the fork's
        server._RBOX[pa] -= 30  # A has shown its box for 30 s
        c, pc = self.term(); sc = str(uuid.uuid4()); self.claude(sc, started=time.time())  # a new Claude in a newer terminal C, its box not drawn yet
        self.assertEqual({x["pane"]: x["session"] for x in self.scan()}, {pf: sf})  # A is still the only box, but its box was there before this Claude started
        boxes.add(pc)
        self.assertEqual({x["pane"]: x["session"] for x in self.scan()}, {pf: sf, pc: sc})
        self.assertEqual((self.opt(a, "claude"), self.opt(c, "rkind")), ("", "hand"))
        (p, pp), (q, pq) = self.term(), self.term(); boxes |= {pp, pq}  # two new boxes and one new Claude that fits both: ambiguous, so neither
        self.claude(str(uuid.uuid4()), started=time.time())
        self.assertEqual({x["pane"]: x["session"] for x in self.scan()}, {pf: sf, pc: sc})
        self.assertEqual([self.opt(x, "claude") for x in (a, p, q)], ["", "", ""])

    def test_hand_two_fits(self):  # with two boxes on the host, a terminal that two Claudes fit takes neither; with one fit it takes it
        (p, pp), (q, pq) = self.term(), self.term(); server.input_box = lambda key, wait=0: "" if key in (pp, pq) else None
        real = server.ssh_terms  # p opened 100 s before q
        server.ssh_terms = lambda: [{**t, "created": t["created"] - 100 * (t["session"] == p)} for t in real()]
        self.addCleanup(setattr, server, "ssh_terms", real)
        x1 = self.claude(str(uuid.uuid4()), started=time.time() - 50); s2 = str(uuid.uuid4()); self.claude(s2, started=time.time() - 40)  # both since p opened, before q
        self.assertEqual(self.scan(), [])
        x1.kill(); x1.wait()
        self.assertEqual([(x["pane"], x["session"]) for x in self.scan()], [(pp, s2)])

    def test_end_kills_rtmux(self):  # Stop ends the server's tmux session by the name it started with, not the id a /clear gave the chat
        real, scripts = server.ssh_run, []
        def spy(h, script, *a, **k): scripts.append(script); return real(h, script, *a, **k)
        server.ssh_run = spy; self.addCleanup(setattr, server, "ssh_run", real)
        for rt in (f"deck-{uuid.uuid4()}", "deck-x; tmux kill-server"):
            new = str(uuid.uuid4()); s, pane = self.term(claude=new, rcwd="/root/x", rkind="tmux", rtmux=rt)
            self.claude(new); self.scan(); scripts.clear()
            self.assertEqual(self.post("/api/end", {"pane": pane, "kill": True}), (200, {"ok": True}))
            kill = [x for x in scripts if "kill-session" in x]
            self.assertEqual(kill, [f"tmux kill-session -t ={rt}"] if rt[5:].count("-") == 4 else [])  # a tampered name is never sent
            self.assertFalse(any(new in x for x in kill))
            self.assertTrue(until(lambda: s not in T("list-sessions", "-F", "#{session_name}").split()))

    def test_no_master_fast(self):
        sid = str(uuid.uuid4()); s, pane = self.term(claude=sid, rcwd="/root/x", rkind="tmux")
        p = self.claude(sid, status="busy"); self.scan()
        down = Path(TMP) / "down2"; down.touch(); os.environ["FAKE_SSH_DOWN"] = str(down); self.addCleanup(down.unlink)
        real, done, calls = server.ssh_run, threading.Event(), []
        def slow(*a, **k):  # no master: exit 255, here after a slow server's few seconds
            calls.append(1)
            try: time.sleep(2.5); return real(*a, **k)
            finally: done.set()
        server.ssh_run = slow; self.addCleanup(setattr, server, "ssh_run", real)
        server._RSCAN[self.hid][0] = 0  # the cache is stale: the next look asks the server again
        t0 = time.time(); ch = server.chats()
        self.assertLess(time.time() - t0, 2)
        self.assertEqual(next(x for x in ch if x["pane"] == pane)["state"], "busy")
        time.sleep(0.5); server.chats(); self.assertEqual(len(calls), 1)  # one ask at a time per host, however long it takes
        self.assertTrue(done.wait(10)); time.sleep(0.2)
        self.assertEqual(next(x for x in server.remote_chats() if x["pane"] == pane)["state"], "busy")  # the last good scan, under 60 s old
        self.assertEqual(self.opt(s, "rpid"), str(p.pid))  # a failed scan matches nothing and clears nothing
        server._RSCAN[self.hid][2] -= 61
        self.assertIsNone(next(x for x in server.remote_chats() if x["pane"] == pane)["state"])

    def test_drop_no_push(self):
        sent, real = [], (server.push_all, server.push_subs)
        server.push_all = lambda msg, skip=(): sent.append(msg) or []; server.push_subs = lambda: [{}]
        self.addCleanup(lambda: (setattr(server, "push_all", real[0]), setattr(server, "push_subs", real[1]), server.WATCH.clear()))
        sf = self.home / ".claude/projects/-root-x"; sf.mkdir(parents=True)
        for status, drop in (("busy", "tmux"), ("waiting", "tmux"), ("busy", "plain"), ("busy", None)):  # plain: Claude ends with the connection
            T("kill-server"); server.WATCH.clear(); sent.clear()
            sid = str(uuid.uuid4()); s, pane = self.term(claude=sid, rcwd="/root/x", rkind="tmux")
            (sf / f"{sid}.jsonl").write_text(line("user", "go", "/root/x") + line("assistant", "All done here.", "/root/x"))
            p = self.claude(sid, status=status); self.scan()
            server.watch_once(); server.WATCH[pane]["busy"] = time.time() - 30  # busy for 30 s
            if drop: os.kill(int(T("display", "-p", "-t", f"={s}:", "#{pane_pid}")), 9); until(lambda: T("display", "-p", "-t", f"={s}:", "#{pane_dead}") == "1")
            else: self.write(p.pid, sid, "/root/x", time.time(), "idle")
            if drop == "plain": p.kill(); p.wait()
            c = next(x for x in self.scan() if x["pane"] == pane)
            self.assertEqual((c["dropped"], c["state"]), (bool(drop), None if drop == "plain" else "idle" if not drop else status))
            server.watch_once()
            if drop:
                self.assertIsNone(server.attn(c), status)
                time.sleep(0.5); self.assertEqual(sent, [], status)
            else:  # the same chat, still connected, finishing: its reply is the news
                self.assertTrue(until(lambda: sent)); self.assertEqual(sent[0]["body"], "All done here.")

    def test_routes(self):
        sid = str(uuid.uuid4()); s, pane = self.term(claude=sid, rcwd="/root/x", rkind="plain")
        self.claude(sid)
        sf = self.home / ".claude/projects/-root-x" / f"{sid}.jsonl"; sf.parent.mkdir(parents=True)
        sf.write_text(line("user", "hi", "/root/x") + line("assistant", "hello", "/root/x"))
        self.scan()
        self.assertEqual(self.get(f"/api/session/{sid}")[0], 404)  # no host and no mirror: nothing to read
        st, d = self.get(f"/api/session/{sid}?host={self.hid}")
        self.assertEqual((st, [i["text"] for i in d["items"]]), (200, ["hi", "hello"]))
        mir = server.RMIR / self.hid / f"{sid}.jsonl"; before = mir.read_bytes()
        st, d = self.get(f"/api/info/{sid}?pane={pane}")
        self.assertEqual(st, 200)
        T("kill-session", "-t", f"={s}")  # no live pane: the title goes on the server's transcript, never the mirror
        for body in ({"session": sid, "name": "Server one", "claude": True, "host": self.hid}, {"session": sid, "name": "Server two", "claude": True}):
            self.assertEqual(self.post("/api/rename", body), (200, {"done": ["claude"]}))
            self.assertEqual(mir.read_bytes(), before)
            self.assertEqual(json.loads(sf.read_text().splitlines()[-1]), {"type": "custom-title", "customTitle": body["name"], "sessionId": sid})
        self.assertEqual(server.title_of(sf), "Server two")


if __name__ == "__main__": unittest.main()
