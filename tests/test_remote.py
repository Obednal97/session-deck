"""Remote chats: a server's transcript mirrored under RMIR, with fake_ssh_run.sh as ssh: the "server" is this Mac with HOME at a temp folder."""
import json, os, subprocess, sys, tempfile, unittest, uuid
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


if __name__ == "__main__": unittest.main()
