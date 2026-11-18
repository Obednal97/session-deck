"""SSH hosts: address parsing, ~/.ssh/config names, the host store; connections in a throwaway tmux server (decktest)."""
import http.client, json, os, signal, subprocess, sys, tempfile, threading, time, unittest, urllib.parse
from pathlib import Path

TMP = tempfile.mkdtemp()
os.environ.update(DECK_SECRETS=TMP, DECK_STORE=f"{TMP}/passkeys.json", DECK_PREFS=f"{TMP}/prefs.json", DECK_RP_ID="localhost", DECK_TS_USER="me@example.com",
                  DECK_SSH_HOSTS=f"{TMP}/ssh-hosts.json", DECK_TMUX_SOCKET="decktest", DECK_SHOW_TEST="1", DECK_SSH_CM=f"{TMP}/cm",
                  DECK_SSH_BIN=str(Path(__file__).resolve().parent / "fake_ssh.sh"), FAKE_SSH_MASTER=f"{TMP}/master", FAKE_SSH_JUMP=f"{TMP}/jump")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import server
# another test module may have imported server first, with its own settings: never let these tests reach the real tmux servers or ssh
server.TMUX_SOCKS, server.SSH_BIN, server.SSH_CM, server.SSH_HOSTS = ["decktest"], os.environ["DECK_SSH_BIN"], Path(os.environ["DECK_SSH_CM"]), Path(os.environ["DECK_SSH_HOSTS"])
server.sockets = lambda: ["decktest"]  # remote chats write tmux options on SSH terminals: only ever this test server's

def guard():  # a real check, not assert (python -O drops those): never run against the real tmux servers or ssh
    if server.TMUX_SOCKS != ["decktest"] or not server.SSH_BIN.endswith(("/fake_ssh.sh", "/fake_ssh_run.sh")): raise RuntimeError("tests would reach the real tmux or ssh")


class Hosts(unittest.TestCase):
    def setUp(self): Path(server.SSH_HOSTS).unlink(missing_ok=True)

    def test_parse_addr(self):
        p = server.parse_addr
        self.assertEqual(p("pi@10.0.0.5:2222"), {"user": "pi", "host": "10.0.0.5", "port": 2222})
        self.assertEqual(p("home"), {"user": None, "host": "home", "port": None})
        self.assertEqual(p("root@[fd7a::1]:22")["host"], "fd7a::1")
        self.assertEqual(p("u@[fd7a::1]"), {"user": "u", "host": "fd7a::1", "port": None})
        self.assertEqual(p("Admin_1@my_host"), {"user": "Admin_1", "host": "my_host", "port": None})
        self.assertEqual(p("_svc@_alias:2200"), {"user": "_svc", "host": "_alias", "port": 2200})
        for bad in ("-oProxyCommand=x", "a b", "h;rm", "host; rm -rf ~", "u@h:0", "u@h:70000", "$(id)@h", "", "u@-h", "-l@h", "u v@h", "'u'@h", 'u@"h"', "u@h`id`", None):
            self.assertIsNone(p(bad), bad)

    def test_config_names(self):
        c = Path(TMP) / "config"
        c.write_text("Host media tv # note\n  HostName 1.2.3.4\nHost *\n  User x\nInclude other\nHost nas-jump\nMatch host y\nHost !neg\n")
        old, server.SSH_CONFIG = server.SSH_CONFIG, c
        try: self.assertEqual(server.ssh_config_names(), ["media", "nas-jump", "tv"])
        finally: server.SSH_CONFIG = old

    def test_save_update_delete(self):
        h, err = server.ssh_host_save({"addr": "pi@10.0.0.5", "auth": "password"})
        self.assertIsNone(err)
        self.assertEqual((h["perm"], h["name"], h["user"], h["host"]), ("default", "10.0.0.5", "pi", "10.0.0.5"))
        h2, _ = server.ssh_host_save({"id": h["id"], "addr": "pi@10.0.0.5", "auth": "password", "name": "Home"})
        self.assertEqual((h2["id"], h2["name"]), (h["id"], "Home"))
        self.assertEqual(len(server.ssh_hosts()), 1)
        self.assertEqual(server.ssh_host_save({"addr": "h2", "auth": "key", "name": ""})[0]["name"], "h2")
        server.ssh_host_delete(server.ssh_hosts()[-1]["id"])
        self.assertEqual(os.stat(server.SSH_HOSTS).st_mode & 0o777, 0o600)
        server.ssh_host_delete(h["id"])
        self.assertEqual(server.ssh_hosts(), [])

    def test_save_rejects(self):
        c = Path(TMP) / "config"; c.write_text("Host media\n")
        old, server.SSH_CONFIG = server.SSH_CONFIG, c
        self.addCleanup(setattr, server, "SSH_CONFIG", old)
        for b in ({"addr": "nope", "auth": "config"}, {"addr": "unknown", "auth": "config"}, {"addr": "h", "auth": "x"}, {"addr": "h", "auth": "key", "perm": "nope"}, {"addr": "h;x", "auth": "key"},
                  {"addr": "h", "auth": "key", "id": "missing"}):
            h, err = server.ssh_host_save(b)
            self.assertIsNone(h); self.assertIsInstance(err, str)
        self.assertEqual(server.ssh_hosts(), [])

class Vault(unittest.TestCase):
    def setUp(self):
        self.login = "me@example.com"
        with server.LOCK: server.DB[self.login] = {"uid": "u", "creds": [], "sessions": {}}

    def stub(self, cid):
        with server.LOCK:
            u = server.DB[self.login]
            if not any(c["id"] == cid for c in u["creds"]): u["creds"].append({"id": cid, "name": cid})
            u["sessions"]["s" + cid] = {"cred": cid, "exp": 9e12, "seen": 0}
        class S:
            via_ts = lambda s: True
            session = lambda s, l=self.login, i="s" + cid: (l, i)
        return S()

    def test_same_key_twice(self):
        h = self.stub("a"); k = server.vault_key(h)
        self.assertEqual(len(k), 43); self.assertEqual(k, server.vault_key(h))

    def test_key_per_passkey(self):
        self.assertNotEqual(server.vault_key(self.stub("a")), server.vault_key(self.stub("b")))

    def test_gone_with_passkey(self):
        k = server.vault_key(self.stub("a"))
        with server.LOCK: server.DB[self.login]["creds"] = []
        self.assertNotEqual(k, server.vault_key(self.stub("a")))

    def test_local_token_route(self):
        class L: via_ts = lambda s: False
        k = server.vault_key(L()); self.assertEqual(len(k), 43); self.assertEqual(k, server.vault_key(L()))
        self.assertEqual(server.SEC["ssh_vk"], k)

def until(fn, secs=5):
    end = time.time() + secs
    while time.time() < end:
        v = fn()
        if v: return v
        time.sleep(0.1)
    return fn()

class Conns(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        guard()
        subprocess.run(["tmux", "-L", "decktest", "kill-server"], capture_output=True)
        server._socks.pop("decktest", None)
        cls.srv = server.ThreadingHTTPServer(("127.0.0.1", 0), server.H); cls.srv.daemon_threads = True
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close()
        subprocess.run(["tmux", "-L", "decktest", "kill-server"], capture_output=True)

    def setUp(self):
        server.ssh_hosts_write([])
        self.h, _ = server.ssh_host_save({"addr": "pi@10.0.0.5:2222", "auth": "password", "name": "Pi"})

    def post(self, path, body):
        c = http.client.HTTPConnection("127.0.0.1", self.srv.server_address[1], timeout=15)
        c.request("POST", path, json.dumps(body), {"X-Deck-Token": server.TOK, "Content-Type": "application/json"})
        r = c.getresponse(); return r.status, json.loads(r.read())

    def screen(self, pane): return server.tm(pane, "capture-pane", "-p", "-t", "{P}")
    def term(self, pane): return next((t for t in server.ssh_terms() if t["pane"] == pane), None)

    def test_argv_shape(self):
        a = server.ssh_argv({"host": "h", "user": "u", "port": 2222, "auth": "key"})
        self.assertEqual(a[0], server.SSH_BIN); self.assertEqual(a[a.index("--") + 1:], ["h"])
        self.assertIn("PreferredAuthentications=publickey", a); self.assertIn("ControlMaster=auto", a)
        self.assertEqual(a[a.index("-p") + 1], "2222"); self.assertEqual(a[a.index("-l") + 1], "u")
        self.assertFalse(any("StrictHostKeyChecking" in x for x in a))
        self.assertIn("BatchMode=yes", server.ssh_argv({"host": "h", "auth": "config"}, ["cat"], batch=True))
        self.assertEqual(server.ssh_argv({"host": "fd7a::1", "auth": "password"}, ["'x y'"])[-3:], ["--", "fd7a::1", "'x y'"])
        self.assertEqual(os.stat(server.SSH_CM).st_mode & 0o777, 0o700)

    def test_argv_refuses_tampered(self):
        for h in ({"host": "-oProxyCommand=x"}, {"host": "h;rm"}, {"host": "h", "user": "-x"}, {"host": "h", "port": "22 -oX"}, {"host": "h", "port": 0}, {"host": None}, {"host": "h", "user": 5}):
            with self.assertRaises(ValueError, msg=h): server.ssh_argv({"auth": "key", **h})

    def test_open_lists_and_hides(self):
        p = server.ssh_open(self.h["id"])
        self.assertRegex(p, r"^decktest\.\d+$")
        t = until(lambda: self.term(p))
        self.assertEqual((t["host"], t["session"], t["title"], t["dead"]), (self.h["id"], f"ssh-{self.h['id']}-1", "Pi", False))
        self.assertIn("-p 2222 -l pi -- 10.0.0.5", until(lambda: "10.0.0.5" in self.screen(p) and self.screen(p)))
        self.assertEqual(server.tm(p, "show-options", "-v", "-t", "{P}", "status").strip(), "off")
        p2 = server.ssh_open(self.h["id"])
        self.assertEqual(until(lambda: self.term(p2))["session"], f"ssh-{self.h['id']}-2")
        # SSH terminals (marked @deck_ssh) and deck-view-* sessions never count as chats, even when they run something called claude;
        # a session that is only named ssh-* is the user's own and does
        for n in ("ssh-zz-1", "deck-view-0123abcd", "plainchat", "ssh-mine"):
            subprocess.run(["tmux", "-L", "decktest", "new-session", "-d", "-s", n, "bash", "-c", "exec -a claude cat"], check=True)
        subprocess.run(["tmux", "-L", "decktest", "set-option", "-t", "=ssh-zz-1:", "@deck_ssh", "zz"], check=True)
        server._socks.pop("decktest", None)
        def live(): server._live[0] = 0; return sorted(s["where"].split(":")[0] for s in server.live_sessions() if s["pane"].startswith("decktest."))
        until(lambda: len(live()) == 2)
        self.assertEqual(live(), ["plainchat", "ssh-mine"])
        self.assertNotIn(p, {s["pane"] for s in server.live_sessions()})
        for n in ("ssh-zz-1", "deck-view-0123abcd", "plainchat", "ssh-mine"): subprocess.run(["tmux", "-L", "decktest", "kill-session", "-t", "=" + n])

    def test_password_typed_once(self):
        p = server.ssh_open(self.h["id"], "s3cret")
        self.assertTrue(until(lambda: "AUTH s3cret" in self.screen(p)), self.screen(p))
        time.sleep(2)  # the fake asks "password: " again; the deck must not answer it
        s = self.screen(p)
        self.assertEqual((s.count("AUTH"), s.count("s3cret")), (1, 1), s)
        self.assertTrue(s.rstrip().endswith("pi@10.0.0.5's password:"), s)
        self.assertNotIn("s3cret", subprocess.run(["tmux", "-L", "decktest", "list-buffers"], capture_output=True, text=True).stdout)

    def test_newest_feeder_only(self):  # a reconnect while an earlier feeder still waits: only the newest one types
        p = server.ssh_open(self.h["id"])
        until(lambda: "password:" in self.screen(p))
        server.tm(p, "send-keys", "-t", "{P}", "x", "Enter")  # the user answers the first prompt by hand; the fake now waits at "password: "
        until(lambda: "AUTH x" in self.screen(p))
        server.tm(p, "send-keys", "-t", "{P}", "-l", "line"); server.tm(p, "send-keys", "-t", "{P}", "Enter")  # cat's output: the prompt is no longer last
        old = threading.Thread(target=server.pw_feed, args=(p, "first", self.h, 8), daemon=True); old.start(); time.sleep(0.5)
        self.assertEqual(self.post("/api/ssh/reconnect", {"pane": p, "password": "second"}), (200, {"ok": True}))
        self.assertTrue(until(lambda: "AUTH second" in self.screen(p)), self.screen(p))
        old.join(10); time.sleep(1)
        self.assertNotIn("first", self.screen(p))

    def test_prompt_forms(self):  # only OpenSSH's own password prompts
        for ok in ("pi@10.0.0.5's password:", "(pi@10.0.0.5) Password:", "(pi@h) password:"): self.assertTrue(server.PW_PROMPT.search(ok), ok)
        for no in ("Password:", "password:", "[sudo] password for pi:", "Enter password:", "New password:", "(a b) Password:"): self.assertFalse(server.PW_PROMPT.search(no), no)

    def test_master_up_no_typing(self):  # through a live master there's no ssh prompt: a later prompt, even one that looks exactly like ssh's, never gets it
        m = Path(os.environ["FAKE_SSH_MASTER"]); m.touch(); self.addCleanup(m.unlink, missing_ok=True)
        ask = "pi@10.0.0.5's password:"
        self.assertTrue(server.PW_PROMPT.search(ask))  # only the master check keeps the password back
        p = server.ssh_open(self.h["id"], "s3cret")
        self.assertTrue(until(lambda: ask in self.screen(p)), self.screen(p))
        self.assertEqual(self.post("/api/ssh/reconnect", {"pane": p, "password": "s3cret"}), (200, {"ok": True}))
        self.assertTrue(until(lambda: ask in self.screen(p)), self.screen(p))
        time.sleep(1.5)
        self.assertNotIn("s3cret", self.screen(p))
        m.unlink(); self.assertEqual(self.post("/api/ssh/reconnect", {"pane": p, "password": "s3cret"}), (200, {"ok": True}))  # and with no master it is typed
        self.assertTrue(until(lambda: "AUTH s3cret" in self.screen(p)), self.screen(p))

    def test_jump_prompt_not_typed(self):  # a ProxyJump host's own password prompt never gets the target's password
        j = Path(os.environ["FAKE_SSH_JUMP"]); j.touch(); self.addCleanup(j.unlink, missing_ok=True)
        p = server.ssh_open(self.h["id"], "s3cret")
        self.assertTrue(until(lambda: "jump@bastion's password:" in self.screen(p)), self.screen(p))
        time.sleep(1.5)
        self.assertNotIn("JUMP", self.screen(p))
        server.tm(p, "send-keys", "-t", "{P}", "jp", "Enter")  # the user answers the jump host; the target's prompt then gets the saved password
        self.assertTrue(until(lambda: "AUTH s3cret" in self.screen(p)), self.screen(p))
        self.assertIn("JUMP jp", self.screen(p))

    def test_password_not_in_ps(self):
        pw = os.urandom(8).hex()  # unique, so no other process's command line can contain it by chance
        p = server.ssh_open(self.h["id"], pw)
        seen = []
        def look():
            seen.append(subprocess.run(["ps", "-axo", "command="], capture_output=True, text=True).stdout)
            return "AUTH " + pw in self.screen(p)
        self.assertTrue(until(look, 5), self.screen(p))
        self.assertTrue(seen and not any(pw in x for x in seen))

    def test_dead_and_reconnect(self):
        p = server.ssh_open(self.h["id"])
        until(lambda: "password:" in self.screen(p))
        os.kill(int(server.tm(p, "display", "-p", "-t", "{P}", "#{pane_pid}")), signal.SIGKILL)
        self.assertTrue(until(lambda: self.term(p)["dead"]))
        self.assertEqual(self.post("/api/ssh/reconnect", {"pane": p, "password": "again"}), (200, {"ok": True}))
        self.assertTrue(until(lambda: not self.term(p)["dead"]))
        self.assertTrue(until(lambda: "AUTH again" in self.screen(p)), self.screen(p))
        self.assertEqual(self.post("/api/ssh/reconnect", {"pane": "decktest.99999"})[0], 400)

    def test_temp_host_dropped(self):
        code, r = self.post("/api/ssh/connect", {"temp": {"addr": "root@10.9.9.9", "auth": "password"}, "password": "pw"})
        self.assertEqual(code, 200)
        t = until(lambda: self.term(r["pane"]))
        h = next(h for h in server.ssh_state()["hosts"] if h["id"] == t["host"])
        self.assertEqual((h["temp"], h["host"], h["user"], h["id"][0]), (True, "10.9.9.9", "root", "t"))
        self.assertEqual(self.post("/api/ssh/close", {"pane": r["pane"]}), (200, {"ok": True}))
        self.assertIsNone(self.term(r["pane"]))
        self.assertFalse(any(h["id"] == t["host"] for h in server.ssh_state()["hosts"]))
        self.assertEqual(self.post("/api/ssh/close", {"pane": r["pane"]})[0], 400)

    def test_temp_host_survives_restart(self):  # a throwaway host comes back from its sessions; a terminal with no record is still listed
        pw = os.urandom(8).hex()
        code, r = self.post("/api/ssh/connect", {"temp": {"addr": "root@10.9.9.9:2200", "auth": "password"}, "password": pw})
        self.assertEqual(code, 200, r)
        t = until(lambda: self.term(r["pane"]))
        self.assertNotIn(pw, subprocess.run(["tmux", "-L", "decktest", "show-options", "-t", f"={t['session']}:"], capture_output=True, text=True).stdout)
        server.SSH_TEMP.clear()  # as after a restart
        st = server.ssh_state(); h = next(h for h in st["hosts"] if h["id"] == t["host"])
        self.assertEqual((h["temp"], h["name"], h["host"], h["user"], h["port"], h["auth"]), (True, "10.9.9.9", "10.9.9.9", "root", 2200, "password"))
        self.assertFalse(any("rec" in x for x in st["terms"]))
        server.SSH_TEMP.clear(); self.assertEqual(server.ssh_host(t["host"])["host"], "10.9.9.9")  # a reconnect before any list finds it too
        server.tm(r["pane"], "set-option", "-u", "-t", f"={t['session']}:", "@deck_ssh_host"); server.SSH_TEMP.clear()
        h = next(h for h in server.ssh_state()["hosts"] if h["id"] == t["host"])
        self.assertEqual((h["lost"], h["name"]), (True, "10.9.9.9"))
        self.assertIsNone(server.ssh_host(t["host"]))
        self.assertEqual(self.post("/api/ssh/close", {"pane": r["pane"]}), (200, {"ok": True}))
        self.assertIsNone(self.term(r["pane"]))
        self.assertFalse(any(h["id"] == t["host"] for h in server.ssh_state()["hosts"]))

    def test_connect_rejects(self):
        for b in ({"host": "nope"}, {"temp": {"addr": "-oProxyCommand=x", "auth": "key"}}, {"temp": {"addr": "h", "auth": "config"}}, {"temp": {"addr": "h", "auth": "x"}},
                  {"host": self.h["id"], "password": "x" * 1025}, {"host": self.h["id"], "password": "a\nb"}):
            self.assertEqual(self.post("/api/ssh/connect", b)[0], 400, b)
        self.assertFalse(any(h.get("temp") and not h.get("lost") for h in server.ssh_state()["hosts"]))  # earlier tests' terminals stand in for hosts they deleted
        server.ssh_hosts_write([{**self.h, "host": "-oProxyCommand=x"}])  # a tampered hosts file
        self.assertEqual(self.post("/api/ssh/connect", {"host": self.h["id"]})[0], 400)

    def test_sessions_payload(self):
        c = http.client.HTTPConnection("127.0.0.1", self.srv.server_address[1], timeout=30)
        c.request("GET", "/api/sessions", headers={"X-Deck-Token": server.TOK}); d = json.loads(c.getresponse().read())
        self.assertEqual(set(d["ssh"]), {"hosts", "terms", "chats"}); self.assertIn(self.h["id"], [h["id"] for h in d["ssh"]["hosts"]])

class Remote(unittest.TestCase):
    """Attach, Get file, Install key and forget a host key, with fake_ssh_run.sh as ssh: the "server" is this Mac with HOME at a temp folder."""
    @classmethod
    def setUpClass(cls):
        guard()
        cls.old = server.SSH_BIN, server.SSH_KEY, server.KNOWN_HOSTS, server.UPL
        server.UPL = Path(TMP) / "uploads"
        cls.home = Path(tempfile.mkdtemp()); os.environ.update(FAKE_SSH_HOME=str(cls.home), FAKE_SSH_DOWN=f"{TMP}/down", FAKE_SSH_NOKEY=f"{TMP}/nokey")
        server.SSH_BIN, server.SSH_KEY, server.KNOWN_HOSTS = str(Path(__file__).resolve().parent / "fake_ssh_run.sh"), Path(TMP) / "mackey" / "id_ed25519", Path(TMP) / "known_hosts"
        subprocess.run(["tmux", "-L", "decktest", "kill-server"], capture_output=True); server._socks.pop("decktest", None)
        cls.srv = server.ThreadingHTTPServer(("127.0.0.1", 0), server.H); cls.srv.daemon_threads = True
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close()
        server.SSH_BIN, server.SSH_KEY, server.KNOWN_HOSTS, server.UPL = cls.old
        subprocess.run(["tmux", "-L", "decktest", "kill-server"], capture_output=True)

    def setUp(self):
        server.ssh_hosts_write([])
        self.h, _ = server.ssh_host_save({"addr": "pi@10.0.0.5:2222", "auth": "password", "name": "Pi"})
        self.pane = server.ssh_open(self.h["id"])
        until(lambda: server.valid_term(self.pane))

    def req(self, method, path, body=None, ctype="application/json"):
        c = http.client.HTTPConnection("127.0.0.1", self.srv.server_address[1], timeout=30)
        c.request(method, path, body if isinstance(body, (bytes, type(None))) else json.dumps(body), {"X-Deck-Token": server.TOK, "Content-Type": ctype})
        return c.getresponse()
    def post(self, path, body):
        r = self.req("POST", path, body); return r.status, json.loads(r.read())

    def test_rpath(self):
        self.assertEqual(server.rpath("~/a b"), "\"$HOME\"/'a b'")
        self.assertEqual(server.rpath("/etc/x"), "/etc/x")
        self.assertEqual(server.rpath("x;$(id)"), "'x;$(id)'")
        for bad in ("a\nb", "", "a\0b", None):
            with self.assertRaises(ValueError, msg=repr(bad)): server.rpath(bad)

    def test_put_and_type(self):
        r = self.req("POST", f"/api/upload?pane={self.pane}&name=notes.txt", b"hello there\n", "application/octet-stream")
        d = json.loads(r.read())
        self.assertEqual(r.status, 200, d)
        self.assertTrue(d["remote"]); self.assertTrue(d["path"].startswith(f"{self.home}/.cache/session-deck/uploads/"), d)  # absolute: what the terminal types works from any folder
        f = Path(d["path"])
        self.assertEqual(f.read_bytes(), b"hello there\n")
        self.assertEqual(list(server.UPL.glob("*-*-*/*")), [])  # the Mac's copy is gone
        self.assertEqual(self.post("/api/ssh/type", {"pane": self.pane, "text": d["path"] + " "}), (200, {"ok": True}))
        self.assertTrue(until(lambda: d["path"] in server.tm(self.pane, "capture-pane", "-p", "-J", "-t", "{P}")))
        for b in ({"pane": self.pane, "text": "x" * 4097}, {"pane": self.pane, "text": 5}, {"pane": "decktest.99999", "text": "x"}):
            self.assertEqual(self.post("/api/ssh/type", b)[0], 400, b)

    def test_put_any_file(self):  # to a server a file goes as it is, under its own name: no type check, no HEIC conversion, no .txt
        files = {"backup.tar.gz": b"\x1f\x8b\x08\x00" + os.urandom(3000) + b"\x00\x00", "nginx.conf": b"server { listen 80; }\n",
                 "IMG_1.HEIC": b"\x00\x00\x00\x18ftypheic" + os.urandom(100), "a b;$(id).sh": b"#!/bin/sh\n"}
        up = self.home / ".cache/session-deck/uploads"; (up / "old").mkdir(parents=True, exist_ok=True); (up / "old/f").write_bytes(b"x"); (up / "gone").mkdir(exist_ok=True)
        for x in (up / "old/f", up / "gone"): os.utime(x, (time.time() - 15 * 86400,) * 2)
        seen = set()
        for name, body in [*files.items(), ("nginx.conf", b"again\n")]:
            r = self.req("POST", f"/api/upload?pane={self.pane}&name={urllib.parse.quote(name)}", body, "application/octet-stream")
            d = json.loads(r.read())
            self.assertEqual(r.status, 200, d)
            want = {"a b;$(id).sh": "a_b__id.sh"}.get(name, name)  # made safe to type
            self.assertEqual(d["path"].rsplit("/", 1)[1], want); self.assertNotIn(d["path"], seen); seen.add(d["path"])
            self.assertEqual(Path(d["path"]).read_bytes(), body, name)  # the second nginx.conf has its own folder: the first is kept
        self.assertEqual(sorted(Path(x).read_bytes() for x in seen if x.endswith("/nginx.conf")), [b"again\n", b"server { listen 80; }\n"])
        self.assertEqual((os.path.exists(up / "old/f"), os.path.exists(up / "gone")), (False, False))  # what's over 14 days old goes; its folder an hour after it's empty
        self.assertEqual(list(server.UPL.glob("*-*-*/*")), [])

    def test_get(self):
        (self.home / "three").write_bytes(b"abc")
        code, d = self.post("/api/ssh/get", {"pane": self.pane, "path": "~/three"})
        self.assertEqual(code, 200, d); self.assertEqual(d["name"], "three")
        r = self.req("GET", "/" + d["url"])
        self.assertEqual((r.status, r.read()), (200, b"abc"))
        self.assertTrue(r.getheader("Content-Disposition").startswith("attachment"))
        code, d = self.post("/api/ssh/get", {"pane": self.pane, "path": "~/missing file"})
        self.assertEqual(code, 400); self.assertIn("missing file", d["error"]); self.assertLessEqual(len(d["error"]), 200)
        Path(os.environ["FAKE_SSH_DOWN"]).touch(); self.addCleanup(Path(os.environ["FAKE_SSH_DOWN"]).unlink, missing_ok=True)
        self.assertEqual(self.post("/api/ssh/get", {"pane": self.pane, "path": "~/three"}), (400, {"error": "Open a terminal to this host first: the deck needs its connection."}))

    def test_get_too_big(self):
        (self.home / "three").write_bytes(b"abc")
        old, server.UP_MAX = server.UP_MAX, 2; self.addCleanup(setattr, server, "UP_MAX", old)
        code, d = self.post("/api/ssh/get", {"pane": self.pane, "path": "~/three"})
        self.assertEqual(code, 400); self.assertIn("over", d["error"])

    def test_get_not_a_file(self):  # a folder, device or FIFO is refused at once: wc on a FIFO or /dev/zero would never end
        (self.home / "dir").mkdir(exist_ok=True); fifo = self.home / "fifo"
        if not fifo.exists(): os.mkfifo(fifo)
        for p in ("~/dir", "~/fifo"):
            t = time.time(); code, d = self.post("/api/ssh/get", {"pane": self.pane, "path": p})
            self.assertEqual((code, d), (400, {"error": "That isn't a file."}), p); self.assertLess(time.time() - t, 5, p)

    def test_installkey_after_unterminated_line(self):  # an existing last key with no newline stays whole, and repeats add no blank lines
        ak = self.home / ".ssh/authorized_keys"; ak.parent.mkdir(exist_ok=True); ak.write_text("ssh-rsa AAAAold me@old")
        self.addCleanup(ak.unlink, missing_ok=True)
        for _ in range(2):
            server.ssh_hosts_write([{**h, "auth": "password"} for h in server.ssh_hosts()])
            self.assertEqual(self.post("/api/ssh/installkey", {"host": self.h["id"]}), (200, {"ok": True}))
        self.assertEqual(ak.read_text(), "ssh-rsa AAAAold me@old\n" + Path(str(server.SSH_KEY) + ".pub").read_text().strip() + "\n")

    def test_installkey_not_accepted(self):  # added, but the server won't take the key: the host keeps password sign-in
        m = Path(os.environ["FAKE_SSH_NOKEY"]); m.touch(); self.addCleanup(m.unlink, missing_ok=True)
        self.assertEqual(self.post("/api/ssh/installkey", {"host": self.h["id"]}), (400, {"error": "The key was added but the server didn't accept it."}))
        self.assertEqual(server.ssh_hosts()[0]["auth"], "password")

    def test_installkey_idempotent(self):
        for _ in range(2):
            server.ssh_hosts_write([{**h, "auth": "password"} for h in server.ssh_hosts()])
            self.assertEqual(self.post("/api/ssh/installkey", {"host": self.h["id"]}), (200, {"ok": True}))
        pub = Path(str(server.SSH_KEY) + ".pub").read_text().strip()
        ak = self.home / ".ssh/authorized_keys"
        self.assertEqual(ak.read_text().splitlines().count(pub), 1)
        self.assertEqual(ak.stat().st_mode & 0o777, 0o600)
        self.assertEqual(server.ssh_hosts()[0]["auth"], "key")
        self.assertEqual(self.post("/api/ssh/installkey", {"host": self.h["id"]})[0], 400)  # a key host needs no install

    def test_forgetkey(self):
        server.KNOWN_HOSTS.write_text("[10.0.0.5]:2222 ssh-ed25519 AAAA1\n10.0.0.5 ssh-ed25519 AAAA2\nother ssh-ed25519 AAAA3\n")
        self.assertEqual(self.post("/api/ssh/forgetkey", {"host": self.h["id"]}), (200, {"removed": 1}))  # port 2222: only [h]:p, the plain name is another server's
        self.assertEqual(server.KNOWN_HOSTS.read_text(), "10.0.0.5 ssh-ed25519 AAAA2\nother ssh-ed25519 AAAA3\n")
        h22, _ = server.ssh_host_save({"addr": "pi@10.0.0.5:22", "auth": "key"})
        self.assertEqual(self.post("/api/ssh/forgetkey", {"host": h22["id"]}), (200, {"removed": 1}))
        self.assertEqual(server.KNOWN_HOSTS.read_text(), "other ssh-ed25519 AAAA3\n")
        self.assertEqual(self.post("/api/ssh/forgetkey", {"host": "nope"})[0], 400)

if __name__ == "__main__": unittest.main()
