"""SSH hosts: address parsing, ~/.ssh/config names, the host store; connections in a throwaway tmux server (decktest)."""
import http.client, json, os, signal, subprocess, sys, tempfile, threading, time, unittest
from pathlib import Path

TMP = tempfile.mkdtemp()
os.environ.update(DECK_SECRETS=TMP, DECK_STORE=f"{TMP}/passkeys.json", DECK_PREFS=f"{TMP}/prefs.json", DECK_RP_ID="localhost", DECK_TS_USER="me@example.com",
                  DECK_SSH_HOSTS=f"{TMP}/ssh-hosts.json", DECK_TMUX_SOCKET="decktest", DECK_SHOW_TEST="1", DECK_SSH_CM=f"{TMP}/cm",
                  DECK_SSH_BIN=str(Path(__file__).resolve().parent / "fake_ssh.sh"), FAKE_SSH_MASTER=f"{TMP}/master")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import server
# another test module may have imported server first, with its own settings: never let these tests reach the real tmux servers or ssh
server.TMUX_SOCKS, server.SSH_BIN, server.SSH_CM, server.SSH_HOSTS = ["decktest"], os.environ["DECK_SSH_BIN"], Path(os.environ["DECK_SSH_CM"]), Path(os.environ["DECK_SSH_HOSTS"])


class Hosts(unittest.TestCase):
    def setUp(self): Path(server.SSH_HOSTS).unlink(missing_ok=True)

    def test_parse_addr(self):
        p = server.parse_addr
        self.assertEqual(p("pi@10.0.0.5:2222"), {"user": "pi", "host": "10.0.0.5", "port": 2222})
        self.assertEqual(p("home"), {"user": None, "host": "home", "port": None})
        self.assertEqual(p("root@[fd7a::1]:22")["host"], "fd7a::1")
        self.assertEqual(p("u@[fd7a::1]"), {"user": "u", "host": "fd7a::1", "port": None})
        for bad in ("-oProxyCommand=x", "a b", "h;rm", "u@h:0", "u@h:70000", "$(id)@h", "", "u@-h", None):
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
        assert server.TMUX_SOCKS == ["decktest"] and server.SSH_BIN.endswith("/fake_ssh.sh")
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
        # sessions named ssh-* or deck-view-* never count as chats, even when they run something called claude
        for n in ("ssh-zz-1", "deck-view-0123abcd", "plainchat"):
            subprocess.run(["tmux", "-L", "decktest", "new-session", "-d", "-s", n, "bash", "-c", "exec -a claude cat"], check=True)
        server._socks.pop("decktest", None)
        def live(): server._live[0] = 0; return [s["where"].split(":")[0] for s in server.live_sessions() if s["pane"].startswith("decktest.")]
        until(lambda: "plainchat" in live())
        self.assertEqual(live(), ["plainchat"])
        self.assertNotIn(p, {s["pane"] for s in server.live_sessions()})
        for n in ("ssh-zz-1", "deck-view-0123abcd", "plainchat"): subprocess.run(["tmux", "-L", "decktest", "kill-session", "-t", "=" + n])

    def test_password_typed_once(self):
        p = server.ssh_open(self.h["id"], "s3cret")
        self.assertTrue(until(lambda: "AUTH s3cret" in self.screen(p)), self.screen(p))
        time.sleep(2)  # the fake asks "password: " again; the deck must not answer it
        s = self.screen(p)
        self.assertEqual((s.count("AUTH"), s.count("s3cret")), (1, 1), s)
        self.assertTrue(s.rstrip().endswith("password:"), s)
        self.assertNotIn("s3cret", subprocess.run(["tmux", "-L", "decktest", "list-buffers"], capture_output=True, text=True).stdout)

    def test_newest_feeder_only(self):  # a reconnect while an earlier feeder still waits: only the newest one types
        p = server.ssh_open(self.h["id"])
        until(lambda: "password:" in self.screen(p))
        server.tm(p, "send-keys", "-t", "{P}", "x", "Enter")  # the user answers the first prompt by hand; the fake now waits at "password: "
        until(lambda: "AUTH x" in self.screen(p))
        server.tm(p, "send-keys", "-t", "{P}", "-l", "line"); server.tm(p, "send-keys", "-t", "{P}", "Enter")  # cat's output: the prompt is no longer last
        old = threading.Thread(target=server.pw_feed, args=(p, "first", 8), daemon=True); old.start(); time.sleep(0.5)
        self.assertEqual(self.post("/api/ssh/reconnect", {"pane": p, "password": "second"}), (200, {"ok": True}))
        self.assertTrue(until(lambda: "AUTH second" in self.screen(p)), self.screen(p))
        old.join(10); time.sleep(1)
        self.assertNotIn("first", self.screen(p))

    def test_prompt_forms(self):  # only OpenSSH's own password prompts
        for ok in ("pi@10.0.0.5's password:", "(pi@10.0.0.5) Password:", "(pi@h) password:"): self.assertTrue(server.PW_PROMPT.search(ok), ok)
        for no in ("Password:", "password:", "[sudo] password for pi:", "Enter password:", "New password:", "(a b) Password:"): self.assertFalse(server.PW_PROMPT.search(no), no)

    def test_master_up_no_typing(self):  # through a live master there's no ssh prompt: a later "Password:" from su, sudo or mysql never gets it
        m = Path(os.environ["FAKE_SSH_MASTER"]); m.touch(); self.addCleanup(m.unlink, missing_ok=True)
        p = server.ssh_open(self.h["id"], "s3cret")
        self.assertTrue(until(lambda: "Password:" in self.screen(p)), self.screen(p))
        self.assertEqual(self.post("/api/ssh/reconnect", {"pane": p, "password": "s3cret"}), (200, {"ok": True}))
        self.assertTrue(until(lambda: "Password:" in self.screen(p)), self.screen(p))
        time.sleep(1.5)
        self.assertNotIn("s3cret", self.screen(p))

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
        self.assertFalse(any(h.get("temp") for h in server.ssh_state()["hosts"]))
        self.assertEqual(self.post("/api/ssh/close", {"pane": r["pane"]})[0], 400)

    def test_connect_rejects(self):
        for b in ({"host": "nope"}, {"temp": {"addr": "-oProxyCommand=x", "auth": "key"}}, {"temp": {"addr": "h", "auth": "config"}}, {"temp": {"addr": "h", "auth": "x"}},
                  {"host": self.h["id"], "password": "x" * 1025}, {"host": self.h["id"], "password": "a\nb"}):
            self.assertEqual(self.post("/api/ssh/connect", b)[0], 400, b)
        self.assertFalse(any(h.get("temp") for h in server.ssh_state()["hosts"]))
        server.ssh_hosts_write([{**self.h, "host": "-oProxyCommand=x"}])  # a tampered hosts file
        self.assertEqual(self.post("/api/ssh/connect", {"host": self.h["id"]})[0], 400)

    def test_sessions_payload(self):
        c = http.client.HTTPConnection("127.0.0.1", self.srv.server_address[1], timeout=30)
        c.request("GET", "/api/sessions", headers={"X-Deck-Token": server.TOK}); d = json.loads(c.getresponse().read())
        self.assertEqual(set(d["ssh"]), {"hosts", "terms"}); self.assertIn(self.h["id"], [h["id"] for h in d["ssh"]["hosts"]])

if __name__ == "__main__": unittest.main()
