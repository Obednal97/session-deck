"""SSH hosts: address parsing, ~/.ssh/config names, the host store."""
import os, sys, tempfile, unittest
from pathlib import Path

TMP = tempfile.mkdtemp()
os.environ.update(DECK_SECRETS=TMP, DECK_STORE=f"{TMP}/passkeys.json", DECK_PREFS=f"{TMP}/prefs.json", DECK_RP_ID="localhost", DECK_TS_USER="me@example.com",
                  DECK_SSH_HOSTS=f"{TMP}/ssh-hosts.json", DECK_TMUX_SOCKET="decktest", DECK_SHOW_TEST="1", DECK_SSH_CM=f"{TMP}/cm")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import server


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

if __name__ == "__main__": unittest.main()
