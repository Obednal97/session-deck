"""The /api/aiva/* proxy: a fake Aiva on a temp Unix socket records what the deck forwards."""
import hashlib, hmac, json, os, socketserver, sys, tempfile, threading, time, unittest
from http.server import BaseHTTPRequestHandler
from pathlib import Path

TMP = tempfile.mkdtemp()
os.environ.update(DECK_SECRETS=TMP, DECK_STORE=f"{TMP}/passkeys.json", DECK_PREFS=f"{TMP}/prefs.json", DECK_RP_ID="localhost", DECK_TS_USER="me@example.com")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import server

KEY = "ab" * 32
GOT = []

class Fake(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def reply(self, body=b""):
        GOT.append({"method": self.command, "path": self.path, "headers": dict(self.headers), "body": body})
        b = json.dumps({"ok": True, "path": self.path}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self): self.reply()
    def do_POST(self): self.reply(self.rfile.read(int(self.headers.get("Content-Length") or 0)))

class Stub:
    def __init__(self, path, ts=False, se=None): self.path, self.headers, self.ts, self.se, self.out = path, {}, ts, se, None
    def via_ts(self): return self.ts
    def session(self): return self.se
    def send(self, code, body, ctype="application/json", csp=None): self.out = (code, json.loads(body) if isinstance(body, bytes) else body)

class AivaProxy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        d = tempfile.mkdtemp(); cls.sock = f"{d}/aiva.sock"; key = Path(d, "deck.key"); key.write_text(KEY + "\n")
        server.AIVA_SOCK, server.AIVA_KEY = cls.sock, key
        cls.srv = socketserver.ThreadingUnixStreamServer(cls.sock, Fake); cls.srv.daemon_threads = True
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
    @classmethod
    def tearDownClass(cls): cls.srv.shutdown(); cls.srv.server_close()
    def setUp(self): GOT.clear(); server.AIVA_SOCK = self.sock

    def post(self, path, body, **kw):
        h = Stub(path, **kw); self.assertTrue(server.aiva_api(h, path, body)); return h, GOT[-1]

    def verify(self, g, strong):
        hd = g["headers"]
        self.assertEqual(hd["X-Aiva-Strong"], strong)
        self.assertLess(abs(int(hd["X-Aiva-Ts"]) - time.time()), 5)
        parts = ["POST", g["path"], hd["X-Aiva-Ts"], hashlib.sha256(g["body"]).hexdigest(), strong]
        self.assertEqual(hd["X-Aiva-Sig"], hmac.new(KEY.encode(), "|".join(parts).encode(), hashlib.sha256).hexdigest())

    def test_get_forwarded(self):
        h = Stub("/api/aiva/messages?after=3")
        self.assertTrue(server.aiva_api(h, "/api/aiva/messages"))
        self.assertEqual(GOT[-1]["path"], "/messages?after=3")
        self.assertEqual(h.out, (200, {"ok": True, "path": "/messages?after=3"}))

    def test_other_paths_not_ours(self):
        self.assertFalse(server.aiva_api(Stub("/api/sessions"), "/api/sessions"))

    def test_post_signed_not_strong_locally(self):
        h, g = self.post("/api/aiva/messages", {"text": "hello"})
        self.assertEqual((g["path"], json.loads(g["body"])), ("/messages", {"text": "hello"}))
        self.verify(g, "0"); self.assertEqual(h.out[0], 200)

    def test_post_strong_with_passkey_session(self):
        h, g = self.post("/api/aiva/approvals/ap_1234abcd", {"decision": "approve", "by": "someone else"}, ts=True, se=("me@example.com", "sid"))
        self.assertEqual(g["path"], "/approvals/ap_1234abcd")
        self.assertEqual(json.loads(g["body"]), {"decision": "approve", "by": "me@example.com"})
        self.verify(g, "1")

    def test_local_approval_by_local(self):
        h, g = self.post("/api/aiva/approvals/ap_1234abcd", {"decision": "reject"})
        self.assertEqual(json.loads(g["body"]), {"decision": "reject", "by": "local"}); self.verify(g, "0")

    def test_socket_missing_503(self):
        server.AIVA_SOCK = self.sock + ".gone"
        for path, body in (("/api/aiva/status", None), ("/api/aiva/messages", {"text": "hi"})):
            h = Stub(path); self.assertTrue(server.aiva_api(h, path, body))
            self.assertEqual(h.out, (503, {"error": "Aiva isn't running"}))

if __name__ == "__main__": unittest.main()
