"""The /api/aiva/* proxy: a fake Aiva on a temp Unix socket records what the deck forwards."""
import base64, hashlib, hmac, json, os, re, socket, socketserver, sys, tempfile, threading, time, unittest
from http.server import ThreadingHTTPServer
from http.server import BaseHTTPRequestHandler
from pathlib import Path

TMP = tempfile.mkdtemp()
os.environ.update(DECK_SECRETS=TMP, DECK_STORE=f"{TMP}/passkeys.json", DECK_PREFS=f"{TMP}/prefs.json", DECK_RP_ID="localhost", DECK_TS_USER="me@example.com")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import server

KEY = "ab" * 32
GOT = []
MSGS = [{"id": i, "role": "aiva", "text": f"Aiva \u00b7 Chief of staff: message {i}"} for i in range(1, 351)]  # like Aiva's store: pages of 100 after N, or the last N

def messages(q):
    a, t = (int(m[1]) if m else None for m in (re.search(r"after=(\d+)", q), re.search(r"tail=(\d+)", q)))
    return MSGS[-t:] if t else [m for m in MSGS if m["id"] > (a or 0)][:100]

class Fake(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def reply(self, body=b""):
        GOT.append({"method": self.command, "path": self.path, "headers": dict(self.headers), "body": body})
        p, _, q = self.path.partition("?")
        b = b"[]" if p == "/location" else json.dumps({"messages": messages(q)} if self.command == "GET" and p == "/messages" else {"ok": True, "path": self.path}).encode()
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
        self.assertEqual(h.out[0], 200); self.assertEqual(h.out[1]["messages"][0]["id"], 4)

    def get(self, q):
        h = Stub("/api/aiva/messages" + q); self.assertTrue(server.aiva_api(h, "/api/aiva/messages")); return h.out

    def test_first_load_tail_gets_latest(self):  # 350 messages: the chat's first load (tail=200) shows the last 200, ending at the real latest
        code, d = self.get("?tail=200")
        self.assertEqual(GOT[-1]["path"], "/messages?tail=200")
        ids = [m["id"] for m in d["messages"]]
        self.assertEqual((code, len(ids), ids[0], ids[-1]), (200, 200, 151, 350))

    def test_after_pages_of_100(self):  # a full page (100) is the page's cue to fetch again at once
        self.assertEqual(len(self.get("?after=100")[1]["messages"]), 100)
        self.assertEqual(len(self.get("?after=300")[1]["messages"]), 50)

    def test_query_must_be_whole_numbers(self):
        for q in ("?tail=abc", "?after=-1", "?after=1e3", "?tail=\u00b2"):
            n = len(GOT); self.assertEqual(self.get(q)[0], 400, q); self.assertEqual(len(GOT), n, q)  # never reaches Aiva
        self.get("?after=5&evil=1&tail=7"); self.assertEqual(GOT[-1]["path"], "/messages?after=5&tail=7")

    def test_non_ascii_approval_id_not_ours(self):
        self.assertFalse(server.aiva_api(Stub("/api/aiva/approvals/ap_\u00e9"), "/api/aiva/approvals/ap_\u00e9", {"decision": "approve"}))

    def test_non_ascii_approval_id_gets_an_answer(self):  # through the real handler: an answer, not a dropped connection
        srv = ThreadingHTTPServer(("127.0.0.1", 0), server.H); threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            with socket.create_connection(srv.server_address, timeout=5) as c:
                c.sendall(b"POST /api/aiva/approvals/ap_\xe9 HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Deck-Token: " + server.TOK.encode() +
                          b"\r\nContent-Type: application/json\r\nContent-Length: 24\r\n\r\n" + b'{"decision": "approve"} ')
                r = c.recv(200)
            self.assertRegex(r.split(b"\r\n")[0], rb"^HTTP/1\.[01] (400|404) ")
            self.assertFalse(any(g["path"].startswith("/approvals/ap_") and "\u00e9" in g["path"] for g in GOT))
        finally: srv.shutdown(); srv.server_close()

    def test_offer_answer_signed_by_overridden(self):
        h, g = self.post("/api/aiva/offers/of_1-a", {"answer": "always", "by": "x", "extra": 1}, ts=True, se=("me@example.com", "sid"))
        self.assertEqual((g["path"], json.loads(g["body"])), ("/offers/of_1-a", {"answer": "always", "by": "me@example.com"})); self.verify(g, "1")
        h, g = self.post("/api/aiva/offers/of_1-a", {"answer": "yes"})
        self.assertEqual(json.loads(g["body"]), {"answer": "yes", "by": "local"}); self.verify(g, "0")

    def test_offer_bad_answer_or_id_never_reaches_aiva(self):
        n = len(GOT); h = Stub("/x"); self.assertTrue(server.aiva_api(h, "/api/aiva/offers/of_1", {"answer": "maybe"})); self.assertEqual(h.out[0], 400)
        self.assertFalse(server.aiva_api(Stub("/x"), "/api/aiva/offers/of_\u00e9", {"answer": "yes"}))
        self.assertFalse(server.aiva_api(Stub("/x"), "/api/aiva/offers/" + "a" * 65, {"answer": "yes"}))
        self.assertEqual(len(GOT), n)

    def test_offers_get_status_validated(self):
        for st in ("open", "yes", "no", "always", "never", "expired", "all"):
            h = Stub("/api/aiva/offers?status=" + st); self.assertTrue(server.aiva_api(h, "/api/aiva/offers")); self.assertEqual(GOT[-1]["path"], "/offers?status=" + st)
        n = len(GOT); h = Stub("/api/aiva/offers?status=bad"); self.assertTrue(server.aiva_api(h, "/api/aiva/offers")); self.assertEqual((h.out[0], len(GOT)), (400, n))
        h = Stub("/api/aiva/offers"); server.aiva_api(h, "/api/aiva/offers"); self.assertEqual(GOT[-1]["path"], "/offers")

    def test_other_paths_not_ours(self):
        self.assertFalse(server.aiva_api(Stub("/api/sessions"), "/api/sessions"))

    def test_post_signed_not_strong_locally(self):
        h, g = self.post("/api/aiva/messages", {"text": "hello"})
        self.assertEqual((g["path"], json.loads(g["body"])), ("/messages", {"text": "hello", "device": "unknown"}))
        self.verify(g, "0"); self.assertEqual(h.out[0], 200)

    def test_device_passed_through(self):
        for d, want in (("phone", "phone"), ("laptop", "laptop"), ("tablet", "unknown"), (None, "unknown")):
            self.post("/api/aiva/messages", {"text": "hi", "device": d}); self.assertEqual(json.loads(GOT[-1]["body"])["device"], want)

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



class Location(unittest.TestCase):
    SECRET = "s3cret-" + "x" * 20
    @classmethod
    def setUpClass(cls):
        AivaProxy.setUpClass.__func__(cls)
        cls.sec = Path(tempfile.mkdtemp(), "location.secret"); cls.sec.write_text(cls.SECRET + "\n")
        server.AIVA_LOC_SECRET = cls.sec
        cls.http = ThreadingHTTPServer(("127.0.0.1", 0), server.H); threading.Thread(target=cls.http.serve_forever, daemon=True).start()
    @classmethod
    def tearDownClass(cls): cls.http.shutdown(); cls.http.server_close(); cls.srv.shutdown(); cls.srv.server_close()
    def setUp(self): GOT.clear(); server.AIVA_SOCK = self.sock; server.AIVA_LOC_SECRET = self.sec; server.HITS.pop(("loc-bad",), None)

    def req(self, body=b'{"_type":"location","lat":51.5,"lon":-0.1}', auth=None, token=False, length=None, extra=(), chunked=False):
        h = [f"POST /api/aiva/location HTTP/1.1", "Host: 127.0.0.1", "Content-Type: application/json", f"Content-Length: {len(body) if length is None else length}"]
        if auth is not None: h.append("Authorization: " + auth)
        if token: h.append("X-Deck-Token: " + server.TOK)
        for x in extra: h = [y for y in h if not (x.startswith('Host:') and y.startswith('Host:'))] + [x]
        if chunked: h = [x for x in h if not x.startswith("Content-Length")] + ["Transfer-Encoding: chunked"]; body = b"%x\r\n%s\r\n0\r\n\r\n" % (len(body), body)
        with socket.create_connection(self.http.server_address, timeout=5) as c:
            c.sendall(("\r\n".join(h) + "\r\n\r\n").encode() + body)
            buf = b""
            while True:
                d = c.recv(65536)
                if not d: break
                buf += d
                head, _, rest = buf.partition(b"\r\n\r\n")
                m = re.search(rb"Content-Length: (\d+)", head)
                if rest and m and len(rest) >= int(m[1]): break
        head, _, rest = buf.partition(b"\r\n\r\n")
        return int(head.split()[1]), rest, head

    def basic(self, pw, user="owntracks"): return "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()

    def test_secret_accepted_signed_and_body_unchanged(self):
        body = b'{"_type":"location","lat":51.5,"lon":-0.1,"tst":1}'
        code, out, _ = self.req(body, self.basic(self.SECRET))
        self.assertEqual((code, json.loads(out)), (200, []))
        g = GOT[-1]; self.assertEqual((g["path"], g["body"]), ("/location", body))
        hd = g["headers"]; self.assertEqual(hd["X-Aiva-Strong"], "0")
        parts = ["POST", "/location", hd["X-Aiva-Ts"], hashlib.sha256(body).hexdigest(), "0"]
        self.assertEqual(hd["X-Aiva-Sig"], hmac.new(KEY.encode(), "|".join(parts).encode(), hashlib.sha256).hexdigest())
        self.assertNotIn(self.SECRET, json.dumps(hd))

    def test_wrong_or_missing_secret_401(self):
        for a in (self.basic("nope"), self.basic(""), "Basic !!!", "Bearer abc", "Basic"):
            code, out, head = self.req(auth=a); self.assertEqual(code, 401, a); self.assertNotIn(self.SECRET.encode(), out)
        self.assertEqual(self.req()[0], 401); self.assertEqual(GOT, [])

    def test_login_check(self):
        ts = lambda l: ("Tailscale-User-Login: " + l,)
        self.assertEqual(self.req(auth=self.basic(self.SECRET), extra=ts("stranger@example.com"))[0], 401); self.assertEqual(GOT, [])
        self.assertEqual(self.req(auth=self.basic(self.SECRET), extra=ts("me@example.com"))[0], 200); self.assertEqual(GOT[-1]["path"], "/location")
        self.assertEqual(self.req(auth=self.basic(self.SECRET), extra=("Host: evil.example",))[0], 401)

    def test_wrong_secret_throttle(self):
        server.HITS.pop(("loc-bad",), None)
        for _ in range(20): self.assertEqual(self.req(auth=self.basic("nope"))[0], 401)
        self.assertEqual(self.req(auth=self.basic(self.SECRET))[0], 429); self.assertEqual(GOT, [])
        server.HITS.pop(("loc-bad",), None)

    def test_chunked_body(self):
        body = b'{"lat":51.5,"lon":-0.1}'
        self.assertEqual(self.req(body, self.basic(self.SECRET), chunked=True)[0], 200); self.assertEqual(GOT[-1]["body"], body)

    def test_no_secret_file_503(self):
        server.AIVA_LOC_SECRET = Path(self.sec.parent, "missing")
        code, out, _ = self.req(auth=self.basic(self.SECRET)); self.assertEqual((code, json.loads(out)["error"]), (503, "Location isn't set up")); self.assertEqual(GOT, [])

    def test_token_path(self):
        code, out, _ = self.req(b'{"lat":51.5,"lon":-0.1,"acc":20,"ts":1,"device":"laptop"}', token=True)
        self.assertEqual((code, json.loads(out)), (200, [])); self.assertEqual(GOT[-1]["path"], "/location")
        self.assertEqual(self.req(b'{"lat":1}', token=False)[0], 401)

    def test_body_cap(self):
        code, _, _ = self.req(b"x" * 10, self.basic(self.SECRET), length=65 * 1024); self.assertEqual(code, 413)
        big = b'{"a":"' + b"x" * (64 * 1024 - 10) + b'"}'
        self.assertEqual(self.req(big, self.basic(self.SECRET))[0], 200); self.assertEqual(len(GOT[-1]["body"]), len(big))

    def test_logs_hold_no_secret(self):
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            self.req(b'{"lat":51.123456}', self.basic(self.SECRET)); self.req(b'{"lat":51.123456}', self.basic("wrong"))
        self.assertNotIn(self.SECRET, buf.getvalue()); self.assertNotIn("51.123456", buf.getvalue())

if __name__ == "__main__": unittest.main()