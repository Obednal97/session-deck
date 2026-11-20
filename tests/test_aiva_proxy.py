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

    def test_approval_answer_always_and_never_forwarded(self):  # the panel's free-text answer, Yes always and Never
        h, g = self.post("/api/aiva/approvals/ap_1234abcd", {"decision": "answer", "text": "  Ask for a 12 month quote instead \n", "by": "x"}, ts=True, se=("me@example.com", "sid"))
        self.assertEqual(json.loads(g["body"]), {"decision": "answer", "text": "Ask for a 12 month quote instead", "by": "me@example.com"}); self.verify(g, "1")
        h, g = self.post("/api/aiva/approvals/ap_1234abcd", {"decision": "answer", "text": "x" * 2000})
        self.assertEqual(json.loads(g["body"]), {"decision": "answer", "text": "x" * 2000, "by": "local"}); self.verify(g, "0")
        for d in ("reject_never", "approve_always"):
            h, g = self.post("/api/aiva/approvals/ap_1234abcd", {"decision": d, "text": "only an answer carries text"})
            self.assertEqual(json.loads(g["body"]), {"decision": d, "by": "local"})

    def test_approval_bad_decision_or_answer_never_reaches_aiva(self):
        n = len(GOT)
        for b in ({"decision": "answer"}, {"decision": "answer", "text": ""}, {"decision": "answer", "text": " \n "}, {"decision": "answer", "text": "x" * 2001},
                  {"decision": "answer", "text": ["hi"]}, {"decision": "maybe"}, {"decision": "never"}, {"decision": ["approve"]}, {}):
            h = Stub("/x"); self.assertTrue(server.aiva_api(h, "/api/aiva/approvals/ap_1", b)); self.assertEqual(h.out, (400, {"error": "bad"}), b)
        self.assertEqual(len(GOT), n)

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

    def test_challenge_and_bad_chunks(self):
        self.assertIn(b'WWW-Authenticate: Basic realm="Aiva location"', self.req(auth=self.basic("nope"))[2])
        for bad in (b"-5", b"zz", b"1" * 50):
            h = ["POST /api/aiva/location HTTP/1.1", "Host: 127.0.0.1", "Transfer-Encoding: chunked", "Authorization: " + self.basic(self.SECRET)]
            with socket.create_connection(self.http.server_address, timeout=5) as c:
                c.sendall(("\r\n".join(h) + "\r\n\r\n").encode() + bad + b"\r\nabc\r\n0\r\n\r\n"); r = c.recv(300)
            self.assertIn(b" 400 ", r.split(b"\r\n")[0]); self.assertEqual(GOT, [])

    def test_page_toggle(self):  # On (data-v=1) stores avloc, Off removes it; the pressed state follows the stored value
        import subprocess, shutil
        node = shutil.which("node")
        if not node: self.skipTest("no node")
        src = (Path(__file__).resolve().parent.parent / "index.html").read_text()
        self.assertIn("locSet(lc.dataset.v=='1')", src)
        m = re.search(r"const locSet=.*?;const locOn=\(\)=>\{.*?\};", src)
        js = m[0] + "\nconst st={};global.localStorage={setItem:(k,v)=>st[k]=v,removeItem:k=>delete st[k],getItem:k=>st[k]??null};" \
             "locSet(true);if(!locOn())throw 1;locSet(false);if(locOn())throw 2;console.log('ok')"
        self.assertEqual(subprocess.run([node, "-e", js], capture_output=True, text=True).stdout.strip(), "ok")

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


# aiva-intake: files from Aiva's chat (upload paths in, base64 out to Aiva), uploads for Aiva, and the thread mode
class AivaIntake(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        AivaProxy.setUpClass.__func__(cls)
        cls.upl, cls.old_upl = Path(tempfile.mkdtemp()).resolve(), server.UPL
        cls.http = ThreadingHTTPServer(("127.0.0.1", 0), server.H); threading.Thread(target=cls.http.serve_forever, daemon=True).start()
    @classmethod
    def tearDownClass(cls): server.UPL = cls.old_upl; cls.http.shutdown(); cls.http.server_close(); cls.srv.shutdown(); cls.srv.server_close()
    def setUp(self): GOT.clear(); server.AIVA_SOCK = self.sock; server.UPL = self.upl
    post, verify = AivaProxy.post, AivaProxy.verify

    def saved(self, name, data, on_phone=None):
        d = self.upl / "2026-01-01"; d.mkdir(exist_ok=True); f = d / name; f.write_bytes(data)
        if on_phone: server.NAMES[str(f)] = on_phone
        server.AIVA_UP[str(f.resolve())] = True  # as an aiva=1 upload records it
        return str(f)

    def test_files_forwarded_as_base64_with_names(self):
        pdf, png = b"%PDF-1.4\n% a test document\n", b"\x89PNG\r\n\x1a\n" + bytes(range(64))
        a, b = self.saved("a1.pdf", pdf, "notice.pdf"), self.saved("b2.png", png)
        h, g = self.post("/api/aiva/messages", {"text": "  what is this? ", "device": "phone", "files": [a, b]})
        self.assertEqual((h.out[0], g["path"]), (200, "/messages"))
        sent = json.loads(g["body"])
        self.assertEqual((sent["text"], sent["device"]), ("what is this?", "phone"))
        self.assertEqual([f["name"] for f in sent["files"]], ["notice.pdf", "b2.png"])  # the phone's name when the deck has it, else the saved one
        self.assertEqual([base64.b64decode(f["data"]) for f in sent["files"]], [pdf, png])
        self.verify(g, "0")
        h, g = self.post("/api/aiva/messages", {"text": "", "files": [a]}, ts=True, se=("me@example.com", "sid"))  # no text is fine with files
        self.assertEqual((json.loads(g["body"])["text"], json.loads(g["body"])["device"]), ("", "unknown")); self.verify(g, "1")

    def test_only_aivas_uploads_and_names_get_the_saved_extension(self):
        jpg, png = self.saved("h1.jpg", b"\xff\xd8\xff\xe0" + bytes(32), "IMG_0001.HEIC"), self.saved("p1.png", b"\x89PNG\r\n\x1a\n", "pasted image")
        pdf = self.saved("d1.pdf", b"%PDF-1.4\n", "Notice.PDF")
        h, g = self.post("/api/aiva/messages", {"files": [jpg, png, pdf]})
        self.assertEqual([f["name"] for f in json.loads(g["body"])["files"]], ["IMG_0001.jpg", "pasted image.png", "Notice.PDF"])
        other = self.saved("s1.pdf", b"%PDF-1.4\n"); server.AIVA_UP.pop(str(Path(other).resolve()))  # a session chat's upload: in the folder, not Aiva's
        n = len(GOT); h = Stub("/x"); server.aiva_api(h, "/api/aiva/messages", {"files": [pdf, other]}); self.assertEqual((h.out[0], len(GOT)), (400, n))

    def test_path_outside_uploads_400(self):
        out = Path(tempfile.mkdtemp(), "x.pdf"); out.write_bytes(b"%PDF-1.4\n")
        ok = self.saved("c3.pdf", b"%PDF-1.4\n")
        for fs in ([str(out)], [ok, str(out)], [str(self.upl / "2026-01-01" / ".." / ".." / out.name)], [str(self.upl / "nope.pdf")], "abc"):
            n = len(GOT); h = Stub("/x"); self.assertTrue(server.aiva_api(h, "/api/aiva/messages", {"text": "hi", "files": fs}))
            self.assertEqual(h.out[0], 400, fs); self.assertEqual(len(GOT), n, fs)

    def test_too_many_or_too_big_never_read(self):
        fs = [self.saved(f"m{i}.txt", b"hello") for i in range(6)]
        h = Stub("/x"); server.aiva_api(h, "/api/aiva/messages", {"files": fs}); self.assertEqual(h.out, (400, {"error": "Up to 5 files at a time."}))
        big = self.saved("big.txt", b"x" * ((10 << 20) + 1), "big.txt")
        h = Stub("/x"); server.aiva_api(h, "/api/aiva/messages", {"files": [big]}); self.assertEqual(h.out, (413, {"error": "big.txt is over 10 MB."}))
        self.assertEqual(GOT, [])

    def test_thread_mode_get_and_post(self):
        h = Stub("/api/aiva/thread-mode?x=1"); self.assertTrue(server.aiva_api(h, "/api/aiva/thread-mode"))
        self.assertEqual((GOT[-1]["method"], GOT[-1]["path"], h.out[0]), ("GET", "/thread-mode", 200))
        for m in ("chief-of-staff", "all"):
            h, g = self.post("/api/aiva/thread-mode", {"mode": m, "by": "x"})
            self.assertEqual((g["method"], g["path"], json.loads(g["body"])), ("POST", "/thread-mode", {"mode": m})); self.verify(g, "0")
        h, g = self.post("/api/aiva/thread-mode", {"mode": "all"}, ts=True, se=("me@example.com", "sid")); self.verify(g, "1")

    def test_thread_mode_bad_mode_400(self):
        for b in ({}, {"mode": ""}, {"mode": "everyone"}, {"mode": ["all"]}, {"mode": None}, ["all"]):
            h = Stub("/x"); self.assertTrue(server.aiva_api(h, "/api/aiva/thread-mode", b)); self.assertEqual(h.out[0], 400, b)
        self.assertEqual(GOT, [])

    def upload(self, q, body, length=None):
        h = ["POST /api/upload?" + q + " HTTP/1.1", "Host: 127.0.0.1", "X-Deck-Token: " + server.TOK, f"Content-Length: {len(body) if length is None else length}"]
        with socket.create_connection(self.http.server_address, timeout=10) as c:
            c.sendall(("\r\n".join(h) + "\r\n\r\n").encode() + body); buf = b""
            while not (b"\r\n\r\n" in buf and len(buf.partition(b"\r\n\r\n")[2]) >= int(re.search(rb"Content-Length: (\d+)", buf)[1])):
                d = c.recv(65536)
                if not d: break
                buf += d
        head, _, rest = buf.partition(b"\r\n\r\n")
        return int(head.split()[1]), json.loads(rest)

    def test_upload_for_aiva(self):
        code, r = self.upload("aiva=1&name=bill.pdf", b"%PDF-1.4\n% generated\n")
        self.assertEqual((code, r["name"], r["kind"]), (200, "bill.pdf", "file"))
        self.assertTrue(Path(r["path"]).resolve().is_relative_to(self.upl) and r["path"].endswith(".pdf")); self.assertEqual(server.NAMES[r["path"]], "bill.pdf")
        self.assertEqual(self.upload("aiva=1&name=export.qif", b"!Type:Bank\nD01/01/2026\nT-1.00\n^\n")[1]["path"][-4:], ".qif")
        for name, body in (("setup.exe", b"MZ\x90\x00\x03\x00\x00\x00\x04\x00"), ("report.docx", b"PK\x03\x04" + b"\x00" * 40), ("notes.md", b"# notes\n")):
            code, r = self.upload("aiva=1&name=" + name, body); self.assertEqual(code, 415, name); self.assertIn(name, r["error"])
        code, r = self.upload("aiva=1&name=huge.pdf", b"", length=(10 << 20) + 1); self.assertEqual((code, r["error"]), (413, "huge.pdf is over 10 MB, the most Aiva takes."))
        self.assertEqual(self.upload("name=bill.pdf", b"%PDF-1.4\n")[0], 400)  # neither a chat nor Aiva
        self.assertEqual(self.upload("aiva=1&name=bill.pdf", b"", length=-5)[0], 411)
        self.assertIn(str(Path(self.upload("aiva=1&name=x.pdf", b"%PDF-1.4\n")[1]["path"]).resolve()), server.AIVA_UP)  # recorded for the send
        for i in range(55): self.upload(f"aiva=1&name=t{i}.txt", b"hello %d" % i)
        self.assertEqual(len(server.AIVA_UP), 50)  # only the last 50 are kept
        self.assertEqual(GOT, [])  # an upload never reaches Aiva by itself

    def test_page_blocks(self):
        src = (Path(__file__).resolve().parent.parent / "index.html").read_text()
        self.assertEqual(src.count("aiva-intake:start"), src.count("aiva-intake:end"))
        tm = src[src.index("const TM="):src.index("// aiva-intake:end", src.index("const TM="))]
        for f in ("innerHTML", "outerHTML", "insertAdjacentHTML", "template"): self.assertNotIn(f, tm)  # the thread mode code and the folds are DOM nodes only
        self.assertIn("function avFold(", tm)
        self.assertNotIn("avtm", src); self.assertNotIn("$('main').before(", src)  # no bar above Aiva's chat: the switch lives in Settings
        st = src[src.index("function settings()"):src.index("$('set').onclick")]
        self.assertIn("id=stm", st[st.index("<div class=lbl>Aiva</div>"):st.index("<div class=lbl>Notifications</div>")])
        self.assertIn("t.closest('#stm [data-m]')", src)  # a tap in Settings goes to avTmSet
        self.assertIn("const B=avFold(AV.m.map(avItem))", src)
        self.assertIn(".aiva #clip{display:grid!important}", src)  # the shared hide rule stays as it is; the block shows the paperclip again
        self.assertIn("dropOk=e=>!inSplit&&cur&&(cur.pane||cur.via||cur.aiva)", src)
        self.assertIn("if(!cur.menu&&ATT.some(a=>a.av))return toast(", src)  # a session chat won't send files attached in Aiva's chat
        self.assertIn("$('fi').accept=cur&&cur.aiva?'':FIA", src)

    def test_attached_lines_are_escaped_chips(self):
        import shutil, subprocess
        node = shutil.which("node")
        if not node: self.skipTest("no node")
        src = (Path(__file__).resolve().parent.parent / "index.html").read_text()
        fn = re.search(r"function avAtt\(.*?\n", src)[0] + re.search(r"function avSize\(.*?\n", src)[0]
        js = "const esc=s=>String(s??'').replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]));const FILE='F';let cur={aiva:1};\n" + fn + \
             "const fs=[],t=avAtt('see this\\nAttached: <img src=x onerror=alert(1)>.pdf (2.1 MB)\\nAttached: a.csv (340 KB)',fs);" \
             "cur={pane:'%1'};const g=[];avAtt('Attached: b.pdf (1 KB)',g);console.log(JSON.stringify([t.trim(),fs,g.length,avSize(2202010),avSize(348160),avSize(10)]))"
        r = subprocess.run([node, "-e", js], capture_output=True, text=True); self.assertEqual(r.returncode, 0, r.stderr)
        t, fs, g, *sz = json.loads(r.stdout)
        self.assertEqual((t, len(fs), g, sz), ("see this", 2, 0, ["2.1 MB", "340 KB", "1 KB"]))
        self.assertNotIn("<img", fs[0]); self.assertIn("&lt;img src=x onerror=alert(1)&gt;.pdf", fs[0]); self.assertIn("<small>2.1 MB</small>", fs[0])
        self.assertTrue(fs[1].startswith("<span class=fch "))

if __name__ == "__main__": unittest.main()