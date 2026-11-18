"""Aiva's rich chat: the page draws Aiva's messages without parsing HTML, and the proxy passes `parts` through untouched."""
import json, os, re, socketserver, sys, tempfile, threading, unittest
from http.server import BaseHTTPRequestHandler
from pathlib import Path

TMP = tempfile.mkdtemp()
os.environ.update(DECK_SECRETS=TMP, DECK_STORE=f"{TMP}/passkeys.json", DECK_PREFS=f"{TMP}/prefs.json", DECK_RP_ID="localhost", DECK_TS_USER="me@example.com")
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import server

FORBIDDEN = [r"innerHTML", r"outerHTML", r"insertAdjacentHTML", r"DOMParser", r"createElement\(\s*['\"`]template", r"document\.write", r"\beval\(", r"new\s+Function\b",
             r"createContextualFragment", r"srcdoc", r"\bmarked\b", r"DOMPurify"]

def rich_block():
    s = (ROOT / "index.html").read_text()
    a, b = s.count("// aiva-rich:start"), s.count("// aiva-rich:end")
    if a != 1 or b != 1: raise AssertionError(f"markers: start {a}, end {b}")
    i, j = s.index("// aiva-rich:start"), s.index("// aiva-rich:end")
    if j < i: raise AssertionError("end marker before start")
    return s[i:j]

class RichBlock(unittest.TestCase):
    def test_no_html_parsing_between_markers(self):
        blk = rich_block()
        self.assertIn("function avRich(", blk)  # the renderer really is in there
        for f in FORBIDDEN: self.assertIsNone(re.search(f, blk), f)

    def test_aiva_messages_use_the_renderer(self):  # Ollie's own messages keep ub(); Aiva's no longer go through marked
        s = (ROOT / "index.html").read_text()
        item = s[s.index("const avItem="):s.index("function avPaint(")]
        self.assertIn("avRich(", item); self.assertNotIn("md(", item); self.assertIn("ub(x.text)", item)

    def test_links_https_only(self):  # the deck rebuilds links itself and keeps only https
        blk = rich_block()
        self.assertIn("new URL(h)", blk); self.assertIn("u.protocol=='https:'", blk); self.assertIn("noopener noreferrer", blk)


PARTS = [{"type": "table", "title": "<img src=x onerror=alert(1)>", "columns": ["a", "b"], "rows": [["</table><script>x</script>", 1.5], [{"text": "x", "href": "javascript:alert(1)"}, -2]]},
         {"type": "card", "kind": "trip", "title": "Rome · café ☃", "fields": [{"label": "Seat", "value": "12A"}], "links": [{"label": "Booking", "href": "https://example.com/b?x=1&y=2"}],
          "actions": [{"label": "Book it", "say": "book the 08:15"}]},
         {"type": "chart", "kind": "bar", "title": "Spend", "labels": ["Jan", "Feb"], "series": [{"name": "GBP", "values": [12.5, -3]}], "unit": "GBP"},
         {"type": "mystery", "nested": {"deep": [[[[1]]]]}}]
MSGS = [{"id": 1, "role": "aiva", "text": "Aiva: here", "parts": PARTS, "approval_id": None, "offer_id": None, "device": None}, {"id": 2, "role": "ollie", "text": "hi"}]
BIG = []  # 100 messages, each with about 24 KB of parts: the most a page of Aiva's can carry
for i in range(100):
    BIG.append({"id": 1000 + i, "role": "aiva", "text": f"m{i}", "parts": [{"type": "table", "columns": ["c"], "rows": [["x" * 260 + str(i)] for _ in range(30)]}] * 3})

class Fake(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        b = json.dumps({"messages": BIG if "tail=100" in self.path else MSGS}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

class Stub:
    def __init__(self, path): self.path, self.headers, self.out = path, {}, None
    def via_ts(self): return False
    def session(self): return None
    def send(self, code, body, ctype="application/json", csp=None): self.out = (code, json.loads(body) if isinstance(body, bytes) else body)

class PartsThroughProxy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old = server.AIVA_SOCK; d = tempfile.mkdtemp(); cls.sock = f"{d}/aiva.sock"
        cls.srv = socketserver.ThreadingUnixStreamServer(cls.sock, Fake); cls.srv.daemon_threads = True
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
    @classmethod
    def tearDownClass(cls): cls.srv.shutdown(); cls.srv.server_close(); server.AIVA_SOCK = cls.old
    def setUp(self): server.AIVA_SOCK = self.sock

    def get(self, q):
        h = Stub("/api/aiva/messages" + q); self.assertTrue(server.aiva_api(h, "/api/aiva/messages")); return h.out

    def test_parts_untouched(self):
        code, d = self.get("?after=0")
        self.assertEqual(code, 200); self.assertEqual(d["messages"], MSGS)  # every key, the odd part and the payloads, exactly as Aiva gave them

    def test_a_full_page_of_big_parts_is_not_cut(self):
        self.assertGreater(len(json.dumps({"messages": BIG}).encode()), 2_000_000)
        code, d = self.get("?tail=100")
        self.assertEqual(code, 200); self.assertEqual(d["messages"], BIG)


if __name__ == "__main__": unittest.main()
