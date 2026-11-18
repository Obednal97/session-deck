"""Aiva's rich chat: the page draws Aiva's messages without parsing HTML, and the proxy passes `parts` through untouched."""
import json, os, re, shutil, socketserver, subprocess, sys, tempfile, threading, unittest
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

    def test_offer_and_approval_rows_are_dom_nodes(self):
        s = (ROOT / "index.html").read_text()
        rows = s[s.index("const avBtn="):s.index("function avPaint(")]
        self.assertNotIn("avNodes", s)
        for f in ("innerHTML", "template", "<div class=pg", "esc("): self.assertNotIn(f, rows)

    def test_table_box_focus_ring_is_drawn_inside_it(self):  # its parent clips anything outside the box
        s = (ROOT / "index.html").read_text()
        self.assertIn(".avt:focus-visible{outline-offset:-2px}", s)
        self.assertIn(".a table.sr{overflow:hidden}", s)  # a chart's hidden table is no scroller, so it takes no Tab stop


# The renderer's helpers, run in node from the block itself with a tiny stand-in for the DOM
FAKE_DOM = r"""
class N{constructor(t){this.tagName=t.toUpperCase();this.kids=[];this.dataset={};this.attrs={};this.textContent=''}
 append(...k){this.kids.push(...k)}setAttribute(k,v){this.attrs[k]=String(v)}querySelectorAll(){return[]}
 get text(){return this.textContent+this.kids.map(c=>typeof c=='string'?c:c.text).join('')}}
globalThis.document={createElement:t=>new N(t),createElementNS:(ns,t)=>new N(t)};globalThis.AV={pend:''};
const tryit=f=>{try{f();return 'ok'}catch(e){return 'threw'}};
"""

@unittest.skipUnless(shutil.which("node"), "needs node")
class RichHelpersInNode(unittest.TestCase):
    def run_js(self, code):
        r = subprocess.run(["node"], input=FAKE_DOM + rich_block() + "\nconsole.log(JSON.stringify((()=>{" + code + "})()))",
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def test_links_https_only(self):  # the deck rebuilds links itself and keeps only https
        got = self.run_js(r"""return ['https://a.example/x?y=1','http://a.example','javascript:alert(1)','data:text/html,x','https://u:p@a.example',
          'https://a.example/a b','https://a.example/\u202e','https://a.example/\ufeff','https:///nohost','https://a.example/'+'x'.repeat(500),'https://a.example\\x']
          .map(h=>{const u=aurl(h);return u?u.href:null})""")
        self.assertEqual(got, ["https://a.example/x?y=1"] + [None] * 10)
        a = self.run_js("const a=alink(aurl('https://a.example/p'),'Booking');return [a.target,a.rel,a.href,a.text]")
        self.assertEqual(a, ["_blank", "noopener noreferrer", "https://a.example/p", "Booking a.example"])

    def test_markdown_links(self):
        got = self.run_js(r"""const f=s=>ain(s,0).map(x=>typeof x=='string'?x:[x.tagName,x.href||'',x.text]);
          return [f('[label](javascript:alert(1))'),f('[wiki](https://w.example/A_(b))'),f('see https://example.com.'),f('[https://paypal.com](https://evil.example/)')]""")
        self.assertEqual(got[0], ["label"])  # brackets in the href: the label only, never the markdown
        self.assertEqual(got[1], [["A", "https://w.example/A_(b)", "wiki w.example"]])
        self.assertEqual(got[2], ["see ", ["A", "https://example.com/", "https://example.com"], "."])  # its host isn't shown twice
        self.assertEqual(got[3], [["A", "https://evil.example/", "evil.example"]])  # a label naming another site shows the real host

    def test_trimming_never_splits_a_character(self):
        got = self.run_js(r"""const e='\u{1F600}'.repeat(81),r=as_(e,80);
          return [[...r].length,/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(r),as_('\u{1F600}'.repeat(80),80)==='\u{1F600}'.repeat(80)]""")
        self.assertEqual(got, [80, False, True])

    def test_numbers_and_axes(self):
        got = self.run_js(r"""return [tryit(()=>aticks(1,1+1e-15)),tryit(()=>aticks(5e11,5e11+0.001)),aticks(-430,2100),
          tryit(()=>atable({columns:['EAN'],rows:[[9780141036144]]})),tryit(()=>acard({title:'t',fields:[{label:'n',value:-2e15}]})),
          tryit(()=>achart({type:'chart',kind:'bar',title:'t',labels:['a','b'],series:[{values:[1,1e13]}]})),tryit(()=>atable({columns:['a'],rows:[[NaN]]}))]""")
        self.assertEqual(got[:2], ["threw", "threw"])  # a near-flat axis skips the chart rather than drawing NaN
        self.assertEqual(got[2], [-1000, 0, 1000, 2000, 3000])
        self.assertEqual(got[3:], ["ok", "ok", "threw", "threw"])  # cells and fields take any finite number; charts cap at 1e12

    def test_copy_text_is_the_lead_and_the_parts_drawn(self):
        got = self.run_js(r"""return avPlain('Aiva · Accounting: Receipts (2)',[{type:'table',title:'Receipts',columns:['#','Vendor','Amount'],
          rows:[[1,{text:'Acme',href:'https://acme.example/'},'£12.34'],[2,{text:'Bad',href:'javascript:x'},'unknown']],note:'and 1 more.'},
          {type:'card',title:'Trip',fields:[{label:'Seat',value:'12A'}],body:'Window',links:[{label:'Book',href:'https://b.example/'}]},
          {type:'chart',kind:'bar',title:'Spend',labels:['Jan','Feb'],series:[{values:[12.5,-3]}],unit:'GBP'}])""")
        self.assertEqual(got.split("\n"), [
            "Aiva · Accounting: Receipts (2)", "Receipts", "# | Vendor | Amount", "1 | Acme (https://acme.example/) | £12.34",
            "2 | Bad | unknown", "and 1 more.", "Trip", "Seat: 12A", "Window", "Book: https://b.example/", "Spend: Jan £12.50, Feb -£3"])


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
