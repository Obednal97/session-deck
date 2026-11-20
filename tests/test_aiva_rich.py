"""Aiva's rich chat: the page draws Aiva's messages without parsing HTML, and the proxy passes `parts` through untouched."""
import json, os, re, shutil, socketserver, subprocess, sys, tempfile, threading, unittest
from http.server import BaseHTTPRequestHandler
from pathlib import Path

TMP = tempfile.mkdtemp()
os.environ.update(DECK_SECRETS=TMP, DECK_STORE=f"{TMP}/passkeys.json", DECK_PREFS=f"{TMP}/prefs.json", DECK_RP_ID="localhost", DECK_TS_USER="me@example.com")
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import server

AP0 = {"id": "ap_1a2b3c4d", "task_id": "t_1", "persona": "household", "action": "Send an email", "kind": "aiva_mail.send", "tier": 2, "created": 1763600000.0, "reversible": True,
       "title": "Email to quotes@insurer.example", "subtitle": "Household · Personal · Tier 2", "context": "You asked for three home insurance quotes.",
       "grounding": [{"label": "To", "value": "quotes@insurer.example", "href": ""}, {"label": "Site", "value": "Insurer", "href": "https://insurer.example/quotes"}],
       "draft": "Hello,\nPlease send a quote.", "decision": "Should Household send this email?", "recommendation": {"answer": "yes", "text": "Yes: it only asks for a quote."},
       "answers": ["yes", "no", "always", "never"], "always_covers": "quote emails to insurer.example", "never_covers": "aiva_mail.send proposals from household", "message_id": 812}

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
class N{constructor(t){this.tagName=t.toUpperCase();this.kids=[];this.dataset={};this.attrs={};this.textContent='';this.parent=null;this.hidden=false;this.disabled=false;this.value='';
  const c=new Set();this.classList={add:x=>c.add(x),remove:x=>c.delete(x),contains:x=>c.has(x)}}
 focus(){}append(...k){for(const x of k)if(x&&typeof x=='object'){if(x.parent)x.remove();x.parent=this}this.kids.push(...k)}setAttribute(k,v){this.attrs[k]=String(v)}
 remove(){const p=this.parent;if(p)p.kids=p.kids.filter(k=>k!==this);this.parent=null}
 replaceWith(n){const p=this.parent;p.kids[p.kids.indexOf(this)]=n;n.parent=p;this.parent=null}
 replaceChildren(...k){this.kids.forEach(x=>x.parent=null);this.kids=[];this.append(...k)}
 all(){return this.kids.flatMap(k=>typeof k=='string'?[]:[k,...k.all()])}
 querySelectorAll(s){const T=s.split(',').map(x=>x.trim().toUpperCase());return this.all().filter(n=>T.includes(n.tagName))}// tag names only
 get text(){return this.textContent+this.kids.map(c=>typeof c=='string'?c:c.text).join('')}}
globalThis.document={createElement:t=>new N(t),createElementNS:(ns,t)=>new N(t)};globalThis.AV={pend:'',ap:[],m:[]};
const tryit=f=>{try{f();return 'ok'}catch(e){return 'threw'}};
// what the approvals panel calls outside the block
const IDS={};globalThis.$=id=>IDS[id]||(IDS[id]=new N('button'));globalThis.TS=true;globalThis.cur=null;globalThis.sb=new N('div');globalThis.sd=new N('div');
globalThis.CALLS=[];globalThis.TOASTS=[];globalThis.FAIL=null;globalThis.api=async(p,b)=>{CALLS.push([p,b]);if(FAIL)throw FAIL;return{status:'ok'}};
globalThis.toast=m=>TOASTS.push(m);globalThis.avLoad=async()=>{};globalThis.avAgo=()=>'5m';globalThis.showSheet=()=>{};globalThis.hideSheet=()=>{};
const btn=(c,t)=>c.querySelectorAll('button').find(b=>b.textContent==t),btns=c=>c.querySelectorAll('button').map(b=>b.textContent);
"""

@unittest.skipUnless(shutil.which("node"), "needs node")
class RichHelpersInNode(unittest.TestCase):
    def run_js(self, code):
        r = subprocess.run(["node"], input=FAKE_DOM + rich_block() + "\nAP0=" + json.dumps(AP0) + ";\n(async()=>{" + code + "})().then(v=>console.log(JSON.stringify(v)))",
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
        got = self.run_js(r"""const h='https://'+'\u0440\u0430ypal.com/',a=alink(aurl(h),h);return [a.href,a.textContent,a.text]""")
        self.assertTrue(got[0].startswith("https://xn--"))  # a look-alike host: never shown as a plausible address alone
        self.assertEqual(got[1], got[0][8:-1])
        self.assertEqual(got[2], got[1])

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

    def test_a_table_title_is_drawn_once(self):  # a hidden caption repeating it came out twice in copied text (Aiva, 19 Nov 2026)
        got = self.run_js(r"""const ti='Leeds to York, Fri 4 Dec',f=atable({title:ti,columns:['Depart'],rows:[['17:22']]}),
          t=f.kids[1].kids[0];return [f.text.split(ti).length-1,t.attrs['aria-label'],t.kids.map(k=>k.tagName),t.kids[0].kids[0].kids.map(k=>k.text),
          atable({columns:['Depart','Arrive'],rows:[['17:22','19:24']]}).kids[0].kids[0].kids[0].className]""")
        self.assertEqual(got[0], 1)
        self.assertEqual(got[1], "Leeds to York, Fri 4 Dec")  # its name for a screen reader
        self.assertEqual(got[2], ["THEAD", "TBODY"])
        self.assertEqual(got[3], ["Depart"])  # the header row is still drawn
        self.assertEqual(got[4], "sr")  # an untitled table keeps its hidden caption ("Table: Depart, Arrive")

    def test_copy_text_is_the_lead_and_the_parts_drawn(self):
        got = self.run_js(r"""return avPlain('Aiva · Accounting: Receipts (2)',[{type:'table',title:'Receipts',columns:['#','Vendor','Amount'],
          rows:[[1,{text:'Acme',href:'https://acme.example/'},'£12.34'],[2,{text:'Bad',href:'javascript:x'},'unknown']],note:'and 1 more.'},
          {type:'card',title:'Trip',fields:[{label:'Seat',value:'12A'}],body:'Window',links:[{label:'Book',href:'https://b.example/'}]},
          {type:'chart',kind:'bar',title:'Spend',labels:['Jan','Feb'],series:[{values:[12.5,-3]}],unit:'GBP'}])""")
        self.assertEqual(got.split("\n"), [
            "Aiva · Accounting: Receipts (2)", "Receipts", "# | Vendor | Amount", "1 | Acme (https://acme.example/) | £12.34",
            "2 | Bad | unknown", "and 1 more.", "Trip", "Seat: 12A", "Window", "Book: https://b.example/", "Spend: Jan £12.50, Feb -£3"])


    # the approvals panel (a bottom sheet): one card per approval, kept by id between polls
    def test_approval_card_in_full(self):
        got = self.run_js(r"""AV.m=[{id:812,role:'aiva',text:'x'}];const c=avApCard(AP0),t=c.querySelectorAll('textarea')[0],l=c.querySelectorAll('a')[0];
          return [c.kids[0].tagName,c.kids[0].text,c.text.includes('Household · Personal · Tier 2 · 5m'),c.text.includes('Aiva recommends: Yes'),c.text.includes('Yes: it only asks for a quote.'),
            c.text.includes('Hello,\nPlease send a quote.'),c.text.includes('Should Household send this email?'),btns(c),t.placeholder,t.maxLength,l.href,c.dataset.ap]""")
        self.assertEqual(got[:2], ["B", "Email to quotes@insurer.example"])
        self.assertEqual(got[2:7], [True] * 5)
        self.assertEqual(got[7], ["Yes", "No", "Always", "Never", "Send", "Show in chat"])
        self.assertEqual(got[8:], ["Or tell Aiva what you'd like instead", 2000, "https://insurer.example/quotes", "ap_1a2b3c4d"])

    def test_approval_card_without_always_draft_or_chat_message(self):
        got = self.run_js(r"""const c=avApCard({...AP0,answers:['yes','no','never'],draft:'',message_id:0});return [btns(c),c.all().some(n=>n.className=='apd')]""")
        self.assertEqual(got, [["Yes", "No", "Never", "Send"], False])

    def test_tier_3_without_a_passkey(self):  # No, Never and Send still work; Yes and Always wait for Face ID
        got = self.run_js(r"""TS=false;const c=avApCard({...AP0,tier:3});TS=true;const d=avApCard({...AP0,tier:3});
          return [c.querySelectorAll('button,textarea').map(b=>b.textContent+':'+b.disabled),c.text.includes('Needs a passkey sign-in'),d.querySelectorAll('button').some(b=>b.disabled)]""")
        self.assertEqual(got, [["Yes:true", "No:false", "Always:true", "Never:false", ":false", "Send:false"], True, False])

    def test_sync_keeps_cards_by_id(self):  # a poll while the owner types must not rebuild the card
        got = self.run_js(r"""const B={...AP0,id:'ap_2'},b=$('apb');AV.ap=[AP0,B];avApSync();const box=AP.box,c1=AP.c.get(AP0.id),c2=AP.c.get('ap_2'),t=c2.querySelectorAll('textarea')[0];t.value='half typed';
          const o=[box.kids.filter(n=>n.dataset.ap).length,$('apbn').textContent,b.hidden];avApSync();o.push(AP.c.get(AP0.id)===c1&&AP.c.get('ap_2')===c2,t.value);
          AV.ap=[B,{...AP0,id:'ap_3'}];avApSync();o.push(box.kids.filter(n=>n.dataset.ap).map(n=>n.dataset.ap),AP.c.get('ap_2')===c2,AP.c.has(AP0.id),c1.parent);
          AV.ap=[];avApSync();o.push(b.hidden,AP.none.hidden,AP.c.size);return o""")
        self.assertEqual(got, [2, "2", False, True, "half typed", ["ap_2", "ap_3"], True, False, None, True, False, 0])

    def test_card_decisions(self):  # Always and Never ask first; the answer is trimmed; an error gives the buttons back
        got = self.run_js(r"""const c=avApCard(AP0),o=[];btn(c,'Never').onclick();o.push(btns(c),c.text.includes('Never: aiva_mail.send proposals from household?'));
          btn(c,'Cancel').onclick();o.push(btns(c));btn(c,'Never').onclick();await btn(c,'Confirm').onclick();
          const d=avApCard(AP0);btn(d,'Always').onclick();o.push(d.text.includes('Always: quote emails to insurer.example?'));await btn(d,'Confirm').onclick();
          const e=avApCard(AP0);await btn(e,'Send').onclick();e.querySelectorAll('textarea')[0].value='  Ask for a monthly price instead \n';await btn(e,'Send').onclick();
          await btn(avApCard(AP0),'Yes').onclick();await btn(avApCard(AP0),'No').onclick();
          TS=false;FAIL={reason:'Aiva isn\'t running'};const f=avApCard({...AP0,tier:3});await btn(f,'No').onclick();TS=true;
          o.push(CALLS,TOASTS,f.querySelectorAll('button').map(b=>b.disabled));return o""")
        self.assertEqual(got[:2], [["Confirm", "Cancel", "Send"], True])
        self.assertEqual(got[2][:4], ["Yes", "No", "Always", "Never"]); self.assertTrue(got[3])
        u = "/api/aiva/approvals/ap_1a2b3c4d"
        self.assertEqual(got[4], [[u, {"decision": "reject_never"}], [u, {"decision": "approve_always"}], [u, {"decision": "answer", "text": "Ask for a monthly price instead"}],
                                  [u, {"decision": "approve"}], [u, {"decision": "reject"}], [u, {"decision": "reject"}]])  # an empty box sends nothing
        self.assertEqual(got[5], ["Never again", "Always on", "Sent to Aiva", "Approved", "Rejected", "Aiva isn't running"])
        self.assertEqual(got[6], [True, False, True, False, False])  # back after the error, but Yes and Always stay locked

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
