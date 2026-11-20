"""The QuickBooks robot check: /api/aiva/qbo-signin through the deck (auth, body shape, size, signing), the page's view in node, and the request body reader."""
import json, re, shutil, socket, subprocess, sys, threading, unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_aiva_proxy as tp  # the fake Aiva on a Unix socket (a module, so its tests aren't collected twice)
from test_aiva_proxy import GOT, Stub, server
from test_aiva_rich import FORBIDDEN

ROOT = Path(__file__).resolve().parent.parent

class QboProxy(unittest.TestCase):
    setUpClass, tearDownClass = (classmethod(f.__func__) for f in (tp.AivaProxy.setUpClass, tp.AivaProxy.tearDownClass))
    setUp, verify = tp.AivaProxy.setUp, tp.AivaProxy.verify

    def test_get_forwarded(self):
        h = Stub("/api/aiva/qbo-signin?x=1"); self.assertTrue(server.aiva_api(h, "/api/aiva/qbo-signin"))
        self.assertEqual((GOT[-1]["method"], GOT[-1]["path"], h.out[0]), ("GET", "/qbo-signin", 200))

    def test_good_inputs_signed_not_strong(self):  # Aiva's contract: strong "0", even from a passkey session
        for b, want in (({"tap": [0, 1]}, {"tap": [0.0, 1.0]}), ({"tap": [0.25, 0.5]}, {"tap": [0.25, 0.5]}), ({"text": "a" * 200}, None), ({"text": " x "}, None),
                        ({"key": "Enter"}, None), ({"key": "Backspace"}, None), ({"key": "Tab"}, None)):
            for kw in ({}, {"ts": True, "se": ("me@example.com", "sid")}):
                h = Stub("/api/aiva/qbo-signin", **kw); self.assertTrue(server.aiva_api(h, "/api/aiva/qbo-signin", b))
                g = GOT[-1]; self.assertEqual((g["method"], g["path"], json.loads(g["body"])), ("POST", "/qbo-signin", want or b)); self.verify(g, "0")

    def test_bad_inputs_never_reach_aiva(self):
        n = len(GOT)
        for b in ({}, [], "tap", {"tap": [0.5, 0.5], "text": "x"}, {"tap": [0.5]}, {"tap": [0.1, 0.2, 0.3]}, {"tap": [-0.1, 0.5]}, {"tap": [0.5, 1.01]},
                  {"tap": [True, False]}, {"tap": ["0.5", "0.5"]}, {"tap": [float("nan"), 0.5]}, {"tap": {"x": 0.5}}, {"text": ""}, {"text": "a" * 201},
                  {"text": 5}, {"text": "a\nb"}, {"text": "\x00"}, {"text": "a\u200bb"}, {"text": "\ud800"}, {"key": "Escape"}, {"key": "enter"}, {"key": ["Enter"]}, {"click": [0.5, 0.5]}):
            h = Stub("/api/aiva/qbo-signin"); self.assertTrue(server.aiva_api(h, "/api/aiva/qbo-signin", b), b); self.assertEqual(h.out[0], 400, b)
        self.assertEqual(len(GOT), n)

class Http(unittest.TestCase):  # through the real handler: the deck's sign-in, the size cap and the body reader
    @classmethod
    def setUpClass(cls):
        tp.AivaProxy.setUpClass.__func__(cls)
        cls.http = ThreadingHTTPServer(("127.0.0.1", 0), server.H); threading.Thread(target=cls.http.serve_forever, daemon=True).start()
    @classmethod
    def tearDownClass(cls): cls.http.shutdown(); cls.http.server_close(); cls.srv.shutdown(); cls.srv.server_close()
    def setUp(self): GOT.clear(); server.AIVA_SOCK = self.sock

    def req(self, method, path, body=b"", token=True, length=None, chunk=None):
        h = [f"{method} {path} HTTP/1.1", "Host: 127.0.0.1", "Content-Type: application/json"]
        if token: h.append("X-Deck-Token: " + server.TOK)
        if chunk is not None: h.append("Transfer-Encoding: chunked"); body = chunk
        elif method == "POST": h.append(f"Content-Length: {len(body) if length is None else length}")
        with socket.create_connection(self.http.server_address, timeout=5) as c:
            c.sendall(("\r\n".join(h) + "\r\n\r\n").encode() + body); return int(c.recv(300).split()[1])

    def test_sign_in_required(self):
        self.assertEqual(self.req("GET", "/api/aiva/qbo-signin", token=False), 401)
        self.assertEqual(self.req("POST", "/api/aiva/qbo-signin", b'{"key":"Enter"}', token=False), 401); self.assertEqual(GOT, [])
        self.assertEqual(self.req("GET", "/api/aiva/qbo-signin"), 200); self.assertEqual(GOT[-1]["path"], "/qbo-signin")
        self.assertEqual(self.req("POST", "/api/aiva/qbo-signin", b'{"key":"Enter"}'), 200); self.assertEqual(json.loads(GOT[-1]["body"]), {"key": "Enter"})

    def test_body_cap_and_bad_lengths(self):
        big = json.dumps({"text": "a" * 2000}).encode()
        self.assertEqual(self.req("POST", "/api/aiva/qbo-signin", big), 413)
        self.assertEqual(self.req("POST", "/api/aiva/qbo-signin", b"{}", length=-1), 400)
        self.assertEqual(self.req("POST", "/api/aiva/qbo-signin", b"{}", length="2x"), 400)
        self.assertEqual(self.req("POST", "/api/aiva/qbo-signin", b"{not json"), 400)
        self.assertEqual(self.req("POST", "/api/aiva/qbo-signin", chunk=b"f\r\n{\"key\":\"Enter\"}\r\n0\r\n\r\n"), 200)  # a chunked body is read whole
        self.assertEqual(GOT[-1]["body"], b'{"key": "Enter"}'); GOT.clear()
        self.assertEqual(self.req("POST", "/api/aiva/qbo-signin", b"\xff\xfe"), 400); self.assertEqual(GOT, [])

    def test_siri_bad_length_or_chunk_is_400_not_a_hang(self):
        for kw in ({"length": -5}, {"length": "abc"}, {"chunk": b"-5\r\nabc\r\n0\r\n\r\n"}, {"chunk": b"zz\r\nabc\r\n0\r\n\r\n"}, {"chunk": b"1" * 50 + b"\r\n"}):
            self.assertEqual(self.req("POST", "/api/siri", b"hello", **kw), 400, kw)
        self.assertEqual(self.req("POST", "/api/siri", chunk=b"%x\r\n%s\r\n0\r\n\r\n" % (30000, b"x" * 30000)), 413)

def view_block():
    s = (ROOT / "index.html").read_text()
    a, b = s.count("// qbo-signin:start"), s.count("// qbo-signin:end")
    if a != 1 or b != 1: raise AssertionError(f"markers: start {a}, end {b}")
    return s[s.index("// qbo-signin:start"):s.index("// qbo-signin:end")]

class View(unittest.TestCase):
    def test_no_html_parsing_and_no_outside_scripts(self):
        blk = view_block()
        self.assertIn("function rcPoll(", blk)
        for f in FORBIDDEN: self.assertIsNone(re.search(f, blk), f)
        self.assertNotRegex((ROOT / "index.html").read_text(), r"<script[^>]+src=[\"']?(https?:)?//")

    def test_hash_opens_it(self):
        s = (ROOT / "index.html").read_text()
        self.assertIn("location.hash=='#qbo-signin'", s); self.assertIn("if(rc)rcOpen()", s); self.assertIn('id=rc hidden', s)
        self.assertIn("Aiva\\'s sign-in tab, live. Tap the picture to tap the page, type in the box to type where the cursor is, and use the keys for Enter, Backspace and Tab. After you act, Aiva takes the sign-in on again.", view_block())
        self.assertIn("'QuickBooks sign-in'", view_block()); self.assertNotIn("robot check'", view_block())

# The view in node, with a tiny DOM, fake timers and a fake api()
FAKE = r"""
class N{constructor(t){this.tagName=t.toUpperCase();this.kids=[];this.attrs={};this.textContent='';this.hidden=false}
 append(...k){this.kids.push(...k)}setAttribute(k,v){this.attrs[k]=String(v)}removeAttribute(k){if(k=='src')delete this.src}
 getBoundingClientRect(){return{left:10,top:20,width:200,height:100}}}
const T=[],calls=[],toasts=[];let Q=[];
globalThis.document={hidden:false,createElement:t=>new N(t),addEventListener(){}};
const ROOT=new N('div'),LOCK=new N('div');ROOT.hidden=LOCK.hidden=true;const $=id=>id=='lock'?LOCK:ROOT,toast=m=>toasts.push(m);
globalThis.setTimeout=(f,d)=>{T.push(d);return T.length};globalThis.clearTimeout=()=>{};
const api=async(p,b)=>{calls.push(b||'GET');const r=Q.shift();if(r instanceof Error)throw r;return r};
const flush=()=>new Promise(r=>setImmediate(r));
"""

@unittest.skipUnless(shutil.which("node"), "needs node")
class ViewInNode(unittest.TestCase):
    def run_js(self, code):
        r = subprocess.run(["node"], input=FAKE + view_block() + "\n(async()=>{" + code + "})().then(x=>console.log(JSON.stringify(x)))",
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr); return json.loads(r.stdout)

    def test_fractions_and_backoff(self):
        out = self.run_js("return[rcFrac(110,70,{left:10,top:20,width:200,height:100}),rcFrac(-5,500,{left:10,top:20,width:200,height:100}),[0,1,2,3,9].map(rcDelay)]")
        self.assertEqual(out, [[0.5, 0.5], [0, 1], [700, 1400, 2800, 5600, 10000]])

    def test_polls_while_active_stops_when_inactive_backs_off_on_errors(self):
        out = self.run_js("""
          Q=[{active:true,frame:'QUJD',w:2,h:1}];rcOpen();await flush();const a=[RC.img.src,T.slice(),RC.live.hidden,RC.idle.hidden];
          Q=[Object.assign(new Error('503'),{reason:"Aiva isn't running"}),new Error('x')];rcPoll(RC.n);await flush();rcPoll(RC.n);await flush();const b=[T.slice(-2),RC.msg.textContent];
          Q=[{active:true,frame:'<bad>'}];rcPoll(RC.n);await flush();const c=[RC.img.src,T[T.length-1]];
          Q=[{active:false,reason:'QuickBooks is signed in'}];T.length=0;rcPoll(RC.n);await flush();const d=[T.length,RC.live.hidden,RC.idle.hidden,RC.why.textContent,RC.img.src];
          Q=[{active:true,frame:'QUJD'}];document.hidden=true;rcPoll(RC.n);await flush();const e=Q.length;document.hidden=false;
          RC.img.src='x';LOCK.hidden=false;rcPoll(RC.n);await flush();const l=[Q.length,RC.img.src];LOCK.hidden=true;
          rcClose();Q=[{active:true}];rcPoll(RC.n);await flush();return[a,b,c,d,e,l,Q.length,ROOT.hidden]""")
        a, b, c, d, e, l, left, hidden = out
        self.assertEqual(l, [1, None])  # the lock screen showing: no fetch, and the picture is cleared
        self.assertEqual(a, ["data:image/jpeg;base64,QUJD", [700], False, True])
        self.assertEqual(b, [[1400, 2800], "Aiva didn't answer. Trying again…"])
        self.assertEqual(c, ["data:image/jpeg;base64,QUJD", 700])  # a malformed frame keeps the last picture
        self.assertEqual(d, [0, True, False, "QuickBooks is signed in", None])
        self.assertEqual((e, left, hidden), (1, 1, True))  # hidden page or closed view: no fetch

    def test_reason_shown_and_wait_polls_again_then_comes_back_live(self):
        out = self.run_js("""
          Q=[{active:true,frame:'QUJD',reason:'Intuit wants the robot check.'}];rcOpen();await flush();const a=[RC.msg.textContent,RC.msg.className,T.slice()];
          Q=[{active:false,wait:true,reason:'Aiva is signing in.'}];T.length=0;rcPoll(RC.n);await flush();const b=[RC.idle.hidden,RC.live.hidden,RC.ttl.textContent,RC.why.textContent,T.slice(),RC.img.src];
          Q=[{active:true,frame:'QUJD',reason:'Intuit is showing a screen I do not recognise.'}];T.length=0;rcPoll(RC.n);await flush();const c=[RC.live.hidden,RC.idle.hidden,RC.msg.textContent,T.slice()];
          Q=[{active:false,reason:'Signed in.'}];T.length=0;rcPoll(RC.n);await flush();const d=[RC.ttl.textContent,RC.why.textContent,T.length];
          Q=[{active:true,frame:'QUJD'}];rcPoll(RC.n);await flush();const e=RC.msg.textContent;
          Q=[{active:false,wait:true}];rcPoll(RC.n);await flush();const f=RC.why.textContent;
          return[a,b,c,d,e,f]""")
        a, b, c, d, e, f = out
        self.assertEqual(a, ["Intuit wants the robot check.", "rcm", [700]])
        self.assertEqual(b, [False, True, "Aiva is on it", "Aiva is signing in.", [2000], None])
        self.assertEqual(c, [False, True, "Intuit is showing a screen I do not recognise.", [700]])
        self.assertEqual(d, ["Nothing to do", "Signed in.", 0])
        self.assertEqual((e, f), ("", ""))

    def test_inputs_sent_in_aivas_shape(self):
        out = self.run_js("""
          Q=[{active:true,frame:'QUJD'}];rcOpen();await flush();calls.length=0;
          Q=[{ok:false,reason:'Not now'},{active:true}];RC.img.onclick({clientX:60,clientY:45});await flush();await flush();
          const f=RC.live.kids[2],k=RC.live.kids[3];RC.in.value='hello';Q=[{ok:true},{active:true}];f.onsubmit({preventDefault(){}});await flush();await flush();
          Q=[{ok:true},{active:true}];k.kids[1].onclick();await flush();await flush();
          RC.in.value='';f.onsubmit({preventDefault(){}});return[calls,toasts,RC.in.value]""")
        self.assertEqual(out, [[{"tap": [0.25, 0.25]}, "GET", {"text": "hello"}, "GET", {"key": "Backspace"}, "GET"], ["Not now"], ""])

# The Aiva chat's offer fetch: a failing fetch for a new offer id backs off, and an offer that comes back has its misses reset
@unittest.skipUnless(shutil.which("node"), "needs node")
class OfferFetch(unittest.TestCase):
    def test_backoff_and_misses_reset(self):
        s = (ROOT / "index.html").read_text(); fn = s[s.index("async function avOffers("):s.index("async function avLoad(")]
        js = """let now=1e6,n=0,fail=true,list=[];Date.now=()=>now;const AV={m:[{offer_id:'of_1'}],of:{},mc:{},ot:0,ob:0};
          const api=async()=>{n++;if(fail)throw new Error('x');return{offers:list}};""" + fn + """
          (async()=>{const go=async()=>{try{await avOffers()}catch(e){}},seen=[];
            for(let i=0;i<20;i++){await go();now+=3e3;seen.push(n)}// 60 s of 3 s polls while the fetch fails
            fail=false;now+=3e4;await go();const missed=AV.mc.of_1;
            list=[{id:'of_1',status:'open'}];now+=3e4;await go();
            console.log(JSON.stringify([seen,missed,AV.mc.of_1===undefined,AV.of.of_1,AV.ob]))})()"""
        r = subprocess.run(["node"], input=js, capture_output=True, text=True, timeout=30); self.assertEqual(r.returncode, 0, r.stderr)
        seen, missed, reset, of, ob = json.loads(r.stdout)
        self.assertLessEqual(seen[-1], 6)  # not 20: 6, 12, 24, 30 s apart
        self.assertEqual((missed, reset, of, ob), (1, True, {"status": "open"}, 0))

if __name__ == "__main__": unittest.main()
