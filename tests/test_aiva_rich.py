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
       "answers": ["yes", "no", "always", "never", "answer"], "always_covers": "quote emails to insurer.example", "never_covers": "aiva_mail.send proposals from household", "message_id": 812}

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


    # chief of staff mode: each run of the team's own posts folds into one line, tool-call group style (the thread-mode block, after the renderer's avEl)
    def test_chief_view_folds_team_runs(self):
        s = (ROOT / "index.html").read_text(); i = s.index("const TM=")
        tm = s[i:s.index("// aiva-intake:end", i)]
        js = r"""(()=>{const blk=x=>({x,h:'k'+x.id,mk:()=>[avEl('div','a',x.text)]}),T=(id,persona,text)=>({id,role:'aiva',via:'team',persona,text});
          const M=[{id:1,role:'ollie',text:'hi'},T(2,'household','Aiva · Household: Boiler service booked\nFor Tuesday'),T(3,'finance','Aiva · Finance: Card bill paid\nAll of it'),
            {id:4,role:'ollie',text:'ok'},T(5,'household','Aiva · Household: Bins out tonight'),{id:6,role:'aiva',via:'',text:'Aiva: All quiet'}],B=M.map(blk);
          const hd=b=>{const g=b.mk()[0];return[g.className,g.dataset.g,g.kids[0].className,g.kids[0].kids[0].text,g.kids[0].kids[1].text,g.kids[1].className,g.kids[1].hidden,g.kids[1].kids.map(k=>k.text)]};
          TM.mode='all';const all=avFold(B)===B;TM.mode=null;const none=avFold(B)===B;TM.mode='chief-of-staff';
          const F=avFold(B),old=F[1].h;B[2].h='k3b';const moved=avFold(B)[1].h!=old;
          const three=avFold([T(7,'household','Aiva · Household: a'),T(8,'finance','Aiva · Finance: b'),T(9,'travel','c\nd'),T(10,'household','Aiva · Household: e')].map(blk))[0];
          const parts=avFold([{id:11,role:'aiva',via:'team',persona:'finance',text:'Aiva · Finance: ',parts:[{type:'table',title:'Receipts'}]}].map(blk))[0];
          const old6=avFold(M.map(x=>({...x,via:undefined})).map(blk)).length;
          return[all,none,F.length,F[0]===B[0]&&F[2]===B[3]&&F[4]===B[5],hd(F[1]),hd(F[3]),F[1].h.startsWith('avf:'),moved,hd(three).slice(3,5),old6,hd(parts).slice(3,5)]})()"""
        r = subprocess.run(["node"], input="globalThis.setInterval=()=>0;" + FAKE_DOM + rich_block() + tm + "\nconsole.log(JSON.stringify(" + js + "))",
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        all_, none, n, kept, f1, f2, key, moved, three, old6, parts = json.loads(r.stdout)
        self.assertTrue(all_); self.assertTrue(none)  # everyone mode, or the mode not known yet: nothing folds
        self.assertEqual(n, 5); self.assertTrue(kept)  # Ollie's own message splits the team's posts into two folds
        self.assertEqual(f1, ["tg avf", "av2", "tgh", "2 messages from Household and Finance", "Card bill paid", "tgb", True,
                              ["Aiva · Household: Boiler service booked\nFor Tuesday", "Aiva · Finance: Card bill paid\nAll of it"]])
        self.assertEqual(f2[1], "av5"); self.assertEqual(f2[3:5], ["1 message from Household", "Bins out tonight"])
        self.assertTrue(key); self.assertTrue(moved)  # a folded message that changes redraws its fold
        self.assertEqual(three, ["4 messages from Household, Finance and Travel", "e"])  # no label: the persona's name
        self.assertEqual(old6, 6)  # an older Aiva sends no via: never folds
        self.assertEqual(parts, ["1 message from Finance", "Receipts"])  # only rich parts: the first one's title

    def test_thread_mode_reads_taps_and_frames(self):  # a failed read keeps the mode; a read older than a tap is dropped; every deck frame hears a change
        s = (ROOT / "index.html").read_text(); i = s.index("const TM=")
        js = r"""(async()=>{const G=[];globalThis.tick=()=>{};globalThis.window=globalThis;globalThis.COL=false;
          const fw={avTmNew:(m,q)=>G.push(['col',m,q])},bad={get avTmNew(){throw new Error('cross-origin')}};
          document.querySelectorAll=()=>[{contentWindow:fw},{contentWindow:bad},{contentWindow:{}}];
          let res;globalThis.api=async(p,b)=>{if(b)return{mode:b.mode};if(FAIL)throw FAIL;return new Promise(r=>res=r)};
          const l1=avTmLoad();res({mode:'chief-of-staff'});await l1;const a=TM.mode,g1=G.splice(0);
          FAIL={st:503};await avTmLoad();const b=TM.mode;FAIL=null;
          const l2=avTmLoad();await avTmSet('all');res({mode:'chief-of-staff'});await l2;const c=TM.mode,g2=G.splice(0);
          const l3=avTmLoad();res({mode:'later'});await l3;const e=[TM.mode,G.length];
          let resP;globalThis.api=async(p,b)=>new Promise(r=>b?resP=r:res=r);
          const s4=avTmSet('chief-of-staff'),l4=avTmLoad();resP({mode:'chief-of-staff'});await s4;res({mode:'all'});await l4;const f=TM.mode;G.splice(0);
          avTmNew('chief-of-staff',1);const d=[TM.mode,G.length];
          globalThis.COL='1';const par={deck:{},avTmNew:(m,q)=>G.push(['top',m,q]),document:{querySelectorAll:()=>[{contentWindow:globalThis},{contentWindow:fw}]}};globalThis.parent=par;
          avTmNew('all');return[a,g1,b,c,g2,d,G,e,f]})()"""
        r = subprocess.run(["node"], input="globalThis.setInterval=()=>0;" + FAKE_DOM + rich_block() + s[i:s.index("// aiva-intake:end", i)] +
                           "\n" + js + ".then(v=>console.log(JSON.stringify(v)))", capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        a, g1, b, c, g2, d, g3, e, f = json.loads(r.stdout)
        self.assertEqual((a, g1), ("chief-of-staff", [["col", "chief-of-staff", 1]]))  # the outer page tells its columns; a frame it can't reach is skipped
        self.assertEqual(b, "chief-of-staff")  # a failed read keeps the last known mode
        self.assertEqual((c, g2), ("all", [["col", "all", 1]]))  # the read that started before the tap doesn't undo it
        self.assertEqual(d, ["chief-of-staff", 0])  # a mode heard from another frame isn't sent on again
        self.assertEqual(g3, [["top", "all", 1], ["col", "all", 1]])  # a column tells the outer page and the other columns, not itself
        self.assertEqual(e, ["all", 0])  # a mode this deck doesn't know keeps the last one and tells no frame
        self.assertEqual(f, "chief-of-staff")  # a read started while a tap was being sent doesn't undo it either

    def test_mode_switch_repaints_a_chat_that_starts_with_a_team_run(self):  # paint only lines up from the new list's first two blocks
        s = (ROOT / "index.html").read_text(); i = s.index("const TM=")
        pt = s[s.index("function paint("):s.index("function jumpUI(")]
        js = r"""(()=>{globalThis.window=globalThis;globalThis.COL=false;document.querySelectorAll=()=>[];globalThis.getSelection=()=>({rangeCount:0});globalThis.loadImg=()=>{};
          N.prototype.matches=()=>false;N.prototype.contains=()=>true;Object.defineProperty(N.prototype,'firstChild',{get(){return this.kids[0]}});
          const m={dataset:{},scrollHeight:0,scrollTop:0,contains:()=>true,querySelectorAll:()=>[],set innerHTML(v){this.firstChild=avEl('div','chat');this.firstChild.append(avEl('button','more'))}};
          const T=(id,t)=>({id,role:'aiva',via:'team',persona:'household',text:'Aiva · Household: '+t}),
            M=[T(2,'one'),{id:4,role:'ollie',text:'ok'},{id:5,role:'aiva',via:'',text:'Aiva: done'}];AV.m=M;
          const blk=x=>({x,h:'k'+x.id,mk:()=>[avEl('div','a',x.text)]});globalThis.cur={aiva:1};globalThis.draw=()=>paint(m,avFold(M.map(blk)),false,true);
          const shown=()=>cur.box.kids.slice(1).map(k=>k.className=='tg avf'?'fold:'+k.dataset.g:k.text);
          avTmNew('all');draw();const a=shown();avTmNew('chief-of-staff');const b=shown();avTmNew('all');return[a,b,shown()]})()"""
        r = subprocess.run(["node"], input="globalThis.setInterval=()=>0;" + FAKE_DOM + rich_block() + s[i:s.index("// aiva-intake:end", i)] + pt +
                           "\n" + "console.log(JSON.stringify(" + js + "))", capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        a, b, c = json.loads(r.stdout)
        every = ["Aiva · Household: one", "ok", "Aiva: done"]  # one leading team message: both directions line up on "ok"
        self.assertEqual(a, every); self.assertEqual(b, ["fold:av2", "ok", "Aiva: done"]); self.assertEqual(c, every)

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
        got = self.run_js(r"""const c=avApCard({...AP0,answers:['yes','no','never','answer'],draft:'',message_id:0});return [btns(c),c.all().some(n=>n.className=='apd')]""")
        self.assertEqual(got, [["Yes", "No", "Never", "Send"], False])

    def test_approval_card_draws_only_the_answers_aiva_takes(self):  # Yes only while its action exists; the text box only where an answer can rework it
        got = self.run_js(r"""const c=avApCard({...AP0,answers:['no','never']}),d=avApCard({...AP0,answers:['yes','no','never']});
          return [btns(c),c.querySelectorAll('textarea').length,btns(d),d.querySelectorAll('textarea').length]""")
        self.assertEqual(got, [["No", "Never"], 0, ["Yes", "No", "Never"], 0])

    def test_an_approval_that_failed_says_so(self):  # Aiva approved it, but running it failed
        got = self.run_js(r"""api=async(p,b)=>{CALLS.push([p,b]);return{status:'failed'}};await btn(avApCard(AP0),'Yes').onclick();return TOASTS""")
        self.assertEqual(got, ["Approved, but it failed: see the chat"])

    def test_tier_3_without_a_passkey(self):  # No, Never and Send still work; Yes and Always wait for Face ID
        got = self.run_js(r"""TS=false;const c=avApCard({...AP0,tier:3});TS=true;const d=avApCard({...AP0,tier:3});
          return [c.querySelectorAll('button,textarea').map(b=>b.textContent+':'+b.disabled),c.text.includes('Needs a passkey sign-in'),d.querySelectorAll('button').some(b=>b.disabled)]""")
        self.assertEqual(got, [["Yes:true", "No:false", "Always:true", "Never:false", ":false", "Send:false"], True, False])

    def test_passkey_sign_in_unlocks_a_kept_card(self):  # the lock follows TS on each sync, on the same node, leaving the text box alone
        got = self.run_js(r"""TS=false;AV.ap=[{...AP0,tier:3}];avApSync();const c=AP.c.get(AP0.id),t=c.querySelectorAll('textarea')[0],no=c.all().find(n=>n.textContent=='Needs a passkey sign-in');
          t.value='half typed';const st=()=>[btn(c,'Yes').disabled,btn(c,'Always').disabled,no.hidden],o=[st()];avApSync();o.push(st());
          TS=true;avApSync();o.push(st(),AP.c.get(AP0.id)===c,t.value);TS=false;avApSync();o.push(st());TS=true;return o""")
        self.assertEqual(got, [[True, True, False], [True, True, False], [False, False, True], True, "half typed", [True, True, False]])

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
