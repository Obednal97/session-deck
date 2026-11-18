"""Live terminal: WebSocket framing, the pty bridge to a tmux client, viewer sessions and clean-up, in a throwaway tmux server (decktest)."""
import base64, io, json, os, socket, struct, subprocess, sys, tempfile, threading, time, unittest
from pathlib import Path
from unittest import mock

TMP = tempfile.mkdtemp()
os.environ.update(DECK_SECRETS=TMP, DECK_STORE=f"{TMP}/passkeys.json", DECK_PREFS=f"{TMP}/prefs.json", DECK_RP_ID="localhost", DECK_TS_USER="me@example.com",
                  DECK_SSH_HOSTS=f"{TMP}/ssh-hosts.json", DECK_TMUX_SOCKET="decktest", DECK_SHOW_TEST="1", DECK_SSH_CM=f"{TMP}/cm",
                  DECK_SSH_BIN=str(Path(__file__).resolve().parent / "fake_ssh.sh"), FAKE_SSH_MASTER=f"{TMP}/master")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import server
# another test module may have imported server first, with its own settings: never let these tests reach the real tmux servers or ssh
server.TMUX_SOCKS, server.SSH_BIN, server.SSH_CM, server.SSH_HOSTS = ["decktest"], os.environ["DECK_SSH_BIN"], Path(os.environ["DECK_SSH_CM"]), Path(os.environ["DECK_SSH_HOSTS"])

def T(*a): return subprocess.run(["tmux", "-L", "decktest", *a], capture_output=True, text=True).stdout.strip()

def until(fn, wait=5):
    end = time.time() + wait
    while time.time() < end:
        v = fn()
        if v: return v
        time.sleep(0.05)
    return fn()

def frame(op, data, fin=True):
    """A client frame: always masked."""
    n, k = len(data), os.urandom(4)
    h = bytes([(0x80 if fin else 0) | op]) + (bytes([0x80 | n]) if n < 126 else bytes([0xFE]) + struct.pack(">H", n) if n < 65536 else bytes([0xFF]) + struct.pack(">Q", n))
    return h + k + bytes(b ^ k[i % 4] for i, b in enumerate(data))

def rframe(f):
    """A server frame: never masked."""
    a, b = f.read(2)
    n = b & 127
    if n == 126: n = struct.unpack(">H", f.read(2))[0]
    elif n == 127: n = struct.unpack(">Q", f.read(8))[0]
    assert not b & 0x80, "server frames are unmasked"
    return a & 15, f.read(n)

def attaches():  # tmux clients the deck (this process) started
    return [l for l in subprocess.run(["ps", "-axo", "ppid=,command="], capture_output=True, text=True).stdout.splitlines()
            if l.split(None, 1)[0] == str(os.getpid()) and "attach-session" in l]


class Frames(unittest.TestCase):
    def test_frame_roundtrip(self):
        big = os.urandom(70000)
        self.assertEqual(server.ws_read(io.BytesIO(frame(2, big))), (2, big))
        self.assertEqual(server.ws_read(io.BytesIO(frame(1, b"he", False) + frame(9, b"") + frame(0, b"l", False) + frame(0, b"lo"))), (1, b"hello"))
        self.assertEqual(server.ws_read(io.BytesIO(frame(8, b"\x03\xe8"))), (8, b""))
        for bad in (frame(2, b"x")[:1] + b"\x01x",  # unmasked
                    bytes([0x82, 0xFF]) + struct.pack(">Q", 2 << 20)):  # over the cap
            with self.assertRaises(Exception): server.ws_read(io.BytesIO(bad))
        a, b = socket.socketpair()
        threading.Thread(target=server.ws_write, args=(a, 2, big)).start(); f = b.makefile("rb")  # more than the pair's buffer
        self.assertEqual(rframe(f), (2, big))
        server.ws_write(a, 1, b"x" * 200); self.assertEqual(rframe(f), (1, b"x" * 200))
        server.ws_read(io.BytesIO(frame(9, b"hi") + frame(2, b"z")), a); self.assertEqual(rframe(f), (10, b"hi"))  # a ping is answered
        a.close(); b.close()


class Bridge(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert server.TMUX_SOCKS == ["decktest"]
        T("kill-server"); server._socks.pop("decktest", None)
        T("new-session", "-d", "-s", "ssh-zz-1", "-x", "80", "-y", "24", "cat", ";", "set-option", "-t", "=ssh-zz-1:", "@deck_ssh", "zz", ";", "set-option", "-t", "=ssh-zz-1:", "status", "off")
        cls.pane = "decktest." + T("display", "-p", "-t", "=ssh-zz-1:", "#{pane_id}")[1:]
        cls.srv = server.ThreadingHTTPServer(("127.0.0.1", 0), server.H); cls.srv.daemon_threads = True
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close()
        T("kill-server")

    def ws(self, pane, origin=None):
        s = socket.create_connection(("127.0.0.1", self.srv.server_address[1]), timeout=5)
        h = {"Host": "127.0.0.1", "Upgrade": "websocket", "Connection": "Upgrade", "Sec-WebSocket-Key": base64.b64encode(os.urandom(16)).decode(),
             "Sec-WebSocket-Version": "13", "Origin": origin or f"http://127.0.0.1:{server.PORT}"}
        s.sendall((f"GET /api/term/{pane}?cols=80&rows=24&tok={server.TOK} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items()) + "\r\n").encode())
        f = s.makefile("rb"); status = f.readline().decode()
        while f.readline() not in (b"\r\n", b""): pass
        self.addCleanup(lambda: (f.close(), s.close()))
        return s, f, status

    def recv(self, f, needle, wait=5):
        got, end = b"", time.time() + wait
        while needle not in got and time.time() < end:
            try: op, d = rframe(f)
            except (OSError, ValueError): break
            if op == 2: got += d
        return got

    def test_bad_origin_refused(self):
        n = len(attaches())
        _, _, st = self.ws(self.pane, "https://evil.example")
        self.assertIn(" 403 ", st)
        time.sleep(0.3); self.assertEqual(len(attaches()), n)

    def test_bad_token_refused(self):
        s = socket.create_connection(("127.0.0.1", self.srv.server_address[1]), timeout=5)
        s.sendall(f"GET /api/term/{self.pane}?tok=nope HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: eA==\r\n\r\n".encode())
        self.assertIn(b" 401 ", s.recv(100)); s.close()

    def test_echo(self):
        s, f, st = self.ws(self.pane)
        self.assertIn(" 101 ", st)
        b = "héllo ✓\r".encode()
        s.sendall(frame(2, b[:2])); time.sleep(0.1); s.sendall(frame(2, b[2:]))  # split inside é
        self.assertIn("héllo ✓".encode(), self.recv(f, "héllo ✓".encode()))
        s.sendall(frame(1, json.dumps({"cols": 100, "rows": 30}).encode()))
        self.assertTrue(until(lambda: T("display", "-p", "-t", "=ssh-zz-1:", "#{window_width}x#{window_height}") == "100x30"))

    def test_two_viewers(self):
        (s1, f1, _), (s2, f2, _) = self.ws(self.pane), self.ws(self.pane)
        until(lambda: server.VIEWING.get(self.pane) == 2)
        s1.sendall(frame(2, b"twoview\r"))
        self.assertIn(b"twoview", self.recv(f1, b"twoview")); self.assertIn(b"twoview", self.recv(f2, b"twoview"))

    def test_drop_cleans_up(self):
        T("new-session", "-d", "-s", "work", "cat")
        local = "decktest." + T("display", "-p", "-t", "=work:0", "#{pane_id}")[1:]
        self.addCleanup(T, "kill-session", "-t", "=work")
        with mock.patch.object(server, "valid_pane", lambda p: p == local):
            (s1, f1, a), (s2, f2, b) = self.ws(self.pane), self.ws(local)
            self.assertEqual((a.split()[1], b.split()[1]), ("101", "101"))
            self.assertTrue(until(lambda: len(attaches()) >= 2 and "deck-view-" in T("list-sessions", "-F", "#{session_name}")))
            for x in (f1, s1, f2, s2): x.close()  # no close frame, as when a phone locks
            self.assertTrue(until(lambda: not attaches() and "deck-view-" not in T("list-sessions", "-F", "#{session_name}")
                                  and self.pane not in server.VIEWING and local not in server.VIEWING, 3), (attaches(), server.VIEWING))
        self.assertEqual(T("display", "-p", "-t", "=ssh-zz-1:", "#{pane_dead}"), "0")

    def test_local_view_keeps_window(self):
        T("new-session", "-d", "-s", "work", "cat", ";", "new-window", "-d", "-t", "=work:1", "cat")
        self.addCleanup(T, "kill-session", "-t", "=work")
        chat = "decktest." + T("display", "-p", "-t", "=work:1", "#{pane_id}")[1:]
        with mock.patch.object(server, "valid_pane", lambda p: p == chat):
            s, f, st = self.ws(chat)
            self.assertIn(" 101 ", st)
            v = until(lambda: [l for l in T("list-sessions", "-F", "#{session_name} #{window_index} #{session_attached}").splitlines() if l.startswith("deck-view-")])
            self.assertEqual(v[0].split()[1:], ["1", "1"])
            s.sendall(frame(2, b"inchat\r")); self.assertIn(b"inchat", self.recv(f, b"inchat"))
            self.assertEqual(T("display", "-p", "-t", "=work:", "#{window_index}"), "0")
            s.sendall(frame(8, b"\x03\xe8"))
            self.assertEqual(until(lambda: rframe(f)[0] == 8), True)  # the deck answers with its own close (maybe after output already on its way)
            self.assertTrue(until(lambda: "deck-view-" not in T("list-sessions", "-F", "#{session_name}") and chat not in server.VIEWING, 3))
        self.assertEqual(T("display", "-p", "-t", "=work:", "#{window_index}"), "0")

    def test_view_counts_as_seen(self):  # the terminal view stands in for the chat's status poll: a reply that finishes while watched isn't news
        T("new-session", "-d", "-s", "work", "cat")
        self.addCleanup(T, "kill-session", "-t", "=work")
        chat = "decktest." + T("display", "-p", "-t", "=work:0", "#{pane_id}")[1:]
        st = {"pane": chat, "state": "idle", "menu": None}
        self.addCleanup(lambda: (server.WATCH.pop(chat, None), server.SEEN.pop(chat, None)))
        server.SEEN[chat] = 0; server.WATCH[chat] = {"fin": time.time()}
        self.assertEqual(server.attn(st), "done")
        with mock.patch.object(server, "valid_pane", lambda p: p == chat):
            s, f, _ = self.ws(chat)
            self.assertTrue(until(lambda: chat in server.VIEWING))
            server.WATCH[chat]["fin"] = time.time()  # finishes mid-view
            self.assertIsNone(server.attn(st))
            f.close(); s.close()
            self.assertTrue(until(lambda: chat not in server.VIEWING, 3))
        self.assertGreaterEqual(server.SEEN[chat], server.WATCH[chat]["fin"])
        self.assertIsNone(server.attn(st))


if __name__ == "__main__":
    unittest.main()
