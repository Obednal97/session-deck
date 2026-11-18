"""Router: a WebSocket upgrade passes through with its Connection header; other requests still close after one reply."""
import socket, socketserver, sys, threading, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import router


class Upgrade(unittest.TestCase):
    def setUp(self):
        self.got, self.deck = [], socket.create_server(("127.0.0.1", 0))
        def deck():  # answers 101 to an upgrade (then echoes bytes), 200 to anything else
            while True:
                try: c, _ = self.deck.accept()
                except OSError: return
                buf = b""
                while b"\r\n\r\n" not in buf: buf += c.recv(4096)
                head, _, rest = buf.partition(b"\r\n\r\n"); self.got.append(head.decode())
                if b"upgrade: websocket" not in head.lower(): c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok"); c.close(); continue
                c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n" + rest)
                while (b := c.recv(4096)): c.sendall(b)
                c.close()
        threading.Thread(target=deck, daemon=True).start()
        router.ROUTES = {"me@example.com": str(self.deck.getsockname()[1])}
        self.rt = socketserver.ThreadingTCPServer(("127.0.0.1", 0), router.Route); self.rt.daemon_threads = True
        threading.Thread(target=self.rt.serve_forever, daemon=True).start()
    def tearDown(self):
        self.rt.shutdown(); self.rt.server_close(); self.deck.close()

    def req(self, extra=""):
        s = socket.create_connection(("127.0.0.1", self.rt.server_address[1]), timeout=5)
        s.sendall(f"GET /deck/api/term/x.1 HTTP/1.1\r\nHost: mac\r\nTailscale-User-Login: me@example.com\r\nConnection: keep-alive, Upgrade\r\n{extra}\r\n".encode())
        return s

    def test_upgrade_passes(self):
        s = self.req("Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n")
        buf = b""
        while b"\r\n\r\n" not in buf: buf += s.recv(4096)
        self.assertTrue(buf.startswith(b"HTTP/1.1 101 "), buf)
        h = self.got[0].lower().split("\r\n")
        self.assertIn("connection: upgrade", h); self.assertIn("upgrade: websocket", h); self.assertNotIn("connection: close", h)
        self.assertTrue(h[0].startswith("get /api/term/x.1 "))
        for msg in (b"\x82\x05hello", b"x" * 100000):  # both ways after the 101, more than one read's worth
            s.sendall(msg); got = b""
            while len(got) < len(msg): got += s.recv(65536)
            self.assertEqual(got, msg)
        s.close()

    def test_plain_still_closes(self):
        s = self.req(); out = b""
        while (b := s.recv(4096)): out += b
        self.assertTrue(out.endswith(b"ok")); s.close()
        h = self.got[0].lower().split("\r\n")
        self.assertIn("connection: close", h); self.assertNotIn("connection: keep-alive, upgrade", h)


if __name__ == "__main__":
    unittest.main()
