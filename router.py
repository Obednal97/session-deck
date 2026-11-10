#!/usr/bin/env python3
"""Session Deck router: one shared /deck address for every account on this Mac.

tailscale serve proxies /deck here and sets Tailscale-User-Login itself (dropping any copy the client sent). The router
looks that login up in DECK_ROUTES and pipes the connection, bytes untouched, to that person's own deck, which runs as
their macOS account and checks the login again. Bodies are never buffered, so 1 GB uploads and long replies stream.

  DECK_ROUTER_LISTEN  Unix socket path (live: only root, i.e. tailscaled, can reach it) or a TCP port on 127.0.0.1 (tests)
  DECK_ROUTES         login=/path/to/deck.sock,login2=8831,...  (a socket path or a 127.0.0.1 port)
  DECK_ROUTER_STRIP   path prefix removed if tailscale serve passes it on (default /deck; empty turns it off)
"""
import html, os, socket, socketserver, sys, threading

LISTEN = os.environ.get("DECK_ROUTER_LISTEN", "")
ROUTES = {}
for r in filter(None, os.environ.get("DECK_ROUTES", "").replace(" ", "").split(",")):
    k, _, v = r.partition("=")
    if k and v: ROUTES[k.lower()] = v
STRIP = os.environ.get("DECK_ROUTER_STRIP", "/deck")  # the decks serve from /; strip the shared prefix if serve kept it
IDLE = 300  # seconds without a byte either way before a connection is dropped

PAGE = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Session Deck</title>
<style>body{font:16px/1.5 -apple-system,system-ui,sans-serif;margin:0;padding:48px 20px;background:#0e1118;color:#e6e8ee}
main{max-width:420px;margin:auto}h1{font-size:20px;margin:0 0 8px}p{color:#9aa3b2;margin:0 0 12px}code{color:#e6e8ee}
@media (prefers-color-scheme:light){body{background:#f6f7f9;color:#14171f}p{color:#5b6372}code{color:#14171f}}</style>
<main><h1>{title}</h1><p>{body}</p></main>"""

def page(code, title, body):
    b = PAGE.replace("{title}", title).replace("{body}", body).encode()
    return (f"HTTP/1.1 {code} {'Forbidden' if code == 403 else 'Bad Gateway'}\r\nContent-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(b)}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n").encode() + b

def pipe(src, dst, done=False):
    """Copies src to dst until src ends; then only half-closes dst, unless done (the deck's reply is over: end both)."""
    try:
        while True:
            b = src.recv(1 << 16)
            if not b: break
            dst.sendall(b)
    except OSError: pass
    for s, how in ((dst, socket.SHUT_RDWR if done else socket.SHUT_WR),) + (((src, socket.SHUT_RDWR),) if done else ()):
        try: s.shutdown(how)
        except OSError: pass

class Route(socketserver.BaseRequestHandler):
    def handle(self):
        c = self.request; c.settimeout(IDLE); buf = b""
        try:
            while b"\r\n\r\n" not in buf:
                b = c.recv(1 << 16)
                if not b or len(buf) > 65536: return
                buf += b
        except OSError: return
        head, _, rest = buf.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        logins = [l.split(":", 1)[1].strip().lower() for l in lines[1:] if l.lower().startswith("tailscale-user-login:")]
        to = ROUTES.get(logins[0]) if len(logins) == 1 else None
        if not to:
            who = html.escape(logins[0]) if len(logins) == 1 else "this device"
            return c.sendall(page(403, "Not set up for you", f"Session Deck on this Mac isn't set up for <code>{who}</code>. "
                                  "Ask the Mac's owner to add your Tailscale login."))
        # One request per connection: the decks speak HTTP/1.0 and close after each reply, and so does the router.
        rl = lines[0].split(" ")
        if len(rl) == 3 and STRIP and (rl[1] == STRIP or rl[1].startswith(STRIP + "/") or rl[1].startswith(STRIP + "?")):
            lines[0] = " ".join((rl[0], rl[1][len(STRIP):] if rl[1][len(STRIP):][:1] == "/" else "/" + rl[1][len(STRIP):], rl[2]))
        keep = [l for l in lines if l.split(":", 1)[0].strip().lower() not in ("connection", "keep-alive", "proxy-connection")]
        try:
            u = socket.socket(socket.AF_UNIX) if to.startswith("/") else socket.socket()
            u.settimeout(IDLE); u.connect(to if to.startswith("/") else ("127.0.0.1", int(to)))
        except (OSError, ValueError):
            return c.sendall(page(502, "Your deck isn't running", "It usually comes back within a minute. Try again shortly."))
        u.sendall("\r\n".join(keep + ["Connection: close"]).encode("latin-1") + b"\r\n\r\n" + rest)
        t = threading.Thread(target=pipe, args=(c, u), daemon=True); t.start()
        pipe(u, c, True); t.join(IDLE); u.close()

if __name__ == "__main__":
    if not LISTEN or not ROUTES: sys.exit("set DECK_ROUTER_LISTEN and DECK_ROUTES")
    if LISTEN.startswith("/"):
        try: os.unlink(LISTEN)
        except FileNotFoundError: pass
        os.umask(0o077)  # the socket is 0600: tailscaled (root) can still connect, local accounts can't
        srv = socketserver.ThreadingUnixStreamServer(LISTEN, Route)
    else:
        socketserver.ThreadingTCPServer.allow_reuse_address = True
        srv = socketserver.ThreadingTCPServer(("127.0.0.1", int(LISTEN)), Route)
    srv.daemon_threads = True
    print(f"Session Deck router on {LISTEN} for {len(ROUTES)} login(s)", flush=True)
    srv.serve_forever()
