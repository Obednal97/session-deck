# Sign-in Card Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** the chat page handles Claude's sign-in screen with an Open sign-in page button and a code box.

**Architecture:**
- The server parses the sign-in screen in `pane_screen`, the same place question menus are parsed.
- A new `/api/login` route types the code into the pane.
- `index.html` draws a `#login` card from the `/api/status` poll.

**Tech Stack:** stdlib Python `server.py`, a single `index.html`, unittest with a `decktest` tmux socket.

**Spec:** `docs/superpowers/specs/2026-11-18-login-card-design.md`

## Global Constraints

- **Allowed URL hosts:** the button's URL host must be `claude.com`, `claude.ai` or `anthropic.com`, or a subdomain
  of one, over https.
- **The code:** 1 to 500 characters, all in `[\x21-\x7e]`. It is pasted with tmux `paste-buffer -p`, then Enter.
- **Tests:** they never touch the real tmux servers (`ssh`, `default`) or real ssh. Use the `decktest` socket and
  the existing pins.
- **Copy:** British English, no em dashes.

## Review Focus

- **The URL is partly off the top of the screen.** The URL must not be cut short. Read the scrollback, and give no
  URL (rather than a short one) if its start can't be found.
- **A transcript that quotes a sign-in screen or a lookalike URL.** No card, or no button, for a host that isn't
  allowed.
- **The screen moved on between the poll and the tap.** `/api/login` refuses with 409 and types nothing.
- **A code pasted with a trailing newline or spaces.** Trim it, then type it.
- **A dropped remote chat.** `/api/login` is refused, as `/api/send` is.

---

### Task 1: Server: parse the sign-in screen and type the code

**Files:**
- Modify: `server.py` (`parse_menu` fallback, new `login_screen` beside it, `pane_screen`, the POST routes)
- Test: `tests/test_remote.py`

**Interfaces:**
- **Produces:** `login_screen(plain: str) -> dict | None`, returning `{"step": "code"|"error"|"done", "url": str |
  None, "text": str}`.
  - `pane_screen(key)["login"]`.
  - `POST /api/login {"pane", "code"}`: `{"ok": True}` on success, or 409 with `{"error"}`.

- [ ] **Step 1: Write the failing tests**
  - **Unit tests on captured screens:**
    - the code screen from a chat's `/login` (Login heading, OSC 52 line, Esc to cancel);
    - the signed-out code screen (Esc to go back);
    - the error screen;
    - the done screen;
    - a lookalike screen with `https://evil.example/oauth/authorize?...`, which gives `url` None;
    - a screen with no sign-in text, which gives None;
    - the method screen through `parse_menu`, which gives the options "Claude account with subscription …" and
      "Anthropic Console account …".
  - **API test:**
    - a remote-chat pane running a script that prints the code screen and `read`s a line;
    - `/api/status` has the joined `login.url`;
    - `/api/send` gives 409;
    - `/api/login` with `" abc#def \n"` gives 200, and the pane shows `GOT:abc#def`;
    - `/api/login` with `"a b"` gives 400;
    - `/api/login` once the screen has moved on gives 409.

- [ ] **Step 2: Run** `python3 -m unittest tests.test_remote -k login -k Login` and check the tests fail.

- [ ] **Step 3: Implement**
  - **`login_screen`:** from the last "Paste code here" line, walk up to the last line starting
    `https://`, then join the non-blank lines from there to just above "Paste code here", stopping at the first line
    that starts with a space. Check the host. If the screen shows "Paste code here", use the last 60 lines of
    scrollback.
  - **`parse_menu`:** in the "?" fallback, also accept a line that is exactly `Select login method:`.

- [ ] **Step 4: Run the whole suite**, `python3 -m unittest discover -s tests`. All pass.

- [ ] **Step 5: Commit.**

### Task 2: Page: the sign-in card

**Files:** Modify `index.html` (the `#login` element by `#menu`, its CSS, the `poll`, `send` and click handler).

**Interfaces:**
- **Consumes:** `s.login` from `/api/status`, `POST /api/login`, `POST /api/key {key: "Enter"}`.

- [ ] **Step 1: Implement** the card as in the spec. The link is `<a target=_blank rel=noopener>` with an escaped href.
- [ ] **Step 2: Verify in a browser** against a dev deck on its own port and the `decktest` socket, with a pane
  printing the code screen. Check all three steps and the 409 toast at phone width.
- [ ] **Step 3: Commit**, then do the final review, land and deploy.
