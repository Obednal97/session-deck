# Sign-in card: Claude's /login from the chat page

## Why

When Claude in a deck chat shows its sign-in screen (`/login`, or a signed-out Claude), the chat page shows nothing:
it draws the transcript, and the sign-in screen exists only in the terminal. In the Terminal view the link is
hard-wrapped over a dozen lines, so it can't be tapped or copied cleanly on a phone, and the Paste key needs clipboard
permission that iOS often refuses. The owner hit this signing Claude in on a server over SSH.

## Goal

The chat page handles the sign-in itself:
- a button opens the sign-in page;
- a box takes the code, and the deck types it into Claude's sign-in screen and presses Enter.

This works the same for chats on this Mac and over SSH.

## Non-goals

- Claude's first-run onboarding (the theme picker): deck chats start from an existing setup.
- Plain SSH terminals that aren't matched to a Claude chat. They have no chat page, and the Terminal view still works.
- Push notifications for a sign-in screen.

## Approaches

1. **Chosen: the server reads the sign-in screen from the pane, as it already does for questions, and the page draws a
   card.** This uses the same `pane_screen` path as the question cards, so local and remote chats both get it for free.
2. **Make the Terminal view link wrapped URLs and improve Paste.** The terminal is still the place to do it, xterm
   can't know where a hard-wrapped URL ends, and the clipboard problem remains. Rejected.
3. **Switch the chat to the Terminal view automatically.** This has the same problems as 2. Rejected.

## Design

**Screens, as captured from Claude Code 2.1.327:**
- **Method:** "Select login method:" over a numbered list starting with ❯. It has no key hints and no "?" line, so
  `parse_menu` misses it today. It becomes an ordinary question card.
- **Code:** "Paste code here if prompted" with an input box under it, and the URL (`https://…/oauth/authorize?…`)
  above, hard-wrapped at the pane width. From `/login` in a chat it sits under a "Login" heading and ends "Esc to
  cancel". From a signed-out start it ends "Esc to go back". After the user presses `c`, an "(Sent via OSC 52 …)"
  line appears above the URL.
- **Error:** "OAuth error: …" (wrapped), then "Press Enter to retry."
- **Done:** "Login successful" and "Press Enter to continue". This one was not captured; it is matched loosely.

**Server:**
- `login_screen` turns the screen into `None` or `{"step": "code"|"error"|"done", "url", "text"}`.
- The URL is the last `https://` line block before "Paste code here", with its lines joined.
- The URL is offered only if its host is claude.com, claude.ai or anthropic.com, or a subdomain of one. Screen text
  can come from a remote server or from Claude's own output, so a lookalike screen must not be able to put an
  arbitrary link behind the button.
- `pane_screen` gains `login`. While it is set, `menu` is None and `working` is False.
- `POST /api/login {pane, code}` checks the step is still "code" and that the code is 1 to 500 printable characters
  with no whitespace. It pastes the code (bracketed) and presses Enter. Like the other typing routes, it is refused
  for a dropped remote chat.
- `/api/send` is refused (409) while the sign-in screen is up.
- The "Try again" and "Continue" buttons use the existing `/api/key` Enter.

**Page:**
- A `#login` card sits beside the question card.
  - **Code step:** the heading "Claude needs you to sign in", an **Open sign-in page** link (a new tab), the line
    "Sign in, copy the code it shows, then paste it here.", a code field (no autocorrect or capitals) and a
    **Sign in** button.
  - **Error step:** Claude's error text and **Try again**.
  - **Done step:** "Signed in." and **Continue**.
- The status line is hidden while the card shows, as it is for a question.
- Sending from the message box while the card shows toasts "Use the sign-in card above."

## Left to the builder

Styling, which follows the question card. The exact wording of toasts and errors goes beyond the copy above.
