# SSH in Session Deck

Status: approved by the owner, 2026-11-18.

## Why

The owner wants Termius inside Session Deck, and better. He wants to save connections to any server (his home server, other
servers, clients' machines), or open a throwaway one, from his phone or desktop. "Better" means one thing above all: when he
runs Claude Code on a server over SSH, that chat gets the full deck experience he has with chats on the Mac (transcript,
questions, permission prompts, diffs, subagents, notifications), not just a terminal.

## Goals

1. **Hosts.** A list of saved SSH hosts (name, address, port, username, how to sign in), plus quick one-off connections
   that are never saved.
2. **Sign-in by password or key**, chosen per host. A password can be kept on the device that typed it. A key-based host
   uses the Mac's SSH key, and the deck can put that key on the server using the password once.
3. **A real terminal.** Typing, arrows, Tab completion, Ctrl keys, colours, `vim` and `htop` all work, on a phone and on a
   desktop, with an extra key row on the phone for keys iOS lacks.
4. **Connections that survive the phone.** Every connection runs in tmux on the Mac, so locking the phone, losing signal or
   switching device leaves it running; reopening picks up where it was.
5. **Claude Code over SSH as deck chats.** A Claude chat on a server reads, replies, answers questions and approvals,
   shows diffs and subagents, takes uploaded screenshots and notifies, as a chat on the Mac does.
6. **Its own section.** Everything SSH lives in an SSH section of the menu. SSH terminals and remote Claude chats never
   appear in Active, Pinned (unless pinned), History or Projects.

## Non-goals (for now)

- An SFTP file browser (browsing folders, renaming, deleting), port forwarding, snippets, host groups or tags. Moving
  single files is covered (see Files).
- Importing keys made elsewhere, or a key per host. The Mac's one key serves every key-based host.
- Running the deck on the servers themselves (approach 2 below).
- Listing every `~/.ssh/config` entry automatically.
- Background-process control (the "stop this shell" sheet) for remote chats.

## Anti-goals (a failure even if it works)

- A password written to disk on the Mac, put on a command line, in a log, or in a push notification.
- Host keys accepted silently. Connecting to a changed host key must stop and say so.
- Remote chats mixed into the local Active list or History, or local chats in the SSH section.
- Anything installed on the server. It needs a normal shell and, for goal 5, Claude Code.
- A worse terminal for local Claude chats than today's.

## Constraints

- The Mac is the SSH client. A web page can't open SSH connections, so each connection is `ssh` running in tmux on the Mac,
  and a server must be reachable from the Mac (directly, over Tailscale, or through a `ProxyJump` in `~/.ssh/config`).
- The deck's shape stays: one `server.py`, one `index.html`, no build step, vendored libraries in `vendor/`, the stdlib
  `ThreadingHTTPServer`. One new vendored library is expected (xterm.js, MIT).
- It works through `tailscale serve` and through `router.py` (several people), which pipes raw bytes both ways.
- Several people: each person's deck runs as their own macOS account, so SSH runs as them with their own `~/.ssh`. The
  host list is per account, like pins.
- The owner's existing `~/.ssh/config` entries (for example `nas-jump`, `media` with `ProxyJump`) must keep working; `ssh`
  reads that file as normal.
- Same security as the rest of the deck: every SSH endpoint needs the signed-in Face ID session (or the local token).

## Approaches considered

For goal 5, the transcript and other files live on the server, not the Mac:

1. **Over the same SSH connection (chosen).** Each host's connection is shared (SSH `ControlMaster`). Claude's screen is
   already visible in the Mac's tmux pane, so questions, approvals, status and typing work unchanged. The deck fetches the
   transcript, the `~/.claude/sessions/*.json` files, git changes and file lists, and copies uploads, over the shared
   connection. Nothing is installed on the server. Cost: the deck's file reads get a local and a remote path.
2. **Session Deck on each server**, the Mac's deck passing requests through. Full parity, but every server needs Python
   and tmux kept up to date, and the deck is macOS-only today while most servers run Linux. Rejected.
3. **Screen only.** Least work, but no history, diffs or subagents. Not the experience asked for. Rejected.

The owner chose 1, with "start a chat on a server" in the new-chat sheet.

## Decided by the owner

- Password or key per host; with a key, an option to install it on the server.
- Any number of hosts, not just the home server; throwaway connections too.
- Passwords stored on the phone (the device), not the Mac.
- Approach 1, and starting remote Claude chats from the new-chat sheet.
- Remote Claude survives a dropped link: run inside the server's tmux when it has one, else Disconnected plus Resume.
- Permission mode is a per-host default; new hosts start on asking, not bypass.
- SSH sessions and remote Claude chats show in the SSH section only.

## Design

### The SSH section

A collapsible section in the chat list (collapsed state per device), placed after Aiva's and before Pinned. Its header has
a + button. Inside:

```
SSH                                          +
  ● Home server        2 open · Claude busy        <- a host with live connections
      >_ Terminal            3m
      ✦  Fix backups (Claude)  needs you
  ○ Client VPS         root@203.0.113.5
  ○ NAS                nas-jump (~/.ssh/config)
```

- A host row taps open its page (like a project page): live terminals, live Claude chats, past Claude chats on that host
  (resume or fork), and actions: New terminal, New Claude chat, Edit, Install key, Forget saved password, Delete.
- The + opens a sheet: address field (`user@host[:port]` or a `~/.ssh/config` alias), sign-in (password or key), the
  default permission mode for Claude chats on it, and Save. My call: `~/.ssh/config` entries are not listed
  automatically; the address field suggests their `Host` names (plain names only, no wildcards or `Match` blocks, not
  following `Include`), and one becomes a host only once saved. Connect without saving is a throwaway connection: it appears in the section while open and is gone when closed.
- Opening a host whose sign-in needs a password the device doesn't have asks for it, with "Remember on this device".
- The section's count and attention marker follow the local ones (a remote Claude chat that needs you shows like a local
  one does).

### Hosts and where things are kept

- Host list: `ssh-hosts.json` next to `prefs.json` (0600), so every device sees the same list. Each host: id, name,
  address, port, user, auth (`password` | `key` | `config` for a `~/.ssh/config` alias, which uses whatever that entry
  says), and the default permission mode for Claude chats there (the owner's decision: per host, new hosts start on
  "default (asks before acting)", never bypass unless set; the new-chat sheet can still change it per chat).
- Passwords: on the device only. My call: stored in `localStorage` encrypted (AES-GCM, WebCrypto) with a key the Mac holds
  per signed-in device and gives only to a signed-in session, so a copy of the phone's storage alone is useless and
  removing the device's passkey kills it. The password goes to the Mac only inside a connect request and is used once.
- Key: the Mac's `~/.ssh/id_ed25519` (created if missing). "Install key" appends its public key to the server's
  `~/.ssh/authorized_keys` (as `ssh-copy-id` does) using the password once, then switches the host to key sign-in.
- Host keys: first connection shows the fingerprint to accept, then it goes in `~/.ssh/known_hosts`. A changed key
  refuses to connect and says why; the user can remove the old key from the host's page.

### Connections

- A connection is `ssh` in its own tmux session (my call: one session per connection, named `ssh-<host>-<n>`, so a
  viewer can attach to exactly it without moving anyone else's view) on the deck's usual tmux server. The deck marks
  these sessions (a tmux user option) so they are listed from tmux, never from process scanning.
- Each host has one shared master connection (`ControlMaster=auto`, `ControlPath` in a 0700 folder, `ControlPersist`
  ~10 minutes). Terminals and the deck's own reads reuse it, so a password is asked once per master, not per read.
- Passwords reach `ssh` through `SSH_ASKPASS` with `SSH_ASKPASS_REQUIRE=force`, the helper reading the password from a
  pipe the deck holds, never from a file, argument or environment visible to `ps`.
- Ending a terminal closes its tmux session. Idle terminals are never ended automatically (unlike the 3-day rule for
  chats); the master closes itself once nothing uses it.
- **When the Mac's link to a server drops** (reboot, sshd restart, network blip), every terminal and chat on that host
  loses its connection at once. Terminals show as disconnected with Reconnect (a password host asks the device for the
  password again). Claude chats are covered below so a drop doesn't stop the work.

### The terminal

- xterm.js on the page, fed live over a WebSocket (the router already pipes raw bytes). On the Mac each viewer gets a
  pty running `tmux attach` to that connection's session, sized to the viewer's screen; keystrokes go back the same way.
- Phone extras: a key row with Esc, Tab, Ctrl and Alt (sticky, one press), arrows, and `| ~ / -`; paste; pinch or a
  setting for font size.
- The local chats' Terminal view switches to the same live terminal (my call: it is the same component, and today's
  snapshot view is the weaker one). The chat view and its key bar stay as they are.

### Files (the owner's decision)

Both go over the host's shared connection (`scp`), and both work in stage 1:

- **Attach** in an SSH terminal (the paperclip, as in chats): the file is copied to an uploads folder on the server
  (my call: `~/.cache/session-deck/uploads/`, created if missing, old files tidied as on the Mac) and its server path is
  typed at the prompt, not run.
- **Get file:** type or paste a path on the server; the file opens or saves on the device in use, with the deck's
  existing size limit.

Claude chats on a server use the same two paths: uploads become a server path given to Claude, and files Claude names
in a reply can be opened or saved.

### Claude over SSH

- **Starting one:** the new-chat sheet gets a "Where" choice: This Mac (today) or a saved host. For a host, the folder
  picker lists folders on that server over the master. The deck runs
  Claude in a new connection session with `--session-id <uuid>`, so it knows the transcript's id from the start.
- **Surviving drops (the owner's decision):** if the server has tmux, the deck starts Claude inside a tmux session on the
  server (`deck-<uuid>`, status bar off so the Mac's pane shows only Claude's screen), and the Mac's connection is
  `ssh -t <host> tmux attach -t deck-<uuid>`. A dropped link leaves Claude working; the deck reattaches when the host is
  reachable again (at once for key hosts; for password hosts, when a device that has the password opens the deck).
  Notifications for that chat pause while detached and say so on the chat. Without tmux on the server, the chat runs
  under plain `ssh -t` and a drop shows Disconnected with Resume (`claude --resume <uuid>`). The host page says which
  kind the server is. The deck still installs nothing; it only uses tmux when it's already there.
- **Permission mode:** the host's default (above), changeable per chat. Engines, permission mode, model and effort as today; `rclaude` and `claude-local` only
  if found on the server.
- **Claude typed by hand** in an SSH terminal: the deck spots Claude Code's screen in a terminal pane, then matches the
  pane to the newest `~/.claude/sessions/*.json` on that host whose cwd and start time fit (as the local fallback does
  today). Once matched, that terminal shows as a Claude chat in the host's group.
- **What works:** transcript (fetched incrementally over the master: only new bytes since the last read), questions,
  approvals and typing (from the Mac's pane, unchanged), status, tool calls and diffs, subagents, rename, end chat,
  notifications, git changes (git run on the server), `@` file suggestions, uploads (copied to a folder on the server,
  then the server path is given to Claude), files Claude names in replies (fetched on demand to open or save).
- **History:** past Claude chats on a host are listed on that host's page, from that server's `~/.claude/projects`,
  and can be resumed or forked into a new connection.

### Order of work

1. **SSH:** hosts, password and key sign-in, host keys, throwaway connections, the SSH section, the live terminal
   (including the local chats' Terminal view), Attach and Get file in terminals.
2. **Claude over SSH:** remote chats in the SSH section, starting from the new-chat sheet, the remote transcript and
   the rest of the list above, remote history.

Each stage ships on its own.

## Left to the builder

- WebSocket handling inside `ThreadingHTTPServer` (hand-written upgrade and framing is expected; no new dependency).
- How the local and remote file reads are split in `server.py` (one small interface the transcript, git, file and upload
  code all go through is the expected shape).
- Exact cache and refresh intervals for remote reads, within "a remote chat feels as live as a local one".
- How a lost or slow master shows in the UI.
- The xterm.js version (pinned, vendored) and which of its addons are needed.
- Tests: unit tests in `tests/` for the host store, address parsing, the askpass path and the remote transcript reader
  (against a fake `ssh`); a manual run against a real server for each stage.
