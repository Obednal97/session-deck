# Session Deck as an optional mac-ai-server component

How the multi-account deck (this folder) would move into `Obednal97/mac-ai-server`. Nothing has been pushed; this is a plan.

## What the repo does today (checked 2026-11-10)

- Modules are `modules/NN-name.sh`, sourced one at a time by `install.sh`. Each defines `mod_applies`, `mod_run` and `mod_check`. Opt-in is an env flag tested in `mod_applies` (for example `MAS_MULTIUSER=yes` in `85-multiuser.sh`).
- Config is loaded in this order: `config/defaults.env`, then `~/.mac-ai-server/config.env`, then any `MAS_*` already in the environment. Keys are `MAS_UPPER_SNAKE`, with yes/no values.
- Daemon code lives in `/usr/local/libexec/ai-<name>/`, run by `/usr/bin/python3 -I` (see `netsetup/netsetupd.py`). Shared commands go in `/usr/local/bin`.
- The per-person LaunchDaemon precedent is `mac-ai-server users syncthing <name>`: `/Library/LaunchDaemons/local.syncthing.<name>.plist` with `UserName`, `HOME` and `PATH`, and a web UI on a Unix socket in the person's 0700 home.
- tmux: the owner's `main` (default socket) comes from `local.ai-tmux`, and SSH logins land in `tmux -L ssh` session `work` (`lib/user-kit.sh`). That matches this deck's default `DECK_TMUX_SOCKET=ssh,default`.
- `claude-local` is installed to `/usr/local/bin` when multi-user is on. It sets `ANTHROPIC_BASE_URL=http://localhost:11434`, which is how the deck tells a local chat apart.
- Nothing in the repo uses `tailscale serve`, so the deck would be its first HTTPS endpoint.
- CI runs shellcheck at warning level, the `tests/test_*.sh` suite (with fakes for `sudo`, `launchctl`, `dscl`, `tmux` and `tailscale`), Python unittest under `/usr/bin/python3`, and a privacy scan that rejects real email addresses, tailnet IPs and names on a private blocklist.

## What would move where

| Here | In mac-ai-server |
|---|---|
| `server.py`, `router.py`, `index.html`, `sw.js`, `manifest.webmanifest`, `icons/`, `vendor/` | `deck/`, installed to `/usr/local/libexec/ai-deck/` (root-owned) |
| `install-multiuser.sh` steps 1 to 5 | `modules/75-deck.sh`: `mod_applies` checks `MAS_DECK=yes`, `mod_run` does the copy, the socket folders, the router and the owner's deck, and `mod_check` checks that each service is loaded and each socket answers |
| per-person deck (the LaunchDaemon part of step 4) | `mac-ai-server users deck <name> [--remove]`, built like `users syncthing`, and called from `users add` when `MAS_DECK=yes` |
| `install-multiuser.sh --code` | `mac-ai-server users deck <name> --code [hours]` |
| `--uninstall` | `--remove` on the subcommand, plus entries in `handover/prepare-handover.sh`, which lists shared paths and daemons by hand |
| `multiuser.conf` | not needed: the account list comes from the repo's own `people` helper, and the Tailscale login is a new per-person setting (below) |
| test run (two decks, router, Playwright) | `tests/test_mod_deck.sh` (plist contents and commands, using the fakes) and `tests/test_deck.py` (router routing and 403, single-file secrets, engine list, with no network or tmux) |

## Config keys

The server reads plain env vars, so the module only writes them into each plist.

| server.py / router.py | mac-ai-server | Notes |
|---|---|---|
| (on or off) | `MAS_DECK=no` | new, opt-in |
| `DECK_HOST` (installer), `DECK_RP_ID`, `DECK_ORIGIN`, `DECK_HOSTS` | from `tailscale status --json` `.Self.DNSName` | today these default to the owner's tailnet name; the repo must derive them, not hard-code them |
| `DECK_TS_USER` | new per-person value, e.g. `~/.mac-ai-server/users/<name>/deck-login` | the Tailscale login that may use this deck |
| `DECK_ENGINES` | `MAS_DECK_ENGINES=claude,local` | `rotate` (rclaude) is the owner's private tool and would not ship |
| `DECK_TMUX_SOCKET` / `DECK_TMUX_SESSION` | fixed `ssh,default` / `work` | matches `user-kit.sh`; a key is only needed if someone asks |
| `CLAUDE_CONFIG_DIR` | default `~/.claude` | |
| `DECK_SECRETS` | `~/.mac-ai-server/deck/` (0700) | matches the repo's private-state folder; the file is `session-deck.json` |
| `DECK_SOCKET` | `/usr/local/var/ai-deck/<name>/deck.sock` | |
| `DECK_PORT` / `DECK_TS_PORT` | `0` / `0` | socket only; the owner may keep a local token port |
| `DECK_ROUTER_LISTEN` / `DECK_ROUTES` | written by the module from the people list | |
| labels `local.session-deck.*` | `local.ai-deck.<name>`, `local.ai-deck-router` | repo label style |
| service account `_sessiondeck` | `_aideck` | |

## Changes needed to fit the repo's rules

- **Owner-specific defaults.** Done: the passkey domain comes from `tailscale status`, the config folder is `CLAUDE_CONFIG_DIR` or `~/.claude`, and the lock screen no longer names a host.
- **Python.** The repo runs system `/usr/bin/python3 -I` and installs no pip packages. The deck needs `cryptography` for passkeys (P-256 and RSA verification) and Web Push (ECDH, AES-GCM). Options:
  1. Use Homebrew Python plus `brew install python-cryptography`, as this Mac does now.
  2. Make push optional and verify only ES256 passkeys in pure Python. The verification is about 40 lines of P-256 maths; it would be slow but fine for one sign-in.
  3. Vendor a wheel.

  I recommend option 1, with `mod_check` failing clearly when it is missing.
- **Bash 3.2.** `install-multiuser.sh` already avoids arrays and `mapfile` and passes shellcheck at warning level.
- **Tests.** Every new path has to be wrapped in `${MAS_SYSROOT:-}` (the installer here uses `DECK_SYSROOT` the same way).

## Open questions

1. **Does `tailscale serve --set-path=/deck unix:/path` strip `/deck`** as it does for `http://` targets? Its help documents `unix:` targets, but I couldn't try it without changing the live serve config. The router strips a leftover `/deck` itself (`DECK_ROUTER_STRIP`), so it works either way.
2. **Should the repo install the router at all for a single-person Mac?** With one person, the module could point serve straight at that person's deck socket, and the router would only be added once there is a second person.
3. **Where does each person's Tailscale login come from?** It could be asked for in `users add`, or read once from `tailscale whois` the first time they connect (unknown logins currently get a 403, so whoever sets them up would have to approve).
4. **Keychain access for daemons.** A deck started as a LaunchDaemon can't unlock the person's login keychain. It only reads files and drives tmux, so that's fine; chats it starts run inside the person's existing tmux server. If it has to start a tmux server, that server inherits the daemon's context, and `claude` in it then needs `CLAUDE_CODE_OAUTH_TOKEN` (the repo's documented SSH workaround in `docs/multi-user.md`).
5. **Is WireGuard in scope?** WireGuard users have no Tailscale login, so the deck can't be offered to them as it stands.
