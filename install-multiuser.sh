#!/bin/bash
# Session Deck for several accounts: one deck per macOS account, running as that account, behind one router at /deck.
#
#   sudo ./install-multiuser.sh [--conf FILE]       install or update: copy the code, (re)write the services, restart them all
#        ./install-multiuser.sh --dry-run          show what would change; needs no sudo and changes nothing
#   sudo ./install-multiuser.sh --uninstall [--dry-run]
#   sudo ./install-multiuser.sh --code ACCOUNT [HOURS]   one-time Face ID setup code for that account (default 24 h)
#
# Layout (all root-owned unless said):
#   /usr/local/libexec/session-deck/          the code; no account can change code that runs as another
#   /usr/local/var/session-deck/router/       _sessiondeck only (0700): router.sock, which only root (tailscaled) can reach
#   /usr/local/var/session-deck/<account>/    <account>:_sessiondeck 0710: deck.sock (0660), reachable by that account and the router
#   /Library/LaunchDaemons/local.session-deck-router.plist      the router, as the hidden _sessiondeck account
#   /Library/LaunchDaemons/local.session-deck.<account>.plist   a deck, as that account (launch=agent: their LaunchAgent)
# Each account's own data stays in its home: secrets in one file (DECK_SECRETS/session-deck.json), passkeys and push
# subscriptions in ~/Library/Application Support/session-deck, uploads in ~/Library/Caches/session-deck.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
R="${DECK_SYSROOT:-}"   # tests only: install under a scratch root
CODE="$R/usr/local/libexec/session-deck" RUN="$R/usr/local/var/session-deck" LD="$R/Library/LaunchDaemons"
PY="${DECK_PYTHON:-/opt/homebrew/bin/python3}" SVC=_sessiondeck
FILES="server.py router.py index.html sw.js manifest.webmanifest icons vendor"
CONF="$HERE/multiuser.conf" DRY=0 MODE=install HOURS=24
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --conf) CONF="$2"; shift ;;
    --uninstall) MODE=uninstall ;;
    --code) MODE=code; WHO="${2:-}"; shift; case "${2:-}" in [0-9]*) HOURS="$2"; shift ;; esac ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac; shift
done
die() { echo "error: $*" >&2; exit 1; }
say() { echo "$*"; }
run() { if [ $DRY = 1 ]; then echo "  would run: $*"; else "$@" || die "failed: $*"; fi; }
try() { if [ $DRY = 1 ]; then echo "  would run: $*"; else "$@" >/dev/null 2>&1; fi; return 0; }  # may fail: e.g. stopping what isn't running
[ $DRY = 1 ] || [ "$(id -u)" = 0 ] || die "run it with sudo (or --dry-run to look first)"
[ -x "$PY" ] || die "$PY is missing"
"$PY" -I -c "import cryptography" 2>/dev/null || die "$PY can't import cryptography (brew install python-cryptography?)"

# ---- the config: global KEY=value lines, then "<account> <login> [KEY=value ...]" lines
GLOBAL="" USERS=""
while read -r a b rest; do
  case "$a" in ""|\#*) continue ;; *=*) GLOBAL="$GLOBAL $a"; continue ;; esac
  [ -n "$b" ] || die "$CONF: '$a' has no Tailscale login"
  id -u "$a" >/dev/null 2>&1 || die "$CONF: there's no account called $a"
  case "$a$b$rest" in *[\<\>\&\"\']*) die "$CONF: the line for $a has a character that isn't allowed (<>&\"')" ;; esac
  echo "$USERS" | awk -v l="$b" 'tolower($2)==tolower(l){f=1}END{exit !f}' && die "$CONF: $b is listed twice"
  USERS="$USERS$a $b $rest
"
done < "$CONF"
[ -n "$USERS" ] || die "$CONF lists no accounts"
HOST="$(printf '%s\n' $GLOBAL | sed -n 's/^DECK_HOST=//p' | tail -1)"
[ -n "$HOST" ] || die "$CONF needs DECK_HOST=<this Mac's Tailscale HTTPS name>"

home_of() { dscl . -read "/Users/$1" NFSHomeDirectory 2>/dev/null | awk '{print $2}'; }
launch_of() { echo "$USERS" | awk -v u="$1" '$1==u{for(i=3;i<=NF;i++) if($i=="launch=agent") print "agent"}'; }
# env_of <account>: the deck's environment, one KEY=value per line; settings from the config win (later lines override)
env_of() {
  local u="$1" h line login kv
  h="$(home_of "$u")"; line="$(echo "$USERS" | awk -v u="$u" '$1==u')"; login="$(echo "$line" | awk '{print $2}')"
  printf '%s\n' "HOME=$h" "USER=$u" "LOGNAME=$u" "LANG=en_US.UTF-8" \
    "PATH=$h/.local/bin:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
    "CLAUDE_CONFIG_DIR=$h/.claude" "DECK_SECRETS=$h/.config/session-deck" "DECK_ENGINES=rotate,claude,local" \
    "DECK_TMUX_SOCKET=ssh,default" "DECK_TMUX_SESSION=work" "DECK_PORT=0" "DECK_SOCKET=$RUN/$u/deck.sock" \
    "DECK_HOSTS=$HOST,${HOST%%.*}" "DECK_RP_ID=$HOST" "DECK_ORIGIN=https://$HOST" "DECK_TS_USER=$login"
  for kv in $(echo "$line" | cut -d' ' -f3-); do
    case "$kv" in launch=*) ;; *=*) echo "${kv%%=*}=$(echo "${kv#*=}" | sed "s#^~#$h#")" ;; esac
  done
}
# merged: defaults first, then the config's settings replace a default in place
merged_env() { env_of "$1" | awk -F= '{if(!($1 in v)) o[++n]=$1; v[$1]=$0} END{for(i=1;i<=n;i++) print v[o[i]]}'; }
plist_env() { merged_env "$1" | while IFS= read -r kv; do printf '    <key>%s</key><string>%s</string>\n' "${kv%%=*}" "${kv#*=}"; done; }
plist() {  # plist <label> <user> <program> <log> <env-lines> [daemon [group]]
  local who=""
  [ -n "${6:-}" ] && who="
  <key>UserName</key><string>$2</string>"
  [ -n "${7:-}" ] && who="$who
  <key>GroupName</key><string>$7</string>"
  cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$1</string>$who
  <key>ProgramArguments</key>
  <array><string>$PY</string><string>-I</string><string>$3</string></array>
  <key>WorkingDirectory</key><string>$CODE</string>
  <key>EnvironmentVariables</key>
  <dict>
$5
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>AbandonProcessGroup</key><true/>
  <key>StandardOutPath</key><string>$4</string>
  <key>StandardErrorPath</key><string>$4</string>
</dict>
</plist>
EOF
}
# put <path> <owner:group> <mode>: writes stdin there if it differs; dry run shows what would change
put() {
  local tmp; tmp="$(mktemp)"; cat > "$tmp"
  if [ -f "$1" ] && cmp -s "$tmp" "$1"; then say "  unchanged $1"
  elif [ $DRY = 1 ]; then say "  would $( [ -f "$1" ] && echo change || echo write ) $1 ($2 $3):"; sed 's/^/      | /' "$tmp"
  else install -m "$3" "$tmp" "$1" && chown "$2" "$1" || die "can't write $1"; say "  wrote $1"; fi
  rm -f "$tmp"
}
mkd() { [ -d "$1" ] && [ "$(stat -f '%Su:%Sg %Lp' "$1")" = "$2 $3" ] && return; run mkdir -p "$1"; run chown "$2" "$1"; run chmod "$3" "$1"; }
reload_daemon() { try launchctl bootout "system/$1"; [ $DRY = 1 ] || sleep 1; run launchctl bootstrap system "$2"; }

if [ $MODE = code ]; then
  [ -n "${WHO:-}" ] && echo "$USERS" | awk -v u="$WHO" '$1==u{f=1}END{exit !f}' || die "say which account: --code <account> [hours]"
  [ $DRY = 1 ] && { say "would make a setup code for $WHO"; exit 0; }
  say "Setup code for $WHO (valid $HOURS h, once; open https://$HOST/deck/ on their phone and enter it):"
  # shellcheck disable=SC2046 # one word per KEY=value: the values have no spaces
  cd / && sudo -u "$WHO" env -i $(merged_env "$WHO" | tr '\n' ' ') DECK_CODE_TTL=$((HOURS * 3600)) "$PY" -I "$CODE/server.py" --setup-code
  exit
fi

ACCOUNTS="$(echo "$USERS" | awk 'NF{print $1}')"
if [ $MODE = uninstall ]; then
  say "Removing Session Deck's multi-account services (each account's passkeys, secrets and uploads stay in their home)"
  for u in $ACCOUNTS; do
    if [ "$(launch_of "$u")" = agent ]; then
      h="$(home_of "$u")"; p="$h/Library/LaunchAgents/local.session-deck.plist"
      if [ -f "$p.pre-multiuser" ]; then
        try launchctl bootout "gui/$(id -u "$u")/local.session-deck"; run mv "$p.pre-multiuser" "$p"
        run launchctl bootstrap "gui/$(id -u "$u")" "$p"; say "  restored $u's own LaunchAgent"
      fi
    else
      [ -f "$LD/local.session-deck.$u.plist" ] && { try launchctl bootout "system/local.session-deck.$u"; run rm -f "$LD/local.session-deck.$u.plist"; }
    fi
  done
  [ -f "$LD/local.session-deck-router.plist" ] && { try launchctl bootout system/local.session-deck-router; run rm -f "$LD/local.session-deck-router.plist"; }
  run rm -rf "$CODE" "$RUN"
  dscl . -read "/Users/$SVC" >/dev/null 2>&1 && run dscl . -delete "/Users/$SVC"
  dscl . -read "/Groups/$SVC" >/dev/null 2>&1 && run dscl . -delete "/Groups/$SVC"
  say "Then point /deck back at the owner's own deck:"
  for f in --https=443 --http=80 --http=8080; do say "  tailscale serve --bg $f --set-path=/deck http://127.0.0.1:8788"; done
  exit
fi

say "== 1. Hidden account $SVC for the router"
if id -u $SVC >/dev/null 2>&1; then say "  exists (uid $(id -u $SVC))"
else
  n=450; while dscl . -search /Users UniqueID $n | grep -q . || dscl . -search /Groups PrimaryGroupID $n | grep -q .; do n=$((n + 1)); done
  run dscl . -create /Groups/$SVC PrimaryGroupID $n; run dscl . -create /Groups/$SVC RealName "Session Deck router"
  run dscl . -create /Groups/$SVC Password '*'
  for kv in "UniqueID $n" "PrimaryGroupID $n" "UserShell /usr/bin/false" "NFSHomeDirectory /var/empty" "Password *" "IsHidden 1"; do
    run dscl . -create /Users/$SVC ${kv%% *} "${kv#* }"
  done
  run dscl . -create /Users/$SVC RealName "Session Deck router"
fi

say "== 2. Code in $CODE"
stage="$(mktemp -d)"; (cd "$HERE" && cp -R $FILES "$stage/") || die "can't copy the code from $HERE"
if [ -d "$CODE" ] && diff -rq "$stage" "$CODE" >/dev/null 2>&1; then say "  unchanged"
else
  say "  $( [ -d "$CODE" ] && echo "update: $(diff -rq "$stage" "$CODE" 2>/dev/null | wc -l | tr -d ' ') file(s) differ" || echo new)"
  run mkdir -p "$(dirname "$CODE")"; run rm -rf "$CODE.new"; run cp -R "$stage" "$CODE.new"
  run chown -R root:wheel "$CODE.new"; run chmod -R u=rwX,go=rX "$CODE.new"; run rm -rf "$CODE"; run mv "$CODE.new" "$CODE"
fi
rm -rf "$stage"

say "== 3. Socket folders in $RUN"
mkd "$R/usr/local/var" root:wheel 755; mkd "$RUN" root:wheel 755; mkd "$RUN/router" "$SVC:$SVC" 700
for u in $ACCOUNTS; do mkd "$RUN/$u" "$u:$SVC" 710; done

say "== 4. Decks"
ROUTES=""
for u in $ACCOUNTS; do
  h="$(home_of "$u")"; login="$(merged_env "$u" | sed -n 's/^DECK_TS_USER=//p')"
  ROUTES="$ROUTES${ROUTES:+,}$login=$RUN/$u/deck.sock"
  if [ "$(launch_of "$u")" = agent ]; then
    p="$h/Library/LaunchAgents/local.session-deck.plist"
    say " $u ($login): LaunchAgent in their login session"
    [ -f "$p" ] && [ ! -f "$p.pre-multiuser" ] && ! grep -q "$CODE" "$p" && run cp -p "$p" "$p.pre-multiuser"
    plist local.session-deck "$u" "$CODE/server.py" "$h/Library/Logs/session-deck.log" "$(plist_env "$u")" | put "$p" "$u:staff" 644
    try launchctl bootout "gui/$(id -u "$u")/local.session-deck"; [ $DRY = 1 ] || sleep 1
    run launchctl bootstrap "gui/$(id -u "$u")" "$p"
  else
    p="$LD/local.session-deck.$u.plist"
    say " $u ($login): LaunchDaemon running as $u"
    run sudo -u "$u" mkdir -p "$h/Library/Logs"
    plist "local.session-deck.$u" "$u" "$CODE/server.py" "$h/Library/Logs/session-deck.log" "$(plist_env "$u")" daemon | put "$p" root:wheel 644
    reload_daemon "local.session-deck.$u" "$p"
  fi
done

say "== 5. Router"
renv="$(printf '    <key>%s</key><string>%s</string>\n' DECK_ROUTER_LISTEN "$RUN/router/router.sock" DECK_ROUTES "$ROUTES")"
plist local.session-deck-router "$SVC" "$CODE/router.py" "$RUN/router/router.log" "$renv" daemon "$SVC" | put "$LD/local.session-deck-router.plist" root:wheel 644
reload_daemon local.session-deck-router "$LD/local.session-deck-router.plist"

say "
== Next (by hand)
1. Point the shared address at the router (tailscaled runs as root, so it can reach the 0600 socket):
     tailscale serve --bg --https=443 --set-path=/deck unix:$RUN/router/router.sock
     tailscale serve --bg --http=80 --set-path=/deck unix:$RUN/router/router.sock
     tailscale serve --bg --http=8080 --set-path=/deck unix:$RUN/router/router.sock
   Check: tailscale serve status
2. Give each other person a setup code (their phone, https://$HOST/deck/):
     sudo $0 --code <account>
3. Logs: ~<account>/Library/Logs/session-deck.log and $RUN/router/router.log (readable with sudo)"
