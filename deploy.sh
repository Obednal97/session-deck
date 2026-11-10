#!/bin/bash
# Session Deck deploy: copies the code committed on `main` into the live, root-owned folder and restarts the decks.
# Installed root-owned at /usr/local/libexec/session-deck-deploy by setup-deploy.sh; a sudoers rule lets the owner
# (and Claude, working as the owner) run exactly that file, with no arguments, without a password. It never changes
# accounts, services or Tailscale: that stays with install-multiuser.sh.
set -euo pipefail
SRC="@SRC@" OWNER="@OWNER@" LIVE=/usr/local/libexec/session-deck  # setup-deploy.sh fills in the repo folder and its owner
case $SRC in @*) SRC=$(cd "$(dirname "$0")" && pwd) OWNER=${SUDO_USER:?run with sudo};; esac  # run straight from the repo
FILES="server.py router.py index.html sw.js manifest.webmanifest vendor icons"
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
[ $# = 0 ] || { echo "takes no arguments"; exit 1; }

stage=$(mktemp -d /tmp/session-deck-deploy.XXXXXX); trap 'rm -rf "$stage"' EXIT
# git runs as the owner (it's their repo); only what is committed on main is deployed
sudo -u "$OWNER" git -C "$SRC" archive --format=tar main -- $FILES | tar -x -C "$stage"
rev=$(sudo -u "$OWNER" git -C "$SRC" rev-parse --short main)
for f in $FILES; do [ -e "$stage/$f" ] || { echo "missing $f on main"; exit 1; }; done
[ -z "$(find "$stage" -type l)" ] || { echo "refusing: symlinks in the committed code"; exit 1; }
/opt/homebrew/bin/python3 -m py_compile "$stage/server.py" "$stage/router.py" && rm -rf "$stage/__pycache__"

if diff -rq -x REVISION "$stage" "$LIVE" >/dev/null 2>&1; then echo "live already matches main ($rev)"; exit 0; fi
chown -R root:wheel "$stage"; chmod -R u=rwX,go=rX "$stage"
rm -rf "$LIVE.new" "$LIVE.old"; cp -R "$stage" "$LIVE.new"
mv "$LIVE" "$LIVE.old"; mv "$LIVE.new" "$LIVE"; rm -rf "$LIVE.old"
echo "$rev" > "$LIVE/REVISION"; chmod 644 "$LIVE/REVISION"

for j in $(launchctl print system 2>/dev/null | grep -o 'local\.session-deck[A-Za-z0-9.-]*' | sort -u); do
  launchctl kickstart -k "system/$j" && echo "restarted $j"
done
uid=$(id -u "$OWNER"); launchctl kickstart -k "gui/$uid/local.session-deck" 2>/dev/null && echo "restarted $OWNER's deck"
echo "deployed main@$rev"
