#!/bin/bash
# One-off, run with sudo: installs deploy.sh as a root-owned /usr/local/libexec/session-deck-deploy and a sudoers rule
# letting the owner run exactly that file, with no arguments, without a password. Undo: sudo ./setup-deploy.sh --remove
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
BIN=/usr/local/libexec/session-deck-deploy RULE=/etc/sudoers.d/session-deck-deploy OWNER=${SUDO_USER:?run with sudo from the owner account}
if [ "${1:-}" = --remove ]; then rm -f "$BIN" "$RULE"; echo "removed"; exit 0; fi
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p /usr/local/libexec
tmp=$(mktemp); sed -e "s|@SRC@|$here|" -e "s|@OWNER@|$OWNER|" "$here/deploy.sh" > "$tmp"
install -o root -g wheel -m 755 "$tmp" "$BIN"; rm -f "$tmp"
tmp=$(mktemp); echo "$OWNER ALL=(root) NOPASSWD: $BIN \"\"" > "$tmp"
visudo -cf "$tmp" >/dev/null && install -o root -g wheel -m 440 "$tmp" "$RULE"; rm -f "$tmp"
echo "installed $BIN and $RULE; deploy with: sudo -n $BIN"
