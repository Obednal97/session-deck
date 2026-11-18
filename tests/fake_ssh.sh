#!/bin/sh
# Stands in for ssh in tests: shows its arguments, asks for a password, then asks again as after a wrong one and only echoes what comes in.
# -G prints the user (-l, else this account) and hostname (after --), as ssh does. A shared master is "up" while the file $FAKE_SSH_MASTER
# exists: -O check then succeeds, and a terminal opens with no ssh prompt (a remote program shows the same "user@host's password:" a
# moment later). While $FAKE_SSH_JUMP exists, a ProxyJump host asks for its own password first.
M=${FAKE_SSH_MASTER:-/nonexistent}
case " $* " in *" -O check "*) test -e "$M"; exit $?;; esac
all="$*"; u=$(id -un); g=
while [ $# -gt 0 ]; do case $1 in -l) u=$2; shift;; -G) g=1;; --) h=$2; break;; esac; shift; done
[ -n "$g" ] && { printf 'user %s\nhostname %s\nport 22\n' "$u" "$h"; exit 0; }
echo "$all"
stty -echo 2>/dev/null
if [ -e "$M" ]; then sleep 1; printf "%s@%s's password: " "$u" "$h"; exec cat; fi
if [ -e "${FAKE_SSH_JUMP:-/nonexistent}" ]; then printf "%s" "jump@bastion's password: "; read -r line; echo; echo "JUMP $line"; fi
printf "%s@%s's password: " "$u" "$h"
read -r line
echo
echo "AUTH $line"
printf "%s@%s's password: " "$u" "$h"
exec cat
