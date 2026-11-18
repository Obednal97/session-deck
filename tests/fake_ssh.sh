#!/bin/sh
# Stands in for ssh in tests: shows its arguments, asks for a password, then asks again as after a wrong one and only echoes what comes in.
# A shared master is "up" while the file $FAKE_SSH_MASTER exists: -O check then succeeds, and a terminal opens with no ssh prompt
# (a remote program asks "Password:" a moment later).
M=${FAKE_SSH_MASTER:-/nonexistent}
case " $* " in *" -O check "*) test -e "$M"; exit $?;; esac
echo "$*"
stty -echo 2>/dev/null
if [ -e "$M" ]; then sleep 1; printf "Password: "; exec cat; fi
printf "%s" "user@host's password: "
read -r line
echo
echo "AUTH $line"
printf "%s" "user@host's password: "
exec cat
