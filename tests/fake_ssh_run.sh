#!/bin/sh
# Stands in for ssh in the Remote tests: drops the options up to "--" and the host, then runs the rest here as the server's login shell
# would, with HOME at $FAKE_SSH_HOME; no command is an interactive sh, as a login. Like ssh, exits 255 while $FAKE_SSH_DOWN exists,
# and a fresh key-only sign-in (ControlPath=none) does while $FAKE_SSH_NOKEY exists.
case " $* " in *" -O check "*) exit 0;; esac  # the shared master is always "up"
case " $* " in *" ControlPath=none "*) [ -e "${FAKE_SSH_NOKEY:-/nonexistent}" ] && { echo "Permission denied (publickey)." >&2; exit 255; };; esac  # a key sign-in the server refuses
while [ $# -gt 0 ] && [ "$1" != "--" ]; do shift; done
shift 2
[ -e "${FAKE_SSH_DOWN:-/nonexistent}" ] && { echo "Permission denied (publickey,password)." >&2; exit 255; }
export HOME="$FAKE_SSH_HOME" PATH="$FAKE_SSH_HOME/bin:$PATH"  # the server's own commands (a stand-in tmux) come first
cd
[ $# -eq 0 ] && exec sh -i
exec sh -c "$*"
