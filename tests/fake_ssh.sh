#!/bin/sh
# Stands in for ssh in tests: shows its arguments, asks for a password once, then asks again and only echoes what comes in.
echo "$*"
stty -echo 2>/dev/null
printf "%s" "user@host's password: "
read -r line
echo
echo "AUTH $line"
printf "password: "
exec cat
