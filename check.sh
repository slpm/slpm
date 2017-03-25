#!/bin/sh

set -e

export SLPM_FULLNAME="John Doe"
export USER="jdoe"
./expected-output.sh > expected.out
ssh-agent ./slpm.comp << EOF | diff -u3 expected.out /dev/stdin
correct horse battery staple
twitter.com
1
facebook.com
2
ssh github.com
1
EOF
rm expected.out
