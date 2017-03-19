#!/bin/sh

export SLPM_FULLNAME="John Doe"
export USER="jdoe"
ssh-agent ./slpm.comp << EOF | diff -u3 expected-output /dev/stdin
correct horse battery staple
twitter.com
1
facebook.com
2
ssh github.com
1
EOF
