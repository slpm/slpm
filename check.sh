#!/bin/sh

export SLPM_FULLNAME="John Doe"
export SLPM_PASSPHRASE="correct horse battery staple"
./slpm.comp << EOF | diff -u3 expected-output /dev/stdin
twitter.com
1
facebook.com
2
EOF
