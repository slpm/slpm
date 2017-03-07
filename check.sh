#!/bin/sh

export SLPM_FULLNAME="John Doe"
./slpm.comp << EOF | diff -u3 expected-output /dev/stdin
correct horse battery staple
twitter.com
1
facebook.com
2
EOF
