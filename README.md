## Stateless Password Manager

[![Build Status](https://travis-ci.org/Kodest/slpm.svg?branch=master)](https://travis-ci.org/Kodest/slpm)

`slpm` is a dead simple password manager that will never store anything on disk
nor use any random source as it derives every password from your full name (as
salt) and your passphrase. Therefore your passphrase should be [strong
enough][diceware]! `slpm` currently uses the [MasterPasswordApp
algorithm][mpwalgo] but it will default to [Argon2][] KDF and [blake2b][] secure
hash in the future.

[diceware]: http://world.std.com/~reinhold/diceware.html
[mpwalgo]: http://masterpasswordapp.com/algorithm.html
[Argon2]: https://github.com/p-h-c/phc-winner-argon2
[blake2b]: https://blake2.net/

### Usage:

We run slpm using `Edgar Allan Poe` as full name and `footman liquid vacate
rounding compare parsnip traffic uproar freemason duckbill` as passphrase:

```
$ wget https://github.com/Kodest/slpm/releases/download/v0.3.1/slpm.comp
$ chmod +x slpm.comp
$ ssh-agent bash --norc
bash-4.3$ ssh-add -l
The agent has no identities.
bash-4.3$ SLPM_FULLNAME='Edgar Allan Poe' ./slpm.comp
SLPM_FULLNAME='Edgar Allan Poe'
Passphrase: 
Key derivation complete.
Site: twitter.com
Counter: 1
Maximum Security Password: t3_T9CriCZ^Y@eclVBFK
Long Password: Rosa1+DiztGaxi
Medium Password: Ros5$Luk
Short Password: Ros5
Basic Password: tWU5uzr7
PIN: 2365
Site: facebook.com
Counter: 1
Maximum Security Password: Ulg#3Cdae!20p4edPV8&
Long Password: Fopn9+MateQixe
Medium Password: FopNuz7=
Short Password: Fop6
Basic Password: UWR6qbP5
PIN: 8396
Site: ssh mysite.com
Counter: 1
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPC5/uQ+oWoHbHS2NM/y5LXJUp9vMKK6+TJt9x2h3SWW eapoe@slpm+mysite.com
Site: ^Z
[1]+  Stopped                 SLPM_FULLNAME='Edgar Allan Poe' ./slpm.comp
bash-4.3$ ssh-add -l
256 0f:4c:2d:a0:b0:8e:b0:e0:2c:64:0e:63:ce:72:14:1f slpm+mysite.com (ED25519)
bash-4.3$ fg
SLPM_FULLNAME='Edgar Allan Poe' ./slpm.comp
^D
Bye!    
bash-4.3$ ssh-add -l
The agent has no identities.
bash-4.3$ exit
exit
$ 
```
