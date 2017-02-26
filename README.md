## Stateless Password Manager

[![Build Status](https://travis-ci.org/LaszloAshin/slpm.svg?branch=master)](https://travis-ci.org/LaszloAshin/slpm)

`slpm` is a dead simple password manager that will never store anything on disk
nor use any random source, it derives every password from your full name (as
salt) and your passphrase. Therefore your passphrase should be [strong
enough][diceware]! `slpm` curently uses the [MasterPasswordApp
algorithm][mpwalgo] right now but it will default to [Argon2][] KDF and
[blake2b][] secure hash in the future.

[diceware]: http://world.std.com/~reinhold/diceware.html
[mpwalgo]: http://masterpasswordapp.com/algorithm.html
[Argon2]: https://github.com/p-h-c/phc-winner-argon2
[blake2b]: https://blake2.net/

### Usage:

We run slpm using `Edgar Allan Poe` as full name and `footman liquid vacate
rounding compare parsnip traffic uproar freemason duckbill` as passphrase:

```
$ wget https://github.com/LaszloAshin/slpm/releases/download/v0.1.1/slpm.comp
$ chmod +x slpm.comp
$ SLPM_FULLNAME='Edgar Allan Poe' ./slpm.comp 
SLPM_FULLNAME=Edgar Allan Poe
Password: 
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
Bye!    
```
