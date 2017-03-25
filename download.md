## Download slpm

The latest stable version of slpm is available as [slpm.comp](slpm.comp).
Authenticity of slpm SHOULD be verified every time after the file is downloaded
using [the checksum file](SHA512SUMS) and [its signature](SHA512SUMS.sign).

The signature is made by László ÁSHIN with the following fingerprint:

`8ADA 5049 424D 6F50 7841  BE2D 35BA 1675 CD4A AD15`

Steps to verify:

```
$ wget -q https://slpm.github.io/{slpm.comp,SHA512SUMS,SHA512SUMS.sign}
$ sha512sum -c SHA512SUMS
slpm.comp: OK
$ gpg --recv-keys 35BA1675CD4AAD15
gpg: requesting key CD4AAD15 from hkp server pgp.mit.edu
gpg: key CD4AAD15: public key "László ÁSHIN <laszlo@ashin.hu>" imported
gpg: Total number processed: 1
gpg:               imported: 1  (RSA: 1)
$ gpg --verify SHA512SUMS.sign
gpg: assuming signed data in `SHA512SUMS'
gpg: Signature made Sat 25 Mar 2017 10:47:42 AM CET using RSA key ID CD4AAD15
gpg: Good signature from "László ÁSHIN <laszlo@ashin.hu>"
gpg:                 aka "László Áshin <laszlo@ashin.hu>"
gpg:                 aka "László ÁSHIN <ashinlaszlo@gmail.com>"
gpg:                 aka "[jpeg image of size 2764]"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: 8ADA 5049 424D 6F50 7841  BE2D 35BA 1675 CD4A AD15
$ 
```

## Releases

{% assign latest_release = site.github.releases.first %}
Latest release: {{ latest_release.tag_name }}
