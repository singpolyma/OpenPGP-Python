import OpenPGP
import OpenPGP.Crypto

wkey = OpenPGP.Message.parse(open('key').read())[0]

m = OpenPGP.Message.parse(open('t.php.gpg').read())

verify = OpenPGP.Crypto.Wrapper(wkey)
print verify.verify(m)
