import Crypto.PublicKey.RSA
import Crypto.Util.number
import OpenPGP
import OpenPGP.Crypto
import sys

k = Crypto.PublicKey.RSA.generate(1024)

nkey = OpenPGP.SecretKeyPacket((
	Crypto.Util.number.long_to_bytes(k.n),
	Crypto.Util.number.long_to_bytes(k.e),
	Crypto.Util.number.long_to_bytes(k.d),
	Crypto.Util.number.long_to_bytes(k.p),
	Crypto.Util.number.long_to_bytes(k.q),
	Crypto.Util.number.long_to_bytes(k.u)
))

uid = OpenPGP.UserIDPacket('Test <test@example.com>')

wkey = OpenPGP.Crypto.Wrapper(nkey)
m = wkey.sign_key_userid([nkey, uid])

sys.stdout.write(m.to_bytes())
