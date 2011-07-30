import Crypto.PublicKey.RSA
import Crypto.Util.randpool
import Crypto.Util.number
import OpenPGP
import OpenPGP.Crypto
import sys

pool = Crypto.Util.randpool.RandomPool()
k = Crypto.PublicKey.RSA.generate(512, pool.get_bytes)

nkey = OpenPGP.SecretKeyPacket((
	Crypto.Util.number.long_to_bytes(k.n),
	Crypto.Util.number.long_to_bytes(k.e),
	Crypto.Util.number.long_to_bytes(k.d),
	Crypto.Util.number.long_to_bytes(k.p),
	Crypto.Util.number.long_to_bytes(k.q),
	Crypto.Util.number.long_to_bytes(k.u)
))

uid = OpenPGP.UserIDPacket('Test <test@example.com>')

wkey = OpenPGP.Crypto.RSA(nkey)
m = wkey.sign_key_userid([nkey, uid])

sys.stdout.write(m.to_bytes())
