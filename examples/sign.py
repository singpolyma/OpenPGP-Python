import OpenPGP
import OpenPGP.Crypto
import sys

wkey = OpenPGP.Message.parse(open('key').read())[0]

data = OpenPGP.LiteralDataPacket('This is text.', 'u', 'text/plain')
sign = OpenPGP.Crypto.Wrapper(wkey)
m = sign.sign(data)

sys.stdout.write(m.to_bytes())
