from __future__ import absolute_import
from struct import unpack
import Crypto.Random
import Crypto.Random.random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dsa
from cryptography.hazmat.primitives.interfaces import RSAPrivateKey, RSAPublicKey, DSAPublicKey, DSAPrivateKey
from cryptography.exceptions import InvalidSignature
import Crypto.Hash.MD5
import Crypto.Hash.RIPEMD
import Crypto.Hash.SHA
import Crypto.Hash.SHA224
import Crypto.Hash.SHA256
import Crypto.Hash.SHA384
import Crypto.Hash.SHA512
import OpenPGP
import hashlib, math
import sys
import copy

class Wrapper:
    """ A wrapper for using the classes from OpenPGP.py with cryptography """
    def __init__(self, packet):
        packet = self._parse_packet(packet)
        self._key = self._message = None
        if isinstance(packet, OpenPGP.PublicKeyPacket) or (hasattr(packet, '__getitem__') and isinstance(packet[0], OpenPGP.PublicKeyPacket)): # If it's a key (other keys are subclasses of this one)
            self._key = packet
        else:
            self._message = packet

    def key(self, keyid=None):
        if not self._key: # No key
            return None
        if isinstance(self._key, OpenPGP.Message):
            for p in self._key:
                if isinstance(p, OpenPGP.PublicKeyPacket):
                    if not keyid or p.fingerprint()[len(keyid)*-1:].upper() == keyid.upper():
                        return p
        return self._key

    def public_key(self, keyid=None):
        """ Get _RSAobj or _DSAobj for the public key """
        return self.convert_public_key(self.key(keyid))

    def private_key(self, keyid=None):
        """ Get _RSAobj or _DSAobj for the public key """
        return self.convert_private_key(self.key(keyid))

    def encrypted_data(self):
        if not self._message:
            return None

        for p in self._message:
            if isinstance(p, OpenPGP.EncryptedDataPacket):
                return p

        return None

    def verifier(self, h, m, s):
        """ Used in implementation of verify """
        key = self.public_key(s.issuer())
        if not key or (s.key_algorithm_name() == 'DSA' and not isinstance(key, DSAPublicKey)):
            return False
        if s.key_algorithm_name() == 'DSA':
            raise Exception("TODO: https://github.com/pyca/cryptography/pull/912")
        else: # RSA
            try:
                verifier = key.verifier(s.data[0], padding.PKCS1v15(), h)
                verifier.update(m)
                verifier.verify()
            except InvalidSignature:
              return False

            return True

    def verify(self, packet):
        """ Pass a message to verify with this key, or a key (OpenPGP, _RSAobj, or _DSAobj)
            to check this message with
            Second optional parameter to specify which signature to verify (if there is more than one)
        """
        m = None
        packet = self._parse_packet(packet)
        if not self._message:
            m = packet
            verifier = self.verifier
        else:
            m = self._message
            verifier = self.__class__(packet).verifier

        byhash = {
            'MD5':       lambda m, s: verifier(hashes.MD5(), m, s),
            'RIPEMD160': lambda m, s: verifier(hashes.RIPEMD(), m, s),
            'SHA1':      lambda m, s: verifier(hashes.SHA1(), m, s),
            'SHA224':    lambda m, s: verifier(hashes.SHA224(), m, s),
            'SHA256':    lambda m, s: verifier(hashes.SHA256(), m, s),
            'SHA384':    lambda m, s: verifier(hashes.SHA384(), m, s),
            'SHA512':    lambda m, s: verifier(hashes.SHA512(), m, s)
        }

        return m.verified_signatures({'RSA': byhash, 'DSA': byhash})

    def sign(self, packet, hash='SHA256', keyid=None):
        if self._key and not isinstance(packet, OpenPGP.Packet) and not isinstance(packet, OpenPGP.Message):
            packet = OpenPGP.LiteralDataPacket(packet)
        else:
            packet = self._parse_packet(packet)

        if isinstance(packet, OpenPGP.SecretKeyPacket) or isinstance(packet, RSAPrivateKey) or isinstance(packet, DSAPrivateKey) or (hasattr(packet, '__getitem__') and isinstance(packet[0], OpenPGP.SecretKeyPacket)):
            key = packet
            message = self._message
        else:
            key = self._key
            message = packet

        if not key or not message:
            return None # Missing some data

        if isinstance(message, OpenPGP.Message):
            message = message.signature_and_data()[1]

        if not (isinstance(key, RSAPrivateKey) or isinstance(key, DSAPrivateKey)):
            key = self.__class__(key)
            if not keyid:
                keyid = key.key().fingerprint()[-16:]
            key = key.private_key(keyid)

        key_algorithm = None
        if isinstance(key, RSAPrivateKey):
            key_algorithm = 'RSA'
        elif isinstance(key, DSAPrivateKey):
            key_algorithm = 'DSA'

        sig = OpenPGP.SignaturePacket(message, key_algorithm, hash.upper())

        if keyid:
            sig.hashed_subpackets.append(OpenPGP.SignaturePacket.IssuerPacket(keyid))

        def doDSA(h, m):
            return list(key.sign(h.new(m).digest()[0:int(Crypto.Util.number.size(key.q) / 8)],
                Crypto.Random.random.StrongRandom().randint(1,key.q-1)))

        def doRSA(h, m):
            ctx = key.signer(padding.PKCS1v15(), h())
            ctx.update(m)
            return [ctx.finalize()]

        sig.sign_data({'RSA': {
                'MD5':       lambda m: doRSA(hashes.MD5, m),
                'RIPEMD160': lambda m: doRSA(hashes.RIPEMD160, m),
                'SHA1':      lambda m: doRSA(hashes.SHA1, m),
                'SHA224':    lambda m: doRSA(hashes.SHA224, m),
                'SHA256':    lambda m: doRSA(hashes.SHA256, m),
                'SHA384':    lambda m: doRSA(hashes.SHA384, m),
                'SHA512':    lambda m: doRSA(hashes.SHA512, m)
            }, 'DSA': {
                'MD5':       lambda m: doDSA(Crypto.Hash.MD5, m),
                'RIPEMD160': lambda m: doDSA(Crypto.Hash.RIPEMD, m),
                'SHA1':      lambda m: doDSA(Crypto.Hash.SHA, m),
                'SHA224':    lambda m: doDSA(Crypto.Hash.SHA224, m),
                'SHA256':    lambda m: doDSA(Crypto.Hash.SHA256, m),
                'SHA384':    lambda m: doDSA(Crypto.Hash.SHA384, m),
                'SHA512':    lambda m: doDSA(Crypto.Hash.SHA512, m),
            }})

        return OpenPGP.Message([sig, message])

    # TODO: merge this with the normal sign function
    def sign_key_userid(self, packet, hash='SHA256', keyid=None):
        if isinstance(packet, list):
            packet = OpenPGP.Message(packet)
        elif not isinstance(packet, OpenPGP.Message):
            packet = OpenPGP.Message.parse(packet)

        key = self.key(keyid)
        if not key or not packet: # Missing some data
            return None

        if not keyid:
            keyid = key.fingerprint()[-16:]

        key = self.private_key(keyid)

        sig = None
        for p in packet:
            if isinstance(p, OpenPGP.SignaturePacket):
                sig = p
        if not sig:
            sig = OpenPGP.SignaturePacket(packet, 'RSA', hash.upper())
            sig.signature_type = 0x13
            sig.hashed_subpackets.append(OpenPGP.SignaturePacket.KeyFlagsPacket([0x01]))
            sig.hashed_subpackets.append(OpenPGP.SignaturePacket.IssuerPacket(keyid))
            packet.append(sig)

        def doDSA(h, m):
            return list(key.sign(h.new(m).digest()[0:int(Crypto.Util.number.size(key.q) / 8)],
                Crypto.Random.random.StrongRandom().randint(1,key.q-1)))

        def doRSA(h, m):
            ctx = key.signer(padding.PKCS1v15(), h())
            ctx.update(m)
            return [ctx.finalize()]

        sig.sign_data({'RSA': {
                'MD5':       lambda m: doRSA(hashes.MD5, m),
                'RIPEMD160': lambda m: doRSA(hashes.RIPEMD160, m),
                'SHA1':      lambda m: doRSA(hashes.SHA1, m),
                'SHA224':    lambda m: doRSA(hashes.SHA224, m),
                'SHA256':    lambda m: doRSA(hashes.SHA256, m),
                'SHA384':    lambda m: doRSA(hashes.SHA384, m),
                'SHA512':    lambda m: doRSA(hashes.SHA512, m)
            }, 'DSA': {
                'MD5':       lambda m: doDSA(Crypto.Hash.MD5, m),
                'RIPEMD160': lambda m: doDSA(Crypto.Hash.RIPEMD, m),
                'SHA1':      lambda m: doDSA(Crypto.Hash.SHA, m),
                'SHA224':    lambda m: doDSA(Crypto.Hash.SHA224, m),
                'SHA256':    lambda m: doDSA(Crypto.Hash.SHA256, m),
                'SHA384':    lambda m: doDSA(Crypto.Hash.SHA384, m),
                'SHA512':    lambda m: doDSA(Crypto.Hash.SHA512, m),
            }})

        return packet

    def decrypt(self, packet):
        if isinstance(packet, list):
            packet = OpenPGP.Message(packet)
        elif not isinstance(packet, OpenPGP.Message):
            packet = OpenPGP.Message.parse(packet)

        if isinstance(packet, OpenPGP.SecretKeyPacket) or isinstance(packet, rsa.RSAPrivateKey) or (hasattr(packet, '__getitem__') and isinstance(packet[0], OpenPGP.SecretKeyPacket)):
            keys = packet
        else:
            keys = self._key
            self._message = packet

        if not keys or not self._message:
            return None # Missing some data

        if not isinstance(keys, rsa.RSAPrivateKey):
            keys = self.__class__(keys)

        for p in self._message:
            if isinstance(p, OpenPGP.AsymmetricSessionKeyPacket):
                if isinstance(keys, rsa.RSAPrivateKey):
                    sk = self.try_decrypt_session(keys, p.encrypted_data[2:])
                elif len(p.keyid.replace('0','')) < 1:
                    for k in keys.key:
                        sk = self.try_decrypt_session(self.convert_private_key(k), p.encyrpted_data[2:]);
                        if sk:
                          break
                else:
                    key = keys.private_key(p.keyid)
                    sk = self.try_decrypt_session(key, p.encrypted_data[2:])

                if not sk:
                    continue

                r = self.decrypt_packet(self.encrypted_data(), sk[0], sk[1])
                if r:
                    return r

        return None # Failed

    @classmethod
    def try_decrypt_session(cls, key, edata):
        data = key.decrypt(edata, padding.PKCS1v15())
        sk = data[1:len(data)-2]
        chk = unpack('!H', data[-2:])[0]

        sk_chk = 0
        for i in range(0, len(sk)):
          sk_chk = (sk_chk + ord(sk[i:i+1])) % 65536

        if sk_chk != chk:
            return None
        return (ord(data[0:1]), sk)

    def decrypt_symmetric(self, passphrase):
        epacket = self.encrypted_data()
        if hasattr(passphrase, 'encode'):
            passphrase = passphrase.encode('utf-8')

        decrypted = None
        for p in self._message:
            if isinstance(p, OpenPGP.SymmetricSessionKeyPacket):
                if len(p.encrypted_data) > 0:
                    cipher, key_bytes, key_block_bytes = self.get_cipher(p.symmetric_algorithm)
                    if not cipher:
                        continue
                    cipher = cipher(p.s2k.make_key(passphrase, key_bytes))
                    pad_amount = key_block_bytes - (len(p.encrypted_data) % key_block_bytes)
                    withiv = cipher(b'\0' * key_block_bytes).decryptor()
                    data = withiv.update(p.encrypted_data + (pad_amount*b'\0'))
                    data += withiv.finalize()
                    data = data[:-pad_amount]

                    decrypted = self.decrypt_packet(epacket, ord(data[0:1]), data[1:])
                else:
                    cipher, key_bytes, key_block_bytes = self.get_cipher(p.symmetric_algorithm)
                    if not cipher:
                        continue

                    decrypted = self.decrypt_packet(epacket, p.symmetric_algorithm, p.s2k.make_key(passphrase, key_bytes))

                if decrypted:
                    return decrypted

        return None # If we get here, we failed

    def decrypt_secret_key(self, passphrase):
        if hasattr(passphrase, 'encode'):
            passphrase = passphrase.encode('utf-8')

        packet = copy.copy(self._message or self._key) # Do not mutate original

        cipher, key_bytes, key_block_bytes = self.get_cipher(packet.symmetric_algorithm)
        cipher = cipher(packet.s2k.make_key(passphrase, key_bytes))
        cipher = cipher(packet.encrypted_data[:key_block_bytes]).decryptor()
        pad_amount = key_block_bytes - (len(packet.encrypted_data[key_block_bytes:]) % key_block_bytes)
        material = cipher.update(packet.encrypted_data[key_block_bytes:] + (pad_amount*b'\0'))
        material += cipher.finalize()
        material = material[:-pad_amount]

        if packet.s2k_useage == 254:
            chk = material[-20:]
            material = material[:-20]
            if(chk != hashlib.sha1(material)):
                return None
        else:
            chk = unpack('!H', material[-2:])[0]
            material = material[:-2]
            if chk != OpenPGP.checksum(material):
                return None

        packet.s2k_usage = 0
        packet.symmetric_alorithm = 0
        packet.encrypted_data = None
        packet.input = material
        packet.key_from_input()
        packet.input = None
        return packet

    @classmethod
    def decrypt_packet(cls, epacket, symmetric_algorithm, key):
        cipher, key_bytes, key_block_bytes = cls.get_cipher(symmetric_algorithm)
        if not cipher:
            return None
        cipher = cipher(key)

        pad_amount = key_block_bytes - (len(epacket.data) % key_block_bytes)
        if isinstance(epacket, OpenPGP.IntegrityProtectedDataPacket):
            withiv = cipher(b'\0' * key_block_bytes).decryptor()
            data = withiv.update(epacket.data + (pad_amount*b'\0'))
            data += withiv.finalize()
            data = data[:-pad_amount]
            prefix = data[0:key_block_bytes+2]
            mdc = data[-22:][2:]
            data = data[key_block_bytes+2:-22]

            mkMDC = hashlib.sha1(prefix + data + b'\xd3\x14').digest()
            if mdc != mkMDC:
                return False

            try:
                return OpenPGP.Message.parse(data)
            except:
                return None
        else:
            # No MDC means decrypt with resync
            edata = epacket.data[key_block_bytes+2:]
            pad_amount = key_block_bytes - (len(edata) % key_block_bytes)
            withiv = cipher(epacket.data[2:key_block_bytes+2]).decryptor()
            data = withiv.update(edata + (pad_amount*b'\0'))
            data += withiv.finalize()
            data = data[:-pad_amount]
            try:
                return OpenPGP.Message.parse(data)
            except:
                return None

        return None

    @classmethod
    def _parse_packet(cls, packet):
        if isinstance(packet, OpenPGP.Packet) or isinstance(packet, OpenPGP.Message) or isinstance(packet, Crypto.PublicKey.RSA._RSAobj) or isinstance(packet, Crypto.PublicKey.DSA._DSAobj):
            return packet
        elif isinstance(packet, tuple) or isinstance(packet, list):
            if sys.version_info[0] == 2 and isinstance(packet[0], long) or isinstance(packet[0], int):
                data = []
                for i in packet:
                    data.append(Crypto.Util.number.long_to_bytes(i)) # OpenPGP likes bytes
            else:
                data = packet
            return OpenPGP.SecretKeyPacket(keydata=data, algorithm=1, version=3) # V3 for fingerprint with no timestamp
        else:
            return OpenPGP.Message.parse(packet)

    @classmethod
    def get_cipher(cls, algo):
        def cipher(m, ks, bs):
            return (lambda k: lambda iv:
                    Cipher(m(k), modes.CFB(iv), default_backend()),
                ks, bs)

        if algo == 2:
            return cipher(algorithms.TripleDES, 24, 8)
        elif algo == 3:
            return cipher(algorithms.CAST5, 16, 8)
        elif algo == 4:
            return cipher(algorithms.Blowfish, 16, 8)
        elif algo == 7:
            return cipher(algorithms.AES, 16, 16)
        elif algo == 8:
            return cipher(algorithms.AES, 24, 16)
        elif algo == 9:
            return cipher(algorithms.AES, 32, 16)

        return (None,None,None) # Not supported

    @classmethod
    def convert_key(cls, packet, private=False):
        if isinstance(packet, RSAPrivateKey) or isinstance(packet, RSAPublicKey) or isinstance(packet, DSAPublicKey) or isinstance(packet, DSAPrivateKey):
            if (not private) and (isinstance(packet, DSAPrivateKey) or isinstance(packet, RSAPrivateKey)):
                return packet.public_key()
            else:
                return packet

        packet = cls._parse_packet(packet)
        if isinstance(packet, OpenPGP.Message):
            packet = packet[0]

        if packet.key_algorithm_name() == 'DSA':
          params = dsa.DSAParameterNumbers(
                    cls._bytes_to_long(packet.key['p']),
                    cls._bytes_to_long(packet.key['q']),
                    cls._bytes_to_long(packet.key['g']))
          public = dsa.DSAPublicNumbers(
                    cls._bytes_to_long(packet.key['y']),
                    params)
          if private:
              return dsa.DSAPrivateNumbers(cls._bytes_to_long(packet.key['x']), public).private_key(default_backend())
          else:
              return public.public_key(default_backend())
        else: # RSA
          public = rsa.RSAPublicNumbers(cls._bytes_to_long(packet.key['e']), cls._bytes_to_long(packet.key['n']))
          if private:
              d = cls._bytes_to_long(packet.key['d'])
              p = cls._bytes_to_long(packet.key['q'])
              q = cls._bytes_to_long(packet.key['p'])
              dmp1 = rsa.rsa_crt_dmp1(d, p)
              dmq1 = rsa.rsa_crt_dmp1(d, q)
              u = cls._bytes_to_long(packet.key['u'])
              return rsa.RSAPrivateNumbers(p, q, d, dmp1, dmq1, u, public).private_key(default_backend())
          else:
              return public.public_key(default_backend())

    @classmethod
    def convert_public_key(cls, packet):
        return cls.convert_key(packet, False)

    @classmethod
    def convert_private_key(cls, packet):
        return cls.convert_key(packet, True)

    @classmethod
    def _bytes_to_long(cls, b):
      if hasattr(int, 'from_bytes'):
        return int.from_bytes(b, byteorder='big', signed=False)
      else:
        return long(b.encode('hex'), 16)
