from __future__ import absolute_import
from struct import unpack
import Crypto.Random.random
import Crypto.PublicKey.RSA
import Crypto.PublicKey.DSA
import Crypto.Cipher.DES3
import Crypto.Cipher.AES
import Crypto.Cipher.Blowfish
import Crypto.Cipher.CAST
import Crypto.Signature.PKCS1_v1_5
import Crypto.Hash.MD5
import Crypto.Hash.RIPEMD
import Crypto.Hash.SHA
import Crypto.Hash.SHA224
import Crypto.Hash.SHA256
import Crypto.Hash.SHA384
import Crypto.Hash.SHA512
import Crypto.Util.number
import OpenPGP
import hashlib, math
import sys
import copy

class Wrapper:
    """ A wrapper for using the classes from OpenPGP.py with PyCrypto """
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
        if not key or (s.key_algorithm_name() == 'DSA' and not isinstance(key, Crypto.PublicKey.DSA._DSAobj)):
            return False
        if s.key_algorithm_name() == 'DSA':
            dsaSig = (Crypto.Util.number.bytes_to_long(s.data[0]), Crypto.Util.number.bytes_to_long(s.data[1]))
            dsaLen = int(Crypto.Util.number.size(key.q) / 8)
            return key.verify(h.new(m).digest()[0:dsaLen], dsaSig)
        else: # RSA
            protocol = Crypto.Signature.PKCS1_v1_5.new(key)
            return protocol.verify(h.new(m), s.data[0])

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

        hashes = {
            'MD5':       lambda m, s: verifier(Crypto.Hash.MD5, m, s),
            'RIPEMD160': lambda m, s: verifier(Crypto.Hash.RIPEMD, m, s),
            'SHA1':      lambda m, s: verifier(Crypto.Hash.SHA, m, s),
            'SHA224':    lambda m, s: verifier(Crypto.Hash.SHA224, m, s),
            'SHA256':    lambda m, s: verifier(Crypto.Hash.SHA256, m, s),
            'SHA384':    lambda m, s: verifier(Crypto.Hash.SHA384, m, s),
            'SHA512':    lambda m, s: verifier(Crypto.Hash.SHA512, m, s)
        }

        return m.verified_signatures({'RSA': hashes, 'DSA': hashes})

    def sign(self, packet, hash='SHA256', keyid=None):
        if self._key and not isinstance(packet, OpenPGP.Packet) and not isinstance(packet, OpenPGP.Message):
            packet = OpenPGP.LiteralDataPacket(packet)
        else:
            packet = self._parse_packet(packet)

        if isinstance(packet, OpenPGP.SecretKeyPacket) or isinstance(packet, Crypto.PublicKey.RSA._RSAobj) or isinstance(packet, Crypto.PublicKey.DSA._DSAobj) or (hasattr(packet, '__getitem__') and isinstance(packet[0], OpenPGP.SecretKeyPacket)):
            key = packet
            message = self._message
        else:
            key = self._key
            message = packet

        if not key or not message:
            return None # Missing some data

        if isinstance(message, OpenPGP.Message):
            message = message.signature_and_data()[1]

        if not (isinstance(key, Crypto.PublicKey.RSA._RSAobj) or isinstance(packet, Crypto.PublicKey.DSA._DSAobj)):
            key = self.__class__(key)
            if not keyid:
                keyid = key.key().fingerprint()[-16:]
            key = key.private_key(keyid)

        key_algorithm = None
        if isinstance(key, Crypto.PublicKey.RSA._RSAobj):
            key_algorithm = 'RSA'
        elif isinstance(key, Crypto.PublicKey.DSA._DSAobj):
            key_algorithm = 'DSA'

        sig = OpenPGP.SignaturePacket(message, key_algorithm, hash.upper())

        if keyid:
            sig.hashed_subpackets.append(OpenPGP.SignaturePacket.IssuerPacket(keyid))

        def doDSA(h, m):
            return list(key.sign(h.new(m).digest()[0:int(Crypto.Util.number.size(key.q) / 8)],
                Crypto.Random.random.StrongRandom().randint(1,key.q-1)))

        sig.sign_data({'RSA': {
                'MD5':       lambda m: [Crypto.Signature.PKCS1_v1_5.new(key).sign(Crypto.Hash.MD5.new(m))],
                'RIPEMD160': lambda m: [Crypto.Signature.PKCS1_v1_5.new(key).sign(Crypto.Hash.RIPEMD.new(m))],
                'SHA1':      lambda m: [Crypto.Signature.PKCS1_v1_5.new(key).sign(Crypto.Hash.SHA.new(m))],
                'SHA224':    lambda m: [Crypto.Signature.PKCS1_v1_5.new(key).sign(Crypto.Hash.SHA224.new(m))],
                'SHA256':    lambda m: [Crypto.Signature.PKCS1_v1_5.new(key).sign(Crypto.Hash.SHA256.new(m))],
                'SHA384':    lambda m: [Crypto.Signature.PKCS1_v1_5.new(key).sign(Crypto.Hash.SHA384.new(m))],
                'SHA512':    lambda m: [Crypto.Signature.PKCS1_v1_5.new(key).sign(Crypto.Hash.SHA512.new(m))],
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

        sig.sign_data({'RSA': {
                'MD5':       lambda m: [Crypto.Signature.PKCS1_v1_5.new(key).sign(Crypto.Hash.MD5.new(m))],
                'RIPEMD160': lambda m: [Crypto.Signature.PKCS1_v1_5.new(key).sign(Crypto.Hash.RIPEMD.new(m))],
                'SHA1':      lambda m: [Crypto.Signature.PKCS1_v1_5.new(key).sign(Crypto.Hash.SHA.new(m))],
                'SHA224':    lambda m: [Crypto.Signature.PKCS1_v1_5.new(key).sign(Crypto.Hash.SHA224.new(m))],
                'SHA256':    lambda m: [Crypto.Signature.PKCS1_v1_5.new(key).sign(Crypto.Hash.SHA256.new(m))],
                'SHA384':    lambda m: [Crypto.Signature.PKCS1_v1_5.new(key).sign(Crypto.Hash.SHA384.new(m))],
                'SHA512':    lambda m: [Crypto.Signature.PKCS1_v1_5.new(key).sign(Crypto.Hash.SHA512.new(m))],
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
                    data = cipher(b'\0' * key_block_bytes).decrypt(p.encrypted_data + (pad_amount*b'\0'))[:-pad_amount]

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
        cipher = cipher(packet.encrypted_data[:key_block_bytes])
        pad_amount = key_block_bytes - (len(packet.encrypted_data[key_block_bytes:]) % key_block_bytes)
        material = cipher.decrypt(packet.encrypted_data[key_block_bytes:] + (pad_amount*b'\0'))[:-pad_amount]

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
            data = cipher(b'\0' * key_block_bytes).decrypt(epacket.data + (pad_amount*b'\0'))[:-pad_amount]
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
            data = cipher(epacket.data[2:key_block_bytes+2]).decrypt(edata + (pad_amount*b'\0'))[:-pad_amount]
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
                    m.new(k, mode=Crypto.Cipher.blockalgo.MODE_CFB, IV=iv, segment_size=bs*8),
                ks, bs)

        if algo == 2:
            return cipher(Crypto.Cipher.DES3, 24, 8)
        elif algo == 3:
            return cipher(Crypto.Cipher.CAST, 16, 8)
        elif algo == 4:
            return cipher(Crypto.Cipher.Blowfish, 16, 8)
        elif algo == 7:
            return cipher(Crypto.Cipher.AES, 16, 16)
        elif algo == 8:
            return cipher(Crypto.Cipher.AES, 24, 16)
        elif algo == 9:
            return cipher(Crypto.Cipher.AES, 32, 16)

        return (None,None,None) # Not supported

    @classmethod
    def convert_key(cls, packet, private=False):
        if isinstance(packet, Crypto.PublicKey.RSA._RSAobj) or isinstance(packet, Crypto.PublicKey.DSA._DSAobj):
            return packet
        packet = cls._parse_packet(packet)
        if isinstance(packet, OpenPGP.Message):
            packet = packet[0]

        if packet.key_algorithm_name() == 'DSA':
          public = (Crypto.Util.number.bytes_to_long(packet.key['y']),
                    Crypto.Util.number.bytes_to_long(packet.key['g']),
                    Crypto.Util.number.bytes_to_long(packet.key['p']),
                    Crypto.Util.number.bytes_to_long(packet.key['q']))
          if private:
              private = (Crypto.Util.number.bytes_to_long(packet.key['x']),)
              return Crypto.PublicKey.DSA.construct(public + private)
          else:
              return Crypto.PublicKey.DSA.construct(public)
        else: # RSA
          public = (Crypto.Util.number.bytes_to_long(packet.key['n']), Crypto.Util.number.bytes_to_long(packet.key['e']))
          if private:
              private =  (Crypto.Util.number.bytes_to_long(packet.key['d']),)
              if 'p' in packet.key: # Has optional parts
                  private += (Crypto.Util.number.bytes_to_long(packet.key['p']), Crypto.Util.number.bytes_to_long(packet.key['q']), Crypto.Util.number.bytes_to_long(packet.key['u']))
              return Crypto.PublicKey.RSA.construct(public + private)
          else:
              return Crypto.PublicKey.RSA.construct(public)

    @classmethod
    def convert_public_key(cls, packet):
        return cls.convert_key(packet, False)

    @classmethod
    def convert_private_key(cls, packet):
        return cls.convert_key(packet, True)
