from __future__ import absolute_import
import Crypto.PublicKey.RSA
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

class RSA:
    """ A wrapper for using the classes from OpenPGP.py with PyCrypto """
    def __init__(self, packet):
        packet = self._parse_packet(packet)
        self._key = self._message = None
        if isinstance(packet, OpenPGP.PublicKeyPacket) or isinstance(packet[0], OpenPGP.PublicKeyPacket): # If it's a key (other keys are subclasses of this one)
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
        """ Get _RSAobj for the public key """
        return self.convert_public_key(self.key(keyid))

    def private_key(self, keyid=None):
        """ Get _RSAobj for the public key """
        return self.convert_private_key(self.key(keyid))

    def verifier(self, h, m, s):
        """ Used in implementation of verify """
        key = self.public_key(s.issuer())
        if not key:
            return False
        protocol = Crypto.Signature.PKCS1_v1_5.new(key)
        return protocol.verify(h.new(m), s.data[0])

    def verify(self, packet):
        """ Pass a message to verify with this key, or a key (OpenPGP or _RSAobj) to check this message with
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

        return m.verified_signatures({'RSA': {
                'MD5':       lambda m, s: verifier(Crypto.Hash.MD5, m, s),
                'RIPEMD160': lambda m, s: verifier(Crypto.Hash.RIPEMD, m, s),
                'SHA1':      lambda m, s: verifier(Crypto.Hash.SHA, m, s),
                'SHA224':    lambda m, s: verifier(Crypto.Hash.SHA224, m, s),
                'SHA256':    lambda m, s: verifier(Crypto.Hash.SHA256, m, s),
                'SHA384':    lambda m, s: verifier(Crypto.Hash.SHA384, m, s),
                'SHA512':    lambda m, s: verifier(Crypto.Hash.SHA512, m, s),
            }})

    def sign(self, packet, hash='SHA256', keyid=None):
        if self._key and not isinstance(packet, OpenPGP.Packet) and not isinstance(packet, OpenPGP.Message):
            packet = OpenPGP.LiteralDataPacket(packet)
        else:
            packet = self._parse_packet(packet)

        if isinstance(packet, OpenPGP.SecretKeyPacket) or isinstance(packet, Crypto.PublicKey.RSA._RSAobj) or (hasattr(packet, '__getitem__') and isinstance(packet[0], OpenPGP.SecretKeyPacket)):
            key = packet
            message = self.message
        else:
            key = self._key
            message = packet

        if not key or not message:
            return None # Missing some data

        if isinstance(message, OpenPGP.Message):
            message = message.signature_and_data()[1]

        if not isinstance(key, Crypto.PublicKey.RSA._RSAobj):
            key = self.__class__(key)
            if not keyid:
                keyid = key.key().fingerprint()[-16:]
            key = key.private_key(keyid)
        sig = OpenPGP.SignaturePacket(message, 'RSA', hash.upper())
        sig.hashed_subpackets.append(OpenPGP.SignaturePacket.IssuerPacket(keyid))

        sig.sign_data({'RSA': {
                'MD5':       lambda m: [Crypto.Signature.PKCS1_v1_5.new(key).sign(Crypto.Hash.MD5.new(m))],
                'RIPEMD160': lambda m: [Crypto.Signature.PKCS1_v1_5.new(key).sign(Crypto.Hash.RIPEMD.new(m))],
                'SHA1':      lambda m: [Crypto.Signature.PKCS1_v1_5.new(key).sign(Crypto.Hash.SHA.new(m))],
                'SHA224':    lambda m: [Crypto.Signature.PKCS1_v1_5.new(key).sign(Crypto.Hash.SHA224.new(m))],
                'SHA256':    lambda m: [Crypto.Signature.PKCS1_v1_5.new(key).sign(Crypto.Hash.SHA256.new(m))],
                'SHA384':    lambda m: [Crypto.Signature.PKCS1_v1_5.new(key).sign(Crypto.Hash.SHA384.new(m))],
                'SHA512':    lambda m: [Crypto.Signature.PKCS1_v1_5.new(key).sign(Crypto.Hash.SHA512.new(m))],
            }})

        return OpenPGP.Message([sig, message])

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

        sig = packet.signature_and_data()[1]
        if not sig:
            sig = OpenPGP.SignaturePacket(packet, 'RSA', hash.upper())
            sig.signature_type = 0x13
            sig.hashed_subpackets.append(OpenPGP.SignaturePacket.KeyFlagsPacket([0x01]))
            sig.hashed_subpackets.append(OpenPGP.SignaturePacket.IssuerPacket(keyid))
            packet.append(sig)

        sig.sign_data({'RSA': {hash: lambda m: key.sign(self._emsa_pkcs1_v1_5_encode(m, key.size()/8.0, hash), None)[0]}})

        return packet

    @classmethod
    def _parse_packet(cls, packet):
        if isinstance(packet, OpenPGP.Packet) or isinstance(packet, OpenPGP.Message) or isinstance(packet, _RSAobj):
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
    def convert_key(cls, packet, private=False):
        if isinstance(packet, Crypto.PublicKey.RSA._RSAobj):
            return packet
        packet = cls._parse_packet(packet)
        if isinstance(packet, OpenPGP.Message):
            packet = packet[0]

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
