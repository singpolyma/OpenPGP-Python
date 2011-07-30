from __future__ import absolute_import
import Crypto.PublicKey.RSA
import Crypto.Util.number
import OpenPGP
import hashlib, math

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
                    if not keyid or p.fingerprint[len(keyid)*-1:].upper() == keyid.upper():
                        return p
        return self._key

    def public_key(self, keyid=None):
        """ Get RSAobj for the public key """
        return self.convert_public_key(self.key(keyid))

    def private_key(self, keyid=None):
        """ Get RSAobj for the public key """
        return self.convert_private_key(self.key(keyid))

    def _emsa_pkcs1_v1_5_encode(self, m, emLen, hashName):
        """ http://tools.ietf.org/html/rfc3447#section-9.2 """
        emLen = int(math.ceil(emLen))

        # http://tools.ietf.org/html/rfc3447#page-43
        if hashName == 'MD2':
            t = '\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x02\x05\x00\x04\x10'
            pass # TODO
        elif hashName == 'MD5':
            t = '\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10'
            t += hashlib.md5(m).digest()
        elif hashName == 'SHA1':
            t = '\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'
            t += hashlib.sha1(m).digest()
        elif hashName == 'SHA256':
            t = '\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'
            t += hashlib.sha256(m).digest()
        elif hashName == 'SHA384':
            t = '\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30'
            t += hashlib.sha384(m).digest()
        elif hashName == 'SHA512':
            t = '\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40'
            t += hashlib.sha512(m).digest()

        if emLen < len(t) + 11:
            raise 'Intended encoded message length too short'

        ps = '\xff' * (emLen - len(t) - 3)

        a = '\0\1'+ps+'\0'+t
        return a

    def verify(self, packet, index=0):
        """ Pass a message to verify with this key, or a key (OpenPGP or RSAobj) to check this message with
            Second optional parameter to specify which signature to verify (if there is more than one)
        """
        packet = self._parse_packet(packet)
        if isinstance(packet, OpenPGP.Message) and not isinstance(packet[0], OpenPGP.PublicKeyPacket):
            signature_packet, data_packet = packet.signature_and_data(index)
            key = self.public_key(signature_packet.issuer())
            if not key or signature_packet.key_algorithm_name() != 'RSA':
                return None
            return packet.verify({'RSA': {signature_packet.hash_algorithm_name(): \
                                  lambda m,s: key.verify(self._emsa_pkcs1_v1_5_encode(m, key.size()/8.0, signature_packet.hash_algorithm_name()), (Crypto.Util.number.bytes_to_long(s),)) \
                                  }})
        else:
            signature_packet, data_packet = self._message.signature_and_data(index)
            if not self._message or signature_packet.key_algorithm_name() != 'RSA':
                return None
            if not isinstance(packet, Crypto.PublicKey.RSA.RSAobj):
                packet = self.__class__(packet).public_key(signature_packet.issuer())
            return self._message.verify({'RSA': {signature_packet.hash_algorithm_name(): \
                                  lambda m,s: packet.verify(self._emsa_pkcs1_v1_5_encode(m, packet.size()/8.0, signature_packet.hash_algorithm_name()), (Crypto.Util.number.bytes_to_long(s),)) \
                                  }})

    def sign(self, packet, hash='SHA256', keyid=None):
        if self._key and not isinstance(packet, OpenPGP.Packet) and not isinstance(packet, OpenPGP.Message):
            packet = OpenPGP.LiteralDataPacket(packet)
        else:
            packet = self._parse_packet(packet)

        if isinstance(packet, OpenPGP.SecretKeyPacket) or isinstance(packet, Crypto.PublicKey.RSA.RSAobj) or (hasattr(packet, '__getitem__') and isinstance(packet[0], OpenPGP.SecretKeyPacket)):
            key = packet
            message = self.message
        else:
            key = self._key
            message = packet

        if not key or not message:
            return None # Missing some data

        if isinstance(message, OpenPGP.Message):
            message = message.signature_and_data()[1]

        if not isinstance(key, Crypto.PublicKey.RSA.RSAobj):
            key = self.__class__(key)
            if not keyid:
                keyid = key._key.fingerprint()[-16:]
            key = key.private_key(keyid)
        sig = OpenPGP.SignaturePacket(message, 'RSA', hash.upper())
        sig.hashed_subpackets.append(OpenPGP.SignaturePacket.IssuerPacket(keyid))
        sig.sign_data({'RSA': {hash: lambda m: key.sign(self._emsa_pkcs1_v1_5_encode(m, key.size()/8.0, hash), None)[0]}})

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
        if isinstance(packet, OpenPGP.Packet) or isinstance(packet, OpenPGP.Message):
            return packet
        elif isinstance(packet, tuple) or isinstance(packet, list):
            if isinstance(packet[0], long):
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
        if isinstance(packet, Crypto.PublicKey.RSA.RSAobj):
            return packet
        packet = cls._parse_packet(packet)
        if isinstance(packet, OpenPGP.Message):
            packet = packet[0]

        public = (Crypto.Util.number.bytes_to_long(packet.key['n']), Crypto.Util.number.bytes_to_long(packet.key['e']))
        if private:
            private =  (Crypto.Util.number.bytes_to_long(packet.key['d']),)
            if packet.key.has_key('p'): # Has optional parts
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
