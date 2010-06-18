# Pure Python implementation of OpenPGP <http://tools.ietf.org/html/rfc4880>
# Port of openpgp-php <http://github.com/bendiken/openpgp-php>

from struct import pack, unpack
from time import time
from math import floor, log
import zlib, bz2
import hashlib

def bitlength(data):
    """ http://tools.ietf.org/html/rfc4880#section-12.2 """
    return (len(data) - 1) * 8 + int(floor(log(ord(data[0]), 2))) + 1

class Message(object):
    """ Represents an OpenPGP message (set of packets)
        http://tools.ietf.org/html/rfc4880#section-4.1
        http://tools.ietf.org/html/rfc4880#section-11
        http://tools.ietf.org/html/rfc4880#section-11.3
    """
    @classmethod
    def parse(cls, input_data):
        """ http://tools.ietf.org/html/rfc4880#section-4.1
            http://tools.ietf.org/html/rfc4880#section-4.2
        """
        # TODO: support input_data being a file or input stream
        packets = []
        length = len(input_data)
        while length > 0:
            packet, bytes_used = Packet.parse(input_data)
            if packet:
                packets.append(packet)
            if bytes_used and bytes_used > 0:
                input_data = input_data[bytes_used:]
            else: # Parsing is stuck
                break
            length -= bytes_used
        return Message(packets)

    def __init__(self, packets=[]):
        self._packets = packets

    def to_bytes(self):
        b = ''
        for p in self:
            b += p.to_bytes()
        return b

    def signature_and_data(index=0):
        pass # TODO

    def verify(verifiers, index=0):
       """ Function to verify signature number index
           verifiers is an array of callbacks formatted like {'RSA': {'SHA256': CALLBACK}} that take two parameters: message and signature
       """
       pass # TODO

    def __iter__(self):
        return iter(self._packets)

    def __getitem__(self, item):
        return self._packets[item]

class Packet(object):
    """ OpenPGP packet.
        http://tools.ietf.org/html/rfc4880#section-4.1
        http://tools.ietf.org/html/rfc4880#section-4.3
    """

    @classmethod
    def parse(cls, input_data):
        packet = None
        if(len(input_data) > 0):
            if ord(input_data[0]) & 64:
                tag, head_length, data_length = Packet.parse_new_format(input_data)
            else:
                tag, head_length, data_length = Packet.parse_old_format(input_data)
            input_data = input_data[head_length:]
            if tag:
              packet_class = False
              try:
                  packet_class = Packet.tags[tag]

                  packet = packet_class()
                  packet.tag = tag
                  packet.input = input_data[:data_length]
                  packet.length = data_length
                  packet.read()
                  packet.input = None
              except KeyError:
                  """ Eat the error """
        return (packet, head_length + data_length)

    @classmethod
    def parse_new_format(cls, input_data):
       """ Parses a new-format (RFC 4880) OpenPGP packet.
           http://tools.ietf.org/html/rfc4880#section-4.2.2
       """
       tag = ord(input_data[0]) & 63
       length = ord(input_data[1])
       if length < 192: # One octet length
         return (tag, 2, length)
       if length > 191 and length < 224: # Two octet length
         return (tag, 3, ((length - 192) << 8) + ord(input_data[2]) + 192)
       if length == 255: # Five octet length
         return (tag, 6, unpack('!L', input_data[2:4])[0])
       # TODO: Partial body lengths. 1 << ($len & 0x1F)

    @classmethod
    def parse_old_format(cls, input_data):
        """ Parses an old-format (PGP 2.6.x) OpenPGP packet.
            http://tools.ietf.org/html/rfc4880#section-4.2.1
        """
        tag = ord(input_data[0])
        length = tag & 3
        tag = (tag >> 2) & 15
        if length == 0: # The packet has a one-octet length. The header is 2 octets long.
            head_length = 2
            data_length = ord(input_data[1])
        elif length == 1: # The packet has a two-octet length. The header is 3 octets long.
            head_length = 3
            data_length = unpack('!H', input_data[1:3])[0]
        elif length == 2: # The packet has a four-octet length. The header is 5 octets long.
            head_length = 5
            data_length = unpack('!L', input_data[1:4])[0]
        elif length == 3: # The packet is of indeterminate length. The header is 1 octet long.
            head_length = 1
            data_length = len(input_data) - head_length
        return (tag, head_length, data_length)

    def __init__(self, data=None):
        for tag in Packet.tags:
            if Packet.tags[tag] == self.__class__:
                self.tag = tag
                break
        self.data = data

    def read(self):
      """ Implement in subclass """

    def body(self):
        return self.data # Will normally be overridden by subclasses

    def header_and_body(self):
        body = self.body() # Get body first, we will need it's length
        tag = chr(self.tag | 0xC0) # First two bits are 1 for new packet format
        size = chr(255) + pack('!L', body and len(body) or 0) # Use 5-octet lengths
        return {'header': tag + size, 'body': body }

    def to_bytes(self):
        data = self.header_and_body()
        return data['header'] + (data['body'] and data['body'] or '')

    def read_timestamp(self):
        """ ttp://tools.ietf.org/html/rfc4880#section-3.5 """
        return self.read_unpacked(4, '!L')

    def read_mpi(self):
       """ http://tools.ietf.org/html/rfc4880#section-3.2 """
       length = self.read_unpacked(2, '!H') # length in bits
       length = (int)((length + 7) / 8) # length in bytes
       return self.read_bytes(length)

    def read_unpacked(self, count, fmt):
        """ http://docs.python.org/library/struct.html """
        unpacked = unpack(fmt, self.read_bytes(count))
        return unpacked[0] # unpack returns tuple

    def read_byte(self):
      byte = self.read_bytes(1)
      return byte and byte[0] or None

    def read_bytes(self, count=1):
        b = self.input[:count]
        self.input = self.input[count:]
        return b

    tags = {} # Actual data at end of file

class AsymmetricSessionKeyPacket(Packet):
    """ OpenPGP Public-Key Encrypted Session Key packet (tag 1).
        http://tools.ietf.org/html/rfc4880#section-5.1
    """
    pass # TODO

class SignaturePacket(Packet):
    """ OpenPGP Signature packet (tag 2).
        http://tools.ietf.org/html/rfc4880#section-5.2
    """
    def __init__(self, data=None, key_algorithm=None, hash_algorithm=None):
        super(SignaturePacket, self).__init__()
        self.version = 4 # Default to version 4 sigs
        self.hash_algorithm = hash_algorithm
        if isinstance(self.hash_algorithm, str):
            for a in SignaturePacket.hash_algorithms:
                if SignaturePacket.hash_algorithms[a] == self.hash_algorithm:
                    self.hash_algorithm = a
                    break
        self.key_algorithm = key_algorithm
        if isinstance(self.key_algorithm, str):
            for a in PublicKeyPacket.algorithms:
                if PublicKeyPacket.algorithms[a] == self.key_algorithm:
                    self.key_algorithm = a
                    break
        if data: # If we have any data, set up the creation time
            self.hashed_subpackets = [self.CreationTime(time())]
        if isinstance(data, LiteralDataPacket):
            self.signature_type = data.format == 'b' and 0x00 or 0x01
            data.normalize()
            data = data.data
        self.data = data # Store to-be-signed data in here until the signing happens

    def sign_data(self, signers):
        """ self.data must be set to the data to sign (done by constructor)
            signers in the same format as verifiers for Message.
        """
        self.trailer = self.body(True)
        signer = signers[self.key_algorithm_name()][self.hash_algorithm_name()]
        self.data = signer(self.data + self.trailer)
        self.hash_head = unpack('!H', self.data[:2])[0]

    def read(self):
        self.version = ord(self.read_byte())
        if self.version == 3:
            pass # TODO: V3 sigs
        elif self.version == 4:
            self.signature_type = ord(self.read_byte())
            self.key_algorithm = ord(self.read_byte())
            self.hash_algorithm = ord(self.read_byte())
            self.trailer = chr(4) + chr(self.signature_type) + chr(self.key_algorithm) + chr(self.hash_algorithm)

            hashed_size = self.read_unpacked(2, '!H')
            hashed_subpackets = self.read_bytes(hashed_size)
            self.trailer += pack('!H', hashed_size) + hashed_subpackets
            self.hashed_subpackets = self.get_subpackets(hashed_subpackets)

            self.trailer += chr(4) + chr(0xff) + pack('!L', 6 + hashed_size)

            unhashed_size = self.read_unpacked(2, '!H')
            self.unhashed_subpackets = self.get_subpackets(self.read_bytes(unhashed_size))

            self.hash_head = self.read_unpacked(2, '!H')
            self.data = self.read_mpi()

    def body(trailer=False):
        body = chr(4) + chr(self.signature_type) + chr(self.key_algorithm) + chr(self.hash_algorithm)

        hashed_subpackets = ''
        for p in self.hashed_subpackets:
            hashed_subpackets += p.to_bytes()
        body += pack('!H', len(hashed_subpackets)) + hashed_subpackets

        # The trailer is just the top of the body plus some crap
        if trailer:
            return body + chr(4) + chr(0xff) + pack('!L', len(body))

        unhashed_subpackets = ''
        for p in self.unhashed_subpackets:
            unhashed_subpackets += p.to_bytes()
        body += pack('!H', len(unhashed_subpackets)) + unhashed_subpackets

        body += pack('!H', self.hash_head)
        body += pack('!H', len(self.data)*8) + self.data

        return body

    def key_algorithm_name(self):
        return PublicKeyPacket.algorithms[self.key_algorithm]

    def hash_algorithm_name(self):
        return self.hash_algorithms[self.hash_algorithm]

    def issuer(self):
        for p in self.hashed_subpackets:
            if isinstance(p, self.IssuerPacket):
                return p.data
        for p in self.unhashed_subpackets:
            if isinstance(p, self.IssuerPacket):
                return p.data
        return None

    @classmethod
    def get_subpackets(cls, input_data):
        subpackets = []
        length = len(input_data)
        while length > 0:
            subpacket, bytes_used = cls.get_subpacket(input_data)
            if bytes_used > 0:
                subpackets.append(subpacket)
                input_data = input_data[bytes_used:]
                length -= bytes_used
            else: # Parsing stuck?
                break
        return subpackets

    @classmethod
    def get_subpacket(cls, input_data):
        length = ord(input_data[0])
        length_of_length = 1
        # if($len < 192) One octet length, no furthur processing
        if length > 190 and length < 255: # Two octet length
            length_of_length = 2
            length = ((length - 192) << 8) + ord(input_data[1]) + 192
        if length == 255: # Five octet length
            length_of_length = 5
            length = unpack('!L', input_data[1:4])[0]
        input_data = input_data[length_of_length:] # Chop off length header
        tag = ord(input_data[0])
        try:
            klass = cls.subpacket_types[tag]

            packet = klass()
            packet.tag = tag
            packet.input = input_data[1:length]
            packet.length = length-1
            packet.read()
            packet.input = None
        except KeyError:
            packet = None # Eat error
        input_data = input_data[length:] # Chop off the data from this packet
        return (packet, length_of_length + length)

    class Subpacket(Packet):
        def __init__(self, data=None):
             super(SignaturePacket.Subpacket, self).__init__()
             for tag in SignaturePacket.subpacket_types:
                 if SignaturePacket.subpacket_types[tag] == self.__class__:
                     self.tag = tag
                     break

        def header_and_body(self):
            body = self.body() # Get body first, we'll need its length
            size = chr(255) + pack('!L', len(body)+1) # Use 5-octet lengths + 1 for tag as first packet body octet
            tag = chr(self.tag)
            return {'header': size + tag, 'body': body}

    class SignatureCreationTimePacket(Subpacket):
        """ http://tools.ietf.org/html/rfc4880#section-5.2.3.4 """
        def read(self):
            self.data = self.read_timestamp()

        def body(self):
            return pack('!L', self.data)

    class SignatureExpirationTimePacket(Subpacket):
        def read(self):
            self.data = self.read_timestamp()

        def body(self):
            return pack('!L', self.data)

    class ExportableCertificationPacket(Subpacket):
        pass # TODO

    class TrustSignaturePacket(Subpacket):
        pass # TODO

    class RegularExpressionPacket(Subpacket):
        pass # TODO

    class RevocablePacket(Subpacket):
        pass # TODO

    class KeyExpirationTimePacket(Subpacket):
        def read(self):
            self.data = self.read_timestamp()

        def body(self):
            return pack('!L', self.data)

    class PreferredSymmetricAlgorithmsPacket(Subpacket):
        pass # TODO

    class RevocationKeyPacket(Subpacket):
        pass # TODO

    class IssuerPacket(Subpacket):
        """ http://tools.ietf.org/html/rfc4880#section-5.2.3.5 """
        def read(self):
            self.data = ''
            for i in range(0, 8): # Store KeyID in Hex
                self.data += '%02X' % ord(self.read_byte())

        def body(self):
            b = ''
            for i in range(0, len(self.data), 2):
                b += chr(int(self.data[i] + self.data[i+1], 16))
            return b

    class NotationDataPacket(Subpacket):
        pass # TODO

    class PreferredHashAlgorithmsPacket(Subpacket):
        pass # TODO

    class PreferredCompressionAlgorithmsPacket(Subpacket):
        pass # TODO

    class KeyServerPreferencesPacket(Subpacket):
        pass # TODO

    class PreferredKeyServerPacket(Subpacket):
        pass # TODO

    class PrimaryUserIDPacket(Subpacket):
        pass # TODO

    class PolicyURIPacket(Subpacket):
        pass # TODO

    class KeyFlagsPacket(Subpacket):
        pass # TODO

    class SignersUserIDPacket(Subpacket):
        pass # TODO

    class ReasonforRevocationPacket(Subpacket):
        pass # TODO

    class FeaturesPacket(Subpacket):
        pass # TODO

    class SignatureTargetPacket(Subpacket):
        pass # TODO

    hash_algorithms = {
        1: 'MD5',
        2: 'SHA1',
        3: 'RIPEMD160',
        8: 'SHA256',
        9: 'SHA384',
        10: 'SHA512',
        11: 'SHA224'
    }

    subpacket_types = {
        2: SignatureCreationTimePacket,
        3: SignatureExpirationTimePacket,
        4: ExportableCertificationPacket,
        5: TrustSignaturePacket,
        6: RegularExpressionPacket,
        7: RevocablePacket,
        9: KeyExpirationTimePacket,
        11: PreferredSymmetricAlgorithmsPacket,
        12: RevocationKeyPacket,
        16: IssuerPacket,
        20: NotationDataPacket,
        21: PreferredHashAlgorithmsPacket,
        22: PreferredCompressionAlgorithmsPacket,
        23: KeyServerPreferencesPacket,
        24: PreferredKeyServerPacket,
        25: PrimaryUserIDPacket,
        26: PolicyURIPacket,
        27: KeyFlagsPacket,
        28: SignersUserIDPacket,
        29: ReasonforRevocationPacket,
        30: FeaturesPacket,
        31: SignatureTargetPacket
    }

class EmbeddedSignaturePacket(SignaturePacket.Subpacket, SignaturePacket):
    pass

SignaturePacket.subpacket_types[32] = SignaturePacket.EmbeddedSignaturePacket = EmbeddedSignaturePacket

class SymmetricSessionKeyPacket(Packet):
    """ OpenPGP Symmetric-Key Encrypted Session Key packet (tag 3).
        http://tools.ietf.org/html/rfc4880#section-5.3
    """
    pass # TODO

class OnePassSignaturePacket(Packet):
    """ OpenPGP One-Pass Signature packet (tag 4).
        http://tools.ietf.org/html/rfc4880#section-5.4
    """
    def read(self):
        self.version = ord(self.read_byte())
        self.signature_type = ord(self.read_byte())
        self.hash_algorithm = ord(self.read_byte())
        self.key_algorithm = ord(self.read_byte())
        self.key_id = ''
        for i in range(0, 8): # Store KeyID in Hex
          self.key_id += '%02X' % ord(self.read_byte())
        self.nested = ord(self.read_byte())

    def body(self):
        body = chr(self.version) + chr(self.signature_type) + chr(self.hash_algorithm) + chr(self.key_algorithm)
        for i in range(0, len(self.key_id), 2):
          body += chr(int(self.key_id[i] + self.key_id[i+1], 16))
        body += chr(int(self.nested))
        return body

class PublicKeyPacket(Packet):
    """ OpenPGP Public-Key packet (tag 6).
        http://tools.ietf.org/html/rfc4880#section-5.5.1.1
        http://tools.ietf.org/html/rfc4880#section-5.5.2
        http://tools.ietf.org/html/rfc4880#section-11.1
        http://tools.ietf.org/html/rfc4880#section-12
    """
    def self_signatures(self, message):
        """ Find self signatures in a message, these often contain metadata about the key """
        sigs = []
        keyid16 = self.fingerprint[-16:].upper()
        for p in message:
            if isinstance(p, SignaturePacket):
                if(p.issuer() == keyid16):
                    sigs.append(p)
                else:
                    packets = p.hashed_subpackets + p.unhashed_subpackets
                    for s in packets:
                        if isinstance(s, SignaturePacket.EmbeddedSignaturePacket) and s.issuer().upper() == keyid16:
                            sigs.append(p)
                            break
            elif len(sigs) > 0:
                break # After we've seen a self sig, the next non-sig stop all self-sigs
        return sigs

    def expires(self, message):
        """ Find expiry time of this key based on the self signatures in a message """
        for p in self.self_signatures(message):
            packets = p.hashed_subpackets + p.unhashed_subpackets
            for s in packets:
                if isinstance(s, SignaturePacket.KeyExpirationTimePacket):
                    return self.timestamp + s.data
        return None # Never expires

    def read(self):
        """ http://tools.ietf.org/html/rfc4880#section-5.5.2 """
        self.version = ord(self.read_byte())
        if self.version == 2 or self.version == 3:
            return False # TODO
        elif self.version == 4:
            self.timestamp = self.read_timestamp()
            self.algorithm = ord(self.read_byte())
            self.read_key_material()
            return True

    def read_key_material(self):
        self.key = {}
        for field in self.key_fields[self.algorithm]:
            self.key[field] = self.read_mpi()
        self.key_id = self.fingerprint()[-8:]

    def fingerprint(self):
        """ http://tools.ietf.org/html/rfc4880#section-12.2
            http://tools.ietf.org/html/rfc4880#section-3.3
        """
        if self.version == 2 or self.version == 3:
            self.fingerprint = hashlib.md5(self.key['n'] + self.key['e']).hexdigest().upper()
        elif self.version == 4:
            head = [chr(0x99), None, chr(self.version), pack('!L', self.timestamp), chr(self.algorithm)]
            material = ''
            for i in self.key_fields[self.algorithm]:
                material += pack('!H', bitlength(self.key[i]))
                material += self.key[i]
            head[1] = pack('!H', 6 + len(material))
            self.fingerprint = hashlib.sha1(''.join(head) + material).hexdigest().upper()
        return self.fingerprint

    key_fields = {
        1: ['n', 'e'],          # RSA
       16: ['p', 'g', 'y'],     # ELG-E
       17: ['p', 'q', 'g', 'y'] # DSA
    }

    algorithms = {
        1: 'RSA',
        2: 'RSA',
        3: 'RSA',
       16: 'ELGAMAL',
       17: 'DSA',
       18: 'ECC',
       19: 'ECDSA',
       21: 'DH'
    }

class PublicSubkeyPacket(PublicKeyPacket):
    """ OpenPGP Public-Subkey packet (tag 14).
        http://tools.ietf.org/html/rfc4880#section-5.5.1.2
        http://tools.ietf.org/html/rfc4880#section-5.5.2
        http://tools.ietf.org/html/rfc4880#section-11.1
        http://tools.ietf.org/html/rfc4880#section-12
    """
    pass # TODO

class SecretKeyPacket(Packet):
    """ OpenPGP Secret-Key packet (tag 5).
        http://tools.ietf.org/html/rfc4880#section-5.5.1.3
        http://tools.ietf.org/html/rfc4880#section-5.5.3
        http://tools.ietf.org/html/rfc4880#section-11.2
        http://tools.ietf.org/html/rfc4880#section-12
    """
    pass # TODO

class SecretSubkeyPacket(Packet):
    """ OpenPGP Secret-Subkey packet (tag 7).
        http://tools.ietf.org/html/rfc4880#section-5.5.1.4
        http://tools.ietf.org/html/rfc4880#section-5.5.3
        http://tools.ietf.org/html/rfc4880#section-11.2
        http://tools.ietf.org/html/rfc4880#section-12
    """
    pass # TODO

class CompressedDataPacket(Packet):
    """ OpenPGP Compressed Data packet (tag 8).
        http://tools.ietf.org/html/rfc4880#section-5.6
    """
    # http://tools.ietf.org/html/rfc4880#section-9.3
    algorithms = {0: 'Uncompressed', 1: 'ZIP', 2: 'ZLIB', 3: 'BZip2'}

    def read(self):
        self.algorithm = ord(self.read_byte())
        self.data = self.read_bytes(self.length)
        if self.algorithm == 0:
            self.data = Message.parse(self.data)
        elif self.algorithm == 1:
            self.data = Message.parse(zlib.decompress(self.data, -15))
        elif self.algorithm == 2:
            self.data = Message.parse(zlib.decompress(self.data))
        elif self.algorithm == 3:
            self.data = Message.parse(bz2.decompress(self.data))
        else:
            pass # TODO: error?

    def body(self):
        body = chr(self.algorithm)
        if self.algorithm == 0:
            self.data = self.data.to_bytes()
        elif self.algorithm == 1:
            compressor = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
            body += compressor.compress(self.data.to_bytes())
            body += compressor.flush()
        elif self.algorithm == 2:
            body += zlib.compress(self.data.to_bytes())
        elif self.algorithm == 3:
            body += bz2.compress(self.data.to_bytes())
        else:
            pass # TODO: error?
        return body

    def __iter__(self):
        return iter(self.data)

    def __getitem__(self, item):
        return self.data[item]

class EncryptedDataPacket(Packet):
    """ OpenPGP Symmetrically Encrypted Data packet (tag 9).
        http://tools.ietf.org/html/rfc4880#section-5.7
    """
    pass # TODO

class MarkerPacket(Packet):
    """ OpenPGP Marker packet (tag 10).
        http://tools.ietf.org/html/rfc4880#section-5.8
    """
    pass # TODO

class LiteralDataPacket(Packet):
    """ OpenPGP Literal Data packet (tag 11).
        http://tools.ietf.org/html/rfc4880#section-5.9
    """
    def __init__(self, data=None, format='b', filename='data', timestamp=time()):
        self.data = data
        self.format = format
        self.filename = filename
        self.timestamp = timestamp

    def normalize(self):
        if self.format == 'u' or self.format == 't': # Normalize line endings
            self.data = self.data.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")

    def read(self):
        self.size = self.length - 1 - 4
        self.format = self.read_byte()
        filename_length = ord(self.read_byte())
        self.size -= filename_length
        self.filename = self.read_bytes(filename_length)
        self.timestamp = self.read_timestamp()
        self.data = self.read_bytes(self.size)

    def body(self):
        return self.format + chr(len(self.filename)) + self.filename + pack('!L', self.timestamp) + self.data

class TrustPacket(Packet):
    """ OpenPGP Trust packet (tag 12).
        http://tools.ietf.org/html/rfc4880#section-5.10
    """
    pass # TODO

class UserIDPacket(Packet):
    """ OpenPGP User ID packet (tag 13).
        http://tools.ietf.org/html/rfc4880#section-5.11
        http://tools.ietf.org/html/rfc2822
    """
    pass # TODO

class UserAttributePacket(Packet):
    """ OpenPGP User Attribute packet (tag 17).
        http://tools.ietf.org/html/rfc4880#section-5.12
        http://tools.ietf.org/html/rfc4880#section-11.1
    """
    pass # TODO

class IntegrityProtectedDataPacket(Packet):
    """ OpenPGP Sym. Encrypted Integrity Protected Data packet (tag 18).
        http://tools.ietf.org/html/rfc4880#section-5.13
    """
    pass # TODO

class ModificationDetectionCodePacket(Packet):
    """ OpenPGP Modification Detection Code packet (tag 19).
        http://tools.ietf.org/html/rfc4880#section-5.14
    """
    pass # TODO

class ExperimentalPacket(Packet):
    """ OpenPGP Private or Experimental packet (tags 60..63).
        http://tools.ietf.org/html/rfc4880#section-4.3
    """
    pass # TODO

Packet.tags = {
     1: AsymmetricSessionKeyPacket, # Public-Key Encrypted Session Key
     2: SignaturePacket, # Signature Packet
     3: SymmetricSessionKeyPacket, # Symmetric-Key Encrypted Session Key Packet
     4: OnePassSignaturePacket, # One-Pass Signature Packet
     5: SecretKeyPacket, # Secret-Key Packet
     6: PublicKeyPacket, # Public-Key Packet
     7: SecretSubkeyPacket, # Secret-Subkey Packet
     8: CompressedDataPacket, # Compressed Data Packet
     9: EncryptedDataPacket, # Symmetrically Encrypted Data Packet
    10: MarkerPacket, # Marker Packet
    11: LiteralDataPacket, # Literal Data Packet
    12: TrustPacket, # Trust Packet
    13: UserIDPacket, # User ID Packet
    14: PublicSubkeyPacket, # Public-Subkey Packet
    17: UserAttributePacket, # User Attribute Packet
    18: IntegrityProtectedDataPacket, # Sym. Encrypted and Integrity Protected Data Packet
    19: ModificationDetectionCodePacket, # Modification Detection Code Packet
    60: ExperimentalPacket, # Private or Experimental Values
    61: ExperimentalPacket, # Private or Experimental Values
    62: ExperimentalPacket, # Private or Experimental Values
    63: ExperimentalPacket, # Private or Experimental Values
}
