# Pure Python implementation of OpenPGP <http://tools.ietf.org/html/rfc4880>
# Port of openpgp-php <http://github.com/bendiken/openpgp-php>

from struct import pack, unpack
from time import time
from math import floor, log
import zlib, bz2
import hashlib
import re

def bitlength(data):
    """ http://tools.ietf.org/html/rfc4880#section-12.2 """
    return (len(data) - 1) * 8 + int(floor(log(ord(data[0:1]), 2))) + 1

def decode_s2k_count(c):
    return int(16 + (c & 15)) << ((c >> 4) + 6)

def encode_s2k_count(iterations):
    if iterations >= 65011712:
        return 255

    count = iterations >> 6
    c = 0
    while count >= 32:
        count = count >> 1
        c += 1

    result = (c << 4) | (count - 16)

    if decode_s2k_count(result) < iterations:
        return result + 1

    return result

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
        b = b''
        for p in self:
            b += p.to_bytes()
        return b

    def signature_and_data(self, index=0):
        msg = self
        while isinstance(msg[0], CompressedDataPacket):
            msg = msg[0]

        i = 0
        signature_packet = data_packet = None
        for p in msg:
            if isinstance(p, SignaturePacket):
                if i == index:
                    signature_packet = p
                i += 1
            elif isinstance(p, LiteralDataPacket):
                data_packet = p
            if signature_packet and data_packet:
                break

        return (signature_packet, data_packet)

    def verify(self, verifiers, index=0):
       """ Function to verify signature number index
           verifiers is an array of callbacks formatted like {'RSA': {'SHA256': CALLBACK}} that take two parameters: message and signature
       """
       signature_packet, data_packet = self.signature_and_data(index)
       if not signature_packet or not data_packet:
           return None # No signature or no data

       verifier = verifiers[signature_packet.key_algorithm_name()][signature_packet.hash_algorithm_name()]
       if not verifier:
           return None # No verifier

       data_packet.normalize()
       return verifier(data_packet.data + signature_packet.trailer, signature_packet.data)

    def __iter__(self):
        return iter(self._packets)

    def __getitem__(self, item):
        return self._packets[item]

    def append(self, item):
        self._packets.append(item)

    def __repr__(self):
        return "%s: %s" % (type(self), self.__dict__.__repr__())

    def __eq__(self, other):
        if type(other) is type(self):
            return self.__dict__ == other.__dict__
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

class Packet(object):
    """ OpenPGP packet.
        http://tools.ietf.org/html/rfc4880#section-4.1
        http://tools.ietf.org/html/rfc4880#section-4.3
    """

    @classmethod
    def parse(cls, input_data):
        packet = None
        if len(input_data) > 0:
            if ord(input_data[0:1]) & 64:
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
                  packet.length = None
              except KeyError:
                  """ Eat the error """
        return (packet, head_length + data_length)

    @classmethod
    def parse_new_format(cls, input_data):
       """ Parses a new-format (RFC 4880) OpenPGP packet.
           http://tools.ietf.org/html/rfc4880#section-4.2.2
       """
       tag = ord(input_data[0:1]) & 63
       length = ord(input_data[1:2])
       if length < 192: # One octet length
         return (tag, 2, length)
       if length > 191 and length < 224: # Two octet length
         return (tag, 3, ((length - 192) << 8) + ord(input_data[2:3]) + 192)
       if length == 255: # Five octet length
         return (tag, 6, unpack('!L', input_data[2:6])[0])
       # TODO: Partial body lengths. 1 << ($len & 0x1F)

    @classmethod
    def parse_old_format(cls, input_data):
        """ Parses an old-format (PGP 2.6.x) OpenPGP packet.
            http://tools.ietf.org/html/rfc4880#section-4.2.1
        """
        tag = ord(input_data[0:1])
        length = tag & 3
        tag = (tag >> 2) & 15
        if length == 0: # The packet has a one-octet length. The header is 2 octets long.
            head_length = 2
            data_length = ord(input_data[1:2])
        elif length == 1: # The packet has a two-octet length. The header is 3 octets long.
            head_length = 3
            data_length = unpack('!H', input_data[1:3])[0]
        elif length == 2: # The packet has a four-octet length. The header is 5 octets long.
            head_length = 5
            data_length = unpack('!L', input_data[1:5])[0]
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
        tag = pack('!B', self.tag | 0xC0) # First two bits are 1 for new packet format
        size = pack('!B', 255) + pack('!L', body and len(body) or 0) # Use 5-octet lengths
        return {'header': tag + size, 'body': body }

    def to_bytes(self):
        data = self.header_and_body()
        return data['header'] + (data['body'] and data['body'] or b'')

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
      return byte and byte[0:1] or None

    def read_bytes(self, count=1):
        b = self.input[:count]
        self.input = self.input[count:]
        return b

    tags = {} # Actual data at end of file

    def __repr__(self):
        return "%s: %s" % (type(self), self.__dict__.__repr__())

    def __eq__(self, other):
        if type(other) is type(self):
            return self.__dict__ == other.__dict__
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

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
        self.hashed_subpackets = self.unhashed_subpackets = []
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
            self.hashed_subpackets = [self.SignatureCreationTimePacket(time())]
        if isinstance(data, LiteralDataPacket):
            self.signature_type = data.format != 'b' and 0x01 or 0x00
            data.normalize()
            data = data.data
        elif hasattr(data, 'encode'):
            data = data.encode('utf-8')
        elif isinstance(data, Message) and isinstance(data[0], PublicKeyPacket):
            # data is a message with PublicKey first, UserID second
            key = ''.join(data[0].fingerprint_material())
            user_id = data[1].body()
            data = key + pack('!B', 0xB4) + pack('!L', len(user_id)) + user_id
        self.data = data # Store to-be-signed data in here until the signing happens

    def sign_data(self, signers):
        """ self.data must be set to the data to sign (done by constructor)
            signers in the same format as verifiers for Message.
        """
        self.trailer = self.body(True)
        signer = signers[self.key_algorithm_name()][self.hash_algorithm_name()]
        self.data = signer(self.data + self.trailer)
        if isinstance(self.data, long):
            data = '%02X' % self.data
            self.data = ''
            for i in range(0, len(data), 2):
                self.data += pack('!B', int(data[i:i+2], 16))
        self.hash_head = unpack('!H', self.data[0:2])[0]

    def read(self):
        self.version = ord(self.read_byte())
        if self.version == 2 or self.version == 3:
            assert(ord(self.read_byte()) == 5);
            self.signature_type = ord(self.read_byte())
            creation_type = this.read_timestamp()
            keyid = self.read_bytes(8)
            keyidHex = '';
            for i in range(0, len(keyid)): # Store KeyID in Hex
                keyidHex += '%02X' % ord(keyid[i:i+1])

            self.hashed_subpackets = []
            self.unhashed_subpackets = [
                SignaturePacket.SignatureCreationTimePacket(creation_time),
                SignaturePacket.IssuerPacket(keyidHex)
            ]

            self.key_algorithm = ord(self.read_byte())
            self.hash_algorithm = ord(self.read_byte())
            self.hash_head = self.read_unpacked(2, '!H')
            self.data = []
            while len(self.input > 0):
                self.data += [self.read_mpi()]
        elif self.version == 4:
            self.signature_type = ord(self.read_byte())
            self.key_algorithm = ord(self.read_byte())
            self.hash_algorithm = ord(self.read_byte())
            self.trailer = pack('!B', 4) + pack('!B', self.signature_type) + pack('!B', self.key_algorithm) + pack('!B', self.hash_algorithm)

            hashed_size = self.read_unpacked(2, '!H')
            hashed_subpackets = self.read_bytes(hashed_size)
            self.trailer += pack('!H', hashed_size) + hashed_subpackets
            self.hashed_subpackets = self.get_subpackets(hashed_subpackets)

            self.trailer += pack('!B', 4) + pack('!B', 0xff) + pack('!L', 6 + hashed_size)

            unhashed_size = self.read_unpacked(2, '!H')
            self.unhashed_subpackets = self.get_subpackets(self.read_bytes(unhashed_size))

            self.hash_head = self.read_unpacked(2, '!H')
            self.data = self.read_mpi()

    def calculate_trailer(self):
        # The trailer is just the top of the body plus some crap
        return self.body_start() + pack('!B', 4) + pack('!B', 0xff) + pack('!L', len(body))

    def body_start(self):
        body = pack('!B', 4) + pack('!B', self.signature_type) + pack('!B', self.key_algorithm) + pack('!B', self.hash_algorithm)

        hashed_subpackets = ''
        for p in self.hashed_subpackets:
            hashed_subpackets += p.to_bytes()
        body += pack('!H', len(hashed_subpackets)) + hashed_subpackets

        return body

    def body(self, trailer=False):
        if self.version == 2 or self.version == 3:
            body = pack('!B', self.version) + pack('!B', 5) + pack('!B', self.signature_type)

            for p in self.unhashed_subpackets:
                if isinstance(p, SignaturePacket.SignatureCreationTimePacket):
                    body += pack('!L', p.data)
                    break

            for p in self.unhashed_subpackets:
                if isinstance(p, SignaturePacket.IssuerPacket):
                    for i in range(0, len(p.data), 2):
                        body += pack('!B', int(p.data[i:i+2], 16))
                    break

            body += pack('!B', self.key_algorithm)
            body += pack('!B', self.hash_algorithm)
            body += pack('!H', self.hash_head)

            for mpi in self.data:
                body += pack('!H', bitlength(mpi)) + mpi

            return body
        else:
            if not self.trailer:
                self.trailer = self.calculate_trailer()
            body = self.trailer[0:-6]

            unhashed_subpackets = b''
            for p in self.unhashed_subpackets:
                unhashed_subpackets += p.to_bytes()
            body += pack('!H', len(unhashed_subpackets)) + unhashed_subpackets

            body += pack('!H', self.hash_head)
            body += pack('!H', bitlength(self.data)) + self.data

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
        length = ord(input_data[0:1])
        length_of_length = 1
        # if($len < 192) One octet length, no furthur processing
        if length > 190 and length < 255: # Two octet length
            length_of_length = 2
            length = ((length - 192) << 8) + ord(input_data[1:2]) + 192
        if length == 255: # Five octet length
            length_of_length = 5
            length = unpack('!L', input_data[1:5])[0]
        input_data = input_data[length_of_length:] # Chop off length header
        tag = ord(input_data[0:1])
        try:
            klass = cls.subpacket_types[tag]

            packet = klass()
            packet.tag = tag
            packet.input = input_data[1:length]
            packet.length = length-1
            packet.read()
            packet.input = None
            packet.length = None
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
            body = self.body() or '' # Get body first, we'll need its length
            size = pack('!B', 255) + pack('!L', len(body)+1) # Use 5-octet lengths + 1 for tag as first packet body octet
            tag = pack('!B', self.tag)
            return {'header': size + tag, 'body': body}

    class SignatureCreationTimePacket(Subpacket):
        """ http://tools.ietf.org/html/rfc4880#section-5.2.3.4 """
        def __init__(self, time=time()):
            super(SignaturePacket.SignatureCreationTimePacket, self).__init__()
            self.data = time

        def read(self):
            self.data = self.read_timestamp()

        def body(self):
            return pack('!L', int(self.data))

    class SignatureExpirationTimePacket(Subpacket):
        def read(self):
            self.data = self.read_timestamp()

        def body(self):
            return pack('!L', self.data)

    class ExportableCertificationPacket(Subpacket):
        def read(self):
            self.data = ord(self.input) != 0

        def body(self):
            return pack('!B', self.data and 1 or 0)

    class TrustSignaturePacket(Subpacket):
        def read(self):
            self.depth = ord(self.input[0:1])
            self.trust = ord(self.input[1:2])

        def body(self):
            return pack('!B', self.depth) + pack('!B', self.trust)

    class RegularExpressionPacket(Subpacket):
        def read(self):
            self.data = self.input[0:-1]

        def body(self):
            return self.data + pack('!B', 0)

    class RevocablePacket(Subpacket):
        def read(self):
            self.data = ord(self.input) != 0

        def body(self):
            return pack('!B', self.data and 1 or 0)

    class KeyExpirationTimePacket(Subpacket):
        def read(self):
            self.data = self.read_timestamp()

        def body(self):
            return pack('!L', self.data)

    class PreferredSymmetricAlgorithmsPacket(Subpacket):
        def read(self):
            self.data = []
            while len(self.input) > 0:
                self.data += [self.read_byte()]

        def body(self):
            body = b''
            for algo in self.data:
                body += pack('!B', algo)
            return body

    class RevocationKeyPacket(Subpacket):
        def read(self):
            # bitfield must have bit 0x80 set, says the spec
            bitfield = ord(self.read_byte())
            self.sensitive = bitfield & 0x40 == 0x40
            self.key_algorithm = ord(self.read_byte())

            self.fingerprint = ''
            while len(self.input) > 0:
                self.fingerprint += '%02X' % ord(self.read_byte())

        def body(self):
            body = b''
            body += pack('!B', 0x80 | (self.sensitive and 0x40 or 0x00))
            body += pack('!B', self.key_algorithm)

            for i in range(0, len(self.data), 2):
                body += pack('!B', int(self.data[i] + self.data[i+1], 16))

            return body

    class IssuerPacket(Subpacket):
        """ http://tools.ietf.org/html/rfc4880#section-5.2.3.5 """
        def __init__(self, keyid=None):
            super(SignaturePacket.IssuerPacket, self).__init__()
            self.data = keyid

        def read(self):
            self.data = ''
            for i in range(0, 8): # Store KeyID in Hex
                self.data += '%02X' % ord(self.read_byte())

        def body(self):
            b = b''
            for i in range(0, len(self.data), 2):
                b += pack('!B', int(self.data[i] + self.data[i+1], 16))
            return b

    class NotationDataPacket(Subpacket):
        def read(self):
            flags = self.read_bytes(4)
            namelen = self.read_unpacked(2, '!H')
            datalen = self.read_unpacked(2, '!H')
            self.human_readable = ord(flags[0:1]) & 0x80 == 0x80
            self.name = self.read_bytes(namelen).decode('utf-8')
            self.data = self.read_bytes(datalen)
            if self.human_readable:
                self.data = self.data.decode('utf-8')

        def body(self):
            name_bytes = self.name.encode('utf-8')
            data_bytes = self.data
            if self.human_readable:
                data_bytes = data_bytes.encode('utf-8')
            return pack('!B', self.human_readable and 0x80 or 0x00) + b'\0\0\0' + \
                pack('!H', len(name_bytes)) + pack('!H', len(data_bytes)) + \
                name_bytes + data_bytes

    class PreferredHashAlgorithmsPacket(Subpacket):
        def read(self):
            self.data = []
            while len(self.input) > 0:
                self.data += [self.read_byte()]

        def body(self):
            body = b''
            for algo in self.data:
                body += pack('!B', algo)
            return body

    class PreferredCompressionAlgorithmsPacket(Subpacket):
        def read(self):
            self.data = []
            while len(self.input) > 0:
                self.data += [self.read_byte()]

        def body(self):
            body = b''
            for algo in self.data:
                body += pack('!B', algo)
            return body

    class KeyServerPreferencesPacket(Subpacket):
        def read(self):
            flags = ord(self.read_byte())
            self.no_modify = flags & 0x80 == 0x80

        def body(self):
            return pack('!B', self.no_modify and 0x80 or 0x00)

    class PreferredKeyServerPacket(Subpacket):
        def read(self):
            self.data = self.input

        def body(self):
            return self.data

    class PrimaryUserIDPacket(Subpacket):
        def read(self):
            self.data = ord(self.input) != 0

        def body(self):
            return pack('!B', self.data and 1 or 0)

    class PolicyURIPacket(Subpacket):
        def read(self):
            self.data = self.input

        def body(self):
            return self.data

    class KeyFlagsPacket(Subpacket):
        def __init__(self, flags=[]):
            super(SignaturePacket.KeyFlagsPacket, self).__init__()
            self.flags = flags

        def read(self):
          self.flags = []
          while len(self.input) > 0:
              self.flags.append(ord(self.read_byte()))

        def body(self):
            b = ''
            for f in self.flags:
                b += pack('!B', f)
            return b

    class SignersUserIDPacket(Subpacket):
        def read(self):
            self.data = self.input

        def body(self):
            return self.data

    class ReasonforRevocationPacket(Subpacket):
        def read(self):
            self.code = ord(self.read_byte())
            self.data = self.input

        def body(self):
            return pack('!B', self.code) + self.data

    class FeaturesPacket(KeyFlagsPacket):
        pass # All implemented in parent

    class SignatureTargetPacket(Subpacket):
        def read(self):
            self.key_algorithm = ord(self.read_byte())
            self.hash_algorithm = ord(self.read_byte())
            self.data = self.input

        def body(self):
            return pack('!B', self.key_algorithm) + pack('!B', self.hash_algorithm) + self.data

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
        body = pack('!B', self.version) + pack('!B', self.signature_type) + pack('!B', self.hash_algorithm) + pack('!B', self.key_algorithm)
        for i in range(0, len(self.key_id), 2):
          body += pack('!B', int(self.key_id[i] + self.key_id[i+1], 16))
        body += pack('!B', int(self.nested))
        return body

class PublicKeyPacket(Packet):
    """ OpenPGP Public-Key packet (tag 6).
        http://tools.ietf.org/html/rfc4880#section-5.5.1.1
        http://tools.ietf.org/html/rfc4880#section-5.5.2
        http://tools.ietf.org/html/rfc4880#section-11.1
        http://tools.ietf.org/html/rfc4880#section-12
    """
    def __init__(self, keydata=None, version=4, algorithm=1, timestamp=time()):
        super(PublicKeyPacket, self).__init__()
        self._fingerprint = None
        self.version = version
        self.algorithm = algorithm
        self.timestamp = int(timestamp)
        if isinstance(keydata, tuple) or isinstance(keydata, list):
            self.key = {}
            for i in range(0, min(len(keydata), len(self.key_fields[self.algorithm]))):
                 self.key[self.key_fields[self.algorithm][i]] = keydata[i]
        else:
            self.key = keydata

    def self_signatures(self, message):
        """ Find self signatures in a message, these often contain metadata about the key """
        sigs = []
        keyid16 = self.fingerprint()[-16:].upper()
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

    def fingerprint_material(self):
        if self.version == 2 or self.version == 3:
            return [self.key['n'], self.key['e']]
        elif self.version == 4:
            head = [pack('!B', 0x99), None, pack('!B', self.version), pack('!L', self.timestamp), pack('!B', self.algorithm)]
            material = b''
            for i in self.key_fields[self.algorithm]:
                material += pack('!H', bitlength(self.key[i]))
                material += self.key[i]
            head[1] = pack('!H', 6 + len(material))
            return head + [material]

    def fingerprint(self):
        """ http://tools.ietf.org/html/rfc4880#section-12.2
            http://tools.ietf.org/html/rfc4880#section-3.3
        """
        if self._fingerprint:
            return self._fingerprint
        if self.version == 2 or self.version == 3:
            self._fingerprint = hashlib.md5(b''.join(self.fingerprint_material())).hexdigest().upper()
        elif self.version == 4:
            self._fingerprint = hashlib.sha1(b''.join(self.fingerprint_material())).hexdigest().upper()
        return self._fingerprint

    def body(self):
        if self.version == 2 or self.version == 3:
            pass # TODO
        elif self.version == 4:
            return b''.join(self.fingerprint_material()[2:])

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

class SecretKeyPacket(PublicKeyPacket):
    """ OpenPGP Secret-Key packet (tag 5).
        http://tools.ietf.org/html/rfc4880#section-5.5.1.3
        http://tools.ietf.org/html/rfc4880#section-5.5.3
        http://tools.ietf.org/html/rfc4880#section-11.2
        http://tools.ietf.org/html/rfc4880#section-12
    """
    def __init__(self, keydata=None, version=4, algorithm=1, timestamp=time()):
        super(SecretKeyPacket, self).__init__(keydata, version, algorithm, timestamp)
        self.s2k_useage = 0
        if isinstance(keydata, tuple) or isinstance(keydata, list):
            public_len = len(self.key_fields[self.algorithm])
            for i in range(public_len, len(keydata)):
                 self.key[self.secret_key_fields[self.algorithm][i-public_len]] = keydata[i]

    def read(self):
        super(SecretKeyPacket, self).read() # All the fields from PublicKey
        self.s2k_useage = ord(self.read_byte())
        if self.s2k_useage == 255 or self.s2k_useage == 254:
            self.symmetric_type = ord(self.read_byte())
            self.s2k_type = ord(self.read_byte())
            self.s2k_hash_algorithm = ord(self.read_byte())
            if(self.s2k_type == 1 or self.s2k_type == 3):
                self.s2k_salt = self.read_bytes(8)
            if self.s2k_type == 3:
                self.s2k_count = decode_s2k_count(ord(self.read_byte()))
        elif self.s2k_useage > 0:
            self.symmetric_type = self.s2k_useage
        if self.s2k_useage > 0:
            # TODO: IV of the same length as cipher's block size
            self.encrypted_data = self.input # Rest of input is MPIs and checksum (encrypted)
        else:
            self.data = self.input # Rest of input is MPIs and checksum
            self.key_from_data()

    def key_from_data(self):
        if not self.data:
            return None # Not decrypted yet
        self.input = self.data

        for field in self.secret_key_fields[self.algorithm]:
            self.key[field] = self.read_mpi()

        # TODO: Validate checksum?
        if self.s2k_useage == 254: # 20 octet sha1 hash
            self.private_hash = self.read_bytes(20)
        else: # Two-octet checksum
            self.private_hash = self.read_bytes(2)

        self.input = None

    def body(self):
        b = super(SecretKeyPacket, self).body() + pack('!B', self.s2k_useage)
        secret_material = b''
        if self.s2k_useage == 255 or self.s2k_useage == 254:
            b += pack('!B', self.symmetric_type)
            b += pack('!B', self.s2k_type)
            b += pack('!B', self.s2k_hash_algorithm)
            if self.s2k_type == 1 or self.s2k_type == 3:
                b += self.s2k_salt
            if self.s2k_type == 3:
                b += pack('!B', encode_s2k_count(self.s2k_count))
        if self.s2k_useage > 0:
            b += self.encrypted_data
        else:
            for f in self.secret_key_fields[self.algorithm]:
                f = self.key[f]
                secret_material += pack('!H', bitlength(f))
                secret_material += f
            b += secret_material

            # 2-octet checksum
            chk = 0
            for i in range(0, len(secret_material)):
                chk = (chk + ord(secret_material[i:i+1])) % 65536
            b += pack('!H', chk)

        return b

    secret_key_fields = {
        1: ['d', 'p', 'q', 'u'], # RSA
       16: ['x'],                # ELG-E
       17: ['x'],                # DSA
    }

class SecretSubkeyPacket(SecretKeyPacket):
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
        body = pack('!B', self.algorithm)
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
        super(LiteralDataPacket, self).__init__()
        if hasattr(data, 'encode'):
            data = data.encode('utf-8')
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
        return self.format + pack('!B', len(self.filename)) + self.filename + pack('!L', int(self.timestamp)) + self.data

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
    def __init__(self, name='', comment=None, email=None):
        super(UserIDPacket, self).__init__()
        self.name = self.comment = self.email = None
        self.text = ''
        if (not comment) and (not email):
            self.input = name.encode('utf-8')
            self.read()
        else:
            self.name = name
            self.comment = comment
            self.email = email

    def read(self):
        self.text = self.input.decode('utf-8')
        # User IDs of the form: "name (comment) <email>"
        parts = re.findall('^([^\(]+)\(([^\)]+)\)\s+<([^>]+)>$', self.text)
        if len(parts) > 0:
            self.name = parts[0][0].strip()
            self.comment = parts[0][1].strip()
            self.email = parts[0][2].strip()
        else: # User IDs of the form: "name <email>"
            parts = re.findall('^([^<]+)\s+<([^>]+)>$', self.text)
            if len(parts) > 0:
                self.name = parts[0][0].strip()
                self.email = parts[0][1].strip()
            else: # User IDs of the form: "name"
                parts = re.findall('^([^<]+)$', self.text)
                if len(parts) > 0:
                    self.name = parts[0][1].strip()
                else: # User IDs of the form: "<email>"
                    parts = re.findall('^<([^>]+)>$', self.text)
                    if len(parts) > 0:
                        self.email = parts[0][1].strip()

    def __str__(self):
        text = []
        if self.name:
            text.append(self.name)
        if self.comment:
            text.append('('+self.comment+')')
        if self.email:
            text.append('<'+self.email+'>')
        if len(text) < 1:
            text = [self.text]
        return ' '.join(text)

    def body(self):
        return self.__str__().encode('utf-8')

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
