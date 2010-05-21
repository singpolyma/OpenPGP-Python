# Pure Python implementation of OpenPGP <http://tools.ietf.org/html/rfc4880>
# Port of openpgp-php <http://github.com/bendiken/openpgp-php>

from struct import pack, unpack

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
         return (tag, 6, unpack('!L', input_data[2:4])[0]);
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
    pass # TODO

class SymmetricSessionKeyPacket(Packet):
    """ OpenPGP Symmetric-Key Encrypted Session Key packet (tag 3).
        http://tools.ietf.org/html/rfc4880#section-5.3
    """
    pass # TODO

class OnePassSignaturePacket(Packet):
    """ OpenPGP One-Pass Signature packet (tag 4).
        http://tools.ietf.org/html/rfc4880#section-5.4
    """
    pass # TODO

class PublicKeyPacket(Packet):
    """ OpenPGP Public-Key packet (tag 6).
        http://tools.ietf.org/html/rfc4880#section-5.5.1.1
        http://tools.ietf.org/html/rfc4880#section-5.5.2
        http://tools.ietf.org/html/rfc4880#section-11.1
        http://tools.ietf.org/html/rfc4880#section-12
    """
    pass # TODO

class PublicSubkeyPacket(Packet):
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
    pass # TODO

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
    pass # TODO

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
