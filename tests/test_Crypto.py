import nose
import os.path
import OpenPGP
import OpenPGP.Crypto

class TestMessageVerification:
    def oneMessageRSA(self, pkey, path):
        pkeyM = OpenPGP.Message.parse(open(os.path.dirname(__file__) + '/data/' + pkey, 'rb').read())
        m = OpenPGP.Message.parse(open(os.path.dirname(__file__) + '/data/' + path, 'rb').read())
        verify = OpenPGP.Crypto.RSA(pkeyM)
        nose.tools.assert_equal(verify.verify(m), True)

    def testUncompressedOpsRSA(self):
        self.oneMessageRSA('pubring.gpg', 'uncompressed-ops-rsa.gpg')

    def testCompressedSig(self):
        self.oneMessageRSA('pubring.gpg', 'compressedsig.gpg')

    def testCompressedSigZLIB(self):
        self.oneMessageRSA('pubring.gpg', 'compressedsig-zlib.gpg')

    def testCompressedSigBzip2(self):
        self.oneMessageRSA('pubring.gpg', 'compressedsig-bzip2.gpg')

    def testSigningMessages(self):
        wkey = OpenPGP.Message.parse(open(os.path.dirname(__file__) + '/data/helloKey.gpg', 'rb').read())
        data = OpenPGP.LiteralDataPacket('This is text.', 'u', 'stuff.txt')
        sign = OpenPGP.Crypto.RSA(wkey)
        m = sign.sign(data).to_bytes()
        reparsedM = OpenPGP.Message.parse(m)
        nose.tools.assert_equal(sign.verify(reparsedM), True)

    #def testUncompressedOpsDSA(self):
    #    self.oneMessageDSA('pubring.gpg', 'uncompressed-ops-dsa.gpg')

    #def testUncompressedOpsDSAsha384(self):
    #    self.oneMessageDSA('pubring.gpg', 'uncompressed-ops-dsa-sha384.gpg')

class KeyVerification:
    def oneKeyRSA(self, path):
        m = OpenPGP.Message.parse(open(os.path.dirname(__file__) + '/data/' + path, 'rb').read())
        verify = OpenPGP.Crypt.RSA(m);
        nose.tools.assert_equal(verify.verify(m), True);

    def testHelloKey(self):
        self.oneKeyRSA("helloKey.gpg")
