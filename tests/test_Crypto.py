import nose
import os.path
import OpenPGP
import OpenPGP.Crypto

class TestMessageVerification:
    def oneMessage(self, pkey, path):
        pkeyM = OpenPGP.Message.parse(open(os.path.dirname(__file__) + '/data/' + pkey, 'rb').read())
        m = OpenPGP.Message.parse(open(os.path.dirname(__file__) + '/data/' + path, 'rb').read())
        verify = OpenPGP.Crypto.Wrapper(pkeyM)
        nose.tools.assert_equal(verify.verify(m), m.signatures())

    def testUncompressedOpsRSA(self):
        self.oneMessage('pubring.gpg', 'uncompressed-ops-rsa.gpg')

    def testCompressedSig(self):
        self.oneMessage('pubring.gpg', 'compressedsig.gpg')

    def testCompressedSigZLIB(self):
        self.oneMessage('pubring.gpg', 'compressedsig-zlib.gpg')

    def testCompressedSigBzip2(self):
        self.oneMessage('pubring.gpg', 'compressedsig-bzip2.gpg')

    def testSigningMessagesRSA(self):
        wkey = OpenPGP.Message.parse(open(os.path.dirname(__file__) + '/data/helloKey.gpg', 'rb').read())
        data = OpenPGP.LiteralDataPacket('This is text.', 'u', 'stuff.txt')
        sign = OpenPGP.Crypto.Wrapper(wkey)
        m = sign.sign(data).to_bytes()
        reparsedM = OpenPGP.Message.parse(m)
        nose.tools.assert_equal(sign.verify(reparsedM), reparsedM.signatures())

    def testSigningMessagesDSA(self):
        wkey = OpenPGP.Message.parse(open(os.path.dirname(__file__) + '/data/secring.gpg', 'rb').read())
        data = OpenPGP.LiteralDataPacket('This is text.', 'u', 'stuff.txt')
        dsa = OpenPGP.Crypto.Wrapper(wkey).private_key('7F69FA376B020509')
        m = OpenPGP.Crypto.Wrapper(data).sign(dsa, 'SHA512', '7F69FA376B020509').to_bytes()
        reparsedM = OpenPGP.Message.parse(m)
        nose.tools.assert_equal(OpenPGP.Crypto.Wrapper(wkey).verify(reparsedM), reparsedM.signatures())

    def testUncompressedOpsDSA(self):
        self.oneMessage('pubring.gpg', 'uncompressed-ops-dsa.gpg')

    def testUncompressedOpsDSAsha384(self):
        self.oneMessage('pubring.gpg', 'uncompressed-ops-dsa-sha384.txt.gpg')

class TestKeyVerification:
    def oneKeyRSA(self, path):
        m = OpenPGP.Message.parse(open(os.path.dirname(__file__) + '/data/' + path, 'rb').read())
        verify = OpenPGP.Crypto.Wrapper(m);
        nose.tools.assert_equal(verify.verify(m), m.signatures());

    def testHelloKey(self):
        self.oneKeyRSA("helloKey.gpg")
