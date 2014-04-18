import nose
import os.path
import OpenPGP
import OpenPGP.Crypto
import Crypto.Util
import Crypto.PublicKey.RSA

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
        verify = OpenPGP.Crypto.Wrapper(m)
        nose.tools.assert_equal(verify.verify(m), m.signatures())

    def testSigningKeysRSA(self):
        k = Crypto.PublicKey.RSA.generate(1024)

        nkey = OpenPGP.SecretKeyPacket((
            Crypto.Util.number.long_to_bytes(k.n),
            Crypto.Util.number.long_to_bytes(k.e),
            Crypto.Util.number.long_to_bytes(k.d),
            Crypto.Util.number.long_to_bytes(k.p),
            Crypto.Util.number.long_to_bytes(k.q),
            Crypto.Util.number.long_to_bytes(k.u)
        ))

        uid = OpenPGP.UserIDPacket('Test <test@example.com>')

        wkey = OpenPGP.Crypto.Wrapper(nkey)
        m = wkey.sign_key_userid([nkey, uid]).to_bytes()
        reparsedM = OpenPGP.Message.parse(m)

        nose.tools.assert_equal(wkey.verify(reparsedM), reparsedM.signatures())

    def testHelloKey(self):
        self.oneKeyRSA("helloKey.gpg")

class TestDecryption:
    def oneSymmetric(self, pss, cnt, path):
        m = OpenPGP.Message.parse(open(os.path.dirname(__file__) + '/data/' + path, 'rb').read())
        m2 = OpenPGP.Crypto.Wrapper(m).decrypt_symmetric(pss)
        while(isinstance(m2[0], OpenPGP.CompressedDataPacket)):
            m2 = m2[0].data
        for p in m2:
            if(isinstance(p,OpenPGP.LiteralDataPacket)):
                nose.tools.assert_equal(p.data, cnt)

    def testDecryptAES(self):
        self.oneSymmetric("hello", b"PGP\n", "symmetric-aes.gpg")

    def testDecryptNoMDC(self):
        self.oneSymmetric("hello", b"PGP\n", "symmetric-no-mdc.gpg")

    def testDecrypt3DES(self):
        self.oneSymmetric("hello", b"PGP\n", "symmetric-3des.gpg")

    def testDecryptBlowfish(self):
        self.oneSymmetric("hello", b"PGP\n", "symmetric-blowfish.gpg")

    def testDecryptCAST5(self):
        self.oneSymmetric("hello", b"PGP\n", "symmetric-cast5.gpg")

    def testDecryptSessionKey(self):
        self.oneSymmetric("hello", b"PGP\n", "symmetric-with-session-key.gpg")

    def testDecryptSecretKey(self):
        key = OpenPGP.Message.parse(open(os.path.dirname(__file__) + '/data/encryptedSecretKey.gpg', 'rb').read())
        skey = OpenPGP.Crypto.Wrapper(key[0]).decrypt_secret_key("hello")
        nose.tools.assert_equal(not (not skey), True)

    def testDecryptAsymmetric(self):
        m = OpenPGP.Message.parse(open(os.path.dirname(__file__) + '/data/hello.gpg', 'rb').read())
        key = OpenPGP.Message.parse(open(os.path.dirname(__file__) + '/data/helloKey.gpg', 'rb').read())
        m2 = OpenPGP.Crypto.Wrapper(key).decrypt(m)
        while(isinstance(m2[0], OpenPGP.CompressedDataPacket)):
            m2 = m2[0].data
        for p in m2:
            if(isinstance(p,OpenPGP.LiteralDataPacket)):
                nose.tools.assert_equal(p.data, b"hello\n")

class TestEncryption:
    def testEncryptSymmetric(self):
        data = OpenPGP.LiteralDataPacket('This is text.', 'u', 'stuff.txt')
        encrypted = OpenPGP.Crypto.Wrapper(OpenPGP.Message([data])).encrypt('secret')
        decrypted = OpenPGP.Crypto.Wrapper(encrypted).decrypt_symmetric('secret')
        nose.tools.assert_equal(decrypted[0].data, b'This is text.')

    def testEncryptAsymmetric(self):
        key = OpenPGP.Message.parse(open(os.path.dirname(__file__) + '/data/helloKey.gpg', 'rb').read())
        data = OpenPGP.LiteralDataPacket('This is text.', 'u', 'stuff.txt')
        encrypted = OpenPGP.Crypto.Wrapper(OpenPGP.Message([data])).encrypt(key)
        decryptor = OpenPGP.Crypto.Wrapper(key)
        decrypted = decryptor.decrypt(encrypted)
        nose.tools.assert_equal(decrypted[0].data, b'This is text.')
