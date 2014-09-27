import nose
import os.path
import OpenPGP

class TestASCIIArmor:
    def readLocalFile(self, filename):
        return open(os.path.dirname(__file__) + filename, 'r').read()

    def test_unarmor_one(self):
         armored = self.readLocalFile('/data/helloKey.asc')
         _, unarmored = OpenPGP.unarmor(armored)[0]
         message = OpenPGP.Message.parse(unarmored)
         nose.tools.assert_equal(message[0].fingerprint(), '421F28FEAAD222F856C8FFD5D4D54EA16F87040E')

    def test_enarmor_one(self):
         expected = self.readLocalFile('/data/helloKey.asc')
         messages = OpenPGP.unarmor(expected) # [(header, data), ...]
         header, data = messages[0]
         actual = OpenPGP.enarmor(data, headers = [keyValue.split(': ', 1) for keyValue in header.split('\n')])
         nose.tools.assert_equal(actual, expected)

class TestSerialization:
    def one_serialization(self, path):
        inm = OpenPGP.Message.parse(open(os.path.dirname(__file__) + '/data/' + path, 'rb').read())
        mid = inm.to_bytes()
        out = OpenPGP.Message.parse(mid)
        nose.tools.assert_equal(inm, out)

    def test000001006public_key(self):
        self.one_serialization("000001-006.public_key")

    def test000002013user_id(self):
        self.one_serialization("000002-013.user_id")

    def test000003002sig(self):
        self.one_serialization("000003-002.sig")

    def test000004012ring_trust(self):
        self.one_serialization("000004-012.ring_trust")

    def test000005002sig(self):
        self.one_serialization("000005-002.sig")

    def test000006012ring_trust(self):
        self.one_serialization("000006-012.ring_trust")

    def test000007002sig(self):
        self.one_serialization("000007-002.sig")

    def test000008012ring_trust(self):
        self.one_serialization("000008-012.ring_trust")

    def test000009002sig(self):
        self.one_serialization("000009-002.sig")

    def test000010012ring_trust(self):
        self.one_serialization("000010-012.ring_trust")

    def test000011002sig(self):
        self.one_serialization("000011-002.sig")

    def test000012012ring_trust(self):
        self.one_serialization("000012-012.ring_trust")

    def test000013014public_subkey(self):
        self.one_serialization("000013-014.public_subkey")

    def test000014002sig(self):
        self.one_serialization("000014-002.sig")

    def test000015012ring_trust(self):
        self.one_serialization("000015-012.ring_trust")

    def test000016006public_key(self):
        self.one_serialization("000016-006.public_key")

    def test000017002sig(self):
        self.one_serialization("000017-002.sig")

    def test000018012ring_trust(self):
        self.one_serialization("000018-012.ring_trust")

    def test000019013user_id(self):
        self.one_serialization("000019-013.user_id")

    def test000020002sig(self):
        self.one_serialization("000020-002.sig")

    def test000021012ring_trust(self):
        self.one_serialization("000021-012.ring_trust")

    def test000022002sig(self):
        self.one_serialization("000022-002.sig")

    def test000023012ring_trust(self):
        self.one_serialization("000023-012.ring_trust")

    def test000024014public_subkey(self):
        self.one_serialization("000024-014.public_subkey")

    def test000025002sig(self):
        self.one_serialization("000025-002.sig")

    def test000026012ring_trust(self):
        self.one_serialization("000026-012.ring_trust")

    def test000027006public_key(self):
        self.one_serialization("000027-006.public_key")

    def test000028002sig(self):
        self.one_serialization("000028-002.sig")

    def test000029012ring_trust(self):
        self.one_serialization("000029-012.ring_trust")

    def test000030013user_id(self):
        self.one_serialization("000030-013.user_id")

    def test000031002sig(self):
        self.one_serialization("000031-002.sig")

    def test000032012ring_trust(self):
        self.one_serialization("000032-012.ring_trust")

    def test000033002sig(self):
        self.one_serialization("000033-002.sig")

    def test000034012ring_trust(self):
        self.one_serialization("000034-012.ring_trust")

    def test000035006public_key(self):
        self.one_serialization("000035-006.public_key")

    def test000036013user_id(self):
        self.one_serialization("000036-013.user_id")

    def test000037002sig(self):
        self.one_serialization("000037-002.sig")

    def test000038012ring_trust(self):
        self.one_serialization("000038-012.ring_trust")

    def test000039002sig(self):
        self.one_serialization("000039-002.sig")

    def test000040012ring_trust(self):
        self.one_serialization("000040-012.ring_trust")

    def test000041017attribute(self):
        self.one_serialization("000041-017.attribute")

    def test000042002sig(self):
        self.one_serialization("000042-002.sig")

    def test000043012ring_trust(self):
        self.one_serialization("000043-012.ring_trust")

    def test000044014public_subkey(self):
        self.one_serialization("000044-014.public_subkey")

    def test000045002sig(self):
        self.one_serialization("000045-002.sig")

    def test000046012ring_trust(self):
        self.one_serialization("000046-012.ring_trust")

    def test000047005secret_key(self):
        self.one_serialization("000047-005.secret_key")

    def test000048013user_id(self):
        self.one_serialization("000048-013.user_id")

    def test000049002sig(self):
        self.one_serialization("000049-002.sig")

    def test000050012ring_trust(self):
        self.one_serialization("000050-012.ring_trust")

    def test000051007secret_subkey(self):
        self.one_serialization("000051-007.secret_subkey")

    def test000052002sig(self):
        self.one_serialization("000052-002.sig")

    def test000053012ring_trust(self):
        self.one_serialization("000053-012.ring_trust")

    def test000054005secret_key(self):
        self.one_serialization("000054-005.secret_key")

    def test000055002sig(self):
        self.one_serialization("000055-002.sig")

    def test000056012ring_trust(self):
        self.one_serialization("000056-012.ring_trust")

    def test000057013user_id(self):
        self.one_serialization("000057-013.user_id")

    def test000058002sig(self):
        self.one_serialization("000058-002.sig")

    def test000059012ring_trust(self):
        self.one_serialization("000059-012.ring_trust")

    def test000060007secret_subkey(self):
        self.one_serialization("000060-007.secret_subkey")

    def test000061002sig(self):
        self.one_serialization("000061-002.sig")

    def test000062012ring_trust(self):
        self.one_serialization("000062-012.ring_trust")

    def test000063005secret_key(self):
        self.one_serialization("000063-005.secret_key")

    def test000064002sig(self):
        self.one_serialization("000064-002.sig")

    def test000065012ring_trust(self):
        self.one_serialization("000065-012.ring_trust")

    def test000066013user_id(self):
        self.one_serialization("000066-013.user_id")

    def test000067002sig(self):
        self.one_serialization("000067-002.sig")

    def test000068012ring_trust(self):
        self.one_serialization("000068-012.ring_trust")

    def test000069005secret_key(self):
        self.one_serialization("000069-005.secret_key")

    def test000070013user_id(self):
        self.one_serialization("000070-013.user_id")

    def test000071002sig(self):
        self.one_serialization("000071-002.sig")

    def test000072012ring_trust(self):
        self.one_serialization("000072-012.ring_trust")

    def test000073017attribute(self):
        self.one_serialization("000073-017.attribute")

    def test000074002sig(self):
        self.one_serialization("000074-002.sig")

    def test000075012ring_trust(self):
        self.one_serialization("000075-012.ring_trust")

    def test000076007secret_subkey(self):
        self.one_serialization("000076-007.secret_subkey")

    def test000077002sig(self):
        self.one_serialization("000077-002.sig")

    def test000078012ring_trust(self):
        self.one_serialization("000078-012.ring_trust")

    def test002182002sig(self):
        self.one_serialization("002182-002.sig")

    def testpubringgpg(self):
        self.one_serialization("pubring.gpg")

    def testsecringgpg(self):
        self.one_serialization("secring.gpg")

    def testcompressedsiggpg(self):
        self.one_serialization("compressedsig.gpg")

    def testcompressedsigzlibgpg(self):
        self.one_serialization("compressedsig-zlib.gpg")

    def testcompressedsigbzip2gpg(self):
        self.one_serialization("compressedsig-bzip2.gpg")

    def testonepass_sig(self):
        self.one_serialization("onepass_sig")

    def testsymmetrically_encrypted(self):
        self.one_serialization("symmetrically_encrypted")

    def testuncompressedopsdsagpg(self):
        self.one_serialization("uncompressed-ops-dsa.gpg")

    def testuncompressedopsdsasha384txtgpg(self):
        self.one_serialization("uncompressed-ops-dsa-sha384.txt.gpg")

    def testuncompressedopsrsagpg(self):
        self.one_serialization("uncompressed-ops-rsa.gpg")

    def testSymmetricAES(self):
        self.one_serialization("symmetric-aes.gpg")

    def testSymmetricNoMDC(self):
        self.one_serialization("symmetric-no-mdc.gpg")

class TestFingerprint:
    def one_fingerprint(self, path, kf):
        m = OpenPGP.Message.parse(open(os.path.dirname(__file__) + '/data/' + path, 'rb').read())
        nose.tools.assert_equal(m[0].fingerprint(), kf)

    def test000001006public_key(self):
        self.one_fingerprint("000001-006.public_key", "421F28FEAAD222F856C8FFD5D4D54EA16F87040E")

    def test000016006public_key(self):
        self.one_fingerprint("000016-006.public_key", "AF95E4D7BAC521EE9740BED75E9F1523413262DC")

    def test000027006public_key(self):
        self.one_fingerprint("000027-006.public_key", "1EB20B2F5A5CC3BEAFD6E5CB7732CF988A63EA86")

    def test000035006public_key(self):
        self.one_fingerprint("000035-006.public_key", "CB7933459F59C70DF1C3FBEEDEDC3ECF689AF56D")

class TestStreaming:
    def test_partial_results(self):
        m = OpenPGP.Message.parse(OpenPGP.Message([OpenPGP.UserIDPacket('My name <e@example.com>'), OpenPGP.UserIDPacket('Your name <y@example.com>')]).to_bytes())
        m[0] # Just the first one
        nose.tools.assert_equal(len(m.force()), 2)

    def test_file_stream(self):
        m = OpenPGP.Message.parse(open(os.path.dirname(__file__) + '/data/pubring.gpg', 'rb'))
        nose.tools.assert_equal(len(m.force()), 1944)
