import unittest
from openfhe import CCParamsBFVRNS, GenCryptoContext, KeyPair, PublicKey, PrivateKey, PKESchemeFeature
class TestCryptoContext(unittest.TestCase):
    def test_cc_generation(self):
        pass
    def test_key_generation(self):
        params = CCParamsBFVRNS()
        params.SetPlaintextModulus(65537)
        cc = GenCryptoContext(params)
        cc.Enable(PKESchemeFeature.PKE)
        keypair = cc.KeyGen()
        self.assertIsInstance(keypair,KeyPair)
        self.assertIsInstance(keypair.publicKey,PublicKey)
        self.assertIsInstance(keypair.secretKey,PrivateKey)
if __name__ == '__main__':
    unittest.main()

