from openfhe import CCParamsBFVRNS, GenCryptoContext, KeyPair, PublicKey, PrivateKey, PKESchemeFeature

class TestCryptoContext:
    def test_cc_generation(self):
        pass

    def test_key_generation(self):
        params = CCParamsBFVRNS()
        params.SetPlaintextModulus(65537)
        cc = GenCryptoContext(params)
        cc.Enable(PKESchemeFeature.PKE)
        keypair = cc.KeyGen()
        assert isinstance(keypair, KeyPair)
        assert isinstance(keypair.publicKey, PublicKey)
        assert isinstance(keypair.secretKey, PrivateKey)
