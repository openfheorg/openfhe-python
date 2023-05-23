from openfhe import *

class TestPKEexamples:
    def test_simple_intergers(self):
        parameters = CCParamsBFVRNS()
        parameters.SetPlaintextModulus(65537)
        assert parameters.GetPlaintextModulus() == 65537
        parameters.SetMultiplicativeDepth(2)
        assert parameters.GetMultiplicativeDepth() == 2

        cryptoContext = GenCryptoContext(parameters)
        # check parameters with GetCryptoParameters()
        cryptoContext.Enable(PKESchemeFeature.PKE)
        cryptoContext.Enable(PKESchemeFeature.KEYSWITCH)
        cryptoContext.Enable(PKESchemeFeature.LEVELEDSHE)

        keypair = cryptoContext.KeyGen()
        assert isinstance(keypair, KeyPair)
        assert isinstance(keypair.publicKey, PublicKey)
        assert isinstance(keypair.secretKey, PrivateKey)

        vectorOfInts1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
        plaintext1 = cryptoContext.MakePackedPlaintext(vectorOfInts1)
        assert isinstance(plaintext1, Plaintext)

        vectorOfInts2 = [3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12]
        plaintext2 = cryptoContext.MakePackedPlaintext(vectorOfInts2)
        assert isinstance(plaintext2, Plaintext)

        vectorOfInts3 = [1, 2, 5, 2, 5, 6, 7, 8, 9, 10, 11, 12]
        plaintext3 = cryptoContext.MakePackedPlaintext(vectorOfInts3)
        assert isinstance(plaintext3, Plaintext)

        ciphertext1 = cryptoContext.Encrypt(keypair.publicKey, plaintext1)
        ciphertext2 = cryptoContext.Encrypt(keypair.publicKey, plaintext2)
        ciphertext3 = cryptoContext.Encrypt(keypair.publicKey, plaintext3)
        assert isinstance(ciphertext1, Ciphertext)
        assert isinstance(ciphertext2, Ciphertext)
        assert isinstance(ciphertext3, Ciphertext)

        # Homomorphic additions
        ciphertextAdd12 = cryptoContext.EvalAdd(ciphertext1, ciphertext2)
        ciphertextAddResult = cryptoContext.EvalAdd(ciphertextAdd12, ciphertext3)

        plaintextAddResult = Decrypt(ciphertextAddResult,keypair.secretKey)
        assert isinstance(plaintextAddResult, Plaintext)
        # uncomment next line when == operator is binded
        #assert plaintextAddResult == cryptoContext.MakePackedPlaintext([5, 6, 9, 10, 15, 18, 21, 24, 27, 30, 33, 36])


    def test_simple_integers_bgvrns(self):
        pass
    def test_simple_integers_serial(self):
        pass
    def test_simple_integers_serial_bgvrns(self):
        pass
    def test_simple_real_numbers(self):
        pass