import logging
import pytest

import openfhe as fhe

LOGGER = logging.getLogger("test_serial_cc")


def test_serial_cryptocontext(tmp_path):
    parameters = fhe.CCParamsBFVRNS()
    parameters.SetPlaintextModulus(65537)
    parameters.SetMultiplicativeDepth(2)

    cryptoContext = fhe.GenCryptoContext(parameters)
    cryptoContext.Enable(fhe.PKESchemeFeature.PKE)

    keypair = cryptoContext.KeyGen()
    vectorOfInts1 = list(range(12))
    plaintext1 = cryptoContext.MakePackedPlaintext(vectorOfInts1)
    ciphertext1 = cryptoContext.Encrypt(keypair.publicKey, plaintext1)

    assert fhe.SerializeToFile(str(tmp_path / "cryptocontext.json"), cryptoContext, fhe.JSON)
    LOGGER.debug("The cryptocontext has been serialized.")
    assert fhe.SerializeToFile(str(tmp_path / "ciphertext1.json"), ciphertext1, fhe.JSON)

    cryptoContext.ClearEvalMultKeys()
    cryptoContext.ClearEvalAutomorphismKeys()
    fhe.ReleaseAllContexts()

    cc, success = fhe.DeserializeCryptoContext(str(tmp_path / "cryptocontext.json"), fhe.JSON)
    assert success
    assert isinstance(cc, fhe.CryptoContext)
    assert fhe.SerializeToFile(str(tmp_path / "cryptocontext2.json"), cc, fhe.JSON)
    LOGGER.debug("The cryptocontext has been serialized.")

    ct1, success = fhe.DeserializeCiphertext(str(tmp_path / "ciphertext1.json"), fhe.JSON)
    assert success
    assert isinstance(ct1, fhe.Ciphertext)
    LOGGER.debug("Cryptocontext deserializes to %s %s", success, ct1)
    assert fhe.SerializeToFile(str(tmp_path / "ciphertext12.json"), ct1, fhe.JSON)


@pytest.mark.parametrize("mode", [fhe.JSON, fhe.BINARY])
def test_serial_cryptocontext_str(mode):
    parameters = fhe.CCParamsBFVRNS()
    parameters.SetPlaintextModulus(65537)
    parameters.SetMultiplicativeDepth(2)

    cryptoContext = fhe.GenCryptoContext(parameters)
    cryptoContext.Enable(fhe.PKESchemeFeature.PKE)
    cryptoContext.Enable(fhe.PKESchemeFeature.PRE)

    keypair = cryptoContext.KeyGen()
    vectorOfInts = list(range(12))
    plaintext = cryptoContext.MakePackedPlaintext(vectorOfInts)
    ciphertext = cryptoContext.Encrypt(keypair.publicKey, plaintext)
    evalKey = cryptoContext.ReKeyGen(keypair.secretKey, keypair.publicKey)


    cryptoContext_ser = fhe.Serialize(cryptoContext, mode)
    LOGGER.debug("The cryptocontext has been serialized.")
    publickey_ser = fhe.Serialize(keypair.publicKey, mode)
    LOGGER.debug("The public key has been serialized.")
    secretkey_ser = fhe.Serialize(keypair.secretKey, mode)
    LOGGER.debug("The private key has been serialized.")
    ciphertext_ser = fhe.Serialize(ciphertext, mode)
    LOGGER.debug("The ciphertext has been serialized.")
    evalKey_ser = fhe.Serialize(evalKey, mode)
    LOGGER.debug("The evaluation key has been serialized.")


    cryptoContext.ClearEvalMultKeys()
    cryptoContext.ClearEvalAutomorphismKeys()
    fhe.ReleaseAllContexts()

    cc = fhe.DeserializeCryptoContextString(cryptoContext_ser, mode)
    assert isinstance(cc, fhe.CryptoContext)
    LOGGER.debug("The cryptocontext has been deserialized.")

    pk = fhe.DeserializePublicKeyString(publickey_ser, mode)
    assert isinstance(pk, fhe.PublicKey)
    LOGGER.debug("The public key has been deserialized.")

    sk = fhe.DeserializePrivateKeyString(secretkey_ser, mode)
    assert isinstance(sk, fhe.PrivateKey)
    LOGGER.debug("The private key has been deserialized.")

    ct = fhe.DeserializeCiphertextString(ciphertext_ser, mode)
    assert isinstance(ct, fhe.Ciphertext)
    LOGGER.debug("The ciphertext has been reserialized.")

    ek = fhe.DeserializeEvalKeyString(evalKey_ser, mode)
    assert isinstance(ek, fhe.EvalKey)
    LOGGER.debug("The evaluation key has been deserialized.")
