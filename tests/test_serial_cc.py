import logging
import pytest

import openfhe as fhe

pytestmark = pytest.mark.skipif(fhe.get_native_int() == 32, reason="Doesn't work for NATIVE_INT=32")

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

    fhe.ClearEvalMultKeys()
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


VECTOR1_ROTATION = 1
VECTOR2_ROTATION = 2
VECTOR3_ROTATION = -1
VECTOR4_ROTATION = -2

@pytest.mark.parametrize("mode", [fhe.JSON, fhe.BINARY])
def test_serial_cryptocontext_str(mode):
    parameters = fhe.CCParamsBFVRNS()
    parameters.SetPlaintextModulus(65537)
    parameters.SetMultiplicativeDepth(2)

    cryptoContext = fhe.GenCryptoContext(parameters)
    cryptoContext.Enable(fhe.PKE)
    cryptoContext.Enable(fhe.KEYSWITCH)
    cryptoContext.Enable(fhe.LEVELEDSHE)
    cryptoContext.Enable(fhe.PKESchemeFeature.PRE)

    keypair = cryptoContext.KeyGen()

    # First plaintext vector is encoded
    vectorOfInts1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    plaintext1 = cryptoContext.MakePackedPlaintext(vectorOfInts1)

    # Second plaintext vector is encoded
    vectorOfInts2 = [3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    plaintext2 = cryptoContext.MakePackedPlaintext(vectorOfInts2)

    # Third plaintext vector is encoded
    vectorOfInts3 = [1, 2, 5, 2, 5, 6, 7, 8, 9, 10, 11, 12]
    plaintext3 = cryptoContext.MakePackedPlaintext(vectorOfInts3)

    # Create a final array adding the three vectors
    initialPlaintextAddResult = [vectorOfInts1[i] + vectorOfInts2[i] + vectorOfInts3[i] for i in range(len(vectorOfInts1))]
    initialPlaintextAddResult = cryptoContext.MakePackedPlaintext(initialPlaintextAddResult)

    # Multiply the values
    initialPlaintextMultResult = [vectorOfInts1[i] * vectorOfInts2[i] * vectorOfInts3[i] for i in range(len(vectorOfInts1))]
    initialPlaintextMultResult = cryptoContext.MakePackedPlaintext(initialPlaintextMultResult)

    # Rotate the values
    initialPlaintextRot1 = rotate_vector(vectorOfInts1, VECTOR1_ROTATION)
    initialPlaintextRot1 = cryptoContext.MakePackedPlaintext(initialPlaintextRot1)
    initialPlaintextRot2 = rotate_vector(vectorOfInts2, VECTOR2_ROTATION)
    initialPlaintextRot2 = cryptoContext.MakePackedPlaintext(initialPlaintextRot2)
    initialPlaintextRot3 = rotate_vector(vectorOfInts3, VECTOR3_ROTATION)
    initialPlaintextRot3 = cryptoContext.MakePackedPlaintext(initialPlaintextRot3)
    initialPlaintextRot4 = rotate_vector(vectorOfInts3, VECTOR4_ROTATION)
    initialPlaintextRot4 = cryptoContext.MakePackedPlaintext(initialPlaintextRot4)

    # The encoded vectors are encrypted
    ciphertext1 = cryptoContext.Encrypt(keypair.publicKey, plaintext1)
    ciphertext2 = cryptoContext.Encrypt(keypair.publicKey, plaintext2)
    ciphertext3 = cryptoContext.Encrypt(keypair.publicKey, plaintext3)

    evalKey = cryptoContext.ReKeyGen(keypair.secretKey, keypair.publicKey)
    cryptoContext.EvalMultKeyGen(keypair.secretKey)
    cryptoContext.EvalRotateKeyGen(keypair.secretKey, [VECTOR1_ROTATION, VECTOR2_ROTATION, VECTOR3_ROTATION, VECTOR4_ROTATION])

    cryptoContext_ser = fhe.Serialize(cryptoContext, mode)
    LOGGER.debug("The cryptocontext has been serialized.")
    publickey_ser = fhe.Serialize(keypair.publicKey, mode)
    LOGGER.debug("The public key has been serialized.")
    secretkey_ser = fhe.Serialize(keypair.secretKey, mode)
    LOGGER.debug("The private key has been serialized.")
    ciphertext1_ser = fhe.Serialize(ciphertext1, mode)
    LOGGER.debug("The ciphertext 1 has been serialized.")
    ciphertext2_ser = fhe.Serialize(ciphertext2, mode)
    LOGGER.debug("The ciphertext 2 has been serialized.")
    ciphertext3_ser = fhe.Serialize(ciphertext3, mode)
    LOGGER.debug("The ciphertext 3 has been serialized.")
    evalKey_ser = fhe.Serialize(evalKey, mode)
    LOGGER.debug("The evaluation key has been serialized.")
    multKey_ser = fhe.SerializeEvalMultKeyString(mode, "")
    LOGGER.debug("The relinearization key has been serialized.")
    automorphismKey_ser = fhe.SerializeEvalAutomorphismKeyString(mode, "")
    LOGGER.debug("The rotation evaluation keys have been serialized.")

    fhe.ClearEvalMultKeys()
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

    ct1 = fhe.DeserializeCiphertextString(ciphertext1_ser, mode)
    assert isinstance(ct1, fhe.Ciphertext)
    LOGGER.debug("The ciphertext 1 has been reserialized.")

    ct2 = fhe.DeserializeCiphertextString(ciphertext2_ser, mode)
    assert isinstance(ct2, fhe.Ciphertext)
    LOGGER.debug("The ciphertext 2 has been reserialized.")

    ct3 = fhe.DeserializeCiphertextString(ciphertext3_ser, mode)
    assert isinstance(ct3, fhe.Ciphertext)
    LOGGER.debug("The ciphertext 3 has been reserialized.")

    ek = fhe.DeserializeEvalKeyString(evalKey_ser, mode)
    assert isinstance(ek, fhe.EvalKey)
    LOGGER.debug("The evaluation key has been deserialized.")

    fhe.DeserializeEvalMultKeyString(multKey_ser, mode)
    LOGGER.debug("The relinearization key has been deserialized.")

    fhe.DeserializeEvalAutomorphismKeyString(automorphismKey_ser, mode)
    LOGGER.debug("The rotation evaluation keys have been deserialized.")

    # Homomorphic addition

    ciphertextAdd12 = cc.EvalAdd(ct1, ct2)
    ciphertextAddResult = cc.EvalAdd(ciphertextAdd12, ct3)

    # Homomorphic multiplication
    ciphertextMult12 = cc.EvalMult(ct1, ct2)
    ciphertextMultResult = cc.EvalMult(ciphertextMult12, ct3)

    # Homomorphic rotation
    ciphertextRot1 = cc.EvalRotate(ct1, VECTOR1_ROTATION)
    ciphertextRot2 = cc.EvalRotate(ct2, VECTOR2_ROTATION)
    ciphertextRot3 = cc.EvalRotate(ct3, VECTOR3_ROTATION)
    ciphertextRot4 = cc.EvalRotate(ct3, VECTOR4_ROTATION)
    
    # Decrypt the result of additions
    plaintextAddResult = cc.Decrypt(sk, ciphertextAddResult)

    # Decrypt the result of multiplications
    plaintextMultResult = cc.Decrypt(sk, ciphertextMultResult)

    # Decrypt the result of rotations
    plaintextRot1 = cc.Decrypt(sk, ciphertextRot1)
    plaintextRot2 = cc.Decrypt(sk, ciphertextRot2)
    plaintextRot3 = cc.Decrypt(sk, ciphertextRot3)
    plaintextRot4 = cc.Decrypt(sk, ciphertextRot4)

    # Shows only the same number of elements as in the original plaintext vector
    # By default it will show all coefficients in the BFV-encoded polynomial
    plaintextRot1.SetLength(len(vectorOfInts1))
    plaintextRot2.SetLength(len(vectorOfInts1))
    plaintextRot3.SetLength(len(vectorOfInts1))
    plaintextRot4.SetLength(len(vectorOfInts1))

    assert str(plaintextAddResult) == str(initialPlaintextAddResult)
    assert str(plaintextMultResult) == str(initialPlaintextMultResult)
    assert str(plaintextRot1) == str(initialPlaintextRot1)
    assert str(plaintextRot2) == str(initialPlaintextRot2)
    assert str(plaintextRot3) == str(initialPlaintextRot3)
    assert str(plaintextRot4) == str(initialPlaintextRot4)

def rotate_vector(vector, rotation):
    """
    Rotate a vector by a specified number of positions.
    Positive values rotate left, negative values rotate right.

    :param vector: List[int], the vector to rotate.
    :param rotation: int, the number of positions to rotate.
    :return: List[int], the rotated vector.
    """
    n = len(vector)
    if rotation > 0:
        rotated = vector[rotation:] + [0] * rotation
    elif rotation < 0:
        rotation = abs(rotation)
        rotated = [0] * rotation + vector[:n - rotation]
    else:
        rotated = vector
    return rotated
