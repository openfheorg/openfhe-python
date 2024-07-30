import logging
import random

import pytest
import openfhe as fhe

pytestmark = pytest.mark.skipif(fhe.get_native_int() == 32, reason="Doesn't work for NATIVE_INT=32")

LOGGER = logging.getLogger("test_bgv")


@pytest.fixture(scope="module")
def bgv_context():
    """
    This fixture creates a small CKKS context, with its paramters and keys.
    We make it because context creation can be slow.
    """
    parameters = fhe.CCParamsBGVRNS()
    parameters.SetPlaintextModulus(65537)
    parameters.SetMultiplicativeDepth(2)

    crypto_context = fhe.GenCryptoContext(parameters)
    crypto_context.Enable(fhe.PKESchemeFeature.PKE)
    crypto_context.Enable(fhe.PKESchemeFeature.KEYSWITCH)
    crypto_context.Enable(fhe.PKESchemeFeature.LEVELEDSHE)
    key_pair = crypto_context.KeyGen()
    # Generate the relinearization key
    crypto_context.EvalMultKeyGen(key_pair.secretKey)
    # Generate the rotation evaluation keys
    crypto_context.EvalRotateKeyGen(key_pair.secretKey, [1, 2, -1, -2])
    return parameters, crypto_context, key_pair


def bgv_equal(raw, ciphertext, cc, keys):
    """Compare an unencrypted list of values with encrypted values"""
    pt = cc.Decrypt(ciphertext, keys.secretKey)
    pt.SetLength(len(raw))
    compare = pt.GetPackedValue()
    success = all([a == b for (a, b) in zip(raw, compare)])
    if not success:
        LOGGER.info("Mismatch between %s %s", raw, compare)
    return success


def roll(a, n):
    """Circularly rotate a list, like numpy.roll but without numpy."""
    return [a[i % len(a)] for i in range(-n, len(a) - n)]


@pytest.mark.parametrize("n,final", [
    (0, [0, 1, 2, 3, 4, 5, 6, 7]),
    (2, [6, 7, 0, 1, 2, 3, 4, 5]),
    (3, [5, 6, 7, 0, 1, 2, 3, 4]),
    (-1, [1, 2, 3, 4, 5, 6, 7, 0]),
    ])
def test_roll(n, final):
    assert roll(list(range(8)), n) == final


def shift(a, n):
    """Rotate a list with infill of 0."""
    return [(a[i] if 0 <= i < len(a) else 0) for i in range(-n, len(a) - n)]


@pytest.mark.parametrize("n,final", [
    (0, [1, 2, 3, 4, 5, 6, 7, 8]),
    (2, [0, 0, 1, 2, 3, 4, 5, 6]),
    (3, [0, 0, 0, 1, 2, 3, 4, 5]),
    (-1, [2, 3, 4, 5, 6, 7, 8, 0]),
    ])
def test_shift(n, final):
    assert shift(list(range(1, 9)), n) == final


def test_simple_integers(bgv_context):
    parameters, crypto_context, key_pair = bgv_context
    rng = random.Random(342342)
    cnt = 12
    raw = [[rng.randint(1, 12) for _ in range(cnt)] for _ in range(3)]
    plaintext = [crypto_context.MakePackedPlaintext(r) for r in raw]
    ciphertext = [crypto_context.Encrypt(key_pair.publicKey, pt) for pt in plaintext]
    assert bgv_equal(raw[0], ciphertext[0], crypto_context, key_pair)

    # Homomorphic additions
    ciphertext_add12 = crypto_context.EvalAdd(ciphertext[0], ciphertext[1])
    ciphertext_add_result = crypto_context.EvalAdd(ciphertext_add12, ciphertext[2])
    assert bgv_equal(
        [a + b + c for (a, b, c) in zip(*raw)],
        ciphertext_add_result, crypto_context, key_pair
        )

    # Homomorphic Multiplication
    ciphertext_mult12 = crypto_context.EvalMult(ciphertext[0], ciphertext[1])
    ciphertext_mult_result = crypto_context.EvalMult(ciphertext_mult12, ciphertext[2])
    assert bgv_equal(
        [a * b * c for (a, b, c) in zip(*raw)],
        ciphertext_mult_result, crypto_context, key_pair
        )

    # Homomorphic Rotations. These values must be initialized with EvalRotateKeyGen.
    for rotation in [1, 2, -1, -2]:
        ciphertext_rot1 = crypto_context.EvalRotate(ciphertext[0], rotation)
        # This is a rotation with infill of 0, NOT a circular rotation.
        assert bgv_equal(shift(raw[0], -rotation), ciphertext_rot1, crypto_context, key_pair)
