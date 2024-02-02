import random

import pytest
import openfhe as fhe


@pytest.fixture(scope="module")
def ckks_context():
    """
    This fixture creates a small CKKS context, with its paramters and keys.
    We make it because context creation can be slow.
    """
    batch_size = 8
    parameters = fhe.CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(5)
    # Choose scaling < 64 so that this works for 64bit architectures.
    parameters.SetScalingModSize(56)
    parameters.SetBatchSize(batch_size)
    parameters.SetScalingTechnique(fhe.ScalingTechnique.FIXEDAUTO)
    parameters.SetNumLargeDigits(2)
    cc = fhe.GenCryptoContext(parameters)
    cc.Enable(fhe.PKESchemeFeature.PKE)
    cc.Enable(fhe.PKESchemeFeature.KEYSWITCH)
    cc.Enable(fhe.PKESchemeFeature.LEVELEDSHE)
    keys = cc.KeyGen()
    cc.EvalRotateKeyGen(keys.secretKey, [1, -2])
    return parameters, cc, keys


def test_add_two_numbers(ckks_context):
    params, cc, keys = ckks_context
    batch_size = params.GetBatchSize()
    rng = random.Random(42429842)
    raw = [[rng.uniform(-1, 1) for _ in range(batch_size)] for _ in range(2)]
    ptxt = [cc.MakeCKKSPackedPlaintext(x) for x in raw]
    ctxt = [cc.Encrypt(keys.publicKey, y) for y in ptxt]

    ct_added = cc.EvalAdd(ctxt[0], ctxt[1])
    pt_added = cc.Decrypt(ct_added, keys.secretKey)
    pt_added.SetLength(batch_size)
    final_added = pt_added.GetCKKSPackedValue()
    raw_added = [a + b for (a, b) in zip(*raw)]
    total = sum(abs(a - b) for (a, b) in zip(raw_added, final_added))
    assert total < 1e-3
