import pytest
import openfhe


@pytest.fixture(scope="module")
def ckks_context():
    """
    This fixture creates a small CKKS context, with its paramters and keys.
    We make it because context creation can be slow.
    """
    batch_size = 8
    parameters = openfhe.CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(5)
    parameters.SetScalingModSize(56)
    parameters.SetBatchSize(batch_size)
    parameters.SetScalingTechnique(openfhe.ScalingTechnique.FIXEDAUTO)
    parameters.SetNumLargeDigits(2)
    cc = openfhe.GenCryptoContext(parameters)
    cc.Enable(openfhe.PKESchemeFeature.PKE)
    cc.Enable(openfhe.PKESchemeFeature.KEYSWITCH)
    cc.Enable(openfhe.PKESchemeFeature.LEVELEDSHE)
    keys = cc.KeyGen()
    cc.EvalRotateKeyGen(keys.secretKey,[1,-2])
    return parameters, cc, keys


def test_add_two_numbers(ckks_context):
    params, cc, keys = ckks_context
    batch_size = params.GetBatchSize()
    raw = [
        [1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7],
        [2.0, 0.1, 1.3, 1.9, 4.1, 12.7, 0.02, 0.37],
    ]
    ptxt = [cc.MakeCKKSPackedPlaintext(x) for x in raw]
    ctxt = [cc.Encrypt(keys.publicKey, y) for y in ptxt]

    ct_added = cc.EvalAdd(ctxt[0], ctxt[1])
    pt_added = cc.Decrypt(ct_added, keys.secretKey)
    pt_added.SetLength(batch_size)
    final_added = pt_added.GetCKKSPackedValue()
    raw_added = [a + b for (a, b) in zip(*raw)]
    total = 0.0
    total = sum(abs(a - b) for (a, b) in zip(raw_added, final_added))
    assert total < 1e-3
