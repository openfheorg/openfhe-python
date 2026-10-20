import random

import numpy as np
import pytest
import openfhe as fhe

pytestmark = pytest.mark.skipif(fhe.get_native_int() == 32, reason="Doesn't work for NATIVE_INT=32")


def test_ckks_depth_helpers_are_on_crypto_context():
    assert fhe.CryptoContext.GetBootstrapDepth([2, 2], fhe.UNIFORM_TERNARY) > 0
    assert fhe.CryptoContext.GetBootstrapDepth(9, [2, 2], fhe.UNIFORM_TERNARY) > 0
    assert fhe.CryptoContext.GetFBTDepth([3, 3], [1, -1], 2, 1, fhe.SPARSE_ENCAPSULATED) > 0
    assert fhe.CryptoContext.GetFBTDepth([3, 3], [1 + 0j, -1 + 0j], 4, 1, fhe.SPARSE_ENCAPSULATED) > 0
    assert fhe.CryptoContext.GetFEFBTDepth([3, 2], [1 + 0j, -1 + 0j], fhe.SPARSE_ENCAPSULATED) > 0


@pytest.fixture(scope="module")
def ckks_context():
    """
    This fixture creates a small CKKS context, with its paramters and keys.
    We make it because context creation can be slow.
    """
    batch_size = 8
    parameters = fhe.CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(5)
    if fhe.get_native_int() == 128:
        parameters.SetFirstModSize(89)
        parameters.SetScalingModSize(78)
        parameters.SetBatchSize(batch_size)
        parameters.SetScalingTechnique(fhe.ScalingTechnique.FIXEDAUTO)
        parameters.SetNumLargeDigits(2)

    elif fhe.get_native_int() == 64:
        parameters.SetFirstModSize(60)
        parameters.SetScalingModSize(56)
        parameters.SetBatchSize(batch_size)
        parameters.SetScalingTechnique(fhe.ScalingTechnique.FLEXIBLEAUTO)
        parameters.SetNumLargeDigits(2)

    else:
        raise ValueError("Expected a native int size 64 or 128.")

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


def test_existing_eval_automorphism_key_indices(ckks_context):
    _, cc, existing_keys = ckks_context
    keys = cc.KeyGen()
    key_tag = keys.secretKey.GetKeyTag()
    assert cc.GetExistingEvalAutomorphismKeyIndices(keyTag=key_tag) == []

    cc.EvalRotateKeyGen(keys.secretKey, [1, -2])
    # CKKS rotation offsets map to powers of 5 modulo the cyclotomic order.
    cyclotomic_order = 2 * cc.GetRingDimension()
    expected = sorted(pow(5, offset, cyclotomic_order) for offset in [1, -2])
    indices = cc.GetExistingEvalAutomorphismKeyIndices(key_tag)
    assert isinstance(indices, list)
    assert indices == expected
    assert fhe.CryptoContext.GetExistingEvalAutomorphismKeyIndices(key_tag) == expected
    # The documented way to go from a slot offset to an entry in this list. This also
    # cross-checks the 5^offset formula above for both rotation directions.
    for offset in [1, -2]:
        assert cc.FindAutomorphismIndex(offset) == pow(5, offset, cyclotomic_order)
        assert cc.FindAutomorphismIndex(offset) in indices
    # keyTag defaults to "", which matches no key map.
    assert cc.GetExistingEvalAutomorphismKeyIndices() == []

    # Repeated key generation must not duplicate indices or affect another tag.
    cc.EvalRotateKeyGen(keys.secretKey, [1, 3])
    updated = sorted(expected + [pow(5, 3, cyclotomic_order)])
    assert cc.GetExistingEvalAutomorphismKeyIndices(key_tag) == updated
    assert cc.GetExistingEvalAutomorphismKeyIndices(existing_keys.secretKey.GetKeyTag()) == expected
    assert indices == expected


def test_find_automorphism_indices_signed_offsets(ckks_context):
    _, cc, _ = ckks_context
    cyclotomic_order = 2 * cc.GetRingDimension()
    offsets = [0, 1, -2, 3, -1, -2]
    expected = [pow(5, offset, cyclotomic_order) for offset in offsets]
    assert cc.FindAutomorphismIndices(idxList=offsets) == expected
    assert [cc.FindAutomorphismIndex(idx=offset) for offset in offsets] == expected
    assert cc.FindAutomorphismIndices([]) == []
    for offset in [-(2**31) - 1, 2**31]:
        with pytest.raises(TypeError):
            cc.FindAutomorphismIndex(offset)
        with pytest.raises(TypeError):
            cc.FindAutomorphismIndices([1, offset])


def test_existing_bootstrap_key_indices():
    parameters = fhe.CCParamsCKKSRNS()
    parameters.SetSecurityLevel(fhe.HEStd_NotSet)
    parameters.SetRingDim(512)
    parameters.SetSecretKeyDist(fhe.UNIFORM_TERNARY)
    level_budget = [2, 2]
    depth = fhe.CryptoContext.GetBootstrapDepth(level_budget, fhe.UNIFORM_TERNARY)
    parameters.SetMultiplicativeDepth(depth + 2)
    parameters.SetScalingTechnique(fhe.FIXEDAUTO)
    parameters.SetScalingModSize(78 if fhe.get_native_int() == 128 else 59)
    parameters.SetFirstModSize(89 if fhe.get_native_int() == 128 else 60)
    cc = fhe.GenCryptoContext(parameters)
    for feature in [fhe.PKE, fhe.KEYSWITCH, fhe.LEVELEDSHE, fhe.ADVANCEDSHE, fhe.FHE]:
        cc.Enable(feature)

    slots = 8
    cc.EvalBootstrapSetup(level_budget, [0, 0], slots)
    keys = cc.KeyGen()
    key_tag = keys.secretKey.GetKeyTag()
    assert cc.GetExistingEvalAutomorphismKeyIndices(key_tag) == []
    cc.EvalBootstrapKeyGen(keys.secretKey, slots)
    indices = cc.GetExistingEvalAutomorphismKeyIndices(key_tag)
    assert isinstance(indices, list)
    assert indices == sorted(set(indices))
    assert len(indices) > 1
    assert 2 * cc.GetRingDimension() - 1 in indices  # Conjugation key.


def test_numpy_encode_decode_fast_paths(ckks_context):
    """numpy is a required dependency: arrays encode through the buffer fast path
    and the *Array accessors return numpy arrays that match the list API."""
    params, cc, keys = ckks_context
    batch_size = params.GetBatchSize()
    rng = np.random.default_rng(42429842)
    raw = rng.uniform(-1, 1, batch_size)

    pt_arr = cc.MakeCKKSPackedPlaintext(raw)
    pt_list = cc.MakeCKKSPackedPlaintext(raw.tolist())
    assert pt_arr.GetRealPackedValue() == pytest.approx(pt_list.GetRealPackedValue())

    values = pt_arr.GetRealPackedValueArray()
    assert isinstance(values, np.ndarray) and values.dtype == np.float64
    assert values == pytest.approx(pt_arr.GetRealPackedValue())
    complex_values = pt_arr.GetCKKSPackedValueArray()
    assert complex_values.dtype == np.complex128
    assert complex_values.real == pytest.approx(values)

    ct = cc.Encrypt(keys.publicKey, pt_arr)
    decrypted = cc.Decrypt(ct, keys.secretKey)
    decrypted.SetLength(batch_size)
    assert decrypted.GetRealPackedValueArray() == pytest.approx(raw, abs=1e-3)

    with pytest.raises((ValueError, TypeError)):
        cc.MakeCKKSPackedPlaintext(raw.reshape(2, batch_size // 2))


def test_eval_fast_rotation_matches_eval_rotate(ckks_context):
    """Hoisted rotations: one precompute reused across rotations (the digit
    decomposition is aliased, not copied, so reuse must not corrupt it)."""
    params, cc, keys = ckks_context
    batch_size = params.GetBatchSize()
    rng = random.Random(7)
    raw = [rng.uniform(-1, 1) for _ in range(batch_size)]
    ct = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(raw))
    digits = cc.EvalFastRotationPrecompute(ct)
    m = 2 * cc.GetRingDimension()
    for index in (1, -2, 1):  # repeat an index: the reused digits must stay intact
        plain = cc.Decrypt(cc.EvalRotate(ct, index), keys.secretKey)
        plain.SetLength(batch_size)
        fast = cc.Decrypt(cc.EvalFastRotation(ct, index, m, digits), keys.secretKey)
        fast.SetLength(batch_size)
        assert fast.GetRealPackedValueArray() == pytest.approx(
            plain.GetRealPackedValueArray(), abs=1e-3)
