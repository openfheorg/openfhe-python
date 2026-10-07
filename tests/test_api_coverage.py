import openfhe as fhe
import pytest

pytestmark = pytest.mark.skipif(fhe.get_native_int() == 32, reason="CKKS is not supported for NATIVE_INT=32")


@pytest.fixture(scope="module")
def ckks_context():
    """A small CKKS context shared by the tests below, since setup is slow."""
    params = fhe.CCParamsCKKSRNS()
    params.SetMultiplicativeDepth(6)
    params.SetBatchSize(8)
    params.SetScalingModSize(50)
    params.SetRingDim(1024)
    params.SetSecurityLevel(fhe.HEStd_NotSet)

    cc = fhe.GenCryptoContext(params)
    for feature in [fhe.PKE, fhe.KEYSWITCH, fhe.LEVELEDSHE, fhe.ADVANCEDSHE, fhe.MULTIPARTY]:
        cc.Enable(feature)

    keys = cc.KeyGen()
    cc.EvalMultKeyGen(keys.secretKey)
    cc.EvalSumKeyGen(keys.secretKey)
    return cc, keys


def decrypt(cc, ciphertext, secret_key, length=2):
    plaintext = cc.Decrypt(ciphertext, secret_key)
    plaintext.SetLength(length)
    return [round(value.real, 4) for value in plaintext.GetCKKSPackedValue()]


def test_spreadsheet_add_apis_are_exposed():
    expected_methods = {
        fhe.CryptoContext: {
            "ClearAllCKKSCaches",
            "ClearSchemeSwitchPrecom",
            "ComposedEvalMult",
            "DeserializeEvalSumKey",
            "EvalAddInPlaceNoCheck",
            "EvalBootstrapPrecompute",
            "EvalBootstrapStCFirst",
            "EvalChebyPolys",
            "EvalChebyshevSeriesWithPrecomp",
            "EvalHermiteTrigSeries",
            "EvalMultInPlace",
            "EvalMultNoCheck",
            "EvalMultNoRelinNoCheck",
            "EvalPolyWithPrecomp",
            "EvalPowers",
            "GetAllEvalAutomorphismKeys",
            "GetAllEvalMultKeys",
            "GetAllEvalSumKeys",
            "GetEncodingParams",
            "GetEvalAutomorphismNoKeyIndices",
            "GetPlaintextForDecrypt",
            "GetRootOfUnity",
            "GetScheme",
            "getSchemeId",
            "GetSwkFC",
            "GetUniqueValues",
            "KeySwitch",
            "KeySwitchDown",
            "KeySwitchDownFirstElement",
            "KeySwitchExt",
            "KeySwitchInPlace",
            "LevelReduce",
            "LevelReduceInPlace",
            "MultiEvalAutomorphismKeyGen",
            "RecoverSharedKey",
            "SerializedObjectName",
            "SerializedVersion",
            "SerializeEvalSumKey",
            "SetBinCCForSchemeSwitch",
            "SetParamsFromCKKSCryptocontext",
            "setSchemeId",
            "SetSwkFC",
            "ShareKeys",
            "SparseKeyGen",
        },
        fhe.CCParamsBFVRNS: {"GetThresholdNumOfParties"},
        fhe.CCParamsBGVRNS: {"GetThresholdNumOfParties"},
        fhe.CCParamsCKKSRNS: {"GetThresholdNumOfParties"},
        fhe.Ciphertext: {
            "CloneEmpty",
            "GetHopLevel",
            "GetScalingFactorInt",
            "NumberCiphertextElements",
            "SetEncodingType",
            "SetHopLevel",
            "SetScalingFactorInt",
            "SetKeyTag",
        },
        fhe.Plaintext: {
            "GetCKKSDataType",
            "GetElementModulus",
            "GetElementRingDimension",
            "GetEncodingParams",
            "GetEncodingType",
            "GetScalingFactorInt",
            "SetCKKSDataType",
            "SetScalingFactorInt",
        },
        fhe.PublicKey: {"GetCryptoContext"},
        fhe.SchSwchParams: {"SetParamsFromCKKSCryptocontextCalled"},
    }

    missing = {
        cls.__name__: sorted(name for name in names if not hasattr(cls, name))
        for cls, names in expected_methods.items()
    }
    assert not {cls: names for cls, names in missing.items() if names}


def test_new_value_conversions_and_support_types():
    ciphertext = fhe.Ciphertext()
    scaling_factor = 2**60 + 123
    ciphertext.SetScalingFactorInt(scaling_factor)
    ciphertext.SetEncodingType(fhe.CKKS_PACKED_ENCODING)
    ciphertext.SetHopLevel(3)

    assert ciphertext.GetScalingFactorInt() == scaling_factor
    assert ciphertext.GetEncodingType() == fhe.CKKS_PACKED_ENCODING
    assert ciphertext.GetHopLevel() == 3
    assert ciphertext.NumberCiphertextElements() == 0
    assert isinstance(ciphertext.CloneEmpty(), fhe.Ciphertext)

    params = fhe.CCParamsCKKSRNS()
    assert params.GetThresholdNumOfParties() == 1

    scheme_switch_params = fhe.SchSwchParams()
    assert scheme_switch_params.SetParamsFromCKKSCryptocontextCalled() is None


@pytest.mark.parametrize("scalar", [2.0, complex(2.0, 0.0)], ids=["double", "complex"])
@pytest.mark.parametrize("scalar_first", [False, True], ids=["ct_scalar", "scalar_ct"])
def test_inplace_scalar_overloads_apply_the_right_operation(ckks_context, scalar, scalar_first):
    """EvalMultInPlace used to be registered as EvalAddInPlace, so assert the values.

    Both scalar types and both argument orders are bound for each operation, so all
    four overloads of each are exercised here.
    """
    cc, keys = ckks_context
    ciphertext = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext([0.25, 0.5]))

    multiplied = ciphertext.Clone()
    if scalar_first:
        cc.EvalMultInPlace(scalar, multiplied)
    else:
        cc.EvalMultInPlace(multiplied, scalar)
    assert decrypt(cc, multiplied, keys.secretKey) == [0.5, 1.0]

    added = ciphertext.Clone()
    if scalar_first:
        cc.EvalAddInPlace(scalar, added)
    else:
        cc.EvalAddInPlace(added, scalar)
    assert decrypt(cc, added, keys.secretKey) == [2.25, 2.5]


def test_no_check_variants_match_their_checked_counterparts(ckks_context):
    cc, keys = ckks_context
    ciphertext = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext([0.25, 0.5]))

    added = ciphertext.Clone()
    cc.EvalAddInPlaceNoCheck(added, ciphertext)
    assert decrypt(cc, added, keys.secretKey) == [0.5, 1.0]

    assert decrypt(cc, cc.EvalMultNoCheck(ciphertext, 2), keys.secretKey) == [0.5, 1.0]
    assert decrypt(cc, cc.ComposedEvalMult(ciphertext, ciphertext), keys.secretKey) == [0.0625, 0.25]

    squared = cc.EvalMultNoRelinNoCheck(ciphertext, ciphertext)
    assert squared.NumberCiphertextElements() == 3  # not relinearized back to 2
    assert decrypt(cc, cc.Relinearize(squared), keys.secretKey) == [0.0625, 0.25]


def test_series_precomputation_matches_direct_evaluation(ckks_context):
    cc, keys = ckks_context
    ciphertext = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext([0.25, 0.5]))
    coefficients = [1.0, 2.0, 3.0]

    powers = cc.EvalPowers(ciphertext, coefficients)
    assert isinstance(powers, fhe.SeriesPowers)
    assert decrypt(cc, cc.EvalPolyWithPrecomp(powers, coefficients), keys.secretKey) == decrypt(
        cc, cc.EvalPoly(ciphertext, coefficients), keys.secretKey
    )

    cheby_polys = cc.EvalChebyPolys(ciphertext, coefficients, -1.0, 1.0)
    assert isinstance(cheby_polys, fhe.SeriesPowers)
    assert decrypt(cc, cc.EvalChebyshevSeriesWithPrecomp(cheby_polys, coefficients), keys.secretKey) == decrypt(
        cc, cc.EvalChebyshevSeries(ciphertext, coefficients, -1.0, 1.0), keys.secretKey
    )


def test_key_sharing_round_trip(ckks_context):
    """RecoverSharedKey dereferences sk->GetCryptoContext(), so the key needs a context."""
    cc, keys = ckks_context
    number_of_parties, threshold = 3, 2

    shares = cc.ShareKeys(keys.secretKey, number_of_parties, threshold, 1, "additive")
    assert len(shares) == number_of_parties - 1

    recovered = fhe.PrivateKey(cc)
    assert recovered.GetCryptoContext() is not None
    cc.RecoverSharedKey(recovered, shares, number_of_parties, threshold, "additive")

    ciphertext = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext([0.25, 0.5]))
    assert decrypt(cc, ciphertext, recovered) == [0.25, 0.5]


def test_private_key_without_context_has_none():
    assert fhe.PrivateKey().GetCryptoContext() is None


@pytest.mark.parametrize("sertype", [fhe.BINARY, fhe.JSON], ids=["binary", "json"])
def test_eval_sum_key_serialization_round_trip(ckks_context, sertype, tmp_path):
    cc, keys = ckks_context
    key_tag = keys.secretKey.GetKeyTag()

    by_tag = str(tmp_path / "by_tag")
    by_context = str(tmp_path / "by_context")
    assert fhe.CryptoContext.SerializeEvalSumKey(by_tag, sertype, key_tag)
    assert fhe.CryptoContext.SerializeEvalSumKey(by_context, sertype, cc)

    assert fhe.CryptoContext.DeserializeEvalSumKey(by_tag, sertype)
    assert fhe.CryptoContext.DeserializeEvalSumKey(by_context, sertype)
    assert key_tag in fhe.CryptoContext.GetAllEvalSumKeys()


@pytest.mark.parametrize("sertype", [fhe.BINARY, fhe.JSON], ids=["binary", "json"])
def test_eval_sum_key_serialization_reports_unusable_paths(ckks_context, sertype):
    """An unopenable file returns False instead of surfacing a cereal stream error."""
    cc, keys = ckks_context
    unusable = "/nonexistent-directory-for-openfhe-tests/keys"

    assert fhe.CryptoContext.SerializeEvalSumKey(unusable, sertype, keys.secretKey.GetKeyTag()) is False
    assert fhe.CryptoContext.SerializeEvalSumKey(unusable, sertype, cc) is False
    assert fhe.CryptoContext.DeserializeEvalSumKey(unusable, sertype) is False


def test_element_params_feed_get_plaintext_for_decrypt(ckks_context):
    cc, _ = ckks_context
    element_params = cc.GetElementParams()

    assert element_params.GetRingDimension() == cc.GetRingDimension()
    assert element_params.GetCyclotomicOrder() == cc.GetCyclotomicOrder()

    plaintext = fhe.CryptoContext.GetPlaintextForDecrypt(
        fhe.CKKS_PACKED_ENCODING, element_params, cc.GetEncodingParams()
    )
    assert isinstance(plaintext, fhe.Plaintext)


def test_context_getters(ckks_context):
    cc, _ = ckks_context

    assert cc.getSchemeId() == fhe.CKKSRNS_SCHEME
    assert cc.SerializedObjectName() == "CryptoContext"
    assert fhe.CryptoContext.SerializedVersion() >= 1
    assert cc.GetEncodingParams().GetBatchSize() == 8
    assert isinstance(cc.GetScheme(), fhe.SchemeBase)
    # DCRTPoly stores a root of unity per RNS tower, so the aggregate one is 0
    assert cc.GetRootOfUnity() == 0


def test_static_key_maps_and_index_helpers(ckks_context):
    cc, keys = ckks_context
    key_tag = keys.secretKey.GetKeyTag()

    assert key_tag in fhe.CryptoContext.GetAllEvalMultKeys()
    assert key_tag in fhe.CryptoContext.GetAllEvalSumKeys()
    assert key_tag in fhe.CryptoContext.GetAllEvalAutomorphismKeys()

    assert fhe.CryptoContext.GetUniqueValues({1, 2, 3}, {3, 4, 5}) == {4, 5}

    existing = set(fhe.CryptoContext.GetExistingEvalAutomorphismKeyIndices(key_tag))
    assert existing
    absent = max(existing) + 1
    assert fhe.CryptoContext.GetEvalAutomorphismNoKeyIndices(key_tag, existing | {absent}) == {absent}


def test_key_switching_and_level_reduction(ckks_context):
    cc, keys = ckks_context
    ciphertext = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext([0.25, 0.5]))

    switch_key = cc.KeySwitchGen(keys.secretKey, keys.secretKey)
    assert decrypt(cc, cc.KeySwitch(ciphertext, switch_key), keys.secretKey) == [0.25, 0.5]

    in_place = ciphertext.Clone()
    cc.KeySwitchInPlace(in_place, switch_key)
    assert decrypt(cc, in_place, keys.secretKey) == [0.25, 0.5]

    extended = cc.KeySwitchExt(ciphertext, True)
    assert isinstance(cc.KeySwitchDownFirstElement(extended), fhe.DCRTPoly)
    assert decrypt(cc, cc.KeySwitchDown(extended), keys.secretKey) == [0.25, 0.5]

    # LevelReduce drops RNS towers without touching GetLevel() under FLEXIBLEAUTOEXT,
    # so assert the value survives rather than a level change.
    reduced = cc.LevelReduce(ciphertext, None, 1)
    assert decrypt(cc, reduced, keys.secretKey) == [0.25, 0.5]

    reduced_in_place = ciphertext.Clone()
    cc.LevelReduceInPlace(reduced_in_place, None, 1)
    assert decrypt(cc, reduced_in_place, keys.secretKey) == [0.25, 0.5]


def test_sparse_key_gen_and_public_key_context(ckks_context):
    cc, keys = ckks_context
    assert isinstance(cc.SparseKeyGen(), fhe.KeyPair)
    assert isinstance(keys.publicKey.GetCryptoContext(), fhe.CryptoContext)
