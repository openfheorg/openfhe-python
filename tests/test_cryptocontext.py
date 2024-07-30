import pytest
import openfhe as fhe

pytestmark = pytest.mark.skipif(fhe.get_native_int() != 128, reason="Only for NATIVE_INT=128")

@pytest.mark.parametrize("scaling", [fhe.FIXEDAUTO, fhe.FIXEDMANUAL])
def test_ckks_context(scaling):
    batch_size = 8
    parameters = fhe.CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(5)
    parameters.SetScalingModSize(78)
    parameters.SetBatchSize(batch_size)
    parameters.SetScalingTechnique(scaling)
    parameters.SetNumLargeDigits(2)
    cc = fhe.GenCryptoContext(parameters)
    assert isinstance(cc, fhe.CryptoContext)
