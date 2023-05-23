from openfhe import CCParamsBFVRNS, CCParamsBGVRNS, CCParamsCKKSRNS, ScalingTechnique, SecretKeyDist, SecurityLevel
class TestParameters:
    # write testcases for parameters bindings
    def test_bfv_setters_and_getters(self):
        params = CCParamsBFVRNS()
        params.SetPlaintextModulus(65537)
        params.SetMultiplicativeDepth(2)
        assert params.GetPlaintextModulus() == 65537
        assert params.GetMultiplicativeDepth() == 2
    def test_bgv_setters_and_getters(self):
        params = CCParamsBGVRNS()
        params.SetPlaintextModulus(65537)
        params.SetMultiplicativeDepth(2)
        assert params.GetPlaintextModulus() == 65537
        assert params.GetMultiplicativeDepth() == 2
    def test_ckks_setters_and_getters(self):
        params = CCParamsCKKSRNS()
        params.SetPlaintextModulus(65537)
        assert params.GetPlaintextModulus() == 65537
        params.SetMultiplicativeDepth(5)
        assert params.GetMultiplicativeDepth() == 5
        params.SetScalingModSize(50)
        assert params.GetScalingModSize() == 50
        params.SetBatchSize(8)
        assert params.GetBatchSize() == 8
        # Scaling Techniques
        params.SetScalingTechnique(ScalingTechnique.FIXEDMANUAL)
        assert params.GetScalingTechnique() == ScalingTechnique.FIXEDMANUAL
        params.SetScalingTechnique(ScalingTechnique.FIXEDAUTO)
        assert params.GetScalingTechnique() == ScalingTechnique.FIXEDAUTO
        params.SetScalingTechnique(ScalingTechnique.FLEXIBLEAUTO)
        assert params.GetScalingTechnique() == ScalingTechnique.FLEXIBLEAUTO
        params.SetScalingTechnique(ScalingTechnique.FLEXIBLEAUTOEXT)
        assert params.GetScalingTechnique() == ScalingTechnique.FLEXIBLEAUTOEXT
        params.SetScalingTechnique(ScalingTechnique.NORESCALE)
        assert params.GetScalingTechnique() == ScalingTechnique.NORESCALE
        params.SetScalingTechnique(ScalingTechnique.INVALID_RS_TECHNIQUE)
        assert params.GetScalingTechnique() == ScalingTechnique.INVALID_RS_TECHNIQUE
        params.SetScalingTechnique(ScalingTechnique.FLEXIBLEAUTO)
        assert params.GetScalingTechnique() == ScalingTechnique.FLEXIBLEAUTO
        # TODO: test the getters for the following parameters (not binded in this branch yet)
        params.SetNumLargeDigits(2)
        params.SetFirstModSize(60)
        params.SetDigitSize(3)
        params.SetSecretKeyDist(SecretKeyDist.GAUSSIAN)
        #params.SetSecretKeyDist(SecretKeyDist.SPARSE_TERNARY)
        params.SetSecretKeyDist(SecretKeyDist.UNIFORM_TERNARY)
        params.SetSecurityLevel(SecurityLevel.HEStd_128_classic)
        params.SetSecurityLevel(SecurityLevel.HEStd_192_classic)
        params.SetSecurityLevel(SecurityLevel.HEStd_256_classic)
        params.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
        params.SetRingDim(1<<12)
        params.SetScalingModSize(59)




