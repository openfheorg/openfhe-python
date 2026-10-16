#
# Example for checking CKKS bootstrap memory cleanup.
#
# EvalBootstrapSetup() caches precomputed data in the CKKS scheme. This example
# compares ClearBootstrapPrecom() with ReleaseAllContexts() while keeping the
# local CryptoContext handle alive.
#
# Note: unlike the C++ version, which probes the allocator directly (mallinfo2),
# this Python version uses the process resident set size (VmRSS on Linux) as the
# memory probe, so the absolute numbers differ, but the effect of
# ClearBootstrapPrecom()/ReleaseAllContexts() is still visible.
#

from openfhe import *
import sys


def heap_in_use_bytes():
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
    except OSError:
        pass
    raise Exception("memory probe unavailable on this platform")


def build_bootstrap_context():
    parameters = CCParamsCKKSRNS()
    # SPARSE_ENCAPSULATED is recommended for CKKS bootstrapping (probability of failure below 2^-128). UNIFORM_TERNARY,
    # used here, is the distribution of the homomorphic encryption security guidelines; its probability of failure is
    # 2^-67 for N = 2^16 and 2^-27 for N = 2^17 with full packing.
    sk_dist = SecretKeyDist.UNIFORM_TERNARY
    parameters.SetSecretKeyDist(sk_dist)
    parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
    parameters.SetRingDim(1 << 12)

    if get_native_int() == 128:
        parameters.SetScalingModSize(78)
        parameters.SetFirstModSize(89)
        parameters.SetScalingTechnique(ScalingTechnique.FIXEDAUTO)
    else:
        parameters.SetScalingModSize(59)
        parameters.SetFirstModSize(60)
        parameters.SetScalingTechnique(ScalingTechnique.FLEXIBLEAUTO)

    level_budget = [4, 4]
    depth = 10 + CryptoContext.GetBootstrapDepth(level_budget, sk_dist)
    parameters.SetMultiplicativeDepth(depth)

    cc = GenCryptoContext(parameters)
    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)
    cc.Enable(PKESchemeFeature.ADVANCEDSHE)
    cc.Enable(PKESchemeFeature.FHE)
    return cc


def main():
    cc = build_bootstrap_context()
    ring_dim = cc.GetRingDimension()
    num_slots = ring_dim // 2

    print(f"ring dim = {ring_dim}")

    before = heap_in_use_bytes()
    cc.EvalBootstrapSetup([4, 4], [0, 0], num_slots)
    after = heap_in_use_bytes()
    cc.ClearBootstrapPrecom()
    after_cleanup = heap_in_use_bytes()
    print(f"EvalBootstrapSetup(): before: {before}; after: {after}; "
          f"after ClearBootstrapPrecom(): {after_cleanup}", file=sys.stderr)

    before = heap_in_use_bytes()
    cc.EvalBootstrapSetup([4, 4], [0, 0], num_slots)
    after = heap_in_use_bytes()
    cc.ClearBootstrapPrecom()
    after_cleanup = heap_in_use_bytes()
    ReleaseAllContexts()
    final = heap_in_use_bytes()
    print(f"EvalBootstrapSetup(): before: {before}; after: {after}; "
          f"after ClearBootstrapPrecom(): {after_cleanup}; after ReleaseAllContexts(): {final}", file=sys.stderr)


if __name__ == "__main__":
    main()
