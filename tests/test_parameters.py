import unittest
from openfhe import CCParamsBFVRNS

class TestParameters(unittest.TestCase):
    # write testcases for parameters bindings
    def test_bfv_setters_and_getters(self):
        bfv_params = CCParamsBFVRNS()
        bfv_params.SetPlaintextModulus(65537)
        bfv_params.SetMultiplicativeDepth(2)
        self.assertEqual(bfv_params.GetPlaintextModulus(), 65537)
        self.assertEqual(bfv_params.GetMultiplicativeDepth(), 2)

if __name__ == '__main__':
    unittest.main()