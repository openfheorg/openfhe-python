#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/stl_bind.h>
#include <pybind11/complex.h>
#include <pybind11/functional.h>
#include <pybind11/operators.h>
#include <pybind11/iostream.h>
#include <iostream>
#include <map>
#include "openfhe.h"
#include "key/key-ser.h"
#include "bindings.h"
#include "cryptocontext_wrapper.h"
#include "binfhe_bindings.h"
#include "cryptocontext_docs.h"
#include "plaintext_docs.h"
#include "ciphertext_docs.h"

using namespace lbcrypto;
namespace py = pybind11;
PYBIND11_MAKE_OPAQUE(std::map<usint, EvalKey<DCRTPoly>>);

template <typename T>
void bind_parameters(py::module &m,const std::string name)
{
    py::class_<CCParams<T>>(m, name.c_str())
        .def(py::init<>())
        // getters
        .def("GetPlaintextModulus", &CCParams<T>::GetPlaintextModulus)
        .def("GetScheme", &CCParams<T>::GetScheme)
        .def("GetDigitSize", &CCParams<T>::GetDigitSize)
        .def("GetStandardDeviation", &CCParams<T>::GetStandardDeviation)
        .def("GetSecretKeyDist", &CCParams<T>::GetSecretKeyDist)
        .def("GetMaxRelinSkDeg", &CCParams<T>::GetMaxRelinSkDeg)
        .def("GetPREMode", &CCParams<T>::GetPREMode)
        .def("GetMultipartyMode", &CCParams<T>::GetMultipartyMode)
        .def("GetExecutionMode", &CCParams<T>::GetExecutionMode)
        .def("GetDecryptionNoiseMode", &CCParams<T>::GetDecryptionNoiseMode)
        .def("GetNoiseEstimate", &CCParams<T>::GetNoiseEstimate)
        .def("GetDesiredPrecision", &CCParams<T>::GetDesiredPrecision)
        .def("GetStatisticalSecurity", &CCParams<T>::GetStatisticalSecurity)
        .def("GetNumAdversarialQueries", &CCParams<T>::GetNumAdversarialQueries)
        //.def("GetThresholdNumOfParties", &CCParams<T>::GetThresholdNumOfParties)
        .def("GetKeySwitchTechnique", &CCParams<T>::GetKeySwitchTechnique)
        .def("GetScalingTechnique", &CCParams<T>::GetScalingTechnique)
        .def("GetBatchSize", &CCParams<T>::GetBatchSize)
        .def("GetFirstModSize", &CCParams<T>::GetFirstModSize)
        .def("GetNumLargeDigits", &CCParams<T>::GetNumLargeDigits)
        .def("GetMultiplicativeDepth", &CCParams<T>::GetMultiplicativeDepth)
        .def("GetScalingModSize", &CCParams<T>::GetScalingModSize)
        .def("GetSecurityLevel", &CCParams<T>::GetSecurityLevel)
        .def("GetRingDim", &CCParams<T>::GetRingDim)
        .def("GetEvalAddCount", &CCParams<T>::GetEvalAddCount)
        .def("GetKeySwitchCount", &CCParams<T>::GetKeySwitchCount)
        .def("GetEncryptionTechnique", &CCParams<T>::GetEncryptionTechnique)
        .def("GetMultiplicationTechnique", &CCParams<T>::GetMultiplicationTechnique)
        .def("GetMultiHopModSize", &CCParams<T>::GetMultiHopModSize)
        // setters
        .def("SetPlaintextModulus", &CCParams<T>::SetPlaintextModulus)
        .def("SetDigitSize", &CCParams<T>::SetDigitSize)
        .def("SetStandardDeviation", &CCParams<T>::SetStandardDeviation)
        .def("SetSecretKeyDist", &CCParams<T>::SetSecretKeyDist)
        .def("SetMaxRelinSkDeg", &CCParams<T>::SetMaxRelinSkDeg)
        .def("SetPREMode", &CCParams<T>::SetPREMode)
        .def("SetMultipartyMode", &CCParams<T>::SetMultipartyMode)
        .def("SetExecutionMode", &CCParams<T>::SetExecutionMode)
        .def("SetDecryptionNoiseMode", &CCParams<T>::SetDecryptionNoiseMode)
        .def("SetNoiseEstimate", &CCParams<T>::SetNoiseEstimate)
        .def("SetDesiredPrecision", &CCParams<T>::SetDesiredPrecision)
        .def("SetStatisticalSecurity", &CCParams<T>::SetStatisticalSecurity)
        .def("SetNumAdversarialQueries", &CCParams<T>::SetNumAdversarialQueries)
        //.def("SetThresholdNumOfParties", &CCParams<T>::SetThresholdNumOfParties)
        .def("SetKeySwitchTechnique", &CCParams<T>::SetKeySwitchTechnique)
        .def("SetScalingTechnique", &CCParams<T>::SetScalingTechnique)
        .def("SetBatchSize", &CCParams<T>::SetBatchSize)
        .def("SetFirstModSize", &CCParams<T>::SetFirstModSize)
        .def("SetNumLargeDigits", &CCParams<T>::SetNumLargeDigits)
        .def("SetMultiplicativeDepth", &CCParams<T>::SetMultiplicativeDepth)
        .def("SetScalingModSize", &CCParams<T>::SetScalingModSize)
        .def("SetSecurityLevel", &CCParams<T>::SetSecurityLevel)
        .def("SetRingDim", &CCParams<T>::SetRingDim)
        .def("SetEvalAddCount", &CCParams<T>::SetEvalAddCount)
        .def("SetKeySwitchCount", &CCParams<T>::SetKeySwitchCount)
        .def("SetEncryptionTechnique", &CCParams<T>::SetEncryptionTechnique)
        .def("SetMultiplicationTechnique", &CCParams<T>::SetMultiplicationTechnique)
        .def("SetMultiHopModSize", &CCParams<T>::SetMultiHopModSize)
        .def("__str__",[](const CCParams<T> &params) {
            std::stringstream stream;
            stream << params;
            return stream.str();
        });

        //

}

void bind_crypto_context(py::module &m)
{
    py::class_<CryptoContextImpl<DCRTPoly>, std::shared_ptr<CryptoContextImpl<DCRTPoly>>>(m, "CryptoContext")
        .def(py::init<>())
        .def("GetKeyGenLevel", &CryptoContextImpl<DCRTPoly>::GetKeyGenLevel, cc_GetKeyGenLevel_docs)
        .def("SetKeyGenLevel", &CryptoContextImpl<DCRTPoly>::SetKeyGenLevel, cc_SetKeyGenLevel_docs,
             py::arg("level"))
        //.def("GetScheme",&CryptoContextImpl<DCRTPoly>::GetScheme)
        //.def("GetCryptoParameters", &CryptoContextImpl<DCRTPoly>::GetCryptoParameters)
        .def("GetRingDimension", &CryptoContextImpl<DCRTPoly>::GetRingDimension, cc_GetRingDimension_docs)
        .def("Enable", static_cast<void (CryptoContextImpl<DCRTPoly>::*)(PKESchemeFeature)>(&CryptoContextImpl<DCRTPoly>::Enable), cc_Enable_docs,
             py::arg("feature"))
        .def("KeyGen", &CryptoContextImpl<DCRTPoly>::KeyGen, cc_KeyGen_docs)
        .def("EvalMultKeyGen", &CryptoContextImpl<DCRTPoly>::EvalMultKeyGen,
             cc_EvalMultKeyGen_docs,
             py::arg("privateKey"))
        .def("EvalMultKeysGen", &CryptoContextImpl<DCRTPoly>::EvalMultKeysGen,
             cc_EvalMultKeysGen_docs,
             py::arg("privateKey"))
        .def("EvalRotateKeyGen", &CryptoContextImpl<DCRTPoly>::EvalRotateKeyGen,
             cc_EvalRotateKeyGen_docs,
             py::arg("privateKey"),
             py::arg("indexList"),
             py::arg("publicKey") = nullptr)
        .def("MakeStringPlaintext", &CryptoContextImpl<DCRTPoly>::MakeStringPlaintext,
             cc_MakeStringPlaintext_docs,
             py::arg("str"))
        .def("MakePackedPlaintext", &CryptoContextImpl<DCRTPoly>::MakePackedPlaintext,
             cc_MakePackedPlaintext_docs,
             py::arg("value"),
             py::arg("depth") = 1,
             py::arg("level") = 0)
        .def("MakeCoefPackedPlaintext", &CryptoContextImpl<DCRTPoly>::MakeCoefPackedPlaintext,
            cc_MakeCoefPackedPlaintext_docs,
            py::arg("value"),
            py::arg("depth") = 1,
            py::arg("level") = 0)
        // TODO (Oliveira): allow user to specify different params values
        .def("MakeCKKSPackedPlaintext", static_cast<Plaintext (CryptoContextImpl<DCRTPoly>::*)(const std::vector<std::complex<double>> &, size_t, uint32_t, const std::shared_ptr<ParmType>, usint) const>(&CryptoContextImpl<DCRTPoly>::MakeCKKSPackedPlaintext), cc_MakeCKKSPackedPlaintextComplex_docs,
             py::arg("value"),
             py::arg("depth") = static_cast<size_t>(1),
             py::arg("level") = static_cast<uint32_t>(0),
             py::arg("params") = py::none(),
             py::arg("slots") = 0)
        .def("MakeCKKSPackedPlaintext", static_cast<Plaintext (CryptoContextImpl<DCRTPoly>::*)(const std::vector<double> &, size_t, uint32_t, const std::shared_ptr<ParmType>, usint) const>(&CryptoContextImpl<DCRTPoly>::MakeCKKSPackedPlaintext), cc_MakeCKKSPlaintextReal_docs,
             py::arg("value"),
             py::arg("depth") = static_cast<size_t>(1),
             py::arg("level") = static_cast<uint32_t>(0),
             py::arg("params") = py::none(),
             py::arg("slots") = 0)
        .def("EvalRotate", &CryptoContextImpl<DCRTPoly>::EvalRotate,
            cc_EvalRotate_docs,
            py::arg("ciphertext"),
            py::arg("index"))
        .def("EvalFastRotationPrecompute", &EvalFastRotationPrecomputeWrapper,
            cc_EvalFastRotationPreCompute_docs,
            py::arg("ciphertext"))
        .def("EvalFastRotation", &EvalFastRotationWrapper,
            cc_EvalFastRotation_docs,
            py::arg("ciphertext"),
            py::arg("index"),
            py::arg("m"),
            py::arg("digits"))
        .def("EvalFastRotationExt", &EvalFastRotationExtWrapper, 
            cc_EvalFastRotationExt_docs,
            py::arg("ciphertext"),
            py::arg("index"),
            py::arg("digits"),
            py::arg("addFirst"))
        .def("EvalAtIndexKeyGen", &CryptoContextImpl<DCRTPoly>::EvalAtIndexKeyGen,
            cc_EvalAtIndexKeyGen_docs,
            py::arg("privateKey"),
            py::arg("indexList"),
            py::arg("publicKey") = nullptr)
        .def("EvalAtIndex", &CryptoContextImpl<DCRTPoly>::EvalAtIndex,
            cc_EvalAtIndex_docs,
            py::arg("ciphertext"),
            py::arg("index"))
        .def("Encrypt", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(const PublicKey<DCRTPoly>, Plaintext) const>
            (&CryptoContextImpl<DCRTPoly>::Encrypt),
            cc_Encrypt_docs,
            py::arg("publicKey"),
            py::arg("plaintext"))
        .def("Decrypt", static_cast<Plaintext (*)(CryptoContext<DCRTPoly> &, const PrivateKey<DCRTPoly>, ConstCiphertext<DCRTPoly>)>
            (&DecryptWrapper), cc_Decrypt_docs,
            py::arg("privateKey"),
            py::arg("ciphertext"))
        .def("Decrypt", static_cast<Plaintext (*)(CryptoContext<DCRTPoly> &, ConstCiphertext<DCRTPoly>, const PrivateKey<DCRTPoly>)>
            (&DecryptWrapper), cc_Decrypt_docs,
            py::arg("ciphertext"),
            py::arg("privateKey"))
        .def("EvalAdd", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(ConstCiphertext<DCRTPoly>, ConstCiphertext<DCRTPoly>) const>
            (&CryptoContextImpl<DCRTPoly>::EvalAdd), 
            cc_EvalAdd_docs,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"))
        .def("EvalAdd", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(ConstCiphertext<DCRTPoly>, double) const>
            (&CryptoContextImpl<DCRTPoly>::EvalAdd), 
            cc_EvalAddfloat_docs,
            py::arg("ciphertext"),
            py::arg("scalar"))
        .def("EvalAddInPlace", static_cast<void (CryptoContextImpl<DCRTPoly>::*)(Ciphertext<DCRTPoly> &, ConstCiphertext<DCRTPoly>) const>
            (&CryptoContextImpl<DCRTPoly>::EvalAddInPlace),
            cc_EvalAddInPlace_docs,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"))
        .def("EvalAddInPlace", static_cast<void (CryptoContextImpl<DCRTPoly>::*)(Ciphertext<DCRTPoly> &, ConstPlaintext) const>
            (&CryptoContextImpl<DCRTPoly>::EvalAddInPlace),
            cc_EvalAddInPlacePlaintext_docs,
            py::arg("ciphertext"),
            py::arg("plaintext"))
        .def("EvalAddInPlace", static_cast<void (CryptoContextImpl<DCRTPoly>::*)(ConstPlaintext, Ciphertext<DCRTPoly> &) const>
            (&CryptoContextImpl<DCRTPoly>::EvalAddInPlace),
            "",
            py::arg("plaintext"),
            py::arg("ciphertext"))
        .def("EvalAddMutable", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(Ciphertext<DCRTPoly> &, Ciphertext<DCRTPoly> &) const>
            (&CryptoContextImpl<DCRTPoly>::EvalAddMutable),
            cc_EvalAddMutable_docs,
            py::arg("ct1"),
            py::arg("ct2"))
        .def("EvalAddMutable", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(Ciphertext<DCRTPoly> &, Plaintext) const>
            (&CryptoContextImpl<DCRTPoly>::EvalAddMutable),
            cc_EvalAddMutablePlaintext_docs,
            py::arg("ciphertext"),
            py::arg("plaintext"))
        .def("EvalAddMutable", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(Plaintext, Ciphertext<DCRTPoly> &) const>
            (&CryptoContextImpl<DCRTPoly>::EvalAddMutable),
            "",
            py::arg("plaintext"),
            py::arg("ciphertext"))
        .def("EvalAddMutableInPlace", &CryptoContextImpl<DCRTPoly>::EvalAddMutableInPlace,
            cc_EvalAddMutableInPlace_docs,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"))
        .def("EvalSub", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(ConstCiphertext<DCRTPoly>, ConstCiphertext<DCRTPoly>) const>
            (&CryptoContextImpl<DCRTPoly>::EvalSub),
            cc_EvalSub_docs,
            py::arg("ct1"),
            py::arg("ct2"))
        .def("EvalSub", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(ConstCiphertext<DCRTPoly>, double) const>
            (&CryptoContextImpl<DCRTPoly>::EvalSub),
            cc_EvalSubfloat_docs,
            py::arg("ciphertext"),
            py::arg("constant"))
        .def("EvalSub", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(double, ConstCiphertext<DCRTPoly>) const>
            (&CryptoContextImpl<DCRTPoly>::EvalSub),
            "",
            py::arg("constant"),
            py::arg("ciphertext"))
        .def("EvalSub", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(ConstCiphertext<DCRTPoly>, ConstPlaintext) const>
            (&CryptoContextImpl<DCRTPoly>::EvalSub),
            cc_EvalSubPlaintext_docs,
            py::arg("ciphertext"),
            py::arg("plaintext"))
        .def("EvalSub", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(ConstPlaintext, ConstCiphertext<DCRTPoly>) const>
            (&CryptoContextImpl<DCRTPoly>::EvalSub),
            "",
            py::arg("plaintext"),
            py::arg("ciphertext"))
        .def("EvalSubInPlace", static_cast<void (CryptoContextImpl<DCRTPoly>::*)(Ciphertext<DCRTPoly> &, ConstCiphertext<DCRTPoly>) const>
            (&CryptoContextImpl<DCRTPoly>::EvalSubInPlace),
            cc_EvalSubInPlace_docs,
            py::arg("ct1"),
            py::arg("ct2"))
        .def("EvalSubInPlace", static_cast<void (CryptoContextImpl<DCRTPoly>::*)(Ciphertext<DCRTPoly> &, double) const>
            (&CryptoContextImpl<DCRTPoly>::EvalSubInPlace),
            cc_EvalSubInPlacefloat_docs,
            py::arg("ciphertext"),
            py::arg("constant"))
        .def("EvalSubInPlace", static_cast<void (CryptoContextImpl<DCRTPoly>::*)(double, Ciphertext<DCRTPoly> &) const>
            (&CryptoContextImpl<DCRTPoly>::EvalSubInPlace),
            "",
            py::arg("constant"),
            py::arg("ciphertext"))
        .def("EvalSubMutable", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(Ciphertext<DCRTPoly> &, Ciphertext<DCRTPoly> &) const>
            (&CryptoContextImpl<DCRTPoly>::EvalSubMutable),
            cc_EvalSubMutable_docs,
            py::arg("ct1"),
            py::arg("ct2"))
        .def("EvalSubMutable", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(Ciphertext<DCRTPoly> &, Plaintext) const>
            (&CryptoContextImpl<DCRTPoly>::EvalSubMutable),
            cc_EvalSubMutablePlaintext_docs,
            py::arg("ciphertext"),
            py::arg("plaintext"))
        .def("EvalSubMutable", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(Plaintext, Ciphertext<DCRTPoly> &) const>
            (&CryptoContextImpl<DCRTPoly>::EvalSubMutable),
            "",
            py::arg("plaintext"),
            py::arg("ciphertext"))
        .def("EvalSubMutableInPlace", &CryptoContextImpl<DCRTPoly>::EvalSubMutableInPlace,
            cc_EvalSubMutableInPlace_docs,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"))
        .def("EvalMult", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(ConstCiphertext<DCRTPoly>, ConstCiphertext<DCRTPoly>) const>
            (&CryptoContextImpl<DCRTPoly>::EvalMult),
            cc_EvalMult_docs,
            py::arg("ct1"),
            py::arg("ct2"))
        .def("EvalMult", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(ConstCiphertext<DCRTPoly>, double) const>
            (&CryptoContextImpl<DCRTPoly>::EvalMult),
            cc_EvalMultfloat_docs,
            py::arg("ciphertext"),
            py::arg("constant"))
        .def("EvalMult", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(ConstCiphertext<DCRTPoly>, ConstPlaintext) const>
            (&CryptoContextImpl<DCRTPoly>::EvalMult),
            cc_EvalMultPlaintext_docs,
            py::arg("ciphertext"),
            py::arg("plaintext"))
        .def("EvalMult", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(ConstPlaintext, ConstCiphertext<DCRTPoly>) const>
            (&CryptoContextImpl<DCRTPoly>::EvalMult),
            "",
            py::arg("plaintext"),
            py::arg("ciphertext"))
        .def("EvalMult", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(double, ConstCiphertext<DCRTPoly>) const>
            (&CryptoContextImpl<DCRTPoly>::EvalMult),
            "",
            py::arg("constant"),
            py::arg("ciphertext"))
        .def("EvalMultMutable", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(Ciphertext<DCRTPoly> &, Ciphertext<DCRTPoly> &) const>
            (&CryptoContextImpl<DCRTPoly>::EvalMultMutable),
            cc_EvalMultMutable_docs,
            py::arg("ct1"),
            py::arg("ct2"))
        .def("EvalMultMutable", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(Ciphertext<DCRTPoly> &, Plaintext) const>
            (&CryptoContextImpl<DCRTPoly>::EvalMultMutable),
            cc_EvalMultMutablePlaintext_docs,
            py::arg("ciphertext"),
            py::arg("plaintext"))
        .def("EvalMultMutable", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(Plaintext, Ciphertext<DCRTPoly> &) const>
            (&CryptoContextImpl<DCRTPoly>::EvalMultMutable),
            "",
            py::arg("plaintext"),
            py::arg("ciphertext"))
        .def("EvalMultMutableInPlace", &CryptoContextImpl<DCRTPoly>::EvalMultMutableInPlace,
            cc_EvalMultMutableInPlace_docs,
            py::arg("ct1"),
            py::arg("ct2"))
        .def("EvalSquare", &CryptoContextImpl<DCRTPoly>::EvalSquare,
            cc_EvalSquare_docs,
            py::arg("ct"))
        .def("EvalSquareMutable", &CryptoContextImpl<DCRTPoly>::EvalSquareMutable,
            cc_EvalSquareMutable_docs,
            py::arg("ct"))
        .def("EvalSquareInPlace", &CryptoContextImpl<DCRTPoly>::EvalSquareInPlace,
            cc_EvalSquareInPlace_docs,
            py::arg("ct"))
        .def("EvalMultNoRelin", &CryptoContextImpl<DCRTPoly>::EvalMultNoRelin,
            cc_EvalMultNoRelin_docs,
            py::arg("ct1"),
            py::arg("ct2"))
        .def("Relinearize", &CryptoContextImpl<DCRTPoly>::Relinearize,
            cc_Relinearize_docs,
            py::arg("ciphertext"))
        .def("RelinearizeInPlace", &CryptoContextImpl<DCRTPoly>::RelinearizeInPlace,
            cc_RelinearizeInPlace_docs,
            py::arg("ciphertext"))
        .def("EvalMultAndRelinearize", &CryptoContextImpl<DCRTPoly>::EvalMultAndRelinearize,
            cc_EvalMultAndRelinearize_docs,
            py::arg("ct1"),
            py::arg("ct2"))
        .def("EvalNegate", &CryptoContextImpl<DCRTPoly>::EvalNegate,
            cc_EvalNegate_docs,
            py::arg("ct"))
        .def("EvalNegateInPlace", &CryptoContextImpl<DCRTPoly>::EvalNegateInPlace,
            cc_EvalNegateInPlace_docs,
            py::arg("ct"))
        .def("EvalLogistic", &CryptoContextImpl<DCRTPoly>::EvalLogistic,
            cc_EvalLogistic_docs,
            py::arg("ciphertext"),
            py::arg("a"),
            py::arg("b"),
            py::arg("degree"))
        .def("EvalChebyshevSeries", &CryptoContextImpl<DCRTPoly>::EvalChebyshevSeries,
            cc_EvalChebyshevSeries_docs,
            py::arg("ciphertext"),
            py::arg("coefficients"),
            py::arg("a"),
            py::arg("b"))
        .def("EvalChebyshevSeriesLinear", &CryptoContextImpl<DCRTPoly>::EvalChebyshevSeriesLinear,
            cc_EvalChebyshevSeriesLinear_docs,
            py::arg("ciphertext"),
            py::arg("coefficients"),
            py::arg("a"),
            py::arg("b"))
        .def("EvalChebyshevSeriesPS", &CryptoContextImpl<DCRTPoly>::EvalChebyshevSeriesPS,
            cc_EvalChebyshevSeriesPS_docs,
            py::arg("ciphertext"),
            py::arg("coefficients"),
            py::arg("a"),
            py::arg("b"))
        .def("EvalChebyshevFunction", &CryptoContextImpl<DCRTPoly>::EvalChebyshevFunction,
            cc_EvalChebyshevFunction_docs,
             py::arg("func"),
             py::arg("ciphertext"),
             py::arg("a"),
             py::arg("b"),
             py::arg("degree"))
        .def("EvalSin", &CryptoContextImpl<DCRTPoly>::EvalSin,
             cc_EvalSin_docs,
             py::arg("ciphertext"),
             py::arg("a"),
             py::arg("b"),
             py::arg("degree"))
        .def("EvalCos", &CryptoContextImpl<DCRTPoly>::EvalCos,
             cc_EvalCos_docs,
             py::arg("ciphertext"),
             py::arg("a"),
             py::arg("b"),
             py::arg("degree"))
        .def("EvalDivide", &CryptoContextImpl<DCRTPoly>::EvalDivide,
             cc_EvalDivide_docs,
             py::arg("ciphertext"),
             py::arg("a"),
             py::arg("b"),
             py::arg("degree"))
        .def("EvalSumKeyGen", &CryptoContextImpl<DCRTPoly>::EvalSumKeyGen,
             cc_EvalSumKeyGen_docs,
             py::arg("privateKey"),
             py::arg("publicKey") = py::none())
        //TODO (Oliveira, R.): Solve pointer handling bug when dealing with EvalKeyMap object for the next functions 
        .def("EvalSumRowsKeyGen", &CryptoContextImpl<DCRTPoly>::EvalSumRowsKeyGen,
             cc_EvalSumRowsKeyGen_docs,
             py::arg("privateKey"),
             py::arg("publicKey") = py::none(),
             py::arg("rowSize") = 0,
             py::arg("subringDim") = 0)
        .def("EvalSumColsKeyGen", &CryptoContextImpl<DCRTPoly>::EvalSumColsKeyGen,
             cc_EvalSumColsKeyGen_docs,
             py::arg("privateKey"),
             py::arg("publicKey") = py::none())
        .def("EvalSumRows", &CryptoContextImpl<DCRTPoly>::EvalSumRows,
             cc_EvalSumRows_docs,
             py::arg("ciphertext"),
             py::arg("rowSize"),
             py::arg("evalSumKeyMap"),
             py::arg("subringDim") = 0)
        .def("EvalSumCols", &CryptoContextImpl<DCRTPoly>::EvalSumCols,
             cc_EvalSumCols_docs,
             py::arg("ciphertext"),
             py::arg("rowSize"),
             py::arg("evalSumKeyMap"))
        .def("EvalInnerProduct", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(ConstCiphertext<DCRTPoly>, ConstCiphertext<DCRTPoly>, usint) const>(&CryptoContextImpl<DCRTPoly>::EvalInnerProduct),
             cc_EvalInnerProduct_docs,
             py::arg("ciphertext1"),
             py::arg("ciphertext2"),
             py::arg("batchSize"))
        .def("EvalInnerProduct", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(ConstCiphertext<DCRTPoly>, ConstPlaintext, usint) const>(&CryptoContextImpl<DCRTPoly>::EvalInnerProduct),
             cc_EvalInnerProductPlaintext_docs,
             py::arg("ciphertext"),
             py::arg("plaintext"),
             py::arg("batchSize"))
        .def("EvalMerge", &CryptoContextImpl<DCRTPoly>::EvalMerge,
             cc_EvalMerge_docs,
             py::arg("ciphertextVec"))
        .def("EvalPoly", &CryptoContextImpl<DCRTPoly>::EvalPoly,
             cc_EvalPoly_docs,
             py::arg("ciphertext"),
             py::arg("coefficients"))
        .def("EvalPolyLinear", &CryptoContextImpl<DCRTPoly>::EvalPolyLinear,
             cc_EvalPolyLinear_docs,
             py::arg("ciphertext"),
             py::arg("coefficients"))
        .def("EvalPolyPS", &CryptoContextImpl<DCRTPoly>::EvalPolyPS,
             cc_EvalPolyPS_docs,
             py::arg("ciphertext"),
             py::arg("coefficients"))
        .def("Rescale", &CryptoContextImpl<DCRTPoly>::Rescale,
             cc_Rescale_docs,
             py::arg("ciphertext"))
        .def("EvalBootstrapSetup", &CryptoContextImpl<DCRTPoly>::EvalBootstrapSetup,
             cc_EvalBootstrapSetup_docs,
             py::arg("levelBudget") = std::vector<uint32_t>({5, 4}),
             py::arg("dim1") = std::vector<uint32_t>({0, 0}),
             py::arg("slots") = 0,
             py::arg("correctionFactor") = 0)
        .def("EvalBootstrapKeyGen", &CryptoContextImpl<DCRTPoly>::EvalBootstrapKeyGen,
             cc_EvalBootstrapKeyGen_docs,
             py::arg("privateKey"),
             py::arg("slots"))
        .def("EvalBootstrap", &CryptoContextImpl<DCRTPoly>::EvalBootstrap,
             cc_EvalBootstrap_docs,
             py::arg("ciphertext"),
             py::arg("numIterations") = 1,
             py::arg("precision") = 0)
        //TODO (Oliveira, R.): Solve pointer handling bug when returning EvalKeyMap objects for the next functions
        .def("EvalAutomorphismKeyGen", &EvalAutomorphismKeyGenWrapper, 
            cc_EvalAutomorphismKeyGen_docs,
            py::arg("privateKey"),
            py::arg("indexList"),
            py::return_value_policy::reference_internal)
        .def("EvalAutomorphismKeyGen", &EvalAutomorphismKeyGenWrapper_PublicKey, 
            cc_EvalAutomorphismKeyGenPublic_docs,
            py::arg("publicKey"),
            py::arg("privateKey"),
            py::arg("indexList"),
            py::return_value_policy::reference_internal)
        .def("FindAutomorphismIndex", &CryptoContextImpl<DCRTPoly>::FindAutomorphismIndex,
            cc_FindAutomorphismIndex_docs,
            py::arg("idx"))
        .def("FindAutomorphismIndices", &CryptoContextImpl<DCRTPoly>::FindAutomorphismIndices,
            cc_FindAutomorphismIndices_docs,
            py::arg("idxList"))
        .def_static(
            "ClearEvalMultKeys", []()
            { CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys(); },
            cc_ClearEvalMultKeys_docs)
        .def_static(
            "ClearEvalAutomorphismKeys", []()
            { CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys(); },
            cc_ClearEvalAutomorphismKeys_docs)
        .def_static(
            "SerializeEvalMultKey", [](const std::string &filename, const SerType::SERBINARY &sertype, std::string id = "")
            {
                std::ofstream outfile(filename,std::ios::out | std::ios::binary);
                bool res;
                res = CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey<SerType::SERBINARY>(outfile, sertype, id);
                outfile.close();
                return res; },
            cc_SerializeEvalMultKey_docs,
            py::arg("filename"), py::arg("sertype"), py::arg("id") = "")
        .def_static(
            "SerializeEvalAutomorphismKey", [](const std::string &filename, const SerType::SERBINARY &sertype, std::string id = "")
            {
                std::ofstream outfile(filename,std::ios::out | std::ios::binary);
                bool res;
                res = CryptoContextImpl<DCRTPoly>::SerializeEvalAutomorphismKey<SerType::SERBINARY>(outfile, sertype, id);
                outfile.close();
                return res; },
            cc_SerializeEvalAutomorphismKey_docs,
            py::arg("filename"), py::arg("sertype"), py::arg("id") = "")
        .def_static("DeserializeEvalMultKey", [](std::shared_ptr<CryptoContextImpl<DCRTPoly>> &self, const std::string &filename, const SerType::SERBINARY &sertype)
                    {
                        std::ifstream emkeys(filename, std::ios::in | std::ios::binary);
                         if (!emkeys.is_open()) {
                            std::cerr << "I cannot read serialization from " << filename << std::endl;
                         }
                        bool res;
                        res = self->DeserializeEvalMultKey<SerType::SERBINARY>(emkeys, sertype);
                        return res; },
                        cc_DeserializeEvalMultKey_docs,
                        py::arg("self"),
                        py::arg("filename"), py::arg("sertype"))
        .def_static("DeserializeEvalAutomorphismKey", [](std::shared_ptr<CryptoContextImpl<DCRTPoly>> &self, const std::string &filename, const SerType::SERBINARY &sertype)
                    {
                        std::ifstream erkeys(filename, std::ios::in | std::ios::binary);
                         if (!erkeys.is_open()) {
                            std::cerr << "I cannot read serialization from " << filename << std::endl;
                         }
                        bool res;
                        res = self->DeserializeEvalAutomorphismKey<SerType::SERBINARY>(erkeys, sertype);
                        return res; },
                        cc_DeserializeEvalAutomorphismKey_docs,
                        py::arg("self"),
                        py::arg("filename"), py::arg("sertype"));

    // Generator Functions
    m.def("GenCryptoContext", &GenCryptoContext<CryptoContextBFVRNS>,
        py::arg("params"));
    m.def("GenCryptoContext", &GenCryptoContext<CryptoContextBGVRNS>,
        py::arg("params"));
    m.def("GenCryptoContext", &GenCryptoContext<CryptoContextCKKSRNS>,
        py::arg("params"));
    m.def("ReleaseAllContexts", &CryptoContextFactory<DCRTPoly>::ReleaseAllContexts);
}

int get_native_int(){
    #if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
        return 128;
    #else
        return 64;    
    #endif
}

void bind_enums_and_constants(py::module &m)
{
    /* ---- PKE enums ---- */ 
    // Scheme Types
    py::enum_<SCHEME>(m, "SCHEME")
        .value("INVALID_SCHEME", SCHEME::INVALID_SCHEME)
        .value("CKKSRNS_SCHEME", SCHEME::CKKSRNS_SCHEME)
        .value("BFVRNS_SCHEME", SCHEME::BFVRNS_SCHEME)
        .value("BGVRNS_SCHEME", SCHEME::BGVRNS_SCHEME);
    m.attr("INVALID_SCHEME") = py::cast(SCHEME::INVALID_SCHEME);
    m.attr("CKKSRNS_SCHEME") = py::cast(SCHEME::CKKSRNS_SCHEME);
    m.attr("BFVRNS_SCHEME") = py::cast(SCHEME::BFVRNS_SCHEME);
    m.attr("BGVRNS_SCHEME") = py::cast(SCHEME::BGVRNS_SCHEME);

    // PKE Features
    py::enum_<PKESchemeFeature>(m, "PKESchemeFeature")
        .value("PKE", PKESchemeFeature::PKE)
        .value("KEYSWITCH", PKESchemeFeature::KEYSWITCH)
        .value("PRE", PKESchemeFeature::PRE)
        .value("LEVELEDSHE", PKESchemeFeature::LEVELEDSHE)
        .value("ADVANCEDSHE", PKESchemeFeature::ADVANCEDSHE)
        .value("MULTIPARTY", PKESchemeFeature::MULTIPARTY)
        .value("FHE", PKESchemeFeature::FHE);
    m.attr("PKE") = py::cast(PKESchemeFeature::PKE);
    m.attr("KEYSWITCH") = py::cast(PKESchemeFeature::KEYSWITCH);
    m.attr("PRE") = py::cast(PKESchemeFeature::PRE);
    m.attr("LEVELEDSHE") = py::cast(PKESchemeFeature::LEVELEDSHE);
    m.attr("ADVANCEDSHE") = py::cast(PKESchemeFeature::ADVANCEDSHE);
    m.attr("MULTIPARTY") = py::cast(PKESchemeFeature::MULTIPARTY);
    m.attr("FHE") = py::cast(PKESchemeFeature::FHE);

    // Serialization Types
    py::class_<SerType::SERJSON>(m, "SERJSON");
    py::class_<SerType::SERBINARY>(m, "SERBINARY");
    m.attr("JSON") = py::cast(SerType::JSON);
    m.attr("BINARY") = py::cast(SerType::BINARY);

    // Scaling Techniques
    py::enum_<ScalingTechnique>(m, "ScalingTechnique")
       .value("FIXEDMANUAL", ScalingTechnique::FIXEDMANUAL)
       .value("FIXEDAUTO", ScalingTechnique::FIXEDAUTO)
       .value("FLEXIBLEAUTO", ScalingTechnique::FLEXIBLEAUTO)
       .value("FLEXIBLEAUTOEXT", ScalingTechnique::FLEXIBLEAUTOEXT)
       .value("NORESCALE", ScalingTechnique::NORESCALE)
       .value("INVALID_RS_TECHNIQUE", ScalingTechnique::INVALID_RS_TECHNIQUE);
    m.attr("FIXEDMANUAL") = py::cast(ScalingTechnique::FIXEDMANUAL);
    m.attr("FIXEDAUTO") = py::cast(ScalingTechnique::FIXEDAUTO);
    m.attr("FLEXIBLEAUTO") = py::cast(ScalingTechnique::FLEXIBLEAUTO);
    m.attr("FLEXIBLEAUTOEXT") = py::cast(ScalingTechnique::FLEXIBLEAUTOEXT);
    m.attr("NORESCALE") = py::cast(ScalingTechnique::NORESCALE);
    m.attr("INVALID_RS_TECHNIQUE") = py::cast(ScalingTechnique::INVALID_RS_TECHNIQUE);

    // Key Switching Techniques
    py::enum_<KeySwitchTechnique>(m, "KeySwitchTechnique")
        .value("INVALID_KS_TECH", KeySwitchTechnique::INVALID_KS_TECH)
        .value("BV", KeySwitchTechnique::BV)
        .value("HYBRID", KeySwitchTechnique::HYBRID);
    m.attr("INVALID_KS_TECH") = py::cast(KeySwitchTechnique::INVALID_KS_TECH);
    m.attr("BV") = py::cast(KeySwitchTechnique::BV);
    m.attr("HYBRID") = py::cast(KeySwitchTechnique::HYBRID);

    // Secret Key Dist
    py::enum_<SecretKeyDist>(m, "SecretKeyDist")
        .value("GAUSSIAN", SecretKeyDist::GAUSSIAN)
        .value("UNIFORM_TERNARY", SecretKeyDist::UNIFORM_TERNARY)
        .value("SPARSE_TERNARY", SecretKeyDist::SPARSE_TERNARY);
    m.attr("GAUSSIAN") = py::cast(SecretKeyDist::GAUSSIAN);
    m.attr("UNIFORM_TERNARY") = py::cast(SecretKeyDist::UNIFORM_TERNARY);
    m.attr("SPARSE_TERNARY") = py::cast(SecretKeyDist::SPARSE_TERNARY);

    // ProxyReEncryptionMode
    py::enum_<ProxyReEncryptionMode>(m, "ProxyReEncryptionMode")
        .value("NOT_SET", ProxyReEncryptionMode::NOT_SET)
        .value("INDCPA", ProxyReEncryptionMode::INDCPA)
        .value("FIXED_NOISE_HRA", ProxyReEncryptionMode::FIXED_NOISE_HRA)
        .value("NOISE_FLOODING_HRA", ProxyReEncryptionMode::NOISE_FLOODING_HRA)
        .value("DIVIDE_AND_ROUND_HRA", ProxyReEncryptionMode::DIVIDE_AND_ROUND_HRA);
    m.attr("NOT_SET") = py::cast(ProxyReEncryptionMode::NOT_SET);
    m.attr("INDCPA") = py::cast(ProxyReEncryptionMode::INDCPA);
    m.attr("FIXED_NOISE_HRA") = py::cast(ProxyReEncryptionMode::FIXED_NOISE_HRA);
    m.attr("NOISE_FLOODING_HRA") = py::cast(ProxyReEncryptionMode::NOISE_FLOODING_HRA);
    m.attr("DIVIDE_AND_ROUND_HRA") = py::cast(ProxyReEncryptionMode::DIVIDE_AND_ROUND_HRA);
    
    // MultipartyMode
    py::enum_<MultipartyMode>(m, "MultipartyMode")
        .value("INVALID_MULTIPARTY_MODE", MultipartyMode::INVALID_MULTIPARTY_MODE)
        .value("FIXED_NOISE_MULTIPARTY", MultipartyMode::FIXED_NOISE_MULTIPARTY)
        .value("NOISE_FLOODING_MULTIPARTY", MultipartyMode::NOISE_FLOODING_MULTIPARTY);
    m.attr("INVALID_MULTIPARTY_MODE") = py::cast(MultipartyMode::INVALID_MULTIPARTY_MODE);
    m.attr("FIXED_NOISE_MULTIPARTY") = py::cast(MultipartyMode::FIXED_NOISE_MULTIPARTY);
    m.attr("NOISE_FLOODING_MULTIPARTY") = py::cast(MultipartyMode::NOISE_FLOODING_MULTIPARTY);

    // ExecutionMode
    py::enum_<ExecutionMode>(m, "ExecutionMode")
        .value("EXEC_EVALUATION", ExecutionMode::EXEC_EVALUATION)
        .value("EXEC_NOISE_ESTIMATION", ExecutionMode::EXEC_NOISE_ESTIMATION);
    m.attr("EXEC_EVALUATION") = py::cast(ExecutionMode::EXEC_EVALUATION);
    m.attr("EXEC_NOISE_ESTIMATION") = py::cast(ExecutionMode::EXEC_NOISE_ESTIMATION);

    // DecryptionNoiseMode
    py::enum_<DecryptionNoiseMode>(m, "DecryptionNoiseMode")
        .value("FIXED_NOISE_DECRYPT", DecryptionNoiseMode::FIXED_NOISE_DECRYPT)
        .value("NOISE_FLOODING_DECRYPT", DecryptionNoiseMode::NOISE_FLOODING_DECRYPT);
    m.attr("FIXED_NOISE_DECRYPT") = py::cast(DecryptionNoiseMode::FIXED_NOISE_DECRYPT);
    m.attr("NOISE_FLOODING_DECRYPT") = py::cast(DecryptionNoiseMode::NOISE_FLOODING_DECRYPT);

    // EncryptionTechnique
    py::enum_<EncryptionTechnique>(m, "EncryptionTechnique")
        .value("STANDARD", EncryptionTechnique::STANDARD)
        .value("EXTENDED", EncryptionTechnique::EXTENDED);
    m.attr("STANDARD") = py::cast(EncryptionTechnique::STANDARD);
    m.attr("EXTENDED") = py::cast(EncryptionTechnique::EXTENDED);

    // MultiplicationTechnique
    py::enum_<MultiplicationTechnique>(m, "MultiplicationTechnique")
        .value("BEHZ", MultiplicationTechnique::BEHZ)
        .value("HPS", MultiplicationTechnique::HPS)
        .value("HPSPOVERQ", MultiplicationTechnique::HPSPOVERQ)
        .value("HPSPOVERQLEVELED", MultiplicationTechnique::HPSPOVERQLEVELED);
    m.attr("BEHZ") = py::cast(MultiplicationTechnique::BEHZ);
    m.attr("HPS") = py::cast(MultiplicationTechnique::HPS);
    m.attr("HPSPOVERQ") = py::cast(MultiplicationTechnique::HPSPOVERQ);
    m.attr("HPSPOVERQLEVELED") = py::cast(MultiplicationTechnique::HPSPOVERQLEVELED);

    /* ---- CORE enums ---- */ 
    // Security Level
    py::enum_<SecurityLevel>(m,"SecurityLevel")
        .value("HEStd_128_classic", SecurityLevel::HEStd_128_classic)
        .value("HEStd_192_classic", SecurityLevel::HEStd_192_classic)
        .value("HEStd_256_classic", SecurityLevel::HEStd_256_classic)
        .value("HEStd_NotSet", SecurityLevel::HEStd_NotSet);
    m.attr("HEStd_128_classic") = py::cast(SecurityLevel::HEStd_128_classic);
    m.attr("HEStd_192_classic") = py::cast(SecurityLevel::HEStd_192_classic);
    m.attr("HEStd_256_classic") = py::cast(SecurityLevel::HEStd_256_classic);
    m.attr("HEStd_NotSet") = py::cast(SecurityLevel::HEStd_NotSet);
    
    //Parameters Type
    /*TODO (Oliveira): If we expose Poly's and ParmType, this block will go somewhere else */
    using ParmType = typename DCRTPoly::Params;
    py::class_<ParmType, std::shared_ptr<ParmType>>(m, "ParmType");

    //NATIVEINT function
    m.def("get_native_int", &get_native_int);
  
    // EvalKeyMap
    py::bind_map<std::map<usint, EvalKey<DCRTPoly>>>(m, "EvalKeyMap");
}

void bind_keys(py::module &m)
{
    py::class_<PublicKeyImpl<DCRTPoly>, std::shared_ptr<PublicKeyImpl<DCRTPoly>>>(m, "PublicKey")
        .def(py::init<>());
    py::class_<PrivateKeyImpl<DCRTPoly>, std::shared_ptr<PrivateKeyImpl<DCRTPoly>>>(m, "PrivateKey");
    py::class_<KeyPair<DCRTPoly>>(m, "KeyPair")
        .def_readwrite("publicKey", &KeyPair<DCRTPoly>::publicKey)
        .def_readwrite("secretKey", &KeyPair<DCRTPoly>::secretKey);
    py::class_<EvalKeyImpl<DCRTPoly>, std::shared_ptr<EvalKeyImpl<DCRTPoly>>>(m, "EvalKey")
        .def(py::init<>());
}

void bind_encodings(py::module &m)
{
    py::class_<PlaintextImpl, std::shared_ptr<PlaintextImpl>>(m, "Plaintext")
        .def("GetScalingFactor", &PlaintextImpl::GetScalingFactor,
            ptx_GetScalingFactor_docs)
        .def("SetScalingFactor", &PlaintextImpl::SetScalingFactor,
            ptx_SetScalingFactor_docs,
            py::arg("sf"))
        .def("GetLength", &PlaintextImpl::GetLength,
            ptx_GetLength_docs)
        .def("GetSchemeID", &PlaintextImpl::GetSchemeID,
            ptx_GetSchemeID_docs)
        .def("SetLength", &PlaintextImpl::SetLength,
            ptx_SetLength_docs,
            py::arg("newSize"))
        .def("IsEncoded", &PlaintextImpl::IsEncoded,
            ptx_IsEncoded_docs)
        .def("GetLogPrecision", &PlaintextImpl::GetLogPrecision,
            ptx_GetLogPrecision_docs)
        .def("Encode", &PlaintextImpl::Encode,
            ptx_Encode_docs)
        .def("Decode", &PlaintextImpl::Decode,
            ptx_Decode_docs)
        .def("GetCKKSPackedValue", &PlaintextImpl::GetCKKSPackedValue,
            ptx_GetCKKSPackedValue_docs)
        .def("__repr__", [](const PlaintextImpl &p)
             {
        std::stringstream ss;
        ss << "<Plaintext Object: ";
        p.PrintValue(ss);
        ss << ">";
        return ss.str(); })
        .def("__str__", [](const PlaintextImpl &p)
             {
        std::stringstream ss;
        p.PrintValue(ss);
        return ss.str(); });
}

void bind_ciphertext(py::module &m)
{
    py::class_<CiphertextImpl<DCRTPoly>, std::shared_ptr<CiphertextImpl<DCRTPoly>>>(m, "Ciphertext")
        .def(py::init<>())
        .def("__add__", [](const Ciphertext<DCRTPoly> &a, const Ciphertext<DCRTPoly> &b)
             {return a + b; },py::is_operator(),pybind11::keep_alive<0, 1>())
       // .def(py::self + py::self);
    // .def("GetDepth", &CiphertextImpl<DCRTPoly>::GetDepth)
    // .def("SetDepth", &CiphertextImpl<DCRTPoly>::SetDepth)
     .def("GetLevel", &CiphertextImpl<DCRTPoly>::GetLevel,
        ctx_GetLevel_docs)
     .def("SetLevel", &CiphertextImpl<DCRTPoly>::SetLevel,
        ctx_SetLevel_docs,
        py::arg("level"));
    // .def("GetHopLevel", &CiphertextImpl<DCRTPoly>::GetHopLevel)
    // .def("SetHopLevel", &CiphertextImpl<DCRTPoly>::SetHopLevel)
    // .def("GetScalingFactor", &CiphertextImpl<DCRTPoly>::GetScalingFactor)
    // .def("SetScalingFactor", &CiphertextImpl<DCRTPoly>::SetScalingFactor)
    // .def("GetSlots", &CiphertextImpl<DCRTPoly>::GetSlots)
    // .def("SetSlots", &CiphertextImpl<DCRTPoly>::SetSlots);
}

void bind_schemes(py::module &m){
    /*Bind schemes specific functionalities like bootstrapping functions and multiparty*/
    py::class_<FHECKKSRNS>(m, "FHECKKSRNS")
        .def(py::init<>())
        //.def_static("GetBootstrapDepth", &FHECKKSRNS::GetBootstrapDepth)
        .def_static("GetBootstrapDepth", static_cast<uint32_t (*)(uint32_t, const std::vector<uint32_t>&, SecretKeyDist)>(&FHECKKSRNS::GetBootstrapDepth));                               
    
}

PYBIND11_MODULE(openfhe, m)
{
    m.doc() = "Open-Source Fully Homomorphic Encryption Library";
    // pke library
    bind_enums_and_constants(m);
    bind_parameters<CryptoContextBFVRNS>(m,"CCParamsBFVRNS");
    bind_parameters<CryptoContextBGVRNS>(m,"CCParamsBGVRNS");
    bind_parameters<CryptoContextCKKSRNS>(m,"CCParamsCKKSRNS");
    bind_encodings(m);
    bind_ciphertext(m);
    bind_keys(m);
    bind_crypto_context(m);
    bind_serialization(m);
    bind_schemes(m);
    // binfhe library
    bind_binfhe_enums(m);
    bind_binfhe_context(m);
    bind_binfhe_keys(m);
    bind_binfhe_ciphertext(m);
}
