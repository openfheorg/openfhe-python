#include <pybind11/pybind11.h>
#include <pybind11/operators.h>
#include <iostream>
#include "openfhe.h"
#include "binfhe_bindings.h"
#include "binfhecontext.h"

using namespace lbcrypto;
namespace py = pybind11;

LWECiphertext binfhe_EncryptWrapper(BinFHEContext &self, ConstLWEPrivateKey sk, const LWEPlaintext &m, BINFHE_OUTPUT output = BOOTSTRAPPED,
                                    LWEPlaintextModulus p = 4, uint64_t mod = 0)
{
    NativeInteger mod_native_int = NativeInteger(mod);
    return self.Encrypt(sk, m, output, p, mod_native_int);
}

void bind_binfhe_enums(py::module &m)
{
    py::enum_<BINFHE_PARAMSET>(m, "BINFHE_PARAMSET")
        .value("TOY", BINFHE_PARAMSET::TOY)
        .value("MEDIUM", BINFHE_PARAMSET::MEDIUM)
        .value("STD128_AP", BINFHE_PARAMSET::STD128_AP)
        .value("STD128_APOPT", BINFHE_PARAMSET::STD128_APOPT)
        .value("STD128", BINFHE_PARAMSET::STD128)
        .value("STD128_OPT", BINFHE_PARAMSET::STD128_OPT)
        .value("STD192", BINFHE_PARAMSET::STD192)
        .value("STD192_OPT", BINFHE_PARAMSET::STD192_OPT)
        .value("STD256", BINFHE_PARAMSET::STD256)
        .value("STD256_OPT", BINFHE_PARAMSET::STD256_OPT)
        .value("STD128Q", BINFHE_PARAMSET::STD128Q)
        .value("STD128Q_OPT", BINFHE_PARAMSET::STD128Q_OPT)
        .value("STD192Q", BINFHE_PARAMSET::STD192Q)
        .value("STD192Q_OPT", BINFHE_PARAMSET::STD192Q_OPT)
        .value("STD256Q", BINFHE_PARAMSET::STD256Q)
        .value("STD256Q_OPT", BINFHE_PARAMSET::STD256Q_OPT)
        .value("SIGNED_MOD_TEST", BINFHE_PARAMSET::SIGNED_MOD_TEST);
    m.attr("TOY") = py::cast(BINFHE_PARAMSET::TOY);
    m.attr("MEDIUM") = py::cast(BINFHE_PARAMSET::MEDIUM);
    m.attr("STD128_AP") = py::cast(BINFHE_PARAMSET::STD128_AP);
    m.attr("STD128_APOPT") = py::cast(BINFHE_PARAMSET::STD128_APOPT);
    m.attr("STD128") = py::cast(BINFHE_PARAMSET::STD128);
    m.attr("STD128_OPT") = py::cast(BINFHE_PARAMSET::STD128_OPT);
    m.attr("STD192") = py::cast(BINFHE_PARAMSET::STD192);
    m.attr("STD192_OPT") = py::cast(BINFHE_PARAMSET::STD192_OPT);
    m.attr("STD256") = py::cast(BINFHE_PARAMSET::STD256);
    m.attr("STD256_OPT") = py::cast(BINFHE_PARAMSET::STD256_OPT);
    m.attr("STD128Q") = py::cast(BINFHE_PARAMSET::STD128Q);
    m.attr("STD128Q_OPT") = py::cast(BINFHE_PARAMSET::STD128Q_OPT);
    m.attr("STD192Q") = py::cast(BINFHE_PARAMSET::STD192Q);
    m.attr("STD192Q_OPT") = py::cast(BINFHE_PARAMSET::STD192Q_OPT);
    m.attr("STD256Q") = py::cast(BINFHE_PARAMSET::STD256Q);
    m.attr("STD256Q_OPT") = py::cast(BINFHE_PARAMSET::STD256Q_OPT);
    m.attr("SIGNED_MOD_TEST") = py::cast(BINFHE_PARAMSET::SIGNED_MOD_TEST);

    py::enum_<BINFHE_METHOD>(m, "BINFHE_METHOD")
        .value("INVALID_METHOD", BINFHE_METHOD::INVALID_METHOD)
        .value("AP", BINFHE_METHOD::AP)
        .value("GINX", BINFHE_METHOD::GINX);
    m.attr("INVALID_METHOD") = py::cast(BINFHE_METHOD::INVALID_METHOD);
    m.attr("GINX") = py::cast(BINFHE_METHOD::GINX);
    m.attr("AP") = py::cast(BINFHE_METHOD::AP);

    py::enum_<BINFHE_OUTPUT>(m, "BINFHE_OUTPUT")
        .value("INVALID_OUTPUT", BINFHE_OUTPUT::INVALID_OUTPUT)
        .value("FRESH", BINFHE_OUTPUT::FRESH)
        .value("BOOTSTRAPPED", BINFHE_OUTPUT::BOOTSTRAPPED);
    m.attr("INVALID_OUTPUT") = py::cast(BINFHE_OUTPUT::INVALID_OUTPUT);
    m.attr("FRESH") = py::cast(BINFHE_OUTPUT::FRESH);
    m.attr("BOOTSTRAPPED") = py::cast(BINFHE_OUTPUT::BOOTSTRAPPED);
}

void bind_binfhe_keys(py::module &m)
{
    py::class_<LWEPrivateKeyImpl, std::shared_ptr<LWEPrivateKeyImpl>>(m, "LWEPrivateKey")
        .def(py::init<>())
        .def("GetLength", &LWEPrivateKeyImpl::GetLength)
        .def(py::self == py::self)
        .def(py::self != py::self);
}
void bind_binfhe_ciphertext(py::module &m)
{
    py::class_<LWECiphertextImpl, std::shared_ptr<LWECiphertextImpl>>(m, "LWECiphertext")
        .def(py::init<>())
        .def("GetLength", &LWECiphertextImpl::GetLength)
        .def(py::self == py::self)
        .def(py::self != py::self);
}

void bind_binfhe_context(py::module &m)
{
    py::class_<BinFHEContext>(m, "BinFHEContext")
        .def(py::init<>())
        .def("GenerateBinFHEContext", static_cast<void (BinFHEContext::*)(BINFHE_PARAMSET, BINFHE_METHOD)>(&BinFHEContext::GenerateBinFHEContext),
             py::arg("set"), 
             py::arg("method") = GINX)
        .def("KeyGen", &BinFHEContext::KeyGen)
        .def("BTKeyGen", &BinFHEContext::BTKeyGen)
        .def("Encrypt", &binfhe_EncryptWrapper,
             py::arg("sk"),
             py::arg("m"),
             py::arg("output") = BOOTSTRAPPED,
             py::arg("p") = 4, 
             py::arg("mod") = 0);
}
