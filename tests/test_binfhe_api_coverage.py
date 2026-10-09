import openfhe as fhe
import pytest


def test_spreadsheet_add_apis_are_exposed():
    expected_methods = {
        fhe.BinFHEContext: {
            "HasInternal32RefreshKey",
            "HasInternal32SwitchKey",
            "KeySwitchGen",
            "PubKeyGen",
            "SwitchCTtoqn",
        },
        fhe.LWECiphertext: {"GetptModulus", "SetModulus", "SetptModulus"},
        fhe.LWEPrivateKey: {"GetModulus"},
        fhe.LWEPublicKey: {"GetModulus"},
    }

    missing = {
        cls.__name__: sorted(name for name in names if not hasattr(cls, name))
        for cls, names in expected_methods.items()
    }
    assert not {cls: names for cls, names in missing.items() if names}


def test_new_binfhe_bindings_round_trip():
    cc = fhe.BinFHEContext()
    cc.GenerateBinFHEContext(fhe.TOY, fhe.GINX)

    assert cc.HasInternal32RefreshKey() is False
    assert cc.HasInternal32SwitchKey() is False

    sk = cc.KeyGen()
    skN = cc.KeyGenN()
    public_key = cc.PubKeyGen(skN)

    assert isinstance(sk.GetModulus(), int)
    assert skN.GetModulus() == cc.GetQ()
    assert public_key.GetModulus() == cc.GetQ()

    switching_key = cc.KeySwitchGen(sk, skN)
    assert isinstance(switching_key, fhe.LWESwitchingKey)

    large_ciphertext = cc.Encrypt(skN, 1, fhe.LARGE_DIM, 4, cc.GetQ())
    switched_ciphertext = cc.SwitchCTtoqn(switching_key, large_ciphertext)
    assert cc.Decrypt(sk, switched_ciphertext) == 1

    ciphertext = cc.Encrypt(sk, 1, fhe.FRESH, 4)
    assert ciphertext.GetptModulus() == 4
    ciphertext.SetptModulus(8)
    assert ciphertext.GetptModulus() == 8

    modulus = ciphertext.GetModulus()
    ciphertext.SetModulus(modulus * 2)
    assert ciphertext.GetModulus() == modulus * 2
    ciphertext.SetModulus(modulus)
    assert ciphertext.GetModulus() == modulus


def test_private_key_cannot_be_default_constructed():
    """BinFHEContext guards only against a null key pointer.

    An empty-but-non-null LWEPrivateKey passes that guard and then segfaults in
    BTKeyGen/PubKeyGen/KeySwitchGen, so Python must not be able to build one.
    """
    with pytest.raises(TypeError):
        fhe.LWEPrivateKey()


def test_generated_private_keys_are_unaffected():
    cc = fhe.BinFHEContext()
    cc.GenerateBinFHEContext(fhe.TOY, fhe.GINX)

    assert cc.KeyGen().GetLength() > 0
    assert cc.KeyGenN().GetLength() > 0
    assert cc.KeyGenPair().secretKey.GetLength() > 0


def test_deserialized_private_keys_are_unaffected(tmp_path):
    cc = fhe.BinFHEContext()
    cc.GenerateBinFHEContext(fhe.TOY, fhe.GINX)
    sk = cc.KeyGen()

    path = str(tmp_path / "sk.bin")
    assert fhe.SerializeToFile(path, sk, fhe.BINARY)
    restored, ok = fhe.DeserializeLWEPrivateKey(path, fhe.BINARY)
    assert ok is True
    assert restored.GetLength() == sk.GetLength()
    assert restored.GetModulus() == sk.GetModulus()

    # the restored key still decrypts what the original encrypted
    ciphertext = cc.Encrypt(sk, 1, fhe.FRESH, 4)
    assert cc.Decrypt(restored, ciphertext) == 1


def test_failed_deserialization_yields_a_null_key():
    """A null key is caught by the C++ guard, unlike an empty-but-non-null one."""
    cc = fhe.BinFHEContext()
    cc.GenerateBinFHEContext(fhe.TOY, fhe.GINX)

    key, ok = fhe.DeserializeLWEPrivateKey("/nonexistent-directory-for-openfhe-tests/sk", fhe.BINARY)
    assert ok is False and key is None
    with pytest.raises(RuntimeError):
        cc.PubKeyGen(key)
