BinFHEContext
----------------

.. autoclass:: openfhe.BinFHEContext
    :members:
    :undoc-members:
    :show-inheritance:

LWECiphertext
----------------
.. autoclass:: openfhe.LWECiphertext
    :members:
    :undoc-members:
    :show-inheritance:
    
LWEPrivateKey
----------------
.. autoclass:: openfhe.LWEPrivateKey
    :members:
    :undoc-members:
    :show-inheritance:

LWEPublicKey
----------------
.. autoclass:: openfhe.LWEPublicKey
    :members:
    :undoc-members:
    :show-inheritance:

LWESwitchingKey
----------------
.. autoclass:: openfhe.LWESwitchingKey
    :members:
    :undoc-members:
    :show-inheritance:

LWEKeyPair
----------------
.. autoclass:: openfhe.LWEKeyPair
    :members:
    :undoc-members:
    :show-inheritance:

RingGSWBTKey
----------------
.. autoclass:: openfhe.RingGSWBTKey
    :members:
    :undoc-members:
    :show-inheritance:

Serialization
----------------
BinFHE objects are serialized with the overloads of ``SerializeToFile`` and
deserialized with the functions below, each returning an ``(object, success)``
tuple.

.. autofunction:: openfhe.DeserializeBinFHECryptoContext

.. autofunction:: openfhe.DeserializeLWECiphertext

.. autofunction:: openfhe.DeserializeLWEPrivateKey

.. autofunction:: openfhe.DeserializeLWEPublicKey

.. autofunction:: openfhe.DeserializeBinFHEBTKey
