.. openfhe-python documentation master file, created by
   sphinx-quickstart on Tue Jul 25 18:24:19 2023.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to OpenFHE - Python's documentation!
============================================

OpenFHE - Python
----------------
Fully Homomorphic Encryption (FHE) is a powerful cryptographic primitive that enables performing computations over encrypted data without having access to the secret key. `OpenFHE <https://openfhe.org/>`_ is an open-source FHE library that includes efficient implementations of all common FHE schemes: BFV, BGV, CKKS, DM and CGGI.

``openfhe-python`` is a Python library built as a wrapper for the main capabilities of OpenFHE C++ library. It provides a more user-friendly interface for Python developers, 
while keeping the efficiency of C++ FHE operations.

.. toctree::
   :maxdepth: 3
   :caption: API Reference:
   
   cryptocontext
   cryptoparams
   ciphertext
   plaintext
   keys
   pke_enums
   binfhe
   binfhe_enums

