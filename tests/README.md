# Working with Tests

These tests use [Pytest](https://docs.pytest.org/).

## Running and Using Tests

These tests assume that openfhe-python is installed in the current python environment, which you can check by importing openfhe.
```bash
python -c "__import__('openfhe')"
```
and that the `pytest` package is installed, either through pip or by installing `python3-pytest` in the operating system package manager.

### Specific to the OpenFHE unit tests

Some tests are marked with `@pytest.mark.long` if they are not meant to run
on Github Actions. Run these locally with:

```bash
pytest --run-long
pytest --run-all
```

### General Pytest usage

This is a quick reminder of pytest's features. To test a particular file:

```bash
pytest test_particular_file.py
```

Test all functions matching a name. For instance, this would pick up
`test_add_two_numbers`:

```bash
pytest -k add
```

As a reminder, pytest can be helpful for debugging. This command-line option
shows debug output from logging statements.

```bash
pytest --log-cli-level=debug
```

If a test is failing, pytest can drop into the debugger when an exception
happens.

```bash
pytest --pdb
```

## Guidelines for Writing Tests

**Mark long-running tests with long** -- These tests run with default settings
on Github Actions, which can be underpowered, so there is a way to mark tests
that can be run by hand or on other automation servers.

```python
@pytest.mark.long
def test_ckks_large_context():
    assert true
```

The goal is for the Github Actions tests to reassure a committer that they have
not broken the Python wrapper.

**Import OpenFHE as fhe** -- Unit tests tend to use more imports than most
code, for instance JSON, which conflicts with an OpenFHE name, so qualify
imports in the tests.

```python
import openfhe as fhe

def test_something():
    parameters = fhe.CCParamsCKKSRNS()
```

**Use logging instead of print statements** -- Pytest has nice support for
making logging statements visible, in the case that you are using tests
for debugging.

```python
import logging

LOGGER = logging.getLogger("test_file_name")

def test_something():
    arg = 3
    LOGGER.debug("My message has an argument %s", arg)
```
