# How to Run Tests

Go to root of openfhe-python. First, make the base images.

```bash
docker compose build
```

Then, as you edit code, test it with:
```bash
docker compose run fhe64mprel
docker compose run fhe128mprel
```
This will run the `runtests.sh` script inside the containers. That script builds the Python wrapper and then runs the tests. Output is in the home
directory as `test64.xml` and `test128.xml`.

## Low-level commands

```bash
docker run -v ${PWD}:/workspaces/openfhe-python -it fhe64mprel /bin/bash

su vscode
source ~/venv/bin/activate
cd /workspaces/openfhe-python/build
make
make install
-- Installing: /home/vscode/venv/lib/python3.11/site-packages/openfhe.cpython-311-aarch64-linux-gnu.so
-- Set runtime path of "/home/vscode/venv/lib/python3.11/site-packages/openfhe.cpython-311-aarch64-linux-gnu.so" to ""

cd ../tests
pip install pytest
pytest --run-long
```
