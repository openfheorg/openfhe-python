# Use the official Ubuntu base image
FROM ubuntu:22.04

# Set environment variables to non-interactive (this prevents some prompts)
ENV DEBIAN_FRONTEND=noninteractive

# Install necessary dependencies for OpenFHE and JupyterLab
RUN apt-get update && apt-get install -y \
    git \
    cmake \
    build-essential \
    python3 \
    python3-dev \
    python3-pip \
    python3-venv \
    sudo \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install PyBind11
RUN pip3 install "pybind11[global]"
	
# Install JupyterLab
RUN python3 -m pip install --no-cache-dir jupyterlab

# Clone and build OpenFHE-development
RUN git clone https://github.com/openfheorg/openfhe-development.git \
    && cd openfhe-development \
    && mkdir build \
    && cd build \
    && cmake -DBUILD_UNITTESTS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_BENCHMARKS=OFF .. \
    && make -j$(nproc) \
    && make install

# Assume that OpenFHE installs libraries into /usr/local/lib
# Update LD_LIBRARY_PATH to include this directory
ENV LD_LIBRARY_PATH=/usr/local/lib:${LD_LIBRARY_PATH}

# Clone and build OpenFHE-Python
RUN git clone https://github.com/openfheorg/openfhe-python.git \
    && cd openfhe-python \
    && mkdir build \
    && cd build \
    && cmake .. \
    && make -j$(nproc) \
    && make install

# Install openfhe as a pip package
WORKDIR /openfhe-python
RUN python3 setup.py sdist bdist_wheel && pip install dist/openfhe-*.whl

# Expose the port JupyterLab will listen on
EXPOSE 8888

# Set the working directory
WORKDIR /workspace

# Start JupyterLab without token authentication
CMD ["jupyter-lab", "--ip=0.0.0.0", "--no-browser", "--allow-root", "--NotebookApp.token=''", "--NotebookApp.allow_origin='*'", "--NotebookApp.password=''", "--NotebookApp.password_required=False"]