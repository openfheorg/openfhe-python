# This is a Debian Dockerfile with g++-11.
# I use clang-14 on my local machine. g++-11 also compiles and runs the code.
# Using Debian b/c has aarch64 variants.
# Local files required:
# 1. libtorch-shared-with-deps-latest.zip
# 2. ZscalerRootCA.crt - if you need this for the proxy
ARG VARIANT=bookworm
FROM mcr.microsoft.com/devcontainers/base:${VARIANT}

ARG CC_OPENFHE=/usr/bin/gcc-12
ARG CXX_OPENFHE=/usr/bin/g++-12
ARG nproc=4
ARG NATIVEBIT="128"

LABEL edu.cmu.sei.division="AID"
LABEL edu.cmu.sei.project="DARPA DPRIVE"
LABEL edu.cmu.sei.owner="ajdolgert@sei.cmu.edu"
LABEL edu.cmu.sei.description="OpenFHE for Python testing"

# ARG CC_param=/usr/bin/clang-13
# ARG CXX_param=/usr/bin/clang++-13

ENV DEBIAN_FRONTEND=noninteractive \
    repository="openfhe-development" \
    branch=main \
    NATIVEBIT=${NATIVEBIT}

# This command enables "testing" packages, not "experimental".
# 2023-03-24 Need this command to get g++-11, cmake-3.25.
#RUN echo "deb http://ftp.us.debian.org/debian bookworm main" >> /etc/apt/sources.list

#install pre-requisites for OpenFHE
RUN sudo apt-get update && sudo apt-get install -y \ 
    autoconf \
    build-essential \
    gcc \
    g++ \
    gdb \
    cmake \
    cmake-curses-gui \
    doxygen \
    git \
    graphviz \
    hdf5-helpers \
    hdf5-tools \
    libboost-all-dev \
    libhdf5-dev \
    libomp5 \
    libomp-dev \
    libgmp-dev \
    libntl-dev \
    libssl-dev \
    ninja-build \
    openssl \
    pkg-config \
    python3 \
    python3-dev \
    python3-certifi \
    python3-pip \
    wget

RUN apt-get clean && rm -rf /var/lib/apt/lists/*

############ PROXIES ################### 
# The CERT_PATH points to a .pem, not .crt, because it gets copied with suffix .pem.
ENV HTTP_PROXY="http://cloudproxy.sei.cmu.edu:80" \
    HTTPS_PROXY="http://cloudproxy.sei.cmu.edu:80" \
    NO_PROXY="localhost,.local,*.sei.cmu.edu,*.cert.org" \
    http_proxy="http://cloudproxy.sei.cmu.edu:80" \
    https_proxy="http://cloudproxy.sei.cmu.edu:80" \
    no_proxy="localhost,.local,*.sei.cmu.edu,*.cert.org" \
    VCPKG_FORCE_SYSTEM_BINARIES=1 \
    CERT_PATH=/etc/ssl/certs/ZscalerRootCA.pem \
    CERT_DIR=/etc/ssl/certs/ \
    SSL_CERT_FILE=${CERT_PATH} \
    SSL_CERT_DIR=${CERT_PATH} \
    REQUESTS_CA_BUNDLE=${CERT_PATH}

RUN mkdir -p /usr/local/share/ca-certificates && \
    wget http://aia.sei.cmu.edu/ZscalerRootCertificate-2048-SHA256.crt -O /usr/local/share/ca-certificates/ZscalerRootCA.crt && \
    mkdir -p /etc/pki/ca-trust/source/anchors/ && \
    cp /usr/local/share/ca-certificates/ZscalerRootCA.crt /etc/pki/ca-trust/source/anchors/ && \
    update-ca-certificates

# Confgures Git to use Zscaler's Proxy and trust the cert for SSL Inspection created by wjwos
RUN cd && \
    git config --global http.proxySSLCert ${CERT_PATH} && \
    git config --global http.SSLCAInfo ${CERT_PATH} && \
    git config --global http.proxySSLCAInfo ${CERT_PATH} && \
    git config --global http.proxy ${http_proxy} && \
    git config --system http.proxy ${http_proxy} && \
    git config --global https.proxy ${https_proxy} && \
    git config --system https.proxy ${https_proxy}

#installing OpenFHE
RUN cd / && git clone https://github.com/openfheorg/openfhe-development.git && \
    cd $repository && \
    git checkout $branch && \
    git submodule sync --recursive && \
    git submodule update --init  --recursive

# -DWITH_NTL_ON -DCMAKE_BUILD_TYPE=Debug
RUN sed -i.bak 's/\/\/ #define FIXED_SEED/#define FIXED_SEED/g' /$repository/src/core/include/math/distributiongenerator.h && \
    sed -i.bak 's/-O3/-O0/g' /$repository/CMakeLists.txt && \
    sed -i.bak 's/-Werror//g' /$repository/CMakeLists.txt && \
    mkdir /$repository/build && \
    cd /$repository/build && \
    CC="${CC_OPENFHE}" CXX="${CXX_OPENFHE}" cmake -DNATIVE_SIZE=$NATIVEBIT -DBUILD_BENCHMARKS=OFF -DBUILD_UNITTESTS=OFF -DWITH_OPENMP=ON -DCMAKE_BUILD_TYPE=Debug .. && \
    make -j 4 && \
    make install

RUN update-alternatives --install /usr/bin/python python /usr/bin/python3 1
RUN sudo apt-get update && sudo apt-get install -y \ 
    python3-pip \
    python3-venv

# This image is for testing 
RUN python -m venv /home/vscode/venv && \
    echo "export LD_LIBRARY_PATH=\"$LD_LIBRARY_PATH:/usr/local/lib\"" >> /home/vscode/venv/bin/activate && \
    /home/vscode/venv/bin/pip install 'pybind11[global]' pytest && \
    chown -R vscode:vscode /home/vscode/venv

COPY runtests.sh /home/vscode/runtests.sh

CMD ["/bin/bash", "/home/vscode/runtests.sh"]
