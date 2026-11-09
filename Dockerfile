# syntax=docker/dockerfile:1
#
# go-ocsp-responder container image.
#
# Everything is built from pinned sources inside this file, so the image can be
# rebuilt locally and in CI with the same result. The runtime layout matches the
# previous image: the PKCS#11 module and its libraries live in /usr/local/lib,
# the binaries in /usr/bin, and the aws-kms-pkcs11 config is a symlink into the
# EFS depot. The PKCS#11 and KMS configuration itself is fetched from SSM at
# start up by startup.sh and is not part of the image.

# ---------------------------------------------------------------------------
# Go responder and CSR helper. cgo is required because crypto11 loads the
# PKCS#11 module with dlopen. Bookworm's glibc (2.36) is older than the
# runtime's (2.39), so the binaries run on the Ubuntu 24.04 runtime.
# ---------------------------------------------------------------------------
FROM golang:1.27.3-bookworm@sha256:025eefc1e8dbe63201734a72aaa0a55d7a077f2d8410432f8ae2f3e939f32871 AS go-build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY main.go ./
COPY gencsr/ ./gencsr/
RUN CGO_ENABLED=1 go build -trimpath -o /out/go-ocsp-responder . && \
    CGO_ENABLED=1 go build -trimpath -o /out/gencsr ./gencsr

# ---------------------------------------------------------------------------
# AWS SDK for C++ (built with vcpkg) and the aws-kms-pkcs11 PKCS#11 module.
#
# The responder signs through aws_kms_pkcs11.so, which links libcurl and the
# AWS SDK for C++ (which also uses libcurl as its HTTP client to call KMS).
# That is why the image carries a vcpkg built libcurl and OpenSSL. Pinning the
# vcpkg release pins those versions; bump VCPKG_COMMIT to pick up fixes.
# ---------------------------------------------------------------------------
FROM ubuntu:24.04@sha256:78d4744ead1f5b19b04d0df558ab182a5300903900755e515b2ca4d10eb2044d AS native-build

# vcpkg release 2026.10.16 (curl 8.23.0, openssl 3.6.5, aws-sdk-cpp 1.11.900)
ARG VCPKG_COMMIT=5d4a3dc90c0b3773f3bac81bf41297b54328f471
# aws-kms-pkcs11 at the commit the April 2025 production image was built from.
# Kept deliberately so the PKCS#11 module behaviour does not change in this patch.
ARG AWS_KMS_PKCS11_COMMIT=29bb9a4782407713bbde9e6d3fb6c536dea0fd35

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential ca-certificates curl git libjson-c-dev libp11-kit-dev \
        linux-libc-dev perl pkg-config tar unzip zip && \
    rm -rf /var/lib/apt/lists/*

RUN git init -q /vcpkg && cd /vcpkg && \
    git fetch -q --depth 1 https://github.com/microsoft/vcpkg.git "${VCPKG_COMMIT}" && \
    git checkout -q --detach FETCH_HEAD && \
    ./bootstrap-vcpkg.sh -disableMetrics

# core,kms,acm-pca only: the module needs nothing else, and skipping the
# default s3, dynamodb and kinesis clients keeps the image smaller.
RUN /vcpkg/vcpkg install --triplet x64-linux-dynamic --clean-after-build \
        "aws-sdk-cpp[core,kms,acm-pca]" && \
    /vcpkg/vcpkg list

# LIBRARY_PATH makes the module's own -lcrypto -lcurl -lz resolve to the vcpkg
# libraries it ships with, instead of whatever dev packages the build host has.
RUN git init -q /aws-kms-pkcs11 && cd /aws-kms-pkcs11 && \
    git fetch -q --depth 1 https://github.com/JackOfMostTrades/aws-kms-pkcs11.git "${AWS_KMS_PKCS11_COMMIT}" && \
    git checkout -q --detach FETCH_HEAD && \
    LIBRARY_PATH=/vcpkg/installed/x64-linux-dynamic/lib \
        make AWS_SDK_PATH=/vcpkg/installed/x64-linux-dynamic AWS_SDK_STATIC=n && \
    mkdir -p /out/lib && \
    cp -a /vcpkg/installed/x64-linux-dynamic/lib/*.so* /out/lib/ && \
    cp aws_kms_pkcs11.so /out/lib/ && \
    chmod 0755 /out/lib/aws_kms_pkcs11.so

# ---------------------------------------------------------------------------
# AWS CLI v2, used by startup.sh to read SSM parameters. Version and archive
# hash are pinned; the archive was checked against the AWS CLI team PGP key
# (FB5D B77F D5C1 18B8 0511 ADA8 A631 0ACC 4672 475C) when the pin was set.
# ---------------------------------------------------------------------------
FROM ubuntu:24.04@sha256:78d4744ead1f5b19b04d0df558ab182a5300903900755e515b2ca4d10eb2044d AS awscli
ARG AWSCLI_VERSION=2.39.6
ARG AWSCLI_SHA256=7a121264f2637a3b90767aaf5bdd43ee88b8c925a931d0479fa2ce22b1a2fa76
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl unzip && \
    curl -fsSLo /tmp/awscliv2.zip "https://awscli.amazonaws.com/awscli-exe-linux-x86_64-${AWSCLI_VERSION}.zip" && \
    echo "${AWSCLI_SHA256}  /tmp/awscliv2.zip" | sha256sum -c - && \
    unzip -q /tmp/awscliv2.zip -d /tmp && \
    /tmp/aws/install --install-dir /usr/local/aws-cli --bin-dir /usr/local/bin

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------
FROM ubuntu:24.04@sha256:78d4744ead1f5b19b04d0df558ab182a5300903900755e515b2ca4d10eb2044d

# apt-get upgrade picks up Ubuntu security fixes released after the base image
# was published. Only what startup.sh and the PKCS#11 module need is installed.
RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get install -y --no-install-recommends ca-certificates jq libjson-c5 libstdc++6 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY --from=awscli /usr/local/aws-cli /usr/local/aws-cli
RUN ln -s /usr/local/aws-cli/v2/current/bin/aws /usr/local/bin/aws && aws --version

# PKCS#11 module and the libraries it needs, at the same paths as before.
COPY --from=native-build /out/lib/ /usr/local/lib/
RUN /usr/sbin/ldconfig

COPY --from=go-build /out/go-ocsp-responder /usr/bin/go-ocsp-responder
COPY --from=go-build /out/gencsr /usr/bin/gencsr

# aws-kms-pkcs11 reads its config from /etc; startup.sh writes it into the depot.
RUN mkdir -p /etc/aws-kms-pkcs11/ && ln -s /depot/aws-kms-config.json /etc/aws-kms-pkcs11/config.json

COPY --chmod=0755 startup.sh /startup.sh
EXPOSE 8080

ENTRYPOINT ["/startup.sh"]
