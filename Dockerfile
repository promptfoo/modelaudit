ARG PYTHON_IMAGE=python:3.14-slim@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f
# Keep the major/minor version in sync with packages/modelaudit-picklescan/Cargo.toml rust-version.
ARG PICKLESCAN_RUST_TOOLCHAIN=1.85.0
ARG RUSTUP_VERSION=1.29.0
ARG RUSTUP_INIT_X86_64_UNKNOWN_LINUX_GNU_SHA256=4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10
ARG RUSTUP_INIT_AARCH64_UNKNOWN_LINUX_GNU_SHA256=9732d6c5e2a098d3521fca8145d826ae0aaa067ef2385ead08e6feac88fa5792

FROM ${PYTHON_IMAGE} AS builder
ARG PICKLESCAN_RUST_TOOLCHAIN
ARG RUSTUP_VERSION
ARG RUSTUP_INIT_X86_64_UNKNOWN_LINUX_GNU_SHA256
ARG RUSTUP_INIT_AARCH64_UNKNOWN_LINUX_GNU_SHA256
ARG TARGETARCH

WORKDIR /build

COPY pyproject.toml README.md ./
COPY packages/modelaudit-picklescan ./packages/modelaudit-picklescan
COPY modelaudit ./modelaudit
COPY docker-install-rust.sh ./

RUN apt-get update \
    && apt-get install --yes --no-install-recommends --only-upgrade libc-bin libc6 libcap2 libssl3t64 libsystemd0 libudev1 \
    && apt-get install --yes --no-install-recommends build-essential ca-certificates curl \
    && . ./docker-install-rust.sh \
    && PATH="/root/.cargo/bin:${PATH}" pip wheel --no-cache-dir --wheel-dir /wheels \
        ./packages/modelaudit-picklescan \
        . \
    && pip install --no-cache-dir --prefix=/install /wheels/*.whl

FROM ${PYTHON_IMAGE} AS runtime

WORKDIR /app

RUN apt-get update \
    && apt-get install --yes --no-install-recommends --only-upgrade \
        apt bsdutils gzip libapt-pkg7.0 libc-bin libc6 libblkid1 libcap2 liblastlog2-2 libmount1 libpcre2-8-0 libsmartcols1 libsqlite3-0 \
        libssl3t64 libsystemd0 libudev1 libuuid1 login mount perl-base util-linux \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local

ARG UID=10001
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    appuser

USER appuser

ENTRYPOINT ["modelaudit"]
CMD ["--help"]
