ARG PYTHON_IMAGE=python:3.13-slim@sha256:c33f0bc4364a6881bed1ec0cc2665e6c53c87a43e774aaeab88e6f17af105e4f
# Keep the major/minor version in sync with packages/modelaudit-picklescan/Cargo.toml rust-version.
ARG PICKLESCAN_RUST_TOOLCHAIN=1.83.0
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

RUN apt-get update \
    && apt-get install --yes --no-install-recommends --only-upgrade libc-bin libc6 libcap2 libssl3t64 libsystemd0 libudev1 \
    && apt-get install --yes --no-install-recommends build-essential ca-certificates curl \
    && case "${TARGETARCH:=$(dpkg --print-architecture)}" in \
        amd64) rustup_target="x86_64-unknown-linux-gnu"; rustup_sha256="${RUSTUP_INIT_X86_64_UNKNOWN_LINUX_GNU_SHA256}" ;; \
        arm64) rustup_target="aarch64-unknown-linux-gnu"; rustup_sha256="${RUSTUP_INIT_AARCH64_UNKNOWN_LINUX_GNU_SHA256}" ;; \
        *) echo "Unsupported Docker build architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
    && curl --proto '=https' --tlsv1.2 -fsSL \
        "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${rustup_target}/rustup-init" \
        -o /tmp/rustup-init \
    && printf '%s  %s\n' "${rustup_sha256}" /tmp/rustup-init > /tmp/rustup-init.sha256 \
    && sha256sum -c /tmp/rustup-init.sha256 \
    && chmod +x /tmp/rustup-init \
    && /tmp/rustup-init -y --profile minimal --default-toolchain "${PICKLESCAN_RUST_TOOLCHAIN}" \
    && rm -f /tmp/rustup-init /tmp/rustup-init.sha256 \
    && PATH="/root/.cargo/bin:${PATH}" pip wheel --no-cache-dir --wheel-dir /wheels \
        ./packages/modelaudit-picklescan \
        . \
    && pip install --no-cache-dir --prefix=/install /wheels/*.whl

FROM ${PYTHON_IMAGE} AS runtime

WORKDIR /app

RUN apt-get update \
    && apt-get install --yes --no-install-recommends --only-upgrade \
        bsdutils libc-bin libc6 libblkid1 libcap2 liblastlog2-2 libmount1 libsmartcols1 \
        libssl3t64 libsystemd0 libudev1 libuuid1 login mount util-linux \
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
