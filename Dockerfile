ARG PYTHON_IMAGE=python:3.13-slim@sha256:264c0eeef6549fa9e202c0e39c4bed7ab93693c75b1a942f11f44744c291b326
# Keep the major/minor version in sync with packages/modelaudit-picklescan/Cargo.toml rust-version.
ARG PICKLESCAN_RUST_TOOLCHAIN=1.83.0

FROM ${PYTHON_IMAGE} AS builder
ARG PICKLESCAN_RUST_TOOLCHAIN

WORKDIR /build

COPY pyproject.toml README.md ./
COPY packages/modelaudit-picklescan ./packages/modelaudit-picklescan
COPY modelaudit ./modelaudit

RUN apt-get update \
    && apt-get install --yes --no-install-recommends --only-upgrade libc-bin libc6 \
    && apt-get install --yes --no-install-recommends build-essential ca-certificates curl \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain "${PICKLESCAN_RUST_TOOLCHAIN}" \
    && PATH="/root/.cargo/bin:${PATH}" pip wheel --no-cache-dir --wheel-dir /wheels \
        ./packages/modelaudit-picklescan \
        .

FROM ${PYTHON_IMAGE} AS runtime

WORKDIR /app

RUN apt-get update \
    && apt-get install --yes --no-install-recommends --only-upgrade libc-bin libc6 \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl \
    && rm -rf /wheels

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
