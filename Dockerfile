FROM python:3.13-slim@sha256:d168b8d9eb761f4d3fe305ebd04aeb7e7f2de0297cec5fb2f8f6403244621664

WORKDIR /app

# Copy only necessary files for installation
COPY pyproject.toml README.md ./
COPY packages/modelaudit-picklescan ./packages/modelaudit-picklescan
COPY modelaudit ./modelaudit

# Install only the base package without heavy ML dependencies
# This keeps the lightweight image small and fast to build
RUN apt-get update \
    && apt-get install --yes --no-install-recommends --only-upgrade libc-bin libc6 \
    && apt-get install --yes --no-install-recommends build-essential ca-certificates curl \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain 1.74.1 \
    && export PATH="/root/.cargo/bin:${PATH}" \
    && rustc --version \
    && pip install --no-cache-dir ./packages/modelaudit-picklescan \
    && pip install --no-cache-dir . \
    && rm -rf /root/.cargo /root/.rustup \
    && apt-get purge --yes --auto-remove build-essential curl \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
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

# Set the entrypoint
ENTRYPOINT ["modelaudit"]
CMD ["--help"] 
