#!/bin/sh
# Sourced by builder stages to preserve TARGETARCH fallback assignment.

case "${TARGETARCH:=$(dpkg --print-architecture)}" in \
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
&& rm -f /tmp/rustup-init /tmp/rustup-init.sha256
