# Dockerfile — Reproducible build environment for uv security audit
#
# Builds uv from the pinned commit da5f6a6967b41423fb2a61bf094adff4e403367c
# and provides a self-contained environment for running all audit exploits.
#
# Usage:
#   docker build -t uv-audit .
#   docker run --rm uv-audit bash autofyn_audit/scripts/run_all_exploits.sh
#
# Base image pinned for reproducibility.

FROM python:3.12-slim@sha256:090ba77e2958f6af52a5341f788b50b032dd4ca28377d2893dcf1ecbdfdfe203

# ---- system dependencies ----
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        pkg-config \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

# ---- Rust toolchain (required to build uv from source) ----
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable --profile minimal \
    && rustup --version \
    && cargo --version

# ---- Clone uv at the pinned commit ----
ARG UV_COMMIT=da5f6a6967b41423fb2a61bf094adff4e403367c
WORKDIR /build

RUN git clone https://github.com/astral-sh/uv.git /build/uv \
    && git -C /build/uv checkout "${UV_COMMIT}"

# ---- Build uv ----
RUN cargo build --manifest-path /build/uv/Cargo.toml --bin uv \
    && cp /build/uv/target/debug/uv /usr/local/bin/uv-audit \
    && /usr/local/bin/uv-audit --version

# ---- Copy audit scripts into image ----
WORKDIR /audit
COPY autofyn_audit/ /audit/autofyn_audit/

# Ensure scripts are executable
RUN chmod +x /audit/autofyn_audit/scripts/setup.sh \
    && chmod +x /audit/autofyn_audit/scripts/teardown.sh \
    && chmod +x /audit/autofyn_audit/scripts/run_all_exploits.sh \
    && chmod +x /audit/autofyn_audit/exploits/01_credential_leakage/run_exploit.sh \
    && chmod +x /audit/autofyn_audit/exploits/02_github_url_injection/run_exploit.sh

# Make the audit-built uv available as "uv" so exploit scripts find it.
# The system uv (if any) is superseded by the pinned build.
RUN ln -sf /usr/local/bin/uv-audit /usr/local/bin/uv

# Symlink so exploit scripts that look for target/release/uv also work.
RUN mkdir -p /audit/target/release \
    && ln -sf /usr/local/bin/uv-audit /audit/target/release/uv

ENV HOME=/root

CMD ["bash", "autofyn_audit/scripts/run_all_exploits.sh"]
