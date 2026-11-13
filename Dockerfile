# syntax=docker/dockerfile:1

# Build Ferron and its companion tools against a musl sysroot. The upstream
# revision matches the Ferron git dependencies in crates/*/Cargo.toml.
FROM rust:1.99.1-slim-trixie AS builder

ARG TARGETARCH
ARG FERRON_REV=eabdbdc2079e5c92a80c4cdb324a8d2d6094cc6d

RUN sed -i 's|http://deb.debian.org/debian$|http://ftp.hk.debian.org/debian|' /etc/apt/sources.list.d/debian.sources && \
    apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates clang cmake curl git libclang-dev lld llvm make \
    nasm perl pkg-config python3 && \
    rm -rf /var/lib/apt/lists/*

RUN case "${TARGETARCH}" in \
      amd64) target=x86_64-unknown-linux-musl ;; \
      arm64) target=aarch64-unknown-linux-musl ;; \
      *) echo "Unsupported Docker architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac && \
    rustup target add "${target}" && \
    printf '%s' "${target}" > /tmp/rust-target

RUN git clone --filter=blob:none https://github.com/ferronweb/ferron.git /ferron-src && \
    git -C /ferron-src checkout "${FERRON_REV}"

COPY docker/cross-build/prepare-musl.sh /tmp/prepare-musl.sh
RUN target="$(cat /tmp/rust-target)" && \
    bash /tmp/prepare-musl.sh -o /opt/sysroots "${target}"

WORKDIR /src
COPY . .

# Keep downloaded crates, git dependencies, and compiled objects across source
# edits. Target directories are separate per architecture and kept out of the
# image; build-musl.sh copies the finished binaries to /out before they unmount.
RUN --mount=type=cache,id=ferron-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=ferron-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=ferron-target-${TARGETARCH},target=/src/target,sharing=locked \
    --mount=type=cache,id=ferron-utils-target-${TARGETARCH},target=/src/ferron-target,sharing=locked \
    target="$(cat /tmp/rust-target)" && \
    bash docker/build-musl.sh "${target}" "/opt/sysroots/musl-${target}" /out

# Small runtime with CA certificates for outbound HTTPS.
FROM alpine:3.24.3 AS runtime-alpine
RUN apk add --no-cache ca-certificates && \
    addgroup -S -g 65532 ferron && adduser -S -D -H -u 65532 -G ferron ferron && \
    mkdir -p /etc/ferron /var/lib/ferron /var/log/ferron /var/www/static /var/cache/ferron-acme && \
    chown -R ferron:ferron /var/lib/ferron /var/log/ferron /var/cache/ferron-acme
COPY --from=builder /out/ferron /out/ferron-fmt /out/ferron-kdl2ferron /out/ferron-passwd /out/ferron-precompress /out/ferron-serve /usr/local/bin/
USER ferron
ENTRYPOINT ["/usr/local/bin/ferron"]
CMD ["run", "--config", "/etc/ferron/ferron.conf"]

# One-shot schema initializer; sqlite3 also lets operators manage DB rows.
FROM alpine:3.24.3 AS definitions-init
RUN apk add --no-cache sqlite && mkdir -p /var/lib/ferron
COPY --from=builder /out/abuse-definitions-init /usr/local/bin/abuse-definitions-init
ENTRYPOINT ["/usr/local/bin/abuse-definitions-init"]

# Official static Tailscale binaries.
# Alpine 3.24's apk tailscale (1.98.x) lags upstream security releases, and
# userspace networking needs only these two static binaries at runtime.
# Bump TAILSCALE_VERSION when updating; see https://pkgs.tailscale.com/stable/
FROM alpine:3.24.3 AS tailscale-fetch
ARG TARGETARCH
ARG TAILSCALE_VERSION=1.104.7
RUN apk add --no-cache ca-certificates && \
    case "${TARGETARCH}" in \
      amd64) ts_arch=amd64 ;; \
      arm64) ts_arch=arm64 ;; \
      *) echo "Unsupported architecture for Tailscale: ${TARGETARCH}" >&2; exit 1 ;; \
    esac && \
    wget -O /tmp/tailscale.tgz "https://pkgs.tailscale.com/stable/tailscale_${TAILSCALE_VERSION}_${ts_arch}.tgz" && \
    mkdir -p /tmp/ts /out-bin && \
    tar -xzf /tmp/tailscale.tgz -C /tmp/ts --strip-components=1 && \
    cp /tmp/ts/tailscale /tmp/ts/tailscaled /out-bin/ && \
    chmod 0755 /out-bin/tailscale /out-bin/tailscaled

# Embedded userspace tailscaled; raw TCP Serve forwards tailnet :443 to Ferron.
FROM runtime-alpine AS runtime-tailscale
USER root
COPY --from=tailscale-fetch /out-bin/tailscale /out-bin/tailscaled /usr/local/bin/
RUN mkdir -p /var/lib/tailscale /var/run/tailscale && \
    chown -R ferron:ferron /var/lib/tailscale /var/run/tailscale
COPY --chmod=0755 docker/tailscale/entrypoint.sh /usr/local/bin/ferron-tailscale-entrypoint
USER ferron
ENTRYPOINT ["/usr/local/bin/ferron-tailscale-entrypoint"]
CMD ["run", "--config", "/etc/ferron/ferron.conf"]

# Default image for `docker build .`.
FROM runtime-alpine
