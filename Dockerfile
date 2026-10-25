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

# Small runtime with the sqlite3 CLI for inspecting the definitions database.
FROM alpine:3.24.3 AS runtime-alpine
RUN apk add --no-cache ca-certificates sqlite && \
    addgroup -S -g 65532 ferron && adduser -S -D -H -u 65532 -G ferron ferron && \
    mkdir -p /etc/ferron /var/lib/ferron /var/log/ferron /var/www/static /var/cache/ferron-acme && \
    chown -R ferron:ferron /var/lib/ferron /var/log/ferron /var/cache/ferron-acme
COPY --from=builder /out/ferron /out/ferron-fmt /out/ferron-kdl2ferron /out/ferron-passwd /out/ferron-precompress /out/ferron-serve /usr/local/bin/
USER ferron
EXPOSE 8080 8443
ENTRYPOINT ["/usr/local/bin/ferron"]
CMD ["run", "--config", "/etc/ferron/ferron.conf"]

# Static binaries also work in a minimal runtime without a shell.
FROM gcr.io/distroless/static-debian13:nonroot AS runtime-distroless
COPY --from=builder /out/ferron /out/ferron-fmt /out/ferron-kdl2ferron /out/ferron-passwd /out/ferron-precompress /out/ferron-serve /usr/local/bin/
COPY --from=runtime-alpine /etc/ferron /etc/ferron
COPY --from=runtime-alpine /var/www/static /var/www/static
COPY --from=runtime-alpine --chown=65532:65532 /var/lib/ferron /var/lib/ferron
COPY --from=runtime-alpine --chown=65532:65532 /var/log/ferron /var/log/ferron
COPY --from=runtime-alpine --chown=65532:65532 /var/cache/ferron-acme /var/cache/ferron-acme
USER 65532:65532
EXPOSE 8080 8443
ENTRYPOINT ["/usr/local/bin/ferron"]
CMD ["run", "--config", "/etc/ferron/ferron.conf"]

# One-shot schema initializer; sqlite3 also lets operators manage DB rows.
FROM alpine:3.24.3 AS definitions-init
RUN apk add --no-cache sqlite && mkdir -p /var/lib/ferron
COPY --from=builder /out/abuse-definitions-init /usr/local/bin/abuse-definitions-init
ENTRYPOINT ["/usr/local/bin/abuse-definitions-init"]

# Default image for `docker build .`.
FROM runtime-alpine
