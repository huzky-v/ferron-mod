#!/usr/bin/env bash
#
# Cross-compile the ferron entrypoint workspace for a Linux musl target.
#
# This mirrors the musl toolchain setup from ferron/cross-build/build.sh
# (clang + lld + an Alpine sysroot, static libc++), because the default Ferron
# profile pulls C/C++ dependencies (aws-lc-sys, bundled SQLite) that must be
# cross-compiled alongside the Rust code.
#
# Usage: build-musl.sh <rust-target> <sysroot> [output-dir]
set -euo pipefail

TARGET="${1:?usage: build-musl.sh <rust-target> <sysroot> [output-dir]}"
SYSROOT="${2:?usage: build-musl.sh <rust-target> <sysroot> [output-dir]}"
PROJECT_ROOT="${PROJECT_ROOT:-/src}"
OUT_DIR="${3:-${PROJECT_ROOT}/out}"

CLANG="${CLANG:-clang}"
CLANGXX="${CLANGXX:-clang++}"

if [[ ! -d "${SYSROOT}/lib" ]]; then
	echo "[ERROR] sysroot not found: ${SYSROOT}" >&2
	exit 1
fi

echo "[INFO] Building ${TARGET} with sysroot ${SYSROOT}"

# Rust's musl target links -lgcc_s (shared), which a static-pie musl binary
# does not have. Provide static libunwind plus a -lgcc_s -> libgcc.a linker
# script so both the Rust link and CMake probes resolve under lld.
rust_libdir="$(rustc --print target-libdir --target "${TARGET}")"
if [[ -f "${rust_libdir}/self-contained/libunwind.a" ]]; then
	cp -f "${rust_libdir}/self-contained/libunwind.a" "${SYSROOT}/lib/libunwind.a"
fi
if [[ -f "${SYSROOT}/lib/libgcc.a" ]]; then
	if [[ -f "${SYSROOT}/lib/libunwind.a" ]]; then
		printf 'INPUT(libgcc.a libunwind.a)\n' >"${SYSROOT}/lib/libgcc_s.so"
	else
		printf 'INPUT(libgcc.a)\n' >"${SYSROOT}/lib/libgcc_s.so"
	fi
fi

# Compiler/linker wrappers for C/C++ dependencies and cc-rs. They strip PGO
# flags (only Rust is instrumented) and only add -fuse-ld=lld when linking, so
# pure compiles do not trip -Werror,-Wunused-command-line-argument.
wrapper_dir="${SYSROOT}/bin"
mkdir -p "${wrapper_dir}"
cc_wrapper="${wrapper_dir}/abuse-clang-cc"
cxx_wrapper="${wrapper_dir}/abuse-clang-cxx"
linker_wrapper="${wrapper_dir}/abuse-clang-linker"

cat >"${cc_wrapper}" <<'WRAPPER'
#!/bin/bash
set -euo pipefail
link=1
filtered_args=()
for a in "$@"; do
  case "$a" in
    -fprofile-generate=*|-fprofile-instr-generate=*|-fprofile-instr-use=*|-fprofile-use=*) continue ;;
    -c|-E|-S|-M*) link=0 ;;
  esac
  filtered_args+=("$a")
done
if [[ "$link" -eq 1 ]]; then
  exec "$ABUSE_CLANG" --sysroot="$ABUSE_SYSROOT" -L"$ABUSE_SYSROOT/lib" --target="$ABUSE_TARGET" -fuse-ld=lld "${filtered_args[@]}"
else
  exec "$ABUSE_CLANG" --sysroot="$ABUSE_SYSROOT" -L"$ABUSE_SYSROOT/lib" --target="$ABUSE_TARGET" "${filtered_args[@]}"
fi
WRAPPER

cat >"${cxx_wrapper}" <<'WRAPPER'
#!/bin/bash
set -euo pipefail
link=1
filtered_args=()
for a in "$@"; do
  case "$a" in
    -fprofile-generate=*|-fprofile-instr-generate=*|-fprofile-instr-use=*|-fprofile-use=*) continue ;;
    -c|-E|-S|-M*) link=0 ;;
  esac
  filtered_args+=("$a")
done
if [[ "$link" -eq 1 ]]; then
  exec "$ABUSE_CLANGXX" --sysroot="$ABUSE_SYSROOT" -L"$ABUSE_SYSROOT/lib" --target="$ABUSE_TARGET" -fuse-ld=lld "${filtered_args[@]}"
else
  exec "$ABUSE_CLANGXX" --sysroot="$ABUSE_SYSROOT" -L"$ABUSE_SYSROOT/lib" --target="$ABUSE_TARGET" "${filtered_args[@]}"
fi
WRAPPER

cat >"${linker_wrapper}" <<'WRAPPER'
#!/bin/bash
set -euo pipefail
exec "$ABUSE_CLANG" --target="$ABUSE_TARGET" --sysroot="$ABUSE_SYSROOT" -L"$ABUSE_SYSROOT/lib" -fuse-ld=lld "$@"
WRAPPER

chmod +x "${cc_wrapper}" "${cxx_wrapper}" "${linker_wrapper}"

export ABUSE_CLANG="${CLANG}"
export ABUSE_CLANGXX="${CLANGXX}"
export ABUSE_SYSROOT="${SYSROOT}"
export ABUSE_TARGET="${TARGET}"

target_env="${TARGET//-/_}"
export "CC_${target_env}=${cc_wrapper}"
export "CXX_${target_env}=${cxx_wrapper}"
export "AR_${target_env}=llvm-ar"
export "RANLIB_${target_env}=llvm-ranlib"
export CC="${cc_wrapper}"
export CXX="${cxx_wrapper}"
export AR="llvm-ar"
export RANLIB="llvm-ranlib"

# C++ dependencies (aws-lc, brotli, ...) use static libc++ from the sysroot.
export CXXFLAGS="-U TCMALLOC_INTERNAL_METHODS_ONLY -isystem ${SYSROOT}/include -I${SYSROOT}/include/c++/v1 -stdlib=libc++ -std=c++17 -nostdinc++ -static --target=${TARGET}"
export CXXSTDLIB="c++"

# For bindgen-driven C dependencies.
export BINDGEN_EXTRA_CLANG_ARGS="--sysroot=${SYSROOT} --target=${TARGET} -I${SYSROOT}/include"

export RUSTFLAGS="${RUSTFLAGS:-} -Clink-self-contained=no -Clink-args=-L${SYSROOT}/lib -Clink-args=-lc++abi -Ctarget-feature=+crt-static"
export RUST_LIBC_UNSTABLE_MUSL_V1_2_3=1
export CARGO_CFG_LIBC_UNSTABLE_MUSL_V1_2_3=1

linker_var="CARGO_TARGET_$(echo "${target_env}" | tr '[:lower:]' '[:upper:]')_LINKER"
export "${linker_var}=${linker_wrapper}"

# Reduce allocator memory usage without a large performance impact.
export JEMALLOC_SYS_WITH_MALLOC_CONF='narenas:2,percpu_arena:phycpu,metadata_thp:auto,dirty_decay_ms:100,muzzy_decay_ms:100'

cd "${PROJECT_ROOT}"

mkdir -p "${OUT_DIR}"

if [[ "${BUILD_VARIANT:-full}" == "tailscale" ]]; then
	cargo build --release --locked --target "${TARGET}" \
		-p ferron-abuse-bin --bin ferron --no-default-features
	cp -f "${PROJECT_ROOT}/target/${TARGET}/release/ferron" "${OUT_DIR}/ferron"
	if command -v "${STRIP:-llvm-strip}" >/dev/null 2>&1; then
		"${STRIP:-llvm-strip}" --strip-all "${OUT_DIR}/ferron"
	fi
	echo "[INFO] Built Tailscale-only ${OUT_DIR}/ferron"
	exit 0
fi

cargo build --release --locked --target "${TARGET}" \
	-p ferron-abuse-bin --bin ferron

cargo build --release --locked --target "${TARGET}" \
	-p ferron-abuse-protection --bin abuse-definitions-init

cp -f "${PROJECT_ROOT}/target/${TARGET}/release/ferron" "${OUT_DIR}/ferron"
cp -f "${PROJECT_ROOT}/target/${TARGET}/release/abuse-definitions-init" "${OUT_DIR}/abuse-definitions-init"

# Strip debug/symbol tables. The production image ships stripped binaries, so
# the result stays close to the size of the official Ferron image (~20 MB).
strip_tool="${STRIP:-llvm-strip}"
strip_binary() {
	if command -v "${strip_tool}" >/dev/null 2>&1; then
		"${strip_tool}" --strip-all "$1"
	else
		echo "[WARN] ${strip_tool} not found; $1 retains debug symbols" >&2
	fi
}

if command -v "${strip_tool}" >/dev/null 2>&1; then
	echo "[INFO] Stripping symbols with ${strip_tool}"
else
	echo "[WARN] ${strip_tool} not found; binaries retain debug symbols" >&2
fi
strip_binary "${OUT_DIR}/ferron"
strip_binary "${OUT_DIR}/abuse-definitions-init"

# Companion Ferron utilities (ferron-fmt, ferron-passwd, ferron-precompress,
# ferron-kdl2ferron, ferron-serve), built from the pinned Ferron source that the
# Dockerfile fetches into FERRON_SRC. They are separate workspace crates, so
# they cannot be dependencies of our binary; build them directly.
FERRON_SRC="${FERRON_SRC:-/ferron-src}"
FERRON_TARGET_DIR="${FERRON_TARGET_DIR:-${PROJECT_ROOT}/ferron-target}"
FERRON_UTILS=(ferron-fmt ferron-kdl2ferron ferron-passwd ferron-precompress ferron-serve)

if [[ -d "${FERRON_SRC}" ]]; then
	echo "[INFO] Building Ferron companion utilities from ${FERRON_SRC}"
	# Override the upstream release profile: fat LTO OOMs in a stock Docker VM,
	# and `strip = true` needs a system strip the cross builder does not ship.
	CARGO_PROFILE_RELEASE_LTO=thin \
		CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
		CARGO_PROFILE_RELEASE_PANIC=abort \
		CARGO_PROFILE_RELEASE_STRIP=false \
		cargo build --release --locked \
		--manifest-path "${FERRON_SRC}/Cargo.toml" \
		--target-dir "${FERRON_TARGET_DIR}" \
		--target "${TARGET}" \
		$(printf -- '-p %s ' "${FERRON_UTILS[@]}")
	for tool in "${FERRON_UTILS[@]}"; do
		built="${FERRON_TARGET_DIR}/${TARGET}/release/${tool}"
		if [[ -f "${built}" ]]; then
			cp -f "${built}" "${OUT_DIR}/${tool}"
			strip_binary "${OUT_DIR}/${tool}"
		else
			echo "[ERROR] ${tool} was not built" >&2
			exit 1
		fi
	done
else
	echo "[INFO] FERRON_SRC (${FERRON_SRC}) not present; skipping companion utilities"
fi

ls -lh "${OUT_DIR}"

echo "[INFO] Built ${OUT_DIR}/ferron, abuse-definitions-init, and companion utilities"
