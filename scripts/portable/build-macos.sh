#!/usr/bin/env bash
set -euo pipefail

: "${OPENSSL_VERSION:?OPENSSL_VERSION is required}"
: "${OPENSSL_SHA256:?OPENSSL_SHA256 is required}"

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
work_dir="${RUNNER_TEMP:-$root_dir/.portable-work}/macos-universal"
openssl_archive="$work_dir/openssl.tar.gz"
openssl_source="$work_dir/openssl-$OPENSSL_VERSION"
stage_dir="$work_dir/stage"
archive_name=opensc-portable-macos-universal.zip
deployment_target=11.0
export MACOSX_DEPLOYMENT_TARGET="$deployment_target"

rm -rf -- "$work_dir"
mkdir -p "$work_dir" "$root_dir/dist" "$stage_dir/bin" "$stage_dir/lib"
curl --fail --location --retry 5 --output "$openssl_archive" \
  "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz"
printf '%s  %s\n' "$OPENSSL_SHA256" "$openssl_archive" | shasum -a 256 --check
tar -xzf "$openssl_archive" -C "$work_dir"
"$root_dir/bootstrap"

common_options=(
  --disable-strict --disable-pcsc --disable-sm --disable-zlib --disable-readline
  --disable-openpace --disable-man --disable-doc --disable-tests
  --disable-integration-tests --disable-notify --disable-cmocka
  --enable-openssl
)

for arch in arm64 x86_64; do
  openssl_copy="$work_dir/openssl-$arch"
  openssl_prefix="$work_dir/openssl-install-$arch"
  cp -R "$openssl_source" "$openssl_copy"
  pushd "$openssl_copy"
  if [[ "$arch" == arm64 ]]; then
    openssl_target=darwin64-arm64-cc
  else
    openssl_target=darwin64-x86_64-cc
  fi
  ./Configure "$openssl_target" no-shared no-module no-tests no-apps \
    --prefix="$openssl_prefix" --libdir=lib
  make -j"$(sysctl -n hw.logicalcpu)"
  make install_sw
  popd

  static_build="$work_dir/opensc-static-$arch"
  shared_build="$work_dir/opensc-shared-$arch"
  host="$arch-apple-darwin"
  if [[ "$arch" == arm64 ]]; then
    host=aarch64-apple-darwin
  fi
  arch_flags="-arch $arch -mmacosx-version-min=$deployment_target"
  common_env=(
    "CC=clang"
    "CFLAGS=-O2 $arch_flags"
    "LDFLAGS=$arch_flags"
    "OPENSSL_CFLAGS=-I$openssl_prefix/include"
    "OPENSSL_LIBS=$openssl_prefix/lib/libcrypto.a"
  )

  mkdir -p "$static_build"
  pushd "$static_build"
  env "${common_env[@]}" "$root_dir/configure" \
    "${common_options[@]}" --host="$host" --disable-shared --enable-static
  make -j"$(sysctl -n hw.logicalcpu)"
  popd

  mkdir -p "$shared_build"
  pushd "$shared_build"
  env "${common_env[@]}" "$root_dir/configure" \
    "${common_options[@]}" --host="$host" --enable-shared --disable-static
  make -j"$(sysctl -n hw.logicalcpu)"
  popd

  cp "$static_build/src/tools/pkcs11-tool" "$work_dir/pkcs11-tool-$arch"
  cp "$shared_build/src/pkcs11/.libs/pkcs11-spy.dylib" "$work_dir/pkcs11-spy-$arch.dylib"
done

lipo -create "$work_dir/pkcs11-tool-arm64" "$work_dir/pkcs11-tool-x86_64" \
  -output "$stage_dir/bin/pkcs11-tool"
lipo -create "$work_dir/pkcs11-spy-arm64.dylib" "$work_dir/pkcs11-spy-x86_64.dylib" \
  -output "$stage_dir/lib/pkcs11-spy.dylib"
strip -x "$stage_dir/bin/pkcs11-tool" "$stage_dir/lib/pkcs11-spy.dylib"
codesign --force --sign - "$stage_dir/bin/pkcs11-tool" "$stage_dir/lib/pkcs11-spy.dylib"
cp "$root_dir/packaging/portable/README.txt" "$stage_dir/README.txt"
cp "$root_dir/COPYING" "$stage_dir/LICENSE-OpenSC.txt"
cp "$openssl_source/LICENSE.txt" "$stage_dir/LICENSE-OpenSSL.txt"

for binary in "$stage_dir/bin/pkcs11-tool" "$stage_dir/lib/pkcs11-spy.dylib"; do
  lipo "$binary" -verify_arch arm64 x86_64
  if otool -L "$binary" | grep -Eq 'lib(crypto|ssl|opensc|pkcs11)'; then
    echo "portable binary has an unexpected non-system dependency: $binary" >&2
    otool -L "$binary" >&2
    exit 1
  fi
done

rm -f "$root_dir/dist/$archive_name"
(cd "$stage_dir" && /usr/bin/zip -X -9 -r "$root_dir/dist/$archive_name" .)
shasum -a 256 "$root_dir/dist/$archive_name"
