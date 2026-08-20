#!/usr/bin/env bash
set -euo pipefail

: "${PORTABLE_ARCH:?PORTABLE_ARCH is required}"
: "${OPENSSL_VERSION:?OPENSSL_VERSION is required}"
: "${OPENSSL_SHA256:?OPENSSL_SHA256 is required}"

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
work_dir="${RUNNER_TEMP:-$root_dir/.portable-work}/linux-$PORTABLE_ARCH"
openssl_archive="$work_dir/openssl.tar.gz"
openssl_source="$work_dir/openssl-$OPENSSL_VERSION"
openssl_prefix="$work_dir/openssl-install"
static_build="$work_dir/opensc-static"
shared_build="$work_dir/opensc-shared"
stage_dir="$work_dir/stage"
rutoken_test_dir="$root_dir/dist/rutoken-test-linux-$PORTABLE_ARCH"
archive_name="opensc-portable-linux-$PORTABLE_ARCH.zip"

rm -rf -- "$work_dir" "$rutoken_test_dir"
mkdir -p "$work_dir" "$root_dir/dist" "$stage_dir/bin" "$stage_dir/lib" \
  "$rutoken_test_dir"
curl --fail --location --retry 5 --output "$openssl_archive" \
  "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz"
printf '%s  %s\n' "$OPENSSL_SHA256" "$openssl_archive" | sha256sum --check
tar -xzf "$openssl_archive" -C "$work_dir"

pushd "$openssl_source"
./Configure no-shared no-module no-tests no-apps \
  --prefix="$openssl_prefix" --libdir=lib
make -j"$(getconf _NPROCESSORS_ONLN)"
make install_sw
popd

"$root_dir/bootstrap"
common_options=(
  --disable-strict --disable-pcsc --disable-sm --disable-zlib --disable-readline
  --disable-openpace --disable-man --disable-doc --disable-tests
  --disable-integration-tests --disable-notify --disable-cmocka
  --enable-openssl
)
common_env=(
  "OPENSSL_CFLAGS=-I$openssl_prefix/include"
  "OPENSSL_LIBS=$openssl_prefix/lib/libcrypto.a -ldl -pthread"
)

mkdir -p "$static_build"
pushd "$static_build"
env "${common_env[@]}" "$root_dir/configure" \
  "${common_options[@]}" --disable-shared --enable-static
for component in common scconf ui pkcs15init sm libopensc pkcs11; do
  make -C "src/$component" -j"$(getconf _NPROCESSORS_ONLN)"
done
make -C src/tools -j"$(getconf _NPROCESSORS_ONLN)" pkcs11-tool \
  LIBS="../libopensc/libopensc.la ../common/libscdl.la ../common/libcompat.la $openssl_prefix/lib/libcrypto.a -ldl -pthread"
popd

mkdir -p "$shared_build"
pushd "$shared_build"
env "${common_env[@]}" "$root_dir/configure" \
  "${common_options[@]}" --enable-shared --disable-static
make -j"$(getconf _NPROCESSORS_ONLN)"
popd

cp "$static_build/src/tools/pkcs11-tool" "$stage_dir/bin/pkcs11-tool"
cp "$shared_build/src/pkcs11/.libs/pkcs11-spy.so" "$stage_dir/lib/pkcs11-spy.so"
strip --strip-unneeded "$stage_dir/bin/pkcs11-tool" "$stage_dir/lib/pkcs11-spy.so"
cp "$root_dir/packaging/portable/README.txt" "$stage_dir/README.txt"
cp "$root_dir/packaging/portable/pkcs11-spy.conf" \
  "$stage_dir/lib/pkcs11-spy.conf"
cp "$root_dir/COPYING" "$stage_dir/LICENSE-OpenSC.txt"
cp "$openssl_source/LICENSE.txt" "$stage_dir/LICENSE-OpenSSL.txt"

cc -shared -fPIC -I"$root_dir/src" "$root_dir/tests/rutoken-stub.c" \
  -o "$rutoken_test_dir/rutoken-stub.so"
cc -I"$root_dir/src" "$root_dir/tests/rutoken-driver.c" \
  -o "$rutoken_test_dir/rutoken-driver" -ldl
strip --strip-unneeded "$rutoken_test_dir/rutoken-stub.so" \
  "$rutoken_test_dir/rutoken-driver"

for binary in "$stage_dir/bin/pkcs11-tool" "$stage_dir/lib/pkcs11-spy.so"; do
  if ldd "$binary" | grep -Eq 'lib(crypto|ssl|opensc|pkcs11)'; then
    echo "portable binary has an unexpected non-system dependency: $binary" >&2
    ldd "$binary" >&2
    exit 1
  fi
done

rm -f "$root_dir/dist/$archive_name"
(cd "$stage_dir" && zip -X -9 -r "$root_dir/dist/$archive_name" .)
sha256sum "$root_dir/dist/$archive_name"
