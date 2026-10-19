OpenSC portable PKCS #11 tools
================================

This archive contains an installer-free pkcs11-tool executable and the
pkcs11-spy tracing module for one platform:

  Linux:   bin/pkcs11-tool, lib/pkcs11-spy.so
  Windows: bin/pkcs11-tool.exe, bin/opensc.dll, lib/pkcs11-spy.dll
  macOS:   bin/pkcs11-tool, lib/pkcs11-spy.dylib

pkcs11-tool loads a PKCS #11 module supplied with --module. The executable and
spy module have no runtime dependencies outside this archive and the operating
system. On Windows, opensc.dll must remain beside pkcs11-tool.exe.

To trace a module, set PKCS11SPY to its absolute path, set PKCS11SPY_OUTPUT to
the desired log path, and pass the bundled spy module to pkcs11-tool:

  PKCS11SPY=/absolute/path/to/real-module \
  PKCS11SPY_OUTPUT=/absolute/path/to/pkcs11-spy.log \
  bin/pkcs11-tool --module lib/pkcs11-spy.so --show-info

Use the corresponding environment-variable syntax and .dll name on Windows.
Alternatively, edit lib/pkcs11-spy.conf beside the spy module and uncomment
both variables. A complete recognized file takes precedence over environment
variables (and the Windows Registry); relative paths are resolved from the lib
directory. If the file is absent, incomplete, or contains an unknown setting,
pkcs11-spy keeps the previous environment/Registry behavior.

The spy log can include PINs and object contents passed to PKCS #11 functions;
treat it as sensitive diagnostic data.
The spy names TC26 GOST-2012 key types and mechanisms, including GOST-512,
Kuznechik, Magma, VKO derivation, and Streebog HMAC; unknown vendor values
remain numeric in the log.

To derive a GOST 28147-89 key by VKO, use a GOST R 34.10-2012 private key
created with --usage-derive and a file containing the other party's raw public
point (64 bytes for GOST-256, 128 bytes for GOST-512). The point is CKA_VALUE
of that party's public key; --read-object --type pubkey --output-file can save
it. For example:

  bin/pkcs11-tool --module /absolute/path/to/libsofthsm2.so --login \
    --derive --mechanism GOSTR3410-12-DERIVE --id 01 \
    --input-file peer.point --vko-ukm 0102030405060708 \
    --output-file shared.key

--vko-kdf cpdiversify selects CryptoPro diversification; the default is bare
VKO. --key-type can select GENERIC, MAGMA or KUZNECHIK instead of GOST28147.
The output file contains the raw derived key and should be kept private.
