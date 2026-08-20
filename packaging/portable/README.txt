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
