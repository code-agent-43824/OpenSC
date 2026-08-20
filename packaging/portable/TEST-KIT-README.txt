OpenSC portable PKCS #11 tools test kit
=======================================

This directory is the exact package tested on a clean GitHub Actions runner.
It contains:

  opensc-package/   portable pkcs11-tool and pkcs11-spy;
  softhsm-package/  the matching ordinary SoftHSM portable module;
  rutoken-test/     ABI stub and driver for all Rutoken C_EX_* operations;
  test.py           the direct and pkcs11-spy integration scenario;
  platform.txt      the target selected by the test launcher.

Run it from any directory with the platform Python 3 interpreter:

  Linux/macOS: python3 test.py
  Windows:     python test.py

The test creates an isolated temporary home, initializes the bundled SoftHSM
token, changes its PIN, writes, reads, compares and deletes a data object, then
repeats the scenario through pkcs11-spy and validates the successful call
sequence. It first checks the extended table layout and every Rutoken function
pointer, return value and spy-log entry against the bundled harmless stub. The
temporary token store and spy logs are removed after the run.

Do not replace softhsm-package with a hardware or production module: the test
deliberately calls C_InitToken and would erase the selected token.
