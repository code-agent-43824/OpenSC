# Журнал исследований

## 2026-08-14 — Windows-зависимость pkcs11-tool от opensc.dll

Гипотеза: Windows `pkcs11-tool.exe`, собранный через штатный `Makefile.mak`, самодостаточен при статическом vcpkg triplet.

Проверка: все три Windows build прошли проверку архитектуры, но на чистых runner процесс завершился с `0xC0000135` до вывода. Таблица PE imports показала зависимость от проектной `opensc.dll`; сторонние библиотеки vcpkg при этом действительно связаны статически.

Вывод: Windows portable-архив содержит `bin/opensc.dll` рядом с executable. Сборка проверяет архитектуру и отсутствие динамических OpenSSL/VC runtime dependencies также у этой DLL, а release-job проверяет ее наличие в каждом Windows ZIP.

## 2026-08-14 — исполняемый бит Unix-файлов в Actions artifacts

Гипотеза: архив, восстановленный release-job из скачанного Actions artifact, сохранит исполняемый бит `bin/pkcs11-tool`.

Проверка: обычное извлечение опубликованного Unix test bundle показало неисполняемый `pkcs11-tool`; Actions artifact нельзя использовать как источник режима файла без явного восстановления.

Вывод: функциональный тест на чистом runner явно добавляет исполняемый бит инструменту, а release-job делает `chmod +x` перед созданием итоговых Linux/macOS ZIP. Сам итоговый ZIP поэтому хранит правильный режим независимо от промежуточного artifact.

## 2026-08-14 — минимальная сборка без secure messaging

Гипотеза: штатный strict-режим OpenSC совместим с portable-конфигурацией `--disable-sm`.

Проверка: первый macOS build дошел до `card-sc-hsm.c` и остановился с `-Werror` на неиспользуемой `sc_hsm_perform_chip_authentication`, которая становится недостижимой именно при отключенном secure messaging.

Вывод: portable-конфигурация явно использует `--disable-strict`. Это не скрывает предупреждения в штатной сборке проекта: отдельные обычные workflow OpenSC сохраняют strict-режим, а минимальная сборка выпускает только `pkcs11-tool` и `pkcs11-spy`.

## 2026-08-14 — имя libtool-модуля pkcs11-spy на macOS

Гипотеза: libtool создаст модуль как `.libs/pkcs11-spy.dylib`, по аналогии с обычной динамической библиотекой macOS.

Проверка: shared-сборка полностью завершилась, но такого пути не оказалось; OpenSC собирает `pkcs11-spy` как loadable module, и его суффикс задает libtool, а не имя итогового portable-файла.

Вывод: сборочный скрипт находит фактический `pkcs11-spy.*` внутри `.libs`, исключая метаданные `.la/.lai`, затем упаковывает его под стабильным публичным именем `pkcs11-spy.dylib`.

## 2026-08-14 — порядок статической libcrypto в Linux

Гипотеза: полный `make` в `--disable-shared` конфигурации сможет статически связать все штатные OpenSC tools с абсолютным путем к `libcrypto.a`.

Проверка: библиотеки собрались, но параллельная линковка посторонних tools остановилась на undefined OpenSSL symbols. Их глобальный `LIBS` ставит внутренний `libopensc.a` после `OPTIONAL_OPENSSL_LIBS`; для статического архива порядок существенен.

Вывод: static-stage собирает только цепочку библиотек, нужную `pkcs11-tool`, а сам целевой executable линкует с явным завершающим `libcrypto.a`. Shared-stage остается штатным и создает `pkcs11-spy`; неподлежащие упаковке tools в static-stage не собираются.

## 2026-08-14 — SHA-256 внутри Visual Studio environment

Гипотеза: `Get-FileHash` доступен в PowerShell, запущенном из `vcvarsall` build-step.

Проверка: Windows x64 полностью собрал `pkcs11-tool.exe` и `pkcs11-spy.dll`, прошел проверки PE machine/dependencies и создал ZIP, но завершился ошибкой только потому, что этот cmdlet не разрешился в измененном Visual Studio environment.

Вывод: сборочный скрипт использует системный `certutil -hashfile ... SHA256`, не зависящий от загрузки PowerShell-модуля. Хэш остается диагностическим; release-job независимо создает итоговый `SHA256SUMS`.
