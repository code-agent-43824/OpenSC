# Журнал работ

## 2026-08-14 — portable pkcs11-tool и pkcs11-spy

План: собрать и упаковать `pkcs11-tool` и `pkcs11-spy` для шести целевых платформ, затем на отдельных чистых runner проверить прямой сценарий с обычным portable-архивом последнего релиза SoftHSMv2 и тот же сценарий через spy-модуль с валидацией лога.

Сделано: изучены текущие workflow OpenSC, portable workflow и состав релиза SoftHSMv2 `v2.7.0-portable.23`, интерфейс команд `pkcs11-tool` и переменные `PKCS11SPY`/`PKCS11SPY_OUTPUT`. Добавлены платформенные сборочные скрипты, один кроссплатформенный функциональный тест и workflow из build/verify/release стадий. Тест инициализирует SO/User PIN, меняет User PIN через `C_SetPIN`, записывает, читает, сравнивает и удаляет data object; spy-проход требует успешные `C_InitToken`, `C_InitPIN`, `C_SetPIN`, `C_CreateObject`, `C_GetAttributeValue` и `C_DestroyObject` в правильном порядке. Прямой сценарий локально прошел на обычном архиве SoftHSMv2 `v2.7.0-portable.23`; Python, shell и workflow прошли статические проверки.

Первый полный workflow обнаружил платформенное расхождение: macOS strict-сборка с отключенным secure messaging считала условно неиспользуемую функцию ошибкой. Portable-конфигурация отделена от штатного strict CI с помощью `--disable-strict`.

Далее: отправить исправление в `master`, повторить полный workflow, изучить логи и содержимое всех шести артефактов.
