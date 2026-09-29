# Передача работы

Этап 3 расширения Рутокен реализован в ветке `claude/nice-einstein-yq1c5e`:
команды `--rutoken-*` с JSON в `pkcs11-tool`, лог функций чтения в
`pkcs11-spy`, тесты на заглушке. Прогон на устройстве разобран в
`docs/RUTOKEN-APDU.md`, ответы — в `docs/RUTOKEN-FUNCTIONS.md`.

Ветка слита в `master`. Ждем прогона probe 2 (Linux ARM64) владельцем: вывод
программы, очищенный от PIN `pcscd.log`, файлы `--save-dir` и, по желанию,
результат `--write-tests`.
