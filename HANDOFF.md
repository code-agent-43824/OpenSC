# Передача работы

Этап 3 расширения Рутокен реализован в ветке `claude/nice-einstein-yq1c5e`:
команды `--rutoken-*` с JSON в `pkcs11-tool`, лог функций чтения в
`pkcs11-spy`, тесты на заглушке. Прогон на устройстве разобран в
`docs/RUTOKEN-APDU.md`, ответы — в `docs/RUTOKEN-FUNCTIONS.md`.

Ветка слита в `master`. Probe 2 с `--write-tests` прогнана на устройстве,
результаты — в `docs/RUTOKEN-APDU.md` (раздел «Запись, подпись и PKCS#7») и
`docs/RUTOKEN-FUNCTIONS.md`. Следующий шаг — этап 4: команды PKCS#7 и CSR в
`pkcs11-tool`; от владельца нужен вывод `lsblk` для размеров разделов
Flash.
