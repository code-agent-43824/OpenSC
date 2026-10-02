# Передача работы

Этап 3 расширения Рутокен реализован в ветке `claude/nice-einstein-yq1c5e`:
команды `--rutoken-*` с JSON в `pkcs11-tool`, лог функций чтения в
`pkcs11-spy`, тесты на заглушке. Прогон на устройстве разобран в
`docs/RUTOKEN-APDU.md`, ответы — в `docs/RUTOKEN-FUNCTIONS.md`.

Ветка слита в `master`. Probe 2 с `--write-tests` прогнана на устройстве,
результаты — в `docs/RUTOKEN-APDU.md` (раздел «Запись, подпись и PKCS#7») и
`docs/RUTOKEN-FUNCTIONS.md`. Работа с разделами Flash отложена владельцем
(раздел «Отложено» в `docs/PLAN.md`).

Этап 4 реализован (PKCS#7, CSR, `--rutoken-confirm-by-touch`), биометрия
отложена. Probe 3 (`--modify-tests`) прогнана на втором токене, ответы — в
`docs/RUTOKEN-APDU.md` (раздел «Изменяющие функции») и
`docs/RUTOKEN-FUNCTIONS.md`; заглушка приведена к ним. Дальше — этап 5.
