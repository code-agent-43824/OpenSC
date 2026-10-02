# Передача состояния

Portable CI для `pkcs11-tool` и `pkcs11-spy` завершен и находится в `master`.

- Успешный workflow: <https://github.com/code-agent-43824/OpenSC/actions/runs/32370121050>
- Опубликованный релиз: <https://github.com/code-agent-43824/OpenSC/releases/tag/0.27.1-portable.4>
- В Actions и релизе: шесть product packages и шесть автономных test kits.
- Каждый verify runner запускает точный test kit, который затем публикуется.
- Все release-assets повторно скачаны; `SHA256SUMS` и состав проверены, Linux x64 kit повторно запущен.
- Каждый test kit содержит нативную заглушку Рутокен и driver, который проверяет все 34 поля таблицы и вызывает через spy все 33 операции.
- Активны только portable workflow и прямые тесты `pkcs11-tool` с внешними модулями; остальные 14 workflow отключены.
- Расширения Рутокен 2.19.0.0 описаны в `docs/RUTOKEN-EXTENSIONS.md`, реализация разбита на шесть этапов в `docs/PLAN.md`.
- Базовые команды `--rutoken-info` и `--rutoken-name` готовы. Этап 1 завершен:
  все типы и константы расширения сверены с заголовками 2.19.0.0 и 2.21.3.0.
- Поведение и команды этапов 3–5 описаны в `docs/RUTOKEN-FUNCTIONS.md`.
  Программа `tests/rutoken-hw-probe.c` прогнана на Рутокен ЭЦП 3.0 5100
  Flash; команды токена за каждой функцией расширения — в
  `docs/RUTOKEN-APDU.md`.
- Этап 3 реализован: `--rutoken-license`, `--rutoken-journal`,
  `--rutoken-volumes`, `--rutoken-cert-text`, `--rutoken-pin-status` и
  `--rutoken-json`; spy логирует их результаты без содержимого лицензий.
- Probe 2 (`tests/rutoken-hw-probe.c`) прогнана на устройстве с
  `--write-tests`: журнал, текст сертификата, PKCS#7, CSR, генерация ключа,
  подпись и хранение объектов разобраны на уровне APDU.
- Этап 4 реализован: `--rutoken-pkcs7-sign`, `--rutoken-pkcs7-verify`,
  `--rutoken-csr` и `--rutoken-confirm-by-touch`; биометрия и разделы Flash
  отложены.
- Probe 3 прогнана на Рутокен ЭЦП 3.0 3127 USB во всех режимах, включая
  `--modify-tests`; изменяющие функции разобраны в `docs/RUTOKEN-APDU.md` и
  `docs/RUTOKEN-FUNCTIONS.md`, заглушка отвечает как устройство.
- Этап 5 реализован: `--rutoken-set-name`, `--rutoken-set-license`,
  `--rutoken-set-local-pin`, `--rutoken-unblock-user-pin`,
  `--rutoken-token-manage`, `--rutoken-init-token`,
  `--rutoken-restore-factory-defaults`; PIN только из `env:` или ввода без
  эха, отдельного подтверждения нет (решение владельца). На устройстве команды еще не запускались;
  устаревшие функции и разделы Flash не реализованы.
- Workflow выпуска требует новый тег и не перезаписывает существующие теги и
  релизы.
- Локальный `pkcs11-spy.conf` имеет приоритет над environment/Registry;
  некорректный файл безопасно возвращает прежнее поведение. Шаблон и обе ветки
  проверены во всех шести product/test-kit artifacts.
