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
- Базовые команды `--rutoken-info` и `--rutoken-name` готовы; следующий шаг — остальные read-only команды этапа 3 и JSON-вывод.
- Локальный `pkcs11-spy.conf` имеет приоритет над environment/Registry;
  некорректный файл безопасно возвращает прежнее поведение. Шаблон и обе ветки
  проверены во всех шести product/test-kit artifacts.
