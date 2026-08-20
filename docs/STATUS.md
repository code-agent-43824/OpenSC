# Статус

Реализован workflow portable-релиза `pkcs11-tool` и `pkcs11-spy` для Linux x64/ARM64, Windows x86/x64/ARM64 и macOS universal. Сборки статически включают сторонние библиотеки; Windows-архивы содержат требуемую проектную `opensc.dll` рядом с executable. PE/ELF/Mach-O файлы проверяются на архитектуру и отсутствие незапланированных динамических зависимостей.

Каждый архив перед публикацией передается на отдельный чистый runner. Проверка скачивает соответствующий обычный архив последнего релиза `code-agent-43824/SoftHSMv2`, собирает плоский автономный `opensc-testkit-<platform>` и запускает сценарий именно из него. В test kit входят portable-инструменты OpenSC, модуль SoftHSM, `test.py`, manifest платформы и инструкция. Сценарий выполняется напрямую и через `pkcs11-spy` с проверкой лога.

Полный GitHub Actions прогон [`32304930879`](https://github.com/code-agent-43824/OpenSC/actions/runs/32304930879) успешен: шесть build, шесть clean-runner verify и release job завершились с `PASS`. Все 12 Actions artifacts доступны напрямую, без вложенных ZIP. Дополнительный workflow тестов `pkcs11-tool` с внешними модулями [`32305704510`](https://github.com/code-agent-43824/OpenSC/actions/runs/32305704510) также успешен.

Релиз [`0.27.1-portable.2`](https://github.com/code-agent-43824/OpenSC/releases/tag/0.27.1-portable.2) содержит шесть product ZIP, шесть test-kit ZIP и общий `SHA256SUMS`. Все assets скачаны заново: 12 хэшей совпали, вложенных ZIP нет, Linux x64 test kit повторно прошел вне CI.

Из GitHub Actions выключены 14 общих upstream-workflow. Активны только portable release для обеих утилит и `Tests of external pkcs11 modules`, который непосредственно проверяет `pkcs11-tool`; его push-trigger ограничен изменениями исходного кода и build-файлов.

Официальные расширения Рутокен 2.19.0.0 изучены и описаны в [`RUTOKEN-EXTENSIONS.md`](RUTOKEN-EXTENSIONS.md). В [`PLAN.md`](PLAN.md) добавлена поэтапная полная поддержка 33 указателей расширенной таблицы в `pkcs11-spy` и `pkcs11-tool`, включая семь устаревших ABI-функций, безопасную обработку секретов и аппаратную приемку.

Первая часть реализации расширений готова: общий загрузчик разрешает
`C_EX_GetFunctionListExtended`, `pkcs11-spy` экспортирует и проксирует все 33
указателя таблицы 2.19 с редактированием секретов, а `pkcs11-tool` предоставляет
первые read-only команды `--rutoken-info` и `--rutoken-name`. Локально сверены
ABI-размеры и смещения, spy проверен через свежую сборку portable SoftHSM;
межплатформенная автоматическая проверка остается следующим шагом.
