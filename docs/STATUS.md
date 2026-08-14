# Статус

Реализован workflow portable-релиза `pkcs11-tool` и `pkcs11-spy` для Linux x64/ARM64, Windows x86/x64/ARM64 и macOS universal. Сборки статически включают сторонние библиотеки; Windows-архивы содержат требуемую проектную `opensc.dll` рядом с executable. PE/ELF/Mach-O файлы проверяются на архитектуру и отсутствие незапланированных динамических зависимостей.

Каждый архив перед публикацией передается на отдельный чистый runner. Проверка скачивает не test bundle, а соответствующий обычный архив последнего релиза `code-agent-43824/SoftHSMv2`, затем выполняет прямой data-object сценарий и тот же сценарий через `pkcs11-spy` с проверкой лога.

Полный GitHub Actions прогон `31812435688` успешен: все шесть build и все шесть clean-runner verify jobs завершились с `PASS`. При проверке использовался обычный платформенный архив последнего релиза SoftHSMv2 `v2.7.0-portable.23`, без test bundle.

Релиз `0.27.1-portable.1` опубликован: <https://github.com/code-agent-43824/OpenSC/releases/tag/0.27.1-portable.1>. В нем шесть ZIP и общий `SHA256SUMS`; загруженные заново release-assets прошли проверку хэшей и состава, Unix executable bit сохранен.
