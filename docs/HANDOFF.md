# Передача состояния

Portable CI для `pkcs11-tool` и `pkcs11-spy` завершен и находится в `master`.

- Успешный workflow: <https://github.com/code-agent-43824/OpenSC/actions/runs/38864273170>
- Опубликованный релиз: <https://github.com/code-agent-43824/OpenSC/releases/tag/0.27.1-portable.9>
  (`.8` и подсказки для `--rutoken-set-name` под SO и не-OID
  `--application-id`). Все 12 ZIP скачаны заново, хэши совпали, Linux x64
  test kit повторно прошёл вне CI.
- `.8` принят на Рутокен ЭЦП 2026-10-09: чтения, крипто-roundtrip, CSR,
  полная цепочка CMS (включая негативы) и команды этапа 5 — все успешно.
  Аппаратная приёмка flash и BIO ещё впереди — на проверенном токене их нет.
- GitHub может сам отключить Actions в форке («Workflows on this fork have
  been disabled»); тогда dispatch отвечает `Actions has been disabled for this
  repository`, и владелец включает их кнопкой на вкладке Actions.
- В Actions и релизе: шесть product packages и шесть автономных test kits.
- Каждый verify runner запускает точный test kit, который затем публикуется.
- Для `.8` все 12 ZIP прошли проверку состава в release-job; записи
  `SHA256SUMS` совпали с SHA-256 опубликованных assets. Архивы отдельно не
  скачивались, test kit вне CI повторно не запускался.
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
  `--rutoken-csr` и `--rutoken-confirm-by-touch`; разделы Flash отложены.
- Probe 3 прогнана на Рутокен ЭЦП 3.0 3127 USB во всех режимах, включая
  `--modify-tests`; изменяющие функции разобраны в `docs/RUTOKEN-APDU.md` и
  `docs/RUTOKEN-FUNCTIONS.md`, заглушка отвечает как устройство.
- Этап 5 реализован: `--rutoken-set-name`, `--rutoken-set-license`,
  `--rutoken-set-local-pin`, `--rutoken-unblock-user-pin`,
  `--rutoken-token-manage`, `--rutoken-init-token`,
  `--rutoken-restore-factory-defaults`; PIN только из `env:` или ввода без
  эха, отдельного подтверждения нет (решение владельца). Команды прогнаны
  на Рутокен ЭЦП 2.0 (релиз `0.27.1-portable.5`), исправления собраны в
  `0.27.1-portable.6`; устаревшие функции и
  разделы Flash не реализованы.
- По полевому отчёту внесены исправления: чтение открытого ГОСТ-ключа через
  `CKA_VALUE`, R/W-сессия для SO-логина, подсказка про `--login`, проверка
  минимальной длины PIN по устройству, самоблокировка SO PIN в repair с
  необязательными новыми PIN, режим `--test-login`; в `pkcs11-spy` — строка
  версии форка, статистика вызовов и выключенный по умолчанию
  `PKCS11SPY_UNSAFE_SECRETS`. Детали — в `RUTOKEN-FUNCTIONS.md`
  («Полевой отчёт»). Эти правки в `master` и в релизе
  `0.27.1-portable.6`.
- `pkcs11-tool --derive` выполняет VKO ГОСТ Р 34.10-2012 (RFC 7836) для
  ключей 256/512 бит с ключами ГОСТ 28147-89, Магма, Кузнечик (опции
  `--gost-ukm`, `--gost-kdf`, `--key-type`); сверено с эталонами ТК26 и RFC
  на заглушке. Probe 4 на Рутокен ЭЦП 3.0: токен не принимает сессионные
  закрытые ключи ГОСТ, проверка не выполнилась; probe 5 с `--write-tests
  --derive-tests` переходит на временные объекты токена. В релиз пока не
  входит.
- Workflow выпуска требует новый тег и не перезаписывает существующие теги и
  релизы.
- BIO-расширение spy и начальные команды BIO в `pkcs11-tool` входят в `.7`.
  Их проверили на заглушке и в portable CI; реальное BIO-устройство пока
  не проверяли. Регистрация отпечатка и био-ключ остаются открытыми.
- Локальный `pkcs11-spy.conf` имеет приоритет над environment/Registry;
  некорректный файл безопасно возвращает прежнее поведение. Шаблон и обе ветки
  проверены во всех шести product/test-kit artifacts.

## Probe 5 на устройстве: чего ждать и что делать

Probe 5 (коммит `f7f8e51`, бинарники для Linux x86_64 и ARM64 у владельца)
запускается так: `--login --pin-env ИМЯ --write-tests --derive-tests`. В
probe 4 устройство отклонило сессионные закрытые ключи ГОСТ, подробности —
в `RUTOKEN-FUNCTIONS.md` («Probe 4»). В журнале смотреть шаги
`--derive-tests`:

- Импорт ключей контрольных примеров. Ожидаю, что все три сессионных
  шаблона дадут `0xd1`. Проверка «without CKA_DERIVE, a check only»:
  - `0xd1` — токен вообще не принимает сессионный закрытый ключ ГОСТ;
  - `CKR_OK` — отвергается `CKA_DERIVE` у сессионного ключа.

  Затем «temporary token object» → `CKR_OK`, и все четыре примера (ТК26
  3.13, 3.14, RFC 7836 B.7 — по 32 байта, B.8 — 64 байта) должны дать
  «equal to the control example». Если токен не даёт импортировать
  закрытый ГОСТ-ключ и как объект токена, эталоны пропускаются, остаётся
  проверка на парах.
- Пары ключей. Ожидаю «temporary token key pair» → `CKR_OK` и «both sides
  agree»: 6 строк для 256 бит и 7 для 512 (последняя — VKO-512).
- Уборка. После шага «delete temporary objects after the derive tests»
  должно остаться 0 объектов, затем `C_Finalize -> CKR_OK`.

Если что-то пошло иначе:

| В журнале | Что делать |
|---|---|
| «DIFFERENT from the control example» | Пересчитать VKO независимо. Оракул из сессии не сохранён: `pip install gostcrypto`, кривая `id-tc26-gost-3410-2012-256-paramSetB` = CryptoPro-A, ключи и UKM little-endian, хэш — Стрибог от `x‖y` в LE. Перебрать гипотезы: ключ, UKM или точка в big-endian |
| «the two sides DIFFER» | Ошибка параметров KDF или устройства: сравнить с эталонами того же прогона |
| `C_DeriveKey` → `0xd1` или `CKR_ATTRIBUTE_*` на Магме, Кузнечике или generic | Токен не принимает шаблон выработанного ключа. Подобрать шаблон в `derive_value` (`tests/rutoken-hw-probe.c`) и тот же в `derive_gost_key` (`src/tools/pkcs11-tool.c`) |
| `CKR_MECHANISM_PARAM_INVALID` на KDF | Сверить раскладку ТК26 5.11 и длину UKM (сейчас 8 байт; для VKO-512 — 16) |

Если всё зелёное:

- отметить пункт в `PLAN.md`;
- записать результаты в `RUTOKEN-FUNCTIONS.md`, `STATUS.md` и `WORKLOG.md`;
- попросить владельца проверить `pkcs11-tool --derive` с ключом на токене.

Слияние `46247e4` и `f7f8e51` в `master` и релиз `.10` — только с
разрешения владельца. На SoftHSM-форке `.83` ТК26 3.13 по-прежнему будет
расходиться с эталоном: форк читает закрытый ключ как big-endian. Это
ошибка форка, не наша. Probe 5 теперь печатает коды отказов KDF числом.
