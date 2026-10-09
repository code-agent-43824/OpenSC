# Функции Рутокен этапов 3–5: описание и план реализации

Документ дополняет [`RUTOKEN-EXTENSIONS.md`](RUTOKEN-EXTENSIONS.md). Там описаны
состав расширения и общие требования, здесь — поведение каждой оставшейся
функции, команды `pkcs11-tool`, правила памяти и секретов, проверки и вопросы
к устройству. Ответы дает программа
[`tests/rutoken-hw-probe.c`](../tests/rutoken-hw-probe.c) (раздел «Прогон на
устройстве»): версии 1 и 2 — на Рутокен ЭЦП 3.0 5100 Flash с библиотекой
2.21 для Linux ARM64, версия 3 с изменяющими функциями — на Рутокен ЭЦП 3.0
3127 USB с библиотекой 2.21 для Linux x64. Команды, которые библиотека при
этом отправляет токену, разобраны в [`RUTOKEN-APDU.md`](RUTOKEN-APDU.md).

## Источники и совместимость

- Заголовки `include/` библиотек 2.19.0.0 и 2.21.3.0 с download.rutoken.ru.
  `rtpkcs11f.h` в них одинаков (SHA-256 `d9b8adcc…d050e`), таблица из 34
  указателей не менялась. `rtpkcs11t.h` 2.21 (SHA-256 `ea3b8803…fbb3`) добавляет
  только `CKA_VENDOR_CRYPTOAPI_CONTAINER_NAME`, `CKA_VENDOR_BIO_DATA_ID` и
  `CKR_VENDOR_INTERFACE_NOT_INITIALIZED`.
- [`pkcs11-rutoken.h`](../src/pkcs11/pkcs11-rutoken.h) описывает все типы и
  константы расширения. Размеры, смещения всех полей и значения констант
  совпали с обоими наборами заголовков для Linux x64/ARM64, macOS x64/ARM64 и
  Windows x86/x64/ARM64.
- dev.rutoken.ru: [описание функций](https://dev.rutoken.ru/pages/viewpage.action?pageId=3178555),
  [матрица поддержки](https://dev.rutoken.ru/pages/viewpage.action?pageId=3178536),
  [формат журнала](https://dev.rutoken.ru/pages/viewpage.action?pageId=91979969),
  [управление Flash](https://dev.rutoken.ru/pages/viewpage.action?pageId=16220171),
  [примеры PKCS#11 и биометрии](https://dev.rutoken.ru/pages/viewpage.action?pageId=257720492),
  [политики PIN](https://dev.rutoken.ru/pages/viewpage.action?pageId=79462816).
- Rutoken SDK от 28.08.2026: примеры `sdk/pkcs11/samples/Extended` и
  `PKIExtensions` уточняют порядок вызовов, требования к входу и освобождение
  памяти.
- `librtpkcs11ecp.so` 2.21.3.0 для Linux x64 (SHA-256 `3c4ada3c…88c8`) без
  токена: таблица версии 2.40 с 34 указателями доступна до и после
  `C_Initialize`; `C_EX_GetTokenInfoExtended` до инициализации возвращает
  `CKR_CRYPTOKI_NOT_INITIALIZED`. Через `pkcs11-spy` результат тот же.

### Вне 33 функций: BIO-расширение

Библиотека 2.21.3.0 экспортирует также `C_BIO_GetFunctionListBio` и 15 функций
`C_BIO_*`: адаптеры и сканеры отпечатков, регистрация отпечатка, биометрический
вход. Заголовки `biopkcs11*.h` есть только в SDK, коды ошибок —
`CKR_VENDOR_DEFINED+13…+35`. `pkcs11-spy` теперь экспортирует этот символ и
проксирует всю BIO-таблицу. ABI независимо описан по заголовкам SDK от
28.08.2026; таблица версии 2.40 проверена с библиотекой 2.21.3.0 без
устройства. Заглушка проверяет все 15 обёрток и скрытие BIO PIN по умолчанию.

Базовые команды `pkcs11-tool`: `--rutoken-bio-scanners` (список сканеров),
`--rutoken-bio-authenticate --login [--rutoken-bio-pin env:ИМЯ]
[--rutoken-bio-timeout СЕК]`, `--rutoken-bio-deauthenticate` и
`--rutoken-bio-unblock --login`. Каждая команда инициализирует и завершает
BioLib; это самостоятельные диагностические действия, не цепочка для подписи.
Текстовый и `--rutoken-json` вывод, успешные пути и ошибки проверены на
заглушке через spy. Аппаратная проверка и сценарии регистрации отпечатка и
использования био-ключа остаются открытыми.

## Общие правила

### Память

| Схема | Функции | Правило |
|---|---|---|
| Два прохода: `NULL`, затем буфер | `GetTokenName`, `GetLicense`, `GetJournal`, `GetVolumesInfo` | Размер берется из первого вызова, буфер выделяет вызывающий. Поведение при малом буфере проверяет probe. |
| Буфер выделяет библиотека | `GetCertificateInfoText`, `PKCS7Sign`, `CreateCSR`, `PKCS7Verify`, `PKCS7VerifyFinal` | Каждый полученный буфер освобождается `C_EX_FreeBuffer` на всех путях. Для подписантов по примеру SDK: каждый `pData`, затем массив, затем данные. |
| Структура вызывающего | `GetTokenInfoExtended`, `GetDriveSize`, `SlotManage` | Вызывающий заполняет `ulSizeofThisStructure`, `ulPinID` и т. п. |

### Секреты

- Функциям, получающим PIN напрямую (`InitToken`, сброс к заводским
  настройкам, `SetLocalPIN`, `TokenManage` с новым PIN, в будущем
  `FormatDrive` и `ChangeVolumeAttributes`), PIN передается только как
  `env:ИМЯ` в `--so-pin`, `--new-pin`, `--rutoken-new-so-pin`,
  `--rutoken-auth-pin` или вводится без эха (новый PIN — дважды); значение в
  командной строке отвергается до загрузки модуля. Команды под `C_Login`
  берут PIN как обычно в `pkcs11-tool`: `--pin`, `--so-pin`.
- После вызова PIN и ключ эмитента затираются в памяти `pkcs11-tool`.
- Лицензии, ключи, пароли активации и биометрические данные передаются только
  через файлы; в stdout, JSON и лог spy попадают лишь длины.
- Стандартный spy по-прежнему пишет PIN из `C_Login` открытым текстом.

### Вывод и ошибки

- `--rutoken-json` переключает все команды `--rutoken-*` на один JSON-объект в
  stdout; текст остается по умолчанию. Документ собирается в памяти и
  печатается целиком после последней команды; с другими командами
  `pkcs11-tool` ключ не сочетается. Запросы PIN в этом режиме идут в stderr.
  Бинарные результаты `--output-file` пишутся как есть: DER для CMS и CSR,
  TLV журнала, 72 байта лицензии; файл создается с правами только владельца.
- Нет символа `C_EX_GetFunctionListExtended` — «модуль без расширения Рутокен».
  Указатель `NULL` в таблице обрабатывается как
  `CKR_FUNCTION_NOT_SUPPORTED`.
- Ошибка функции печатается в stderr как `Rutoken: <функция> failed: rv =
  <имя> (<код>)`, в JSON — объект `error` с полями `function`, `rv`, `code`
  внутри раздела команды. Остальные команды выполняются, код выхода 1.
- `CKR_CERT_CHAIN_NOT_VERIFIED` после проверки PKCS#7 означает верную подпись
  с непроверенной цепочкой: код выхода 0 и предупреждение.
- Коды `CKR_VENDOR_DEFINED+1…+12` печатаются по именам, если модуль
  экспортирует расширение.

### Разрушительные операции

По решению владельца команды, которые стирают данные или сбрасывают PIN,
выполняются без отдельного подтверждения.

## Этап 3 — чтение (реализован)

Команды можно давать вместе; выполняются они всегда в порядке info, name,
license, journal, volumes, certificates, PIN status. Все проверены на
заглушке через `pkcs11-spy`; поведение библиотеки ниже — из прогона на
устройстве.

### `--rutoken-info` и `--rutoken-name`

- `C_EX_GetTokenInfoExtended` с `ulSizeofThisStructure = sizeof`. Команда
  расшифровывает тип, класс, флаги, цвет корпуса, батарею и контрольную сумму
  прошивки; поля после `ulATRLen` выводятся, только если возвращенный размер
  их покрывает. JSON: раздел `info` с числами и именами констант, `serial`,
  `atr` в hex, `battery` и `firmware_checksum` — `null`, если не сообщаются.
- Устройство: размер 256 принят, 208 — заполнены поля до `ulATRLen`, 288 —
  возвращено 256, 0 — `CKR_ARGUMENTS_BAD`. Без батареи библиотека дает
  напряжение 0, процент и флаги −1.
- `C_EX_GetTokenName`: длина без завершающего NUL («Rutoken ECP <no label>»,
  22 байта при отсутствии метки), буфер на байт меньше —
  `CKR_BUFFER_TOO_SMALL` и полная длина. JSON: `name.label`.

### `C_EX_GetLicense` — `--rutoken-license N [--output-file F]`

- Вызов `(hSession, N, pLicense, pulLicenseLen)`, сессия любого состояния.
- Устройство: запрос размера возвращает 72 без чтения токена; лицензии 1 и 2
  без записи — 72 нулевых байта; номер 0 — `CKR_ARGUMENTS_BAD`; номер 3 при
  запросе размера — 72; буфер 8 байт — `CKR_BUFFER_TOO_SMALL` и 72.
- Команда печатает длину и признак пустой лицензии. Содержимое пишется только
  в файл, буфер затирается. JSON: `license` с `number`, `length`, `empty`,
  `output_file`.

### `C_EX_GetJournal` — `--rutoken-journal [--output-file F]`

- Вызов `(slotID, pJournal, pulJournalSize)`, два прохода.
- Устройство: пустой журнал — `CKR_OK` и размер 0 и без входа, и после него;
  требование входа из документации для пустого журнала не подтвердилось.
- Журнал хранит последнюю подпись ГОСТ любым ключом. `CKA_VENDOR_KEY_JOURNAL`
  (`CKA_VENDOR_DEFINED | 0x2002`) помечает не ключ, подписи которого попадают
  в журнал, а пару ключей, которой токен подписывает сам журнал (примеры SDK
  `Extended/Journal.c`, `JournalParse.c`).
- Разбор по `JournalParse.c`: TLV `0x80` на запись, внутри `0x85` — 12 байт:
  операция (0x01 — подпись), тип RSF-файла ключа (0x03 `AGOST_PR`, 0x23
  `RSA_PR`, 0x43 — закрытый ключ ГОСТ 2012-512 и др.), флаги RSF (0x01 —
  разрешена выработка ключа согласования, 0x02 — ключ SM, 0x04 — ключ подписи
  журнала, 0x08 — импортирован), флаги операции (0x01 — хэш вычислен токеном),
  флаги PINPad, резерв, ID RSF BE16, общий счетчик успешных подписей BE32;
  `0xAA` — хэш, `0xB6` — подпись, `0x83` — ID токена, `0x86` — сведения о
  загружаемой таблице тегов; неизвестные теги выводятся в hex. Сырые данные —
  в файл. JSON: `journal` с `length`, `raw`, `records` (`operation`,
  `rsf_type`, `rsf_flags`, `operation_flags` с именами, `pinpad_flags`,
  `reserved`, `rsf_id`, `signature_count`, `hash`, `signature`, `device_id`,
  `tag_table_info`), `format_valid`.

### `C_EX_GetDriveSize` и `C_EX_GetVolumesInfo` — `--rutoken-volumes`

- Вызовы `(slotID, pulDriveSize)` в МБ и `(slotID, pInfo, pulInfoCount)` в
  два прохода; сессия и вход не нужны.
- Устройство: объем 30436 МБ, 3 раздела. Массив на 3 элемента —
  `CKR_TOKEN_NOT_PRESENT`, в массив ничего не записано; массив на 2 —
  `CKR_BUFFER_TOO_SMALL` и 3. По трассе библиотека получает записи, но не
  может их преобразовать (разбор в `RUTOKEN-APDU.md`).
- Команда печатает объем, число разделов и таблицу: ID, размер, режим
  доступа, владелец (`SO`, `USER`, локальный PIN 3–31), флаги. JSON: `volumes`
  с `drive_size_mb`, `count`, `list`.

### `C_EX_GetCertificateInfoText` — `--rutoken-cert-text [--id ID | --label L]`

- Вызов `(hSession, hCert, &pInfo, &ulLen)`, затем всегда
  `C_EX_FreeBuffer(pInfo)`.
- Команда находит сертификаты по `CKO_CERTIFICATE` и необязательным
  `CKA_ID`/`CKA_LABEL`, для закрытых нужен `--login`. Завершающие NUL
  отбрасываются. JSON: `certificates.list` с `handle`, `id`, `label`, `text`.
- На устройстве не проверена: сертификатов на токене не было.

### `C_EX_SlotManage`: режимы чтения — `--rutoken-pin-status`

- `MODE_GET_PIN_SET_TO_BE_CHANGED`: `pValue` — `CK_USER_TYPE`; `CKR_OK` —
  смена не требуется, `CKR_PIN_EXPIRED` — требуется. Устройство: `CKR_OK` для
  Пользователя и Администратора при заводских PIN, `*pValue` не меняется.
  Режим отражает принудительную смену, а не PIN по умолчанию; тот — в флагах
  `TOKEN_FLAGS_*_PIN_NOT_DEFAULT`. Probe 3: после
  `MODE_FORCE_USER_TO_CHANGE_PIN` — `CKR_PIN_EXPIRED`, после `C_SetPIN` —
  снова `CKR_OK`.
- `MODE_GET_LOCAL_PIN_INFO`: одна структура `CK_LOCAL_PIN_INFO` с входным
  `ulPinID` (подтверждено: из 32 изменилась только первая). Для PIN 3
  получено 1..249, 10 из 10, `LOCAL_PIN_FLAGS_NOT_DEFAULT`. Код для
  отсутствующего PIN неизвестен, поэтому любой код, кроме `CKR_OK`, команда
  выводит как «not reported» и ошибкой не считает.
- Команда опрашивает Пользователя, Администратора и локальные PIN 3–31 при
  открытой сессии: без нее библиотека на каждый вызов заново подключается к
  токену и выполняет 11 команд идентификации. JSON: `pin_status` с `user`,
  `so`, `local_pins`, `local_pins_not_reported`.

## Этап 4 — PKCS#7, CSR и ключи с кнопкой (реализован)

Команды требуют `--login`, выбирают объект по `--id` или `--label` (ровно
один объект), выводят текст или JSON (`--rutoken-json`: `pkcs7_sign`,
`pkcs7_verify`, `csr`) и освобождают каждый буфер библиотеки через
`C_EX_FreeBuffer`, в том числе после ошибки. За один запуск — одна из трех
команд. Входные файлы — до 256 МиБ. Поведение библиотеки на устройстве —
в разделе ответов ниже и в `RUTOKEN-APDU.md`.

### `C_EX_PKCS7Sign`

- Вызов: `(hSession, pData, ulDataLen, hCert, &pEnvelope, &ulLen, hPrivKey,
  phCertificates, ulCertificatesLen, flags)`. `hPrivKey = 0` — ключ ищется по
  `CKA_ID` сертификата. Флаги: `PKCS7_DETACHED_SIGNATURE`, `USE_HARDWARE_HASH`.
  Требуется вход Пользователя.
- Алгоритмы: ГОСТ Р 34.10-2001 и 2012-256 по документации, в SDK есть и 2012-512.
- Команда: `--rutoken-pkcs7-sign --id CERT_ID --input-file DATA --output-file
  CMS [--rutoken-detached] [--rutoken-hw-hash] [--rutoken-chain-id ID ...]`.
  Ключ ищет библиотека по `CKA_ID` сертификата; конверт пишется с правами
  владельца.

### `C_EX_PKCS7VerifyInit`, `Verify`, `VerifyUpdate`, `VerifyFinal`

- Init: `(hSession, pCms, ulCmsSize, pStore, ckMode, flags)`. Хранилище —
  доверенные сертификаты, дополнительные сертификаты и CRL в DER. Режим CRL:
  `OPTIONAL`, `LEAF`, `ALL`. Флаги: `DO_NOT_USE_INTERNAL_CMS_CERTS`,
  `ALLOW_PARTIAL_CHAINS`, `CHECK_SIGNATURE_ONLY` (только с `OPTIONAL`),
  `USE_TRUSTED_CERTS_FROM_TOKEN` (без доверенных в хранилище).
- Присоединенная подпись: `Verify` возвращает данные и сертификаты подписантов.
  Отсоединенная: `VerifyUpdate` по частям, затем `VerifyFinal` возвращает
  сертификаты.
- По документации и SDK нужен вход Пользователя даже для проверки.
- Команда: `--rutoken-pkcs7-verify --input-file CMS [--rutoken-data-file DATA]
  [--rutoken-trusted F ...] [--rutoken-cert F ...] [--rutoken-crl F ...]
  [--rutoken-crl-mode optional|leaf|all] [--rutoken-verify-flag ИМЯ ...]
  [--output-file DATA_OUT] [--rutoken-signers-dir DIR]`. Данные передаются
  в `VerifyUpdate` блоками по 64 КиБ; после ошибки `VerifyUpdate` вызывается
  `VerifyFinal`, чтобы закончить операцию. Код выхода 0 — только при
  `CKR_OK`; при `CKR_CERT_CHAIN_NOT_VERIFIED` данные и сертификаты
  подписантов сохраняются, код выхода 1. Сертификаты подписантов пишутся как
  `signer-N.der`.
- Выходные буферы, которые библиотека успела выделить до ошибки проверки,
  освобождаются через `C_EX_FreeBuffer` и не записываются в файлы. Тест
  `rutoken-cms-tamper-fuzz.py` проверяет это на синтетическом конверте
  заглушки; он не заменяет проверку ASN.1-парсера библиотеки Рутокен.

### `C_EX_CreateCSR`

- Вызов: `(hSession, hPublicKey, dn, dnLength, &pCsr, &ulLen, hPrivKey,
  attributes, ulAttributesLength, extensions, ulExtensionsLength)`. Все три
  списка — пары строк «тип или OID, значение»; значения как в SDK:
  `UTF8String:…`, `DER:…`, `ASN1:…`, префикс `critical,`, `hash` для SKI.
  `hPrivKey = 0` — ключ ищется по `CKA_ID` открытого ключа.
- Ключи: ГОСТ Р 34.10-2001, 2012-256 (в SDK и 2012-512), RSA.
- Команда: `--rutoken-csr --id KEY_ID --rutoken-dn ТИП=ЗНАЧЕНИЕ ...
  [--rutoken-csr-attr …] [--rutoken-csr-ext …] --output-file CSR.der`.
  Выбирается открытый ключ; строка делится на тип и значение по первому
  `=`.

### Ключи с кнопкой — `--keypairgen --rutoken-confirm-by-touch`

- `CKA_VENDOR_CONFIRM_BY_TOUCH` (`CKA_VENDOR_DEFINED | 0x2003`, `CK_BBOOL`) в
  шаблоне закрытого ключа: Рутокен с кнопкой (Touch, флаг
  `TOKEN_FLAGS_HAS_BUTTON`) подписывает им только после нажатия.
- Перед генерацией `pkcs11-tool` читает `C_EX_GetTokenInfoExtended` и не
  создает ключ, если флага кнопки нет. Библиотека на токене без кнопки сама
  отвергает атрибут: `CKR_TEMPLATE_INCONSISTENT` без команд генерации
  (probe 3), так что проверка в `pkcs11-tool` лишь дает понятное сообщение.
- В заголовке определены и остальные атрибуты закрытых ключей:
  `CKA_VENDOR_KEY_JOURNAL`, устаревшие `KEY_PIN_ENTER` и `KEY_CONFIRM_OP`.

### `C_EX_FreeBuffer`

Отдельной команды нет: вызывается автоматически после каждой функции,
выделившей буфер. Тестовая заглушка считает выделения и освобождения.

### Объекты аутентификации (отложено)

По решению владельца отложены: на проверенном токене биометрии нет.

- Объекты `CKO_VENDOR_AUTHENTICATION_FACTOR` типа `CKVAF_BIO_FP_CONVOLUTION`
  (свертка отпечатка по ГОСТ Р ИСО/МЭК 19794-2), атрибуты: число сверток, ID,
  максимум и остаток попыток, ID биоданных.
- `C_EX_Authenticate(hSession, hAuthObject, pData, ulSize)` — после входа по
  PIN подтверждает отпечатком, открывая ключи с этим требованием;
  `C_EX_Deauthenticate(hSession, hAuthObject)` снимает это;
  `C_EX_UnblockAuthenticator(hSession, hAuthObject)` сбрасывает счетчик под
  входом Администратора.
- Состояние живет в сессии, поэтому отдельная команда «authenticate» в другом
  процессе бесполезна. Команды: `--rutoken-auth-objects` (список, только
  чтение); модификатор `--rutoken-auth-object ID --rutoken-auth-data FILE` для
  любой операции после входа с `Deauthenticate` в конце;
  `--rutoken-unblock-authenticator --id ID` под входом Администратора.

## Этап 5 — изменяющие команды (реализованы)

За один запуск — одна изменяющая команда; ее нельзя сочетать с другими
командами `pkcs11-tool` и с PKCS#7/CSR. Команды чтения `--rutoken-*`
выполняются после изменения и показывают его результат; форматирование идет
отдельно, без входа и без сессии. Результат — текст или JSON (`set_name`,
`set_license`, `set_local_pin`, `unblock_user_pin`, `token_manage`,
`init_token`, `restore_factory_defaults`); для известных причин ошибки к
`error` добавляется `hint`. Spy расшифровывает параметры `InitToken`,
режимов `TokenManage` и `MODE_RESTORE_FACTORY_DEFAULTS`, показывая PIN и
ключ эмитента только длиной. Поведение устройства — из прогона probe 3.

| Функция | Команда | Условия и поведение |
|---|---|---|
| `SetTokenName(hSession, label, len)` | `--rutoken-set-name ИМЯ --login` | Сессия RW под Пользователем. Устройство: 0–255 байт UTF-8 приняты, `C_GetTokenInfo` показывает первые 32; пустое имя читается как «Rutoken ECP <no label>» |
| `SetLicense(hSession, N, 72 байта)` | `--rutoken-set-license N --input-file F --login` | RW под Пользователем (Администратор не проверялся). Устройство: номера 1–4 и ровно 72 байта, иначе `CKR_ARGUMENTS_BAD`; повторная запись принята. Содержимое не печатается, буфер затирается |
| `SetLocalPIN(slot, PIN Пользователя или текущий локальный, новый, ID)` | `--rutoken-set-local-pin ID [--rutoken-auth-pin env:A] [--new-pin env:B]` | Без сессии и входа: `--login` и `--pin` отвергаются, чтобы `C_Login` с локальным PIN не тратил попытку PIN Пользователя. ID 3–31. Устройство: новый PIN — по PIN Пользователя, заданный — только по текущему значению (неверное тратит попытку локального PIN); минимальная длина как у PIN Пользователя, 10 попыток |
| `UnblockUserPIN(hSession)` | `--rutoken-unblock-user-pin --login --login-type so` | Сессия RW под Администратором. Устройство: попытки PIN Пользователя восстановлены, у незаблокированного локального PIN — нет |
| `TokenManage(hSession, mode, pValue)` | `--rutoken-token-manage РЕЖИМ --login --login-type so` | `force-user-pin-change` (6), `default-user-pin` (5, новый PIN из `--new-pin`), `standard-default-user-pin` (3), `reset-user-pin` (4); для Рутокен Bluetooth `bluetooth-timeout:МИН` (1, 0–70, 0 — по умолчанию) и `channel:usb\|bluetooth` (2), на других токенах `CKR_FUNCTION_NOT_SUPPORTED`. Устройство: режим 4 — смена PIN Пользователя, без права Администратора на нее (`TOKEN_FLAGS_ADMIN_CHANGE_USER_PIN`) — `CKR_USER_NOT_LOGGED_IN`; режим 5 включает `TOKEN_FLAGS_USER_PIN_NOT_DEFAULT` |
| `InitToken(slot, SO PIN, CK_RUTOKEN_INIT_PARAM)` | `--rutoken-init-token` | Текущий PIN Администратора — `--so-pin`, новые — `--rutoken-new-so-pin` и `--new-pin`; метка — `--label`; `--rutoken-user-pin-policy user\|admin\|both` (по умолчанию `user`, как с завода), `--rutoken-min-pin-length SO:USER` (6:6), `--rutoken-retries SO:USER` (10:10), `--rutoken-sm-mode N` (0), `--rutoken-repair-mode` — без PIN Администратора. Открытых сессий быть не должно: `CKR_SESSION_EXISTS` без обращения к токену. Устройство: около 3,4 с; удаляются объекты и локальные PIN, остаются лицензии, запись журнала и счетчик изменений |
| `SlotManage(MODE_RESTORE_FACTORY_DEFAULTS)` | `--rutoken-restore-factory-defaults --rutoken-emitent-key F` | Те же параметры форматирования, кроме ремонтного режима; ключ эмитента — 32 байта из файла, `--rutoken-emitent-key-type kuznyechik\|magma` (по умолчанию Кузнечик), `--rutoken-emitent-key-retries N` (10). Устройство: как `InitToken` плюс ключ эмитента, Кузнечик с 10 попытками принят, около 3,3 с |

Не реализованы:

| Функция | Условия | Команда |
|---|---|---|
| `SlotManage(MODE_GET_IMIT)` | MAC ГОСТ по переданному ключу, только Рутокен SC 2.0 | `--rutoken-legacy-imit` |
| `ChangeVolumeAttributes(slot, владелец, PIN, раздел, режим, bPermanent)` | Отложено с разделами Flash. Постоянное изменение переподключает токен, `slotID` может смениться — токен ищется заново по серийному номеру | `--rutoken-volume-access ID:РЕЖИМ [--rutoken-permanent]` |
| `FormatDrive(slot, CKU_SO, PIN, layout[], n)` | Отложено с разделами Flash. Стирает Flash, 1–8 разделов, переподключение | `--rutoken-format-drive РАЗМЕР:РЕЖИМ:ВЛАДЕЛЕЦ,...` |

Устаревшие функции остаются в таблице и получают команды
`--rutoken-legacy-*`, скрытые из краткой справки:

- `LoadActivationKey` — прошивка 20, по матрице не поддерживается ни одной
  моделью.
- `SetActivationPassword`, `GenerateActivationPassword` (номер 1–6 или
  `GENERATE_NEXT_PASSWORD`, набор символов) — Рутокен ЭЦП Bluetooth; пароль
  пишется только в файл.
- `SignInvisibleInit`, `SignInvisible` — «невидимая» подпись PINPad.
- `WrapKey`, `UnwrapKey` — выработка и маскирование сессионного ключа ГОСТ
  28147-89.

## Проверки

1. Заглушка `tests/rutoken-stub.c` получает реалистичное поведение каждой
   функции: два прохода, `CKR_BUFFER_TOO_SMALL`, ошибки, отсутствие
   поддержки, учет выделений и освобождений. Команды этапов 3–5 в тексте и
   JSON, файлы, коды Рутокен, освобождение буферов, отказ от PIN в
   командной строке и отсутствие лицензий, новых PIN и ключа эмитента
   в логе spy проверяются в `make check` (`tests/test-rutoken-extensions.sh`)
   и во всех шести test kit (`scripts/portable/test.py`). Порядок таблицы spy проверяется вызовами с
   дескриптором 99, на который заглушка отвечает только кодом функции. Для
   probe заглушка поддерживает вход Пользователя и Администратора с
   проверкой PIN и счетчиками попыток, сессию для записи, генерацию ключей,
   подпись, создание и удаление объектов, `PKCS7Sign`, все `PKCS7Verify*` и
   `CreateCSR` с условными форматами CMS и CSR, а также изменяющие функции
   этапа 5 (метка, лицензии, локальные PIN, разблокировка, `TokenManage`,
   `InitToken`, сброс к заводским настройкам) и `C_SetPIN` с ответами
   устройства из прогона probe 3; ее `C_Finalize` возвращает ошибку, если
   созданный объект не удален или буфер не освобожден.
2. Профиль portable SoftHSM fork — функции, которые он эмулирует.
3. Аппаратная приемка: `tests/rutoken-hw-probe.c`, затем команды CLI на
   совместимом Рутокене; без устройства — видимый hardware skip.

## Прогон на устройстве

Версия 2 программы без `--pkcs7` и `--write-tests` ничего не меняет на
токене. Она не вызывает `InitToken`, `UnblockUserPIN`, `SetTokenName`,
`SetLicense`, `SetLocalPIN`, `TokenManage`, `ChangeVolumeAttributes`,
`FormatDrive`, устаревшие функции и функции аутентификации, а `SlotManage` —
только в двух режимах чтения. PIN вводится без эха, попытка одна; при одной
оставшейся попытке вход пропускается.

По сравнению с версией 1 добавлены чтения: разделы Flash в массивы на 4, 8,
16 и 0 элементов с выводом всего, что библиотека записала даже при ошибке;
лицензии 3–5 целиком и 6; локальные PIN 0–33 по одному при открытой сессии;
`MODE_GET_PIN_SET_TO_BE_CHANGED` для типов 2, 3, 31, 32; имя в буфер с
запасом; журнал в буфер при нулевом размере; текст «сертификата» для
неверного дескриптора и объекта-не-сертификата.

Изменяющие проверки выполняются только после ввода слова подтверждения:

- `--pkcs7 <CKA_ID>` подписывает фиксированную строку существующим ключом ГОСТ
  с сертификатом (слово `SIGN`);
- `--write-tests` (слово `WRITE`) создает временную пару ключей ГОСТ Р
  34.10-2012 256 по шаблону SDK (без `CKA_VENDOR_KEY_JOURNAL`) и
  самоподписанный сертификат с меткой «OpenSC probe temporary», подписывает
  ими тестовые данные, читает журнал после каждой подписи, получает текст
  сертификата, выполняет проверки PKCS#7 и CSR и удаляет объекты. Удаляются
  только объекты с этой меткой и `CKA_ID` «OpenSC-probe-tmp», в том числе
  оставшиеся от прерванного прогона.

Обе проверки заменяют запись журнала и увеличивают счетчик подписей. Файлы
журнала, сертификата, подписей и CSR пишутся в `--save-dir`.

```sh
git clone https://github.com/code-agent-43824/OpenSC
cd OpenSC
cc -I src -o rutoken-hw-probe tests/rutoken-hw-probe.c -ldl

# терминал 1: pcscd в отладочном режиме с APDU
sudo systemctl stop pcscd.socket pcscd.service
sudo pcscd --foreground --debug --apdu 2>&1 | tee pcscd.log

# терминал 2: только чтение
./rutoken-hw-probe --login --save-dir out /usr/lib/librtpkcs11ecp.so | tee probe.log
# по желанию: временные объекты
./rutoken-hw-probe --login --write-tests --save-dir out-write \
    /usr/lib/librtpkcs11ecp.so | tee probe-write.log

# после прогона
sudo systemctl start pcscd.socket
```

Путь к библиотеке зависит от пакета (`/usr/lib`, `/usr/lib64`,
`/opt/aktivco/rutokenecp/…`). Шаги разделены паузой 0,5 с (`--pause-ms`).
Точнее всего вызовы выделяются в `pcscd.log` по транзакциям
(`BEGIN_TRANSACTION`…`END_TRANSACTION`): время ответа USB-токена в
виртуальной машине доходило до 1 с.

В `pcscd.log` без Secure Messaging PIN передается открытым текстом: в VERIFY,
а в режиме `--modify-tests` еще в командах смены PIN и PIN по умолчанию;
перед отправкой лог нужно очистить (команда в `RUTOKEN-APDU.md`). `probe.log`
PIN не содержит, но включает серийный номер, ATR и метки объектов.

Версия 3 добавляет `--modify-tests` для токена, который можно стереть: без
проверок чтения предыдущих версий она вызывает изменяющие функции и после
каждой читает минимум, показывающий результат. PIN Пользователя и
Администратора запрашиваются (или `--default-pins` — заводские 12345678 и
87654321, или `--pin-env`/`--so-pin-env`), подтверждение — слово `ERASE`.
Порядок: `SetTokenName` (ASCII, UTF-8, 32, 33 и 255 байт, пустое имя);
`SetLicense(1)` дважды, номер 5, 71 байт; `SetLocalPIN` — новый PIN 4 по
PIN Пользователя, смена по старому значению, PIN 3, номера 2 и 32, неверный
PIN; блокировка PIN Пользователя неверными PIN и `UnblockUserPIN` без
Администратора и с ним; `TokenManage` — режимы Bluetooth 1 и 2,
принудительная смена PIN и `C_SetPIN`, собственный PIN по умолчанию, сброс к
нему и возврат стандартного; `InitToken` при открытой сессии и без нее
(заводские PIN, 10 попыток, метка «OpenSC probe 3»); `SlotManage
(MODE_RESTORE_FACTORY_DEFAULTS)` с тестовым ключом эмитента Кузнечик
`00 01 … 1F`; после каждого форматирования — счетчики, журнал, локальные PIN,
метка, лицензии 1–4 и объекты; в конце — ключ ГОСТ с
`CKA_VENDOR_CONFIRM_BY_TOUCH` на токене без кнопки (подпись ограничена 30 с).
Лицензия 1 остается с тестовыми данными.

Для автоматических тестов есть `--pin-env ИМЯ` (PIN из переменной окружения)
и `--assume-yes`; `--selftest-certificate FILE` пишет сертификат из
фиксированных значений для проверки кодировщика. Слово подтверждения и PIN
читаются из `/dev/tty`, поэтому вывод можно направлять в `tee`; без
терминала изменяющие проверки пропускаются. Каталог `--save-dir` создается
с правами 0700. `make check` запускает программу на заглушке без входа, со
сценарием `--write-tests`, включая успешные PKCS#7 и CSR, и с
`--modify-tests`.

## Ответы прогона и открытые вопросы

| Вопрос | Ответ |
|---|---|
| `ulSizeofThisStructure` меньше, больше и 0 | 208 — поля до `ulATRLen`, 288 — возвращено 256, 0 — `CKR_ARGUMENTS_BAD` |
| Имя с NUL, буфер на байт меньше | Длина без NUL; `CKR_BUFFER_TOO_SMALL` и полная длина |
| Размер лицензии, пустая лицензия, номера 0 и 3, буфер 8 байт | 72 без чтения; 72 нулевых байта; `CKR_ARGUMENTS_BAD` и 72; `CKR_BUFFER_TOO_SMALL` и 72 |
| Лицензии 3–6 | 3 и 4 читаются (72 нулевых байта); 5 и 6 — `CKR_ARGUMENTS_BAD` без команды |
| Нужен ли вход для журнала | Нет ни для пустого, ни для непустого |
| Непустой журнал | 126 байт, одна запись последней подписи: теги `AA`, `B6`, `85`, `83`; поля `85` — как в `JournalParse.c`; флаг «хэш вычислен токеном» только у `C_Sign` с хэшированием; счетчик общий для токена; после удаления ключа запись остается |
| Flash без входа, массив на один меньше | Вход не нужен; `CKR_BUFFER_TOO_SMALL`. Массив на 3–16 элементов — `CKR_TOKEN_NOT_PRESENT`, заполнен только элемент 0 (разбор записей библиотекой не совпадает с форматом токена, `RUTOKEN-APDU.md`) |
| Одна структура или массив в `MODE_GET_LOCAL_PIN_INFO` | Одна структура |
| Незаданный локальный PIN, номера вне 3…31 | `CKR_DEVICE_ERROR` (токен: `6A 82`); `CKR_ARGUMENTS_BAD` |
| Типы пользователей для `MODE_GET_PIN_SET_TO_BE_CHANGED` | `CKU_USER`, `CKU_SO`; остальные — `CKR_ARGUMENTS_BAD` |
| Текст сертификата для неверного дескриптора, объекта-не-сертификата | `CKR_OBJECT_HANDLE_INVALID`; `CKR_ATTRIBUTE_TYPE_INVALID` |
| Длина и формат текста сертификата | Текст `X509_print` OpenSSL, длина включает NUL (1171 байт); строится без обращения к токену |
| Возможности модели | Flash, собственные PIN, доверенные сертификаты, ФКН 2, KDF_TREE, ремонтное форматирование; SM, биометрии и внешней аутентификации нет |
| PKCS#7 | Все варианты подписи — `CKR_OK` (конверт 863 байта, открепленный — 819); проверка программная: доверенный сертификат — 1 подписант, `CHECK_SIGNATURE_ONLY` с пустым хранилищем — 0, измененные данные — `CKR_SIGNATURE_INVALID`, `Verify` без `Init` — `CKR_OPERATION_NOT_INITIALIZED` |
| CSR | `CKR_OK`: 227 байт, с keyUsage — 257; нечетное число строк DN — `CKR_ARGUMENTS_BAD` |
| Токен без Flash | `GetDriveSize`, `GetVolumesInfo` — `CKR_FUNCTION_NOT_SUPPORTED` без команд Flash |
| Метка: длина, кириллица, пустая | 0–255 байт UTF-8 приняты, `C_GetTokenInfo` показывает первые 32; пустая читается как «Rutoken ECP <no label>»; файл — заголовок «TN» с длиной и имя |
| Лицензия: вход, номер 5, 71 байт, повтор | Под Пользователем `CKR_OK`; `CKR_ARGUMENTS_BAD`; `CKR_ARGUMENTS_BAD`; повторная запись принята; лицензия переживает форматирование |
| Локальный PIN: авторизация, номера 2 и 32, неверный PIN | Новый — по PIN Пользователя, заданный — только по текущему значению; `CKR_ARGUMENTS_BAD`; `CKR_PIN_INCORRECT` и минус попытка локального PIN, PIN Пользователя не тронут |
| Блокировка и разблокировка PIN Пользователя | 10 неверных — `CKR_PIN_INCORRECT`, 11-й — `CKR_PIN_LOCKED`; `UnblockUserPIN` без входа — `CKR_USER_NOT_LOGGED_IN`, под Администратором — `CKR_OK` |
| `TokenManage` | Bluetooth — `CKR_FUNCTION_NOT_SUPPORTED`; принудительная смена — `CKR_PIN_EXPIRED` до `C_SetPIN` (тот же PIN принят), вход при этом `CKR_OK`; свой PIN по умолчанию — `CKR_OK` и `USER_PIN_NOT_DEFAULT`; сброс PIN к умолчанию, когда менять PIN может только Пользователь, — `CKR_USER_NOT_LOGGED_IN`; возврат стандартного — `CKR_OK` |
| `InitToken`, сброс к заводским настройкам | С открытой сессией — `CKR_SESSION_EXISTS`; без нее `CKR_OK` за 3,3–3,4 с; объекты и локальные PIN удалены; лицензии, запись журнала и счетчик изменений остались |
| Ключ с `CKA_VENDOR_CONFIRM_BY_TOUCH` без кнопки | `CKR_TEMPLATE_INCONSISTENT` без команд генерации; объектов `CKH_VENDOR_TOUCH_INTERFACE` нет |

Открыто: режим 4 `TokenManage` при политике с Администратором,
`SetLicense` под Администратором, `UseRepairMode`, Магма как ключ эмитента,
имена длиннее 255 байт и аутентификаторы; работа с разделами Flash отложена
(`PLAN.md`). Команды токена для записи, подписи, хэша, хранения объектов,
PKCS#7 и изменяющих функций разобраны в `RUTOKEN-APDU.md`.

## Полевой отчёт (Рутокен ЭЦП 2.0, релиз 0.27.1-portable.5)

Владелец прогнал опубликованный релиз на Рутокен ЭЦП 2.0 (serial
4894721a, hw 67.4, fw 34.2, librtpkcs11ecp 2.21.1.0). Полностью работают
все команды чтения (этап 3), PKCS#7 и CSR на ГОСТ-ключе (этап 4) и все
изменяющие команды этапа 5, включая аварийное форматирование. По замечаниям
внесены следующие исправления; тесты — в `tests/test-rutoken-extensions.sh`
и `scripts/portable/test.py`.

| Замечание | Исправление |
| --- | --- |
| Чтение открытого ГОСТ-ключа: `-r -y pubkey` отвечало `Reading public keys of type 0x30 not (yet) supported` | `read_object` для `CKK_GOSTR3410` и `CKK_GOSTR3410_512` отдает `CKA_VALUE` как есть (у форка это основной механизм); SPKI через провайдер ГОСТ не строится |
| SO-логин с `-O` падал с `CKR_SESSION_READ_ONLY_EXISTS` | `--login-type so` теперь сам открывает R/W-сессию (общее поведение, не только для заглушки) |
| «object not found» не отличало «нет объекта» от «нужен логин» | в публичной сессии добавлена подсказка про `--login`; состояние сессии читается через `C_GetSessionInfo` |
| `--rutoken-min-pin-length 1:1` → `CKR_ARGUMENTS_BAD` | длина сверяется с окном PIN устройства (`C_GetTokenInfo`, те же 6..249, что в `-L`) с внятным сообщением |
| repair при живом SO PIN стабильно давал `CKR_PIN_LEN_RANGE` | `--rutoken-repair-mode` сам тратит оставшиеся попытки SO заведомо неверными PIN до блокировки, затем форматирует; при коде `CKR_PIN_LEN_RANGE` выводится подсказка о предусловии |
| repair всегда требовал новые PIN | в repair новые SO и User PIN необязательны: при отсутствии генерируются и один раз показываются на stderr (заводские значения в исходник не вшиваются) |
| нельзя штатно проверить PIN/добить попытки из скрипта | добавлен `--test-login`: логин и выход, код возврата — результат логина, без иных действий |
| `env:<NAME>` ломался под `sudo` | man-страница (раздел Environment) описывает форму `env:<NAME>` и чистку окружения `sudo` (нужно `sudo env NAME=... pkcs11-tool …`) |

`pkcs11-spy`: в шапку лога добавлена строка версии форка, в конце (на
`C_Finalize`) — число вызовов каждой функции и суммарное время; переменная
`PKCS11SPY_UNSAFE_SECRETS` по явному требованию выводит PIN и ключи в
открытом виде для локальной отладки (по умолчанию выключено, в шапке
предупреждение). Штатная маскировка секретов сохранена.

Норма (запланировано/по дизайну, не дефект): на токене без Flash
`--rutoken-volume-access` и `--rutoken-format-drive` дают
`CKR_FUNCTION_NOT_SUPPORTED` (разделы Flash отложены, см. `PLAN.md`);
`--rutoken-pkcs7-sign` поддерживает только ГОСТ-ключи, RSA — `CKR_KEY_TYPE_INCONSISTENT`.


Аппаратная приёмка `0.27.1-portable.8` (2026-10-09, Рутокен ЭЦП, fw 34.2, lib 2.21.1.0): чтения `C_EX_*`, крипто-roundtrip (ГОСТ/RSA/EC/Ed25519), CSR, полная цепочка CMS с негативами (подделка → `CKR_SIGNATURE_INVALID`, без segfault) и команды этапа 5 прошли успешно. Наблюдения (не дефекты): `--rutoken-set-name` меняет имя только под Пользователем (под SO — `CKR_USER_NOT_LOGGED_IN`); `--application-id` принимает только OID (для произвольной метки — `--application-label`). Flash и сканера на токене нет (`--rutoken-volumes` → `0x54`, `--rutoken-bio-scanners` → `0x1b7`). Полный разбор прогона — в `STATUS.md`.
