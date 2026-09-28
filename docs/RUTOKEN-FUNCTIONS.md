# Функции Рутокен этапов 3–5: описание и план реализации

Документ дополняет [`RUTOKEN-EXTENSIONS.md`](RUTOKEN-EXTENSIONS.md). Там описаны
состав расширения и общие требования, здесь — поведение каждой оставшейся
функции, команды `pkcs11-tool`, правила памяти и секретов, проверки и вопросы
к устройству. Ответы дает программа
[`tests/rutoken-hw-probe.c`](../tests/rutoken-hw-probe.c) (раздел «Прогон на
устройстве»); первый прогон выполнен на Рутокен ЭЦП 3.0 5100 Flash с
библиотекой 2.21 для Linux ARM64. Команды, которые библиотека при этом
отправляет токену, разобраны в [`RUTOKEN-APDU.md`](RUTOKEN-APDU.md).

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
`CKR_VENDOR_DEFINED+13…+35`. `pkcs11-spy` этот символ не экспортирует, поэтому
приложение Рутокен БИО через spy BIO-таблицу не найдет. Это отдельная задача
прозрачности spy.

## Общие правила

### Память

| Схема | Функции | Правило |
|---|---|---|
| Два прохода: `NULL`, затем буфер | `GetTokenName`, `GetLicense`, `GetJournal`, `GetVolumesInfo` | Размер берется из первого вызова, буфер выделяет вызывающий. Поведение при малом буфере проверяет probe. |
| Буфер выделяет библиотека | `GetCertificateInfoText`, `PKCS7Sign`, `CreateCSR`, `PKCS7Verify`, `PKCS7VerifyFinal` | Каждый полученный буфер освобождается `C_EX_FreeBuffer` на всех путях. Для подписантов по примеру SDK: каждый `pData`, затем массив, затем данные. |
| Структура вызывающего | `GetTokenInfoExtended`, `GetDriveSize`, `SlotManage` | Вызывающий заполняет `ulSizeofThisStructure`, `ulPinID` и т. п. |

### Секреты

- PIN берется из существующих `--pin`, `--so-pin`, `--new-pin` в виде `env:ИМЯ`
  или запрашивается без эха. Для функций, получающих PIN напрямую
  (`InitToken`, `SetLocalPIN`, `FormatDrive`, `ChangeVolumeAttributes`,
  `TokenManage` с новым PIN), открытое значение в аргументах отвергается.
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

Каждая команда этапа 5 требует `--rutoken-confirm=<операция>` с точным именем
операции (`init-token`, `format-drive`, `restore-factory-defaults` и т. д.).
Без него команда только печатает, что будет сделано.

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
- Разбор: TLV `0x80` на запись, внутри `0x85` — 12 байт (тип операции, тип
  ключа, назначение, флаги, 2 резервных, ID ключа BE16, счетчик подписей
  BE32), `0xAA` — хэш, `0xB6` — подпись, `0x83` — ID устройства; неизвестные
  теги выводятся в hex. Сырые данные — в файл. JSON: `journal` с `length`,
  `raw`, `records`, `format_valid`.

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
  `TOKEN_FLAGS_*_PIN_NOT_DEFAULT`.
- `MODE_GET_LOCAL_PIN_INFO`: одна структура `CK_LOCAL_PIN_INFO` с входным
  `ulPinID` (подтверждено: из 32 изменилась только первая). Для PIN 3
  получено 1..249, 10 из 10, `LOCAL_PIN_FLAGS_NOT_DEFAULT`. Код для
  отсутствующего PIN неизвестен, поэтому любой код, кроме `CKR_OK`, команда
  выводит как «not reported» и ошибкой не считает.
- Команда опрашивает Пользователя, Администратора и локальные PIN 3–31 при
  открытой сессии: без нее библиотека на каждый вызов заново подключается к
  токену и выполняет 11 команд идентификации. JSON: `pin_status` с `user`,
  `so`, `local_pins`, `local_pins_not_reported`.

## Этап 4 — криптография и аутентификация

### `C_EX_PKCS7Sign`

- Вызов: `(hSession, pData, ulDataLen, hCert, &pEnvelope, &ulLen, hPrivKey,
  phCertificates, ulCertificatesLen, flags)`. `hPrivKey = 0` — ключ ищется по
  `CKA_ID` сертификата. Флаги: `PKCS7_DETACHED_SIGNATURE`, `USE_HARDWARE_HASH`.
  Требуется вход Пользователя.
- Алгоритмы: ГОСТ Р 34.10-2001 и 2012-256 по документации, в SDK есть и 2012-512.
- Команда: `--rutoken-pkcs7-sign --id CERT_ID --input-file DATA --output-file
  CMS [--rutoken-detached] [--rutoken-hw-hash] [--rutoken-chain-id ID ...]`.

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
  в `VerifyUpdate` блоками по 64 КиБ.

### `C_EX_CreateCSR`

- Вызов: `(hSession, hPublicKey, dn, dnLength, &pCsr, &ulLen, hPrivKey,
  attributes, ulAttributesLength, extensions, ulExtensionsLength)`. Все три
  списка — пары строк «тип или OID, значение»; значения как в SDK:
  `UTF8String:…`, `DER:…`, `ASN1:…`, префикс `critical,`, `hash` для SKI.
  `hPrivKey = 0` — ключ ищется по `CKA_ID` открытого ключа.
- Ключи: ГОСТ Р 34.10-2001, 2012-256 (в SDK и 2012-512), RSA.
- Команда: `--rutoken-csr --id KEY_ID --rutoken-dn ТИП=ЗНАЧЕНИЕ ...
  [--rutoken-csr-attr …] [--rutoken-csr-ext …] --output-file CSR.der`.

### `C_EX_FreeBuffer`

Отдельной команды нет: вызывается автоматически после каждой функции,
выделившей буфер. Тестовая заглушка считает выделения и освобождения.

### Объекты аутентификации

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

## Этап 5 — изменяющие, разрушительные и устаревшие операции

| Функция | Условия | Команда |
|---|---|---|
| `InitToken(slot, SO PIN, CK_RUTOKEN_INIT_PARAM)` | Полное форматирование, открытых сессий быть не должно (`CKR_SESSION_EXISTS`). `UseRepairMode` форматирует без PIN Администратора. Новые PIN, политика смены PIN Пользователя, минимальные длины, попытки (Администратор 3–10, Пользователь 1–10), метка, `ulSmMode`. Лицензии сохраняются. | `--rutoken-init-token --rutoken-confirm=init-token` и параметры |
| `UnblockUserPIN(hSession)` | Сессия RW под Администратором | `--rutoken-unblock-user-pin` |
| `SetTokenName(hSession, label, len)` | Сессия RW под Пользователем | `--rutoken-set-name ИМЯ` |
| `SetLicense(hSession, N, 72 байта)` | RW под Пользователем или Администратором, возможен `CKR_LICENSE_READ_ONLY` | `--rutoken-set-license N --input-file F --rutoken-confirm=set-license` |
| `SetLocalPIN(slot, PIN Пользователя или старый локальный, новый, ID)` | Без сессии | `--rutoken-set-local-pin ID` |
| `TokenManage(hSession, mode, pValue)` | Режимы 1–2 для Рутокен Bluetooth (таймаут 1–70 мин, канал USB/BT); 3–6 под Администратором: сброс настроенного PIN по умолчанию, сброс PIN, новый PIN по умолчанию (`CK_VENDOR_PIN_PARAMS`), принудительная смена | `--rutoken-token-manage РЕЖИМ[:АРГУМЕНТ]`, подтверждение для сброса PIN |
| `SlotManage(MODE_RESTORE_FACTORY_DEFAULTS)` | ЭЦП 2.0/3.0 и Flash; PIN Администратора, параметры инициализации, новый ключ эмитента 32 байта, счетчик, тип ключа | `--rutoken-restore-factory-defaults --rutoken-confirm=…` |
| `SlotManage(MODE_GET_IMIT)` | MAC ГОСТ по переданному ключу, только Рутокен SC 2.0 | `--rutoken-legacy-imit` |
| `ChangeVolumeAttributes(slot, владелец, PIN, раздел, режим, bPermanent)` | Постоянное изменение переподключает токен, `slotID` может смениться — токен ищется заново по серийному номеру | `--rutoken-volume-access ID:РЕЖИМ [--rutoken-permanent]` |
| `FormatDrive(slot, CKU_SO, PIN, layout[], n)` | Стирает Flash, 1–8 разделов, переподключение | `--rutoken-format-drive РАЗМЕР:РЕЖИМ:ВЛАДЕЛЕЦ,... --rutoken-confirm=format-drive` |

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
   поддержки, учет выделений и освобождений. Для этапа 3 это сделано: команды
   в тексте и JSON, файл лицензии, коды Рутокен, освобождение буферов и
   отсутствие лицензии в логе spy проверяются в `make check`
   (`tests/test-rutoken-extensions.sh`) и во всех шести test kit
   (`scripts/portable/test.py`). Порядок таблицы spy проверяется вызовами с
   дескриптором 99, на который заглушка отвечает только кодом функции.
2. Профиль portable SoftHSM fork — функции, которые он эмулирует.
3. Аппаратная приемка: `tests/rutoken-hw-probe.c`, затем команды CLI на
   совместимом Рутокене; без устройства — видимый hardware skip.

## Прогон на устройстве

Программа ничего не меняет на токене. Она не вызывает `InitToken`,
`UnblockUserPIN`, `SetTokenName`, `SetLicense`, `SetLocalPIN`, `TokenManage`,
`ChangeVolumeAttributes`, `FormatDrive`, устаревшие функции и функции
аутентификации, а `SlotManage` — только в двух режимах чтения. PIN вводится
без эха, попытка одна; при одной оставшейся попытке вход пропускается.
`--pkcs7` подписывает фиксированную строку после ввода `SIGN`; это заменяет
запись журнала и увеличивает счетчик подписей.

```sh
git clone https://github.com/code-agent-43824/OpenSC
cd OpenSC
cc -I src -o rutoken-hw-probe tests/rutoken-hw-probe.c -ldl

# терминал 1: pcscd в отладочном режиме с APDU
sudo systemctl stop pcscd.socket pcscd.service
sudo pcscd --foreground --debug --apdu 2>&1 | tee pcscd.log

# терминал 2
./rutoken-hw-probe /usr/lib/librtpkcs11ecp.so | tee probe.log
./rutoken-hw-probe --login /usr/lib/librtpkcs11ecp.so | tee probe-login.log

# после прогона
sudo systemctl start pcscd.socket
```

Путь к библиотеке зависит от пакета (`/usr/lib`, `/usr/lib64`,
`/opt/aktivco/rutokenecp/…`). Шаги разделены паузой 1 с (`--pause-ms`).
Точнее всего вызовы выделяются в `pcscd.log` по транзакциям
(`BEGIN_TRANSACTION`…`END_TRANSACTION`): время ответа USB-токена в
виртуальной машине доходило до 1 с.

В `pcscd.log` при входе без Secure Messaging команда VERIFY содержит PIN
открытым текстом. Используйте тестовый токен с PIN по умолчанию или удалите эти
строки перед отправкой. `probe.log` PIN не содержит, но включает серийный
номер, ATR и метки объектов.

Для проверки PKCS#7 и CSR на тестовом ключе ГОСТ с сертификатом:
`./rutoken-hw-probe --login --pkcs7 <CKA_ID в hex> --save-dir out <модуль>`
(`CKA_ID` печатается в шаге «key pairs after login»).

## Ответы прогона и открытые вопросы

| Вопрос | Ответ |
|---|---|
| `ulSizeofThisStructure` меньше, больше и 0 | 208 — поля до `ulATRLen`, 288 — возвращено 256, 0 — `CKR_ARGUMENTS_BAD` |
| Имя с NUL, буфер на байт меньше | Длина без NUL; `CKR_BUFFER_TOO_SMALL` и полная длина |
| Размер лицензии, пустая лицензия, номера 0 и 3, буфер 8 байт | 72 без чтения; 72 нулевых байта; `CKR_ARGUMENTS_BAD` и 72; `CKR_BUFFER_TOO_SMALL` и 72 |
| Нужен ли вход для журнала | Для пустого — нет; непустой журнал не наблюдался |
| Flash без входа, массив на один меньше | Вход не нужен; `CKR_BUFFER_TOO_SMALL`. Полный массив на этом токене — `CKR_TOKEN_NOT_PRESENT` |
| Одна структура или массив в `MODE_GET_LOCAL_PIN_INFO` | Одна структура |
| Длина и формат текста сертификата | Не проверено: нет сертификатов |
| Возможности модели | Flash, собственные PIN, доверенные сертификаты, ФКН 2, KDF_TREE, ремонтное форматирование; SM, биометрии и внешней аутентификации нет |
| PKCS#7 и CSR | Не проверено: нет ключа ГОСТ с сертификатом |

Открыто и требует прогонов: значения полей разделов Flash и причина
`CKR_TOKEN_NOT_PRESENT`, непустой журнал, текст сертификата, чтение лицензий 3
и 4, код отсутствующего локального PIN, этап 4. Неразобранные команды токена
перечислены в `RUTOKEN-APDU.md`.
