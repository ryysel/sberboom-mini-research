# SberCast → StarCommand: маршрут и границы достижимости

30.10.2026. Объект: `vendor/staros/box` из дампа StarOS 1.82.7 (BIN SHA-256
`dd6ea676f9c516eacb32a041195a39133dc4f2336edb21a5e9df686edd6e4fa5`),
ARM ELF32. Все адреса — виртуальные адреса этого ELF, не смещения NAND.

Это статический разбор чужого старого дампа. Он не подтверждает поведение
текущей прошивки 1.103.x и не является найденным обходом авторизации.
Во время работы не было подключений к колонке, сопряжения, fuzz, отправки
команд, записи в flash или изменения сервисов.

## Краткий результат

- Найден дополнительный вход вложенного `StarCommand` из SberCast. Он проходит
  через проверку токена, а затем через виртуальный вызов
  `AgentService::processStarCommand`.
- Исполнение разрешается не общей таблицей команд, а наборами
  `supportedCommands()` семи классов-агентов. Список этих классов замкнут.
- ADB этим маршрутом недостижим: `AdbServiceImpl` принимает другой тип
  (`StarMessage`, case 115 по смещению 0x18) и отдельно проверяет пароль.
- Произвольной записи конфигурации и запуска процессов среди обработчиков нет.
- Открыто: смысл результата `4` валидатора, внешние gates перед dispatch,
  применимость к текущей прошивке.

## 1. Вход входящего сообщения

`SberCastServerImpl::wsOnMessageCallback` **0x184ddc**:

- внешний decoder **0x24e5f0**;
- запросы уходят в `onRequest` **0x184220**;
- directive и star-command — в `onStarMessage` **0x183cb8**.

В `onStarMessage` по token-type (`message+0x18`) выбирается валидатор из
`server+0xe0` или `server+0xe8`. Назначение подтверждают setter-методы
`setPinCodeTokenValidator` **0x180ac0** и `setBackendJwtValidator` **0x180bf0**
и RTTI/vtables. Результат проверки передаётся в `processMessage` **0x170b44**,
а не игнорируется.

## 2. Что проверяют валидаторы

- PIN validator: RTTI `sbercast::CastServiceFollowerPinTokenValidatorImpl`,
  vtable **0x7114cc**, метод **0x17f6c4**. Пустое поле → result4; иначе
  виртуальная проверка token storage (slot 0x18) → result0/result3.
- Backend validator: RTTI `staros::CastServiceFollowerBackendJwtValidatorImpl`,
  vtable **0x711180**, метод **0x177b4c** → `BackendJwtValidator::validateJwtToken`
  **0x372568**. Пустое поле → result4.

`processMessage` отображает result1/2/3 в `Parse token Error`,
`bad device ID`, `Directive not allowed`. Result4 — это **пустое поле
токена**; на уровне обработки сообщения он **не является отказом**:
`onStarMessage` направляет result0 и result4 в один и тот же helper
обработки (**0x184158 → 0x182cd8**), а result1/2/3 — в ответчик ошибки.

Но это **не анонимный доступ**. Карта `server+0x110` — реестр активных
WS-сессий: запись создаётся уже в `wsOnOpenCallback` (**0x18381c** →
**0x18358c**) без проверки токена, а новая сессия получает auth type
`+0xd0 = 3` (enum-строки `BACKEND_JWT`, `FIRST_SETUP`, `UNKNOWN`).
`onStarMessage` выставляет `+0xd0` в 1 (PIN) или 0 (backend) **до** проверки
результата (0x1840a8), поэтому даже пустой токен штампует тип.

Принимает ли такую сессию gate **0x182d84**? Auth type он **не читает**.
Вместо этого слот 0xc сессии (**0x185128**) возвращает строку по смещению
`+0xac`: непустая строка — отказ, пустая — разрешение только при
ненулевом `server+0x94`. Смысл строки и флага пока не установлен, поэтому
это **не доказанный обход** и не доказанный барьер.

## 3. Вложенный StarCommand и исправление про 0x37b01c

Для внешнего payload-case 8 processor читает bytes и вызывает protobuf parse
**0x4b0c48**. Тип объекта установлен по constructor **0x560d84**, vtable
**0x7235f8**, RTTI `ru::sber::staros::protobuf::StarCommand`; discriminator
находится по смещению 0x10.

**0x37b01c — не таблица «case → handler», а сгенерированный protobuf-аксессор
oneof:**

- читает `[command+0x10]` и `[command+8]`;
- switch по case (1..0xb, затем 0x64..0x8e через `sub #0x64; cmp #0x2a`)
  возвращает указатель на подсообщение, при необходимости создавая его;
- для неизвестного case уходит в **0x37b13c** и бросает исключение
  `unexpected star command type` (строка **0x63db72**);
- единственный вызов — `bl 0x37b01c` в **0x171840** внутри `processMessage`;
  результат используется как подсообщение, а не как адрес обработчика.

Поэтому ветки в 0x37b01c описывают варианты oneof, а не разрешённые команды.

## 4. Реальная точка диспетчеризации

В `processMessage` по **0x1718fc**:

```text
0x1718fc  ldr r0, [r5, #0x2c]    ; this = CastMessageProcessorImpl
0x171900  ldr r1, [sp, #0x10]    ; разобранный StarCommand
0x171904  ldr r3, [r0]           ; vtable получателя
0x171908  ldr r3, [r3, #0x28]    ; slot 0x28
0x17190c  blx r3
```

Получатель установлен не по догадке:

- конструктор `CastMessageProcessorImpl` **0x17027c** сохраняет принятый
  `AgentService*` в `this+0x2c` (запись **0x170370**);
- объект создаётся в **0x16a238**, аргумент берётся из поля follower-а
  `CastFollowerServiceImpl+0x28d0`;
- поле заполняется в `CastFollowerServiceImpl::init` **0x16d3c4** через
  поиск в `ServiceRegistry` **0x140728** по ключу **`agent`**;
- RTTI сервиса — `staros::AgentService` (vtable **0x719520**), реализация —
  `staros::AgentServiceImpl` (vtable **0x71956c**).

Проверка `[[context+0x24] == 4]` и ветка
`isStarOSStarCommandWakeupRequired` **0x170824** сходятся к тому же вызову:
это решение о wakeup, а не allowlist.

## 5. Внутри AgentService

`AgentServiceImpl` хранит `std::map<std::string, std::shared_ptr<Agent>>`
по смещению **+0x64** (узел 0x30 байт). `processStarCommand` **0x350318**
(slot 0x28):

1. **0x34f540** копирует карту агентов под мьютексом;
2. **0x350248** строит задачу 0x2c байт: `{копия StarCommand, std::map}`;
3. задача публикуется в executor `this+0x98` через **0xa3218**; тело —
   лямбда **0x350274**.

Лямбда вызывает invoker **0x34e908**, который для каждого агента:

```text
0x34e980  ldr r3, [r3, #0x14]    ; Agent::supportedCommands()
0x34e984  blx r3                 ; std::set<int> по значению
          ... бинарный поиск case ...
0x34e9c8  ldr r3, [r3, #0x18]    ; Agent::processStarCommand()
0x34e9cc  blx r3                 ; r1 = &command
```

То есть агент получает команду **только если её case объявлен в его
`supportedCommands()`**. Это и есть фактический allowlist исполнения.

Интерфейс `staros::Agent` (typeinfo **0x719f38**, база
`staros::StateProvider` 0x71a14c) имеет слоты: 0x0c `name()`,
0x14 `supportedCommands()`, 0x18 `processStarCommand(const StarCommand&)`.

## 6. Семь реализаций Agent

Все найдены по secondary-vtable: `offset-to-top == -agent_offset`,
typeinfo указывает на производный класс.

| Класс | Agent @ | `supportedCommands()` | `processStarCommand()` |
|---|---|---|---|
| `BrainServiceImpl` | +0x6c | {4, 10, 101, 102, 115, 116, 117, 118, 141} | 0x150f14 |
| `StarOSBluetoothImpl` | +0x50 | {119, 120} | 0x235bd8 |
| `ReportServiceImpl` | +0x74 | {6} | 0x2ab3bc |
| `LedServiceImpl` | +0x88 | {3, 1, 19, 9, 16, 8, 20, 27, 22, 34} | 0x2cb284 |
| `EnvironmentServiceImpl` | +0x94 | {114} | 0x317c84 |
| `VolumeServiceImpl` | +0x00 | {108, 109, 110, 129} | 0x34e254 |
| `MutableConfigService` | +0x42c | {100} | 0x367ad0 |

Наборы получены из кода: у Brain, Led и Volume — массивы в `.rodata`
(0x5e9a28 ×9, 0x628800 ×10, 0x638694 ×4), у остальных значение кладётся
непосредственным `mov` (BT: 0x77/0x78; Report: 6; Env: 0x72; MCS: 0x64).

Содержательно:

- Brain case 115 — setup-шаг (`SUGGEST_ESA_AUTH`), case 141 — parental control;
- Volume 108/109/110/129 — громкость;
- Led — состояния индикатора; BT — Bluetooth; Env — окружение; Report — отчёт;
- MCS case 100 — group mapping/refresh.

Ни один из них не запускает процесс и не вызывает `system`/`popen`/`exec*`.

## 7. Что это значит для достижимости

1. **ADB недостижим по этому пути.** `AdbServiceImpl::onStarMessage` **0x128acc**
   принимает `StarMessage` с discriminator по смещению **0x18** и case **115**;
   ни один агент такой команды не объявляет. Совпадение числа 115 у
   StarCommand и StarMessage — разные команды в разных типах.
2. **Произвольной записи конфигурации нет.** Единственный конфигурационный
   агент — `MutableConfigService` — объявляет только case 100, который
   разбирает поля групп, а не пишет присланный JSON в `CONFIG_OVERRIDE`.
3. **Shell/exec не появляется.** Максимум — логи, backend-вызовы и обновление
   состояния сервисов.
4. **Список замкнут статически:** других наследников `staros::Agent` в этом
   ELF нет. Runtime-набор зарегистрированных агентов зависит от порядка
   инициализации, но ограничен этими семью классами.

## 8. ADB — отдельный envelope и свой KDF

`AdbServiceImpl::onStarMessage` **0x128acc** читает discriminator
`StarMessage` по **0x18** и принимает case **115/0x73**. Затем пароль
передаётся в `passwordIsCorrect` **0x128848**; только при успехе
выставляется разрешающий флаг и вызывается `enableAdb` **0x127d54**.

Проверка использует секцию `adb`, поля `enableAdbSalt`/`enableAdbHash` и
helper **0x49396c**:

- `EVP_sha256` (PLT **0x280ec**);
- `PKCS5_PBKDF2_HMAC` (PLT **0x25f5c**);
- 1000 итераций, выход 32 байта.

Это **не** `configHash` и **не** RS256 Rabbit Hole. Значения salt/hash не
извлекались и не публикуются; перебор не выполнялся.

## 9. Публичная схема: читать, но не считать доказательством

Использован публичный репозиторий
[TohaRG2/sboom_ha](https://github.com/TohaRG2/sboom_ha), commit
**97fe1e881c16951af5920c8e1aec1d460df68753**, tree
**3df84c6c1cb01efa3dc0228b0aee3e0f9a2f6530**. Прочитаны четыре research-файла;
ни один upstream probe/fuzzer/import/build не исполнялся.

`staros.proto` содержит много `fieldN`/TBD и не даёт полной именованной схемы
`StarCommand`; это рабочая неполная реконструкция, а не извлечённый
`FileDescriptorProto`. Список `EnableAdb`/`CommonConfig` полезен как словарь,
но не доказывает, что соответствующие bytes достигнут нужного сервиса.

## 10. Проверки и ограничения

Собственный офлайн-скрипт проверки layout выполняет **67** stdlib-проверки:
SHA-256/ELF mapping, RTTI/vtables, BL-кодировки, ARM-инструкции, имена PLT,
agent-путь (slot 0x28, invoker, семь Agent-vtable, наборы case), а также
token-result-4, клиентский gate и регистрацию WS-сессии. Он PASS на
Windows и Linux, неправильный ELF отвергается. Это регрессия layout, а не
полная CFG-верификация и не выполнение прошивки.

Проверяемые байты и указатели не доказывают:

- что gate 0x182d84 разрешает обработку: он не читает auth type, но
  требует пустую строку `session+0xac` и ненулевой `server+0x94`, смысл
  которых ещё не установлен;
- внешние gates перед 0x1718fc для каждого типа сообщения;
- поведение type8 (`StarCommand`) по сравнению с type4-dispatch;
- явное преобразование `StarCommand → StarMessage`, если оно существует;
- совместимость с текущей прошивкой 2026 года;
- сетевую достижимость конкретного сообщения с LAN.

Root/shell/ADB не получены. Аппаратный USB-тест остаётся заблокированным до
проверки распиновки и VBUS.
