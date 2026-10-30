# SberBoom Mini: UART, boot chain и Rabbit Hole

Исследовательская выкладка по **первому SberBoom Mini, семейству SBDV-00095**. Дата наблюдений UART: **29 октября 2026**.

**Root/shell не получены. Это не инструкция разблокировки или прошивки.** Цель — предоставить воспроизводимые данные, чтобы другие исследователи могли проверить выводы и предложить следующий обоснованный шаг.

> English summary: UART boot logs and offline firmware analysis for the first-generation SberBoom Mini. No shell or root obtained. The supplied third-party dump contains StarOS 1.82.7 from November 2022; the live device reports U-Boot built in April 2026. Bootloader UART Rabbit Hole v2 and the userspace StarOS JWT service must not be assumed to share a protocol. The SberCast star-command route is traced to a closed set of seven Agent implementations; ADB and arbitrary config writes are not reachable from it. No firmware images, signing keys or device secrets are distributed here.

## Главное

| Вопрос | Что подтверждено / что нет |
|---|---|
| UART на исследованной IO-плате | TP1 GND, TP2 TX; читаемый лог на 115200 8N1 |
| Уровень TX | Пользователь измерил около 3,3 В мультиметром; форма сигнала осциллографом не проверялась |
| Загрузка | Колонка загружается штатно; UART замолкает после Rabbit Hole |
| SoC в логе | A1 Rev A, Board ID 6, 128 MiB DRAM, SPI-NAND |
| Маркировка на присланном фото основной платы | Amlogic A113L; соответствие имён A1/A113L не исследовалось отдельно |
| Живой загрузчик | U-Boot 2019.01, build 20.04.2026, buildroot-23727 |
| Rabbit Hole | `RABBIT HOLE v2` → `timed out` → `LEVELS: none` |
| Заводской сброс | Выполнен пользователем; версия U-Boot и отсутствие shell не изменились |
| Анализируемый дамп | Чужой 128-МиБ BIN, StarOS 1.82.7, Buildroot MP1-RC23, ноябрь 2022 |
| Целостность system в дампе | Все 5423 блока dm-verity, 43 нижних блока дерева и root hash совпали |
| Shell/ADB в старом system | Код присутствует, запуск ограничен разрешениями из kernel cmdline |
| StarOS JWT | Найден и статически прослежен код проверки RS256, device/product, session UUID и `adb_root` |
| SberCast star-command | Прослежен до закрытого набора из семи Agent-классов; ADB и произвольная запись конфигурации этим путём недостижимы |
| UART-алгоритм | Не восстановлен: открытый BL33 не получен; реализация `rabbith.h` не найдена |
| USB-проверка | D+/D−/GND, без VBUS: новое USB-устройство не появилось. Причина не установлена |

## Материалы

- [Хронология и границы достоверности](docs/TIMELINE.md)
- [Платы, фотографии и электрическая безопасность](docs/HARDWARE.md)
- [Анализ дампа и целостности](docs/ANALYSIS.md)
- [JWT Rabbit Hole в StarOS](docs/RABBIT-HOLE.md)
- [SberCast → StarCommand: маршрут и границы достижимости](docs/SBERCAST-ROUTING.md)
- [UART Rabbit Hole / защищённый загрузочный контейнер](docs/UART-BOOTLOADER.md)
- [Вопросы к сообществу](docs/OPEN-QUESTIONS.md)
- [Источники и происхождение материалов](docs/SOURCES.md)
- [Что удалено перед публикацией](docs/PRIVACY.md)
- [Обезличенный UART-лог](logs/uart-2026-10-29-redacted.txt)
- [Метаданные проверок](evidence/)
- [Скрипты офлайн-анализа](tools/README.md)

## Как помочь

Особенно полезны соответствующие исходники или расшифрованный **BL33 именно Sber Mini**, описание `AMLIFPG`/A1 secure boot, корректировки статического разбора JWT и подтверждённая схема USB VBUS detection для этой ревизии.

В issue указывайте модель, PCB/revision, версию прошивки, источник утверждения и различайте собственный результат от аналогии. Не публикуйте токены, MAC/серийники, закрытые ключи или чужие дампы с данными владельца.

## Ограничения

Исследование велось с помощью AI-инструментов. Автоматические аннотации и реконструкция потока управления могут содержать ошибки; важные выводы снабжены адресами/источниками для независимой проверки. Проверка хешей не равна проверке совместимости прошивки. Совпадение названия Rabbit Hole у разных устройств не означает одинаковый алгоритм.

**Не прошивайте исследуемый дамп и не подавайте питание на UART TX.** Не переносите BootROM-инструкции A113X/AXG или Yandex на A1 без проверки.

## Права на материалы

Исходный дамп, бинарники производителя, полные извлечённые конфиги и сторонние библиотеки не включены. Ссылки на их источники приведены отдельно. Лицензии сторонних материалов не меняются. До подтверждения авторства фотографий и выбора лицензии владельцем универсальная лицензия на этот пакет не заявляется.
