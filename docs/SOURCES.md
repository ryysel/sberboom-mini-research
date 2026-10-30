# Источники и происхождение

## Собственные наблюдения этой сессии

- UART-лог 29.10.2026, фото IO/адаптера владельца, сообщения владельца о замере TX и factory reset.
- Статическая обработка предоставленного BIN. Скрипты и метаданные в репозитории.
- Проверка Windows PnP до/после USB-подключения: нового устройства не появилось. Идентификаторы прочих устройств не публикуются.

## Переданные исторические сведения

Памятка `SBERBOOM-MINI-UART.md` от 28.10.2026 описывает сетевые наблюдения 24.10.2026. Она не публикуется дословно: содержит приватные пути. Безопасная сводка — в TIMELINE.md. Исходные приватные лабораторные записи в этой сессии не открывались.

## Документация производителя

- [Официальный factory reset Mini](https://sberdevices.ru/help/sberboom-mini/troubleshooting/reset/). Страница проверена 29.10; указывает кнопку с волной и фиолетовый индикатор, а не кнопку микрофона из цитаты про большой SberBoom.
- [Справка первого Mini и семейства](https://sberdevices.ru/help/sberboom-mini/).

## Первый SberBoom Mini

- [Разборка первого Mini, YouTube](https://www.youtube.com/watch?v=vtKwkDPhUOU) — ссылка из исторической памятки; плата около 27:13. В текущей сессии видео не пересматривалось.
- [Совпадающий старый UART-лог, 4PDA №133135317](https://4pda.to/forum/index.php?showtopic=1068289&view=findpost&p=133135317) — Board ID 6, A1, 128 MiB, Rabbit Hole v2, U-Boot от июля 2024. Это не root.
- [Пост со ссылкой на дамп, 4PDA №139582017](https://4pda.to/forum/index.php?showtopic=1068289&view=findpost&p=139582017).
- [Карточка дампа remont-aud](https://remont-aud.net/dump/prochie/prochee/sber_sberboom_mini_shassi_main_board_t651000018930_hwv_3_0_0_mp/363-1-0-153751) — заявлены T651000018930 HW3.0.0 MP, F50L1G41LB, A113L; 39.48 MB, публикация 23.04.2025. На странице есть несколько жалоб на незапуск после записи. Файл получен от пользователя, не через обход ограничений сайта. Его содержимое и дата сборки описаны отдельно.
- [Ремонтная тема SBDV-00095](https://monitor.espec.ws/section41/printview336409.html) — историческая ссылка, новой проверенной распиновки из неё в этой сессии не получено.
- [Локальный StarOS-протокол / Home Assistant](https://github.com/TohaRG2/sboom_ha) — историческая ссылка, не эксплойт root. 30.10 прочитаны четыре research-файла на pinned commit `97fe1e881c16951af5920c8e1aec1d460df68753`, tree `3df84c6c1cb01efa3dc0228b0aee3e0f9a2f6530`; их содержимое не исполнялось. Схема остаётся неполной реконструкцией.
- [sberboom-remote](https://github.com/matvey68568/sberboom-remote) — публичный исследовательский клиент; исходники просматривались офлайн, код не запускался. Не является доказательством доступного привилегированного пути.

## Другие модели — не переносить автоматически

- [Elektroda, SBDV-00250 / Mini 2](https://www.elektroda.com/rtvforum/topic4182142.html) — полную страницу инструментом получить не удалось (тайм-аут). Сведения из поисковой выдачи/старой памятки, не первичная проверенная схема нашей платы.
- [SberBox Time, обсуждение Rabbit Hole/JWT](https://4pda.to/forum/index.php?showtopic=1041157&view=findpost&p=145457557) — Android/S905D3, не Linux Mini. JWT-код в нашем старом Mini впоследствии найден независимо в бинарнике.

## Загрузчики / Amlogic

- [Патчи SaluteDevices ADNL/Optimus, 29.07.2025](https://lore.landau.one/rulkc/20250729182910.16127-6-avkrasnov@salutedevices.com/T/) — найдена include `rabbith.h`, без реализации. ADNL отмечен для A1; это не гарантия доступа на production secure boot.
- [Архив U-Boot mailing list, аналогичный патч](https://lists.denx.de/pipermail/u-boot/2025-March/584128.html) — поисковая ссылка, прямое чтение давало транспортную ошибку. Использовалось доступное зеркало выше.
- [gxlimg](https://github.com/repk/gxlimg) — просмотрены README, bl2.c, amlcblk.c. Не универсальный дешифратор; ожидает другие открытые заголовки.
- [7Ji: FIP hacking](https://7ji.github.io/booting/2024/07/17/fip-hack-amlogic.html) — общие форматы, не доказательство работы на нашей защищённой A1.
- [A113X BootROM, haxx.in](https://haxx.in/posts/dumping-the-amlogic-a113x-bootrom/) — другой SoC; применимость к A1 не установлена.
- [Повтор исследования A113X, BoredPentester](https://boredpentester.com/retreading-the-amlogic-a113x-trustzone-exploit-process/) — другой SoC.
- [Yandex Rabbit Hole, HackMag](https://hackmag.com/coding/yandex-rabbit-hole) — RSA challenge-response и LZ4C **после расшифрования** на перечисленных Yandex/AXG/G12 устройствах. Не инструкция для Sber A1.

## Зависимости инструментов

- [PySquashfsImage](https://github.com/matteomattei/PySquashfsImage), [PyPI](https://pypi.org/project/PySquashfsImage/)
- [Capstone](https://www.capstone-engine.org/), [pyelftools](https://github.com/eliben/pyelftools), [python-zstandard](https://github.com/indygreg/python-zstandard)

Открытые материалы не подтверждают обход UART Rabbit Hole v2 на исследуемой сборке. Отрицательный результат поиска — не доказательство отсутствия реализации где-либо ещё.
