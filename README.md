# Bridges Watcher

Скрипт следит за указанным IMAP-почтовым ящиком, разбирает входящие письма по
настраиваемым шаблонам и отправляет нормализованные уведомления в Slack. Правила
разбора описываются в `parser_config.csv`, поэтому поведение можно менять без
редактирования кода.

## Содержимое репозитория
```
C:\Folder\
    ├─ x_core.py          # основной скрипт
    ├─ parser_config.csv  # конфигурация правил парсинга писем
    ├─ .env               # секреты и настройки окружения (создаётся вручную)
    ├─ run.bat            # сценарий для запуска под Windows
    ├─ run_hidden.vbs     # необязательно, запуск bat-файла в фоне
    ├─ xcore.log          # журнал работы скрипта (создаётся автоматически)
    └─ xcore_uid.pkl      # сохранённые UID обработанных писем (создаётся автоматически)
```

## Быстрый старт
### 1. Требования
- Python 3.10+ (проверено на Windows).
- Доступ в интернет к IMAP серверу и Slack webhook.
- Права на установку зависимостей: `boto3`, `requests`, `beautifulsoup4`, `python-dotenv`.

### 2. Установка
1. Подготовьте рабочую папку, например `C:\Folder`.
2. Скопируйте сюда содержимое репозитория (файлы `x_core.py`, `parser_config.csv`, `run.bat`, `run_hidden.vbs`).
3. Установите Python, если он ещё не установлен, и узнайте путь до `python.exe` (`where python`).
4. Установите зависимости из командной строки (при необходимости используйте полный путь к интерпретатору):
   ```cmd
   pip install boto3 requests beautifulsoup4 python-dotenv
   ```
   Если `pip` отсутствует — скачайте `https://bootstrap.pypa.io/get-pip.py` и выполните `python get-pip.py`.

### 3. Настройка переменных окружения
Создайте файл `.env` в корне проекта и заполните его:
```
IMAP_HOST=imap.example.com
IMAP_USER=user@example.com
IMAP_PASS=SuperSecret
SLACK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ
UID_OBJECT_KEY=xcore_uid.pkl
CHECK_SEC=10
DEBUG_EMAIL=0
```
- `CHECK_SEC` — пауза между опросами почтового ящика (секунды).
- `DEBUG_EMAIL=1` включает подробные записи в `xcore.log` о причинах отправки/пропуска письма.

### 4. Запуск
Создайте `run.bat`, указав путь до Python:
```bat
@echo off
cd /d "C:\Folder"
for /f "delims=" %%a in (.env) do set %%a
"C:\Path\to\Python\python.exe" x_core.py
```
Запустите бат-файл двойным кликом или через консоль (`cmd.exe`). Для скрытого
старта можно воспользоваться `run_hidden.vbs`, который запускает `run.bat`
без отображения окна.

### 5. Планировщик задач Windows
1. `Win + R` → `taskschd.msc`.
2. «Create Task», задайте имя/описание.
3. В разделе «Triggers» создайте расписание (по времени/при входе в систему и т.д.).
4. В «Actions» выберите «Start a program» и укажите `C:\Folder\run.bat`.
5. При необходимости включите «Run whether user is logged on or not». Для проверки
   выполните задачу вручную или запустите батник.

## Настройка `parser_config.csv`
Каждая строка CSV описывает правило обработки одного письма. Скрипт применяет
все правила по очереди; если регулярное выражение (`pattern`) даёт совпадения,
то результат форматируется согласно `field_map` и `slack_format` и отправляется в Slack.

### Обязательные столбцы
| Поле        | Описание |
|-------------|----------|
| `name`      | Уникальный идентификатор правила (используется в логах и при агрегации событий). |
| `pattern`   | Регулярное выражение с именованными группами `?P<name>`. Применяется ко всему телу письма (после `strip_pattern`). |
| `field_map` | JSON-словарь с Python-выражениями. Ключ — имя поля, значение — выражение, исполняемое через `eval` в контексте найденных групп. |
| `slack_format` | Шаблон итогового сообщения. Подстановки выполняются через `.format(**fields)`. Символы `\n` превращаются в переводы строк в Slack. |

### Дополнительные столбцы
| Поле | Назначение |
|------|------------|
| `note` | Добавляет блок `*ACTIONS:*` в конец сообщения. |
| `exclude_fields` | Список полей, которые нужно удалить перед форматированием (через запятую). |
| `email_address` | Фильтр по адресу отправителя (`From`). Поддерживает подстроки. |
| `email_theme` | Регулярка для темы письма (`Subject`). |
| `strip_pattern` | Регулярное выражение, которое удаляется из письма до поиска `pattern` (удобно для подписей и футеров). |
| `truncate_pattern` | Если совпадение найдено внутри `rest`, всё после него отрезается. |

### Доступные переменные в `field_map`
Помимо групп из `pattern`, доступны дополнительные значения:
- `rest` — текст совпадения (после `strip_pattern`/`truncate_pattern`).
- `email_ts` — дата письма в формате `YYYY-MM-DD HH:MM:SS` (берётся из заголовка `Date`).
- `email_from`, `email_subject` — значения `From` и `Subject`.
- `status_hint` — первое найденное в теле письма значение `Active alerts` или `Resolved` (полезно, когда в блоке нет собственной группы `status`).
- `status_value` — `status` либо `status_hint`, уже очищенный от пробелов.

### Советы по написанию шаблонов
- Используйте двойные кавычки внутри JSON: `"{""key"": ""value""}"`.
- Если нужно многострочное регулярное выражение, добавьте inline-флаги (`(?isx)` и т.д.). Скрипт всё равно компилирует шаблон с `re.S`.
- Для сложных сообщений удобно сначала убрать «хвосты» футеров через `strip_pattern`, а затем применять основной `pattern`.
- При нескольких совпадениях с одинаковыми `name`, уровнем (`LEVEL`) и статусом (`STATUS`) тексты объединяются и отправляются одним Slack-сообщением.

### Примеры правил
**XCORE лог:**
```
xcore_log,"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+\[(?P<lvl>[A-Z]+)\s*\]\s+(?P<comp>[^:]+):\s*(?P<rest>.*?)(?=(\d{4}-\d{2}-\d{2} \d{2}|\Z))","{""stat"": ""rest.split(':')[1].strip() if ':' in rest else ''""}","*CATEGORY:* XCORE\n*TIMESTAMP:* {ts}\n*LEVEL:* {lvl}\n*STATUS:* {stat}\n*EVENT_TEXT:*\n```\n{rest}\n```",,,,,"this\s*alert\s*has\s*been\s*automatically\s*generated[\s\S]*","\d{4}-\d{2}-\d{2} \d{2}"
```
Это правило ищет временную метку, уровень (`[INFO]`, `[WARN]`, …) и текст события. В Slack выводится категория `XCORE`, а
раздел `STATUS` вычисляется через `field_map`.

**TPT Hub (Grafana) оповещения:**
```
tpt_hub_alert,"(?isx)(?:^|\n)(?:(?P<status>Active\ alerts|Resolved)\s*:?)?\s*message:\s*(?P<msg>.*?)(?=\nalertname:)\nalertname:\s*(?P<alertname>[^\n]*)\nconsumer:\s*(?P<consumer>[^\n]*)\ngrafana_folder:\s*(?P<grafana_folder>[^\n]*)\ninstance:\s*(?P<instance>[^\n]*)(?:.*?)(?=\npriority:)\npriority:\s*(?P<priority>\w+)(?:.*?)(?=\n(?:message:|Active\ alerts|Resolved)|\Z)","{""lvl"": ""(priority or '').strip().upper() + ' PRIORITY' if priority else ''"",""stat"": ""'ACTIVE ALERT' if ((status or status_hint or '').strip().lower().startswith('active')) else 'RESOLVED' if (status or status_hint) else 'STATUS UNKNOWN'"",""rest"": ""'\\n'.join([p for p in [msg.strip(), ('consumer: ' + consumer.strip()) if consumer.strip() else '', ('grafana_folder: ' + grafana_folder.strip()) if grafana_folder.strip() else '', ('instance: ' + instance.strip()) if instance.strip() else ''] if p])"",""ts"": ""email_ts""}","*CATEGORY:* TPT-HUB\n*TIMESTAMP:* {ts}\n*LEVEL:* {lvl}\n*STATUS:* {stat}\n*EVENT_TEXT:*\n```\n{rest}\n```",,,"(?i)^\[Alert\]\s*TPT Grafana","(?is)(?:Sent by Grafana|To unsubscribe)[\\s\\S]*$",""
```
- `email_theme` ограничивает правило письмами с темой вида `[Alert] TPT Grafana: …`.
- `strip_pattern` срезает служебный хвост Grafana (`Sent by Grafana…`, `To unsubscribe…`).
- Регулярное выражение разбивает сообщение на блоки по `message / consumer / grafana_folder / instance / priority`.
- `ts` заполняется автоматически из заголовка письма `Date`.
- `LEVEL` формируется из `priority` (например, `high → HIGH PRIORITY`).
- `STATUS` зависит от строки «Active alerts» или «Resolved» и корректно обрабатывает повторяющиеся блоки в одном письме.
- `EVENT_TEXT` содержит тело алерта, а также поля `consumer`, `grafana_folder` и `instance` на отдельных строках.

Таким образом в Slack приходит сообщение вида:
```
CATEGORY: TPT-HUB
TIMESTAMP: 2025-09-24 10:47:54
LEVEL: HIGH PRIORITY
STATUS: ACTIVE ALERT
EVENT_TEXT:
No quotes from …
consumer: Beta_MT5
grafana_folder: [Live] TPT Hub
instance: 18.135.192.67:9100
```

## Отладка
- Все ошибки записываются в `xcore.log`. Там же фиксируются причины пропуска писем (если `DEBUG_EMAIL=1`).
- Файл `xcore_uid.pkl` хранит UID обработанных писем. Его можно удалить, если нужно принудительно переотправить старые уведомления (будьте осторожны: Slack получит дубликаты).
- При изменении `parser_config.csv` и `.env` скрипт автоматически перезагружает настройки без перезапуска.

Если добавляете новое правило — сначала протестируйте регулярное выражение в любом онлайн-тестере, затем внесите строку в `parser_config.csv` и проверьте журнал (`xcore.log`), чтобы убедиться в отсутствии предупреждений «bad cfg row skipped».
