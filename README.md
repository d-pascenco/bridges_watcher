# Bridges Watcher

Этот проект автоматически проверяет почтовый ящик, парсит входящие письма по заданным шаблонам и отправляет отформатированные уведомления в Slack.

## Что входит в репозиторий

```text
C:\Folder\
    ├─ x_core.py          # основной файл скрипта
    ├─ .env               # переменные окружения для IMAP и Slack
    ├─ parser_config.csv  # конфигурация правил парсинга писем
    ├─ run.bat            # сценарий для ручного/планового запуска
    ├─ run_hidden.vbs     # опциональный запуск без консоли
    ├─ xcore.log          # журнал работы (создаётся автоматически)
    └─ xcore_uid.pkl      # сохранённые UID обработанных писем (создаётся автоматически)
```

## Установка и запуск

### 1. Подготовка окружения
1. Создайте рабочую папку, например `C:\Folder`, и скопируйте в неё содержимое репозитория.
2. Убедитесь, что установлен Python 3.10+.
3. Найдите путь до `python.exe` (команда `where python` в CMD).
4. Установите зависимости. Если Python не в `PATH`, используйте полный путь до интерпретатора.
   ```cmd
   pip install boto3 requests beautifulsoup4 python-dotenv
   ```
   Пример с явным путём:
   ```cmd
   C:\Users\User\AppData\Local\Programs\Python\Python313\python.exe -m pip install boto3 requests beautifulsoup4 python-dotenv
   ```
5. При отсутствии `pip` скачайте `get-pip.py` с https://bootstrap.pypa.io/get-pip.py и выполните его через `python.exe`.

### 2. Настройка переменных окружения
Создайте файл `.env` в корне репозитория и укажите параметры подключения и работы:
```
IMAP_HOST=imap.example.com
IMAP_USER=user@example.com
IMAP_PASS=password123
SLACK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ
UID_OBJECT_KEY=uid.pkl
CHECK_SEC=10
```

### 3. Скрипт запуска (run.bat)
Сохраните в `run.bat` следующий сценарий:
```bat
@echo off
cd /d "C:\Folder"
for /f "delims=" %%a in (.env) do set %%a
"C:\Users\User\AppData\Local\Programs\Python\Python313\python.exe" x_core.py
```

### 4. Ручной запуск
Запустите `C:\Folder\run.bat` двойным кликом или из командной строки. При необходимости можно использовать `run_hidden.vbs`, чтобы скрыть консольное окно.

### 5. Планировщик задач Windows
1. Откройте планировщик (`Win + R` → `taskschd.msc`).
2. Создайте новую задачу (`Create Task`) и настройте триггеры/действия.
3. В действиях укажите запуск `C:\Folder\run.bat`.
4. Для проверки запустите задачу вручную или выполните `C:\Folder\run.bat` в CMD.

## Настройка `parser_config.csv`
Файл `parser_config.csv` определяет шаблоны для разбора писем и формирование сообщений в Slack. Каждая строка описывает один шаблон.

### Обязательные поля
1. **name** — уникальное имя шаблона (для логов и отладки). Пример: `xcore_log`.
2. **pattern** — регулярное выражение с именованными группами (`?P<имя>...`), применяется ко всему телу письма.
   Пример:
   ```regex
   (?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+\[(?P<lvl>[A-Z]+)\]\s+(?P<rest>.*?)
   ```
3. **field_map** — JSON-словарь с Python-выражениями (`eval`), позволяющий вычислять дополнительные поля из уже найденных данных.
   Пример:
   ```json
   {"stat": "rest.split(':')[1].strip() if ':' in rest else ''"}
   ```
4. **slack_format** — шаблон итогового сообщения для Slack. Строки разделяются `\n`, подстановки выполняются по именам полей.
   Пример:
   ```text
   CATEGORY: XCORE\nTIMESTAMP: {ts}\nLEVEL: {lvl}\nSTATUS: {stat}\nEVENT_TEXT:\n{rest}
   ```

### Необязательные поля
5. **note** — произвольный комментарий, который добавляется к сообщению в Slack (скрипт автоматически добавляет префикс `*ACTIONS:*`).
6. **exclude_fields** — список полей, которые не отображаются в Slack. Перечисляются через запятую без пробелов (пример: `stat,ts`).
7. **email_address** — фильтр по адресу отправителя (`msg.get("From")`). Поддерживает подстроки. Примеры: `alerts@domain.com`, `@mycompany.com`.
8. **email_theme** — RegEx-фильтр по теме письма (`Subject`). Пример: `^XCORE Alert.*`.
9. **strip_pattern** — RegEx, который удаляется из тела письма до поиска `pattern` (очищает подписи, футеры, трек-коды). Работает как «глобальный remove».
10. **truncate_pattern** — RegEx, который ищется внутри `{rest}`; всё после совпадения обрезается. Полезно для удаления повторяющихся хвостов.

### Пример строки в CSV
```
xcore_log,"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+\[(?P<lvl>[A-Z]+)\s*\]\s+(?P<comp>[^:]+):\s*(?P<rest>.*?)(?=(\d{4}-\d{2}-\d{2} \d{2}|\Z))","{""stat"": ""rest.split(':')[1].strip() if ':' in rest else ''""}","*CATEGORY:* XCORE\n*TIMESTAMP:* {ts}\n*LEVEL:* {lvl}\n*STATUS:* {stat}\n*EVENT_TEXT:*\n```\n{rest}\n```",,,,,"this\s*alert\s*has\s*been\s*automatically\s*generated[\s\S]*","\d{4}-\d{2}-\d{2} \d{2}"
```

### Общие рекомендации
- Для сложных значений (например, `pattern` или `field_map`) используйте двойные кавычки.
- `field_map` должен содержать корректный JSON-объект.
- Поля `slack_format` и `note` поддерживают `\n` для переноса строк.
- Фильтры `email_address` и `email_theme` применяются до поиска `pattern`.
- В `slack_format` доступны данные из `groupdict` (результат `pattern`) и все вычисленные поля из `field_map`.
- В сообщении Slack разрешён стандартный mrkdwn (`*bold*`, кодовые блоки ``` и др.). Последовательность `\n` превращается в перевод строки.
- Поля из `exclude_fields` исключаются до форматирования; если исключённое поле используется в `slack_format`, будет ошибка `KeyError`.
- Если в письме несколько совпадений для одного шаблона, `{rest}` агрегируется через `\n` и отправляется одним сообщением.

### Пример сообщения в Slack
```
> CATEGORY: XCORE
> TIMESTAMP: 2024-07-10 12:34:56.789
> LEVEL: ERROR
> STATUS: critical system timeout
> EVENT_TEXT:
Job failed: critical system timeout
> ACTIONS: какая-то запись (или отсутствие).
```

## Дополнительно
- Логи (`xcore.log`) и файл уникальных идентификаторов (`xcore_uid.pkl`) создаются автоматически в корневой папке.
- Переменная `DEBUG_EMAIL=1` в `.env` включает подробный лог в `xcore.log` с информацией о каждом обработанном письме.
- Для отладки проверяйте лог и сообщения о состоянии Slack вебхука. При ответе 404 от Slack скрипт не завершится, но сообщит о неверной ссылке на вебхук.
