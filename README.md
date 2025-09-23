# 0. Создать попку репозитория. Допустим C:\Folder
Будущая структура:
C:\Folder\
    ├─ code.py
    ├─ .env
    ├─ run.bat
    └─ (будут создаваться) log.log, uid.pkl и др.
	
# 1. Подготавливаем код проекта и помещаем в файл code.py

# 2. Установить Python

# 3. Найти папку с исполняемым файлом Python.exe (cmd -> where python)

# 4. Установить зависимости в CMD от имени администратора или в той же директории Python, где его исполняемый файл: pip install boto3 requests beautifulsoup4
- добавить Python в PATH 
или использовать такую команду:
C:\Users\d.pascenco\AppData\Local\Programs\Python\Python313\python.exe -m pip install boto3 requests beautifulsoup4

# 5. Если pip не установлен, Скачать get-pip.py отсюда: https://bootstrap.pypa.io/get-pip.py

# 6. Содать файл с названием .env и поместить туда креды. Пример:
IMAP_HOST=imap.example.com  (настройки IMAP)
IMAP_USER=user@example.com  (настройки IMAP)
IMAP_PASS=password123 (настройки IMAP)
SLACK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ
UID_OBJECT_KEY=uid.pkl (это мой файл уникальных идентификаторов объектов в списках)
CHECK_SEC=10 (частота итераций)

# 7. Для запуска в run.bat указываем:
@echo off
cd /d "C:\Folder"
for /f "delims=" %%a in (.env) do set %%a
"C:\Users\d.pascenco\AppData\Local\Programs\Python\Python313\python.exe" code.py

# 8. Запуск: C:\Folder\run.bat

# 9. Создаем расписание в windows scheduler: Win+R -> taskschd.msc -> Actions - > Create task -- заполняем конфигруацию таска.

# 10. запускаем вручную через cmd C:\Folder\run.bat
