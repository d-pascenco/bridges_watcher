@echo off
cd /d "C:\bridges_watcher"
for /f "delims=" %%a in (.env) do set %%a
"C:\Users\d.pascenco\AppData\Local\Programs\Python\Python313\python.exe" x_core.py
