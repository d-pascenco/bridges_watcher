@echo off
cd /d "C:\x_core_email"
for /f "delims=" %%a in (.env) do set %%a
"C:\Users\dealer\AppData\Local\Programs\Python\Python313\python.exe" x_core.py
