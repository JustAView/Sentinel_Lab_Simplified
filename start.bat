@echo off
chcp 65001 >nul
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  start "" http://127.0.0.1:8765
  py -3 server.py
) else (
  where python >nul 2>nul
  if %errorlevel%==0 (
    start "" http://127.0.0.1:8765
    python server.py
  ) else (
    echo Python 3 не найден.
    echo Установите Python 3 с сайта https://www.python.org/downloads/
    echo При установке включите Add Python to PATH.
    pause
  )
)
pause

