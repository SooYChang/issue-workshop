@echo off
cd /d "%~dp0"
python -c "import pypdf" 2>nul || python -m pip install -q pypdf
python workshop.py
echo.
echo The workshop stopped.
pause
