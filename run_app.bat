@echo off
cd /d %~dp0
set PYTHONPATH=%PYTHONPATH%;%~dp0src
streamlit run src/app.py
