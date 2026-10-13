@echo off
echo ========================================================
echo   FlowSentry AI - Starting Application Server
echo   Intelligent Workflow Failure Detection & Recovery
echo ========================================================
echo.

set FLOWSENTRY_PORT=5000
set FLOWSENTRY_HOST=127.0.0.1

REM Optional: Set GEMINI_API_KEY if available
REM set GEMINI_API_KEY=your_key_here

echo Server starting on http://127.0.0.1:5000 ...
py app.py
pause
