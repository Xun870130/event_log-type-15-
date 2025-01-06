@echo off
event_log_analyzer.exe D:\VScode\project\event_log\example\1224smbios.log
:WAIT
echo tap Q to esc
choice /c Q /n >nul
goto :EOF