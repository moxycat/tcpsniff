@echo off

echo Building executable...

REM Create bin directory
mkdir ..\bin

REM Compile executable
gcc.exe *.c -o ..\bin\tcpsniff.exe

REM Remove any debug symbols
strip.exe ..\bin\tcpsniff.exe

echo Finished!

exit /b
