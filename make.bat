REM If this script doesn't work try compiling with Visual Studio.
@echo off
mkdir bin
gcc.exe -O3 -lws2_32.lib src/*.c -o bin/tcpsniff.exe
strip.exe bin/tcpsniff.exe
