@echo off
REM build.bat — Compila scanner.exe com MSVC ou MinGW-w64
REM Execute este arquivo a partir da pasta scanner\

setlocal

REM --- Tenta MSVC primeiro ---
where cl.exe >nul 2>&1
if %errorlevel% == 0 (
    echo [build] Usando MSVC...
    cl.exe scanner.cpp /O2 /W3 /std:c++17 /Fe:..\scanner.exe /link psapi.lib
    if %errorlevel% == 0 (
        echo [build] scanner.exe gerado em ..\scanner.exe
    ) else (
        echo [build] Falha na compilacao com MSVC.
    )
    goto :end
)

REM --- Tenta MinGW-w64 ---
where x86_64-w64-mingw32-g++.exe >nul 2>&1
if %errorlevel% == 0 (
    echo [build] Usando MinGW-w64...
    x86_64-w64-mingw32-g++.exe -O3 -std=c++17 -Wall -o ..\scanner.exe scanner.cpp -lpsapi -static
    if %errorlevel% == 0 (
        echo [build] scanner.exe gerado em ..\scanner.exe
    ) else (
        echo [build] Falha na compilacao com MinGW-w64.
    )
    goto :end
)

REM --- Tenta g++ generico (MinGW no PATH) ---
where g++.exe >nul 2>&1
if %errorlevel% == 0 (
    echo [build] Usando g++...
    g++.exe -O3 -std=c++17 -Wall -o ..\scanner.exe scanner.cpp -lpsapi -static
    if %errorlevel% == 0 (
        echo [build] scanner.exe gerado em ..\scanner.exe
    ) else (
        echo [build] Falha na compilacao com g++.
    )
    goto :end
)

echo [build] Nenhum compilador encontrado (cl.exe, x86_64-w64-mingw32-g++, g++).
echo [build] Instale Visual Studio Build Tools ou MinGW-w64.
exit /b 1

:end
endlocal
