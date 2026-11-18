@echo off
rem Compila o "DGX Virus Remover.exe" com o compilador do .NET Framework 4.8 (nao precisa de Visual Studio).
rem Uso: build.bat          (compila e pausa se der erro)
rem      build.bat ci       (usado pelo GitHub Actions: sem pausa)
cd /d "%~dp0"
set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
set "ICON="
if exist "assets\DGX Virus Remover.ico" set ICON="/win32icon:assets\DGX Virus Remover.ico"
"%CSC%" /nologo /codepage:65001 /nowarn:649 /target:winexe /platform:anycpu /optimize+ /win32manifest:app.manifest %ICON% "/out:DGX Virus Remover.exe" /r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll /r:System.Management.dll src\*.cs
if errorlevel 1 (
  echo.
  echo FALHA NA COMPILACAO
  if /i not "%~1"=="ci" pause
  exit /b 1
)
echo Compilado: %~dp0DGX Virus Remover.exe
