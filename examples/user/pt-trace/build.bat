@echo off
rem ==========================================================================
rem  Build pt-trace.exe (run from a "x64 Native Tools Command Prompt for VS").
rem
rem  Point these at your libipt (Intel Processor Trace decoder library) build:
rem      set LIBIPT_INC=C:\path\to\libipt\include   (folder with intel-pt.h)
rem      set LIBIPT_LIB=C:\path\to\libipt\lib       (folder with libipt.lib)
rem  ...or edit the defaults below.
rem ==========================================================================
setlocal
if "%LIBIPT_INC%"=="" set LIBIPT_INC=C:\libipt\include
if "%LIBIPT_LIB%"=="" set LIBIPT_LIB=C:\libipt\lib

cl /nologo /W3 /O2 pt-trace.c ^
   /I "%LIBIPT_INC%" ^
   /Fe:pt-trace.exe ^
   /link /LIBPATH:"%LIBIPT_LIB%" libipt.lib

endlocal
