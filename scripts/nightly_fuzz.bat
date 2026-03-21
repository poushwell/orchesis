@echo off
REM ═══════════════════════════════════════
REM  Orchesis Nightly Fuzzer
REM  Runs automatically via Task Scheduler
REM ═══════════════════════════════════════

set PROJECT=C:\Users\lenovo\Desktop\Orchesis_final\orchesis
set LOGDIR=%PROJECT%\.orchesis\nightly-logs
set POLICY=%PROJECT%\examples\production_policy.yaml
set TIMESTAMP=%date:~-4%%date:~3,2%%date:~0,2%_%time:~0,2%%time:~3,2%
set TIMESTAMP=%TIMESTAMP: =0%
set LOGFILE=%LOGDIR%\nightly_%TIMESTAMP%.log

cd /d %PROJECT%

if not exist %LOGDIR% mkdir %LOGDIR%

echo ═══════════════════════════════════════ >> %LOGFILE%
echo  Orchesis Nightly Run: %date% %time% >> %LOGFILE%
echo ═══════════════════════════════════════ >> %LOGFILE%

echo. >> %LOGFILE%
echo [1/6] Fuzzer (10000 requests)... >> %LOGFILE%
call orchesis fuzz --policy %POLICY% --count 10000 --save-bypasses >> %LOGFILE% 2>&1

echo. >> %LOGFILE%
echo [2/6] Mutation engine (1000 mutations)... >> %LOGFILE%
call orchesis mutate --policy %POLICY% --count 1000 >> %LOGFILE% 2>&1

echo. >> %LOGFILE%
echo [3/6] Invariant checks... >> %LOGFILE%
call orchesis invariants --policy %POLICY% >> %LOGFILE% 2>&1

echo. >> %LOGFILE%
echo [4/6] Adversarial scenarios... >> %LOGFILE%
call orchesis scenarios --policy %POLICY% >> %LOGFILE% 2>&1

echo. >> %LOGFILE%
echo [5/6] Full test suite... >> %LOGFILE%
call pytest --tb=short -q >> %LOGFILE% 2>&1

echo. >> %LOGFILE%
echo [6/6] Reliability report... >> %LOGFILE%
call orchesis reliability-report >> %LOGFILE% 2>&1

echo. >> %LOGFILE%
echo ═══════════════════════════════════════ >> %LOGFILE%
echo  Completed: %date% %time% >> %LOGFILE%
echo ═══════════════════════════════════════ >> %LOGFILE%
