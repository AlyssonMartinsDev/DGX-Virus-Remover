<# : ====== parte BATCH (o PowerShell ignora este bloco) ======
@echo off
setlocal
title Removedor TJprojMain v2
set "SELF=%~f0"
set "TJ_ARGS=%*"

rem --- Exige administrador; se nao for, reabre elevado mantendo os argumentos ---
net session >nul 2>&1 || (
  echo Solicitando privilegios de administrador...
  powershell -NoProfile -Command "$a=@{FilePath=$env:SELF;Verb='RunAs'}; if($env:TJ_ARGS){$a.ArgumentList=$env:TJ_ARGS}; Start-Process @a"
  exit /b
)

rem --- Executa o restante deste arquivo como PowerShell ---
powershell -NoProfile -ExecutionPolicy Bypass -Command "& ([ScriptBlock]::Create([IO.File]::ReadAllText($env:SELF)))"
echo.
pause
exit /b
#>
# ====================== parte POWERSHELL ======================
# Uso:  Remover_TJprojMain.bat            -> remove de verdade
#       Remover_TJprojMain.bat /simular   -> so mostra o que faria (nao altera nada)

$ErrorActionPreference = 'Continue'
$DryRun = "$env:TJ_ARGS" -match '(?i)/(simular|dry)'
$ts     = Get-Date -Format 'yyyyMMdd_HHmmss'
$quar   = Join-Path $env:SystemDrive "Quarentena_TJprojMain\$ts"
$stats  = @{ Encontrados = 0; Corrigidos = 0; Falhas = 0; Reboot = 0 }

# Log ao lado do .bat; se a pasta nao for gravavel (pendrive protegido etc.), vai para %TEMP%
$log = Join-Path (Split-Path -Parent $env:SELF) "TJprojMain_$ts.log"
try { Add-Content -LiteralPath $log -Value "Removedor TJprojMain v2 - $(Get-Date)" -ErrorAction Stop }
catch { $log = Join-Path $env:TEMP "TJprojMain_$ts.log"; Add-Content -LiteralPath $log -Value "Removedor TJprojMain v2 - $(Get-Date)" }

# Caminhos do TJprojMain. Nenhum arquivo legitimo do Windows fica nessas pastas com esses nomes
# (o explorer real e C:\Windows\explorer.exe; svchost/spoolsv reais ficam em System32).
$rxFile = '^[A-Za-z]:\\Windows\\(Resources(\\Themes)?|System)\\(svchost|spoolsv|explorer|icsys\.icn)\.exe$'
$rxRef  = '(?i)\\Windows\\(Resources(\\Themes)?|System)\\(svchost|spoolsv|explorer|icsys\.icn)\.exe|icsys\.icn\.exe'
$rel    = foreach ($d in 'Windows\Resources', 'Windows\Resources\Themes', 'Windows\System') {
              foreach ($n in 'svchost.exe', 'spoolsv.exe', 'explorer.exe', 'icsys.icn.exe') { Join-Path $d $n } }

# ---------------------------------------------------------------- funcoes
function Log([string]$msg, [string]$color = 'Gray') {
    $line = '[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $msg
    Write-Host $line -ForegroundColor $color
    try { Add-Content -LiteralPath $script:log -Value $line } catch {}
}
function Section([string]$t) { Write-Host ''; Log "===== $t =====" White }

# Executa uma correcao (ou so descreve, no modo /simular)
function Act([string]$desc, [scriptblock]$action) {
    $stats.Encontrados++
    if ($DryRun) { Log "[SIMULACAO] $desc" Cyan; return }
    $ErrorActionPreference = 'Stop'
    try   { & $action; Log "OK: $desc" Green; $stats.Corrigidos++ }
    catch { Log "FALHA: $desc -> $($_.Exception.Message)" Red; $stats.Falhas++ }
}

# Move para quarentena (renomeado .vir, com SHA256 no log). Se o arquivo estiver travado,
# agenda a exclusao para o proximo boot (MoveFileEx DELAY_UNTIL_REBOOT).
function Quarantine([string]$path) {
    $stats.Encontrados++
    if ($DryRun) { Log "[SIMULACAO] quarentena: $path" Cyan; return }
    $ErrorActionPreference = 'Stop'
    try {
        (Get-Item -LiteralPath $path -Force).Attributes = [IO.FileAttributes]::Normal
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        New-Item -ItemType Directory -Path $quar -Force | Out-Null
        $dest = Join-Path $quar (($path -replace '[:\\]', '_') + '.vir')
        Move-Item -LiteralPath $path -Destination $dest -Force
        Log "QUARENTENA: $path  (SHA256 $hash)" Green
        $stats.Corrigidos++
    } catch {
        Log "Nao foi possivel mover $path ($($_.Exception.Message)). Agendando exclusao no proximo boot." Red
        try {
            if (-not ('TJ.Native' -as [type])) {
                Add-Type -Namespace TJ -Name Native -MemberDefinition '[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern bool MoveFileEx(string src, string dst, int flags);'
            }
            if ([TJ.Native]::MoveFileEx($path, $null, 4)) { $stats.Reboot++ } else { $stats.Falhas++ }
        } catch { $stats.Falhas++ }
    }
}

# ---------------------------------------------------------------- inicio
Clear-Host
Log 'Removedor TJprojMain v2' White
Log "Log: $log"
if ($DryRun) { Log 'MODO SIMULACAO: nada sera alterado.' Cyan }
else {
    Log 'Criando ponto de restauracao (pode demorar)...'
    try { Checkpoint-Computer -Description "Antes do removedor TJprojMain $ts" -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
          Log 'Ponto de restauracao criado.' Green }
    catch { Log "Ponto de restauracao nao criado: $($_.Exception.Message)" DarkYellow }
}

# Todas as unidades com pasta Windows (inclui Windows "offline" em outros discos, como o original fazia com C/D/E)
$roots = @([IO.DriveInfo]::GetDrives() | Where-Object {
            $_.IsReady -and "$($_.DriveType)" -in 'Fixed', 'Removable' -and
            (Test-Path -LiteralPath (Join-Path $_.RootDirectory.FullName 'Windows')) } |
         ForEach-Object { $_.RootDirectory.FullName })

# Hives de registro: maquina + todos os usuarios carregados
$hives = @('Registry::HKEY_LOCAL_MACHINE') + @(Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue |
         Where-Object { $_.PSChildName -notmatch '_Classes$' } | ForEach-Object { 'Registry::' + $_.Name })

# ---------------------------------------------------------------- 1. processos + arquivos
Section "1. Processos e arquivos (unidades: $($roots -join ' '))"
# Os executaveis se relancam entre si, entao: mata TODOS de uma vez e ja move os arquivos, em rodadas.
$restantes = @()
for ($round = 1; $round -le 6; $round++) {
    $procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.ExecutablePath -match $rxFile })
    $files = @(foreach ($r in $roots) { foreach ($p in $rel) { $f = Join-Path $r $p; if ([IO.File]::Exists($f)) { $f } } })
    $restantes = $files
    if ($procs.Count -eq 0 -and $files.Count -eq 0) {
        if ($round -eq 1) { Log 'Nenhum processo ou arquivo do TJprojMain encontrado.' Green }
        else { Log 'Processos e arquivos eliminados.' Green }
        break
    }
    Log "Rodada $round : $($procs.Count) processo(s), $($files.Count) arquivo(s)" Yellow
    foreach ($p in $procs) { Log "  processo PID $($p.ProcessId): $($p.ExecutablePath)" Yellow }
    if ($procs.Count -and -not $DryRun) {
        Stop-Process -Id $procs.ProcessId -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 300
    }
    foreach ($f in $files) { Quarantine $f }
    if ($DryRun) { break }
    Start-Sleep -Milliseconds 700
}

# Copias soltas do icsys.icn.exe em pastas temporarias
$tmpDirs = @("$env:SystemRoot\Temp") + @(Get-ChildItem "$env:SystemDrive\Users" -Directory -Force -ErrorAction SilentlyContinue |
           ForEach-Object { Join-Path $_.FullName 'AppData\Local\Temp' })
Get-ChildItem -LiteralPath $tmpDirs -Filter 'icsys.icn.exe' -Recurse -Force -File -ErrorAction SilentlyContinue |
    ForEach-Object { Quarantine $_.FullName }

# ---------------------------------------------------------------- 2. inicializacao no registro
Section '2. Inicializacao automatica (Run / RunOnce / Policies)'
$runKeys = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
           'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
           'SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
           'SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce',
           'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
           'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
           'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
foreach ($h in $hives) {
    foreach ($rk in $runKeys) {
        $path = "$h\$rk"
        $key = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
        if (-not $key) { continue }
        foreach ($n in $key.GetValueNames()) {
            $v = "$($key.GetValue($n))"
            if ($n -and $v -match $rxRef) {
                Act "remover [$($path -replace '^Registry::')] '$n' = $v" { Remove-ItemProperty -LiteralPath $path -Name $n -Force }
            }
        }
    }
}

# ---------------------------------------------------------------- 3. Winlogon / Load
Section '3. Winlogon (Shell / Userinit) e Windows\Load'
$defaults = @{ Shell = 'explorer.exe'; Userinit = "$env:SystemRoot\system32\userinit.exe," }
$checks = @(@('SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', 'Shell'),
            @('SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', 'Userinit'),
            @('SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',  'Load'),
            @('SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',  'Run'))
foreach ($h in $hives) {
    foreach ($c in $checks) {
        $path = "$h\$($c[0])"; $n = $c[1]
        $v = (Get-ItemProperty -LiteralPath $path -Name $n -ErrorAction SilentlyContinue).$n
        if ($v -and "$v" -match $rxRef) {
            if ($h -eq 'Registry::HKEY_LOCAL_MACHINE' -and $defaults.ContainsKey($n)) {
                $def = $defaults[$n]
                Act "restaurar [$($path -replace '^Registry::')] $n ('$v' -> '$def')" { Set-ItemProperty -LiteralPath $path -Name $n -Value $def }
            } else {
                Act "remover [$($path -replace '^Registry::')] $n = $v" { Remove-ItemProperty -LiteralPath $path -Name $n -Force }
            }
        }
    }
}

# ---------------------------------------------------------------- 4. servicos
Section '4. Servicos'
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -match $rxRef } | ForEach-Object {
    $s = $_
    Act "remover servico '$($s.Name)' -> $($s.PathName)" {
        Stop-Service -Name $s.Name -Force -ErrorAction SilentlyContinue
        & sc.exe delete $s.Name | Out-Null
        if ($LASTEXITCODE) { throw "sc delete retornou $LASTEXITCODE" }
    }
}

# ---------------------------------------------------------------- 5. tarefas agendadas
Section '5. Tarefas agendadas (inclui jobs antigos do comando AT)'
Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
    $t = $_
    $cmd = (@($t.Actions) | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '
    if ($cmd -match $rxRef) {
        Act "remover tarefa '$($t.TaskPath)$($t.TaskName)' -> $cmd" { Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false }
    }
}
Get-ChildItem "$env:SystemRoot\Tasks" -Filter *.job -Force -File -ErrorAction SilentlyContinue | ForEach-Object {
    $txt = [Text.Encoding]::Unicode.GetString([IO.File]::ReadAllBytes($_.FullName))
    if ($txt -match $rxRef) { Quarantine $_.FullName }
}

# ---------------------------------------------------------------- 6. pendrives
Section '6. autorun.inf em unidades removiveis'
[IO.DriveInfo]::GetDrives() | Where-Object { $_.IsReady -and "$($_.DriveType)" -eq 'Removable' } | ForEach-Object {
    $inf = Join-Path $_.RootDirectory.FullName 'autorun.inf'
    if ([IO.File]::Exists($inf)) {
        $c = Get-Content -LiteralPath $inf -Raw -ErrorAction SilentlyContinue
        if ($c -match '(?im)^\s*(open|shellexecute|shell\\)') { Log "autorun.inf executavel em $($_.Name)" Yellow; Quarantine $inf }
    }
}

# ---------------------------------------------------------------- 7. politicas (so relatorio)
Section '7. Politicas que malware costuma ativar (apenas aviso)'
$pol = @{ 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'   = @('DisableTaskMgr', 'DisableRegistryTools')
          'SOFTWARE\Policies\Microsoft\Windows\System'                 = @('DisableCMD')
          'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' = @('NoFolderOptions') }
$polHit = $false
foreach ($h in $hives) { foreach ($k in $pol.Keys) { foreach ($n in $pol[$k]) {
    $v = (Get-ItemProperty -LiteralPath "$h\$k" -Name $n -ErrorAction SilentlyContinue).$n
    if ($v) { $polHit = $true; Log "AVISO: $n=$v em $(("$h\$k") -replace '^Registry::'). Se nao for politica da empresa, remova." DarkYellow }
} } }
if (-not $polHit) { Log 'Nenhuma politica suspeita ativa.' Green }

# ---------------------------------------------------------------- resumo
Section 'Resumo'
Log "Itens encontrados: $($stats.Encontrados)   Corrigidos: $($stats.Corrigidos)   Falhas: $($stats.Falhas)   Exclusao no reboot: $($stats.Reboot)" White
if (-not $DryRun -and $stats.Corrigidos) { Log "Quarentena: $quar (arquivos renomeados para .vir)" }
$aindaExiste = @($restantes | Where-Object { [IO.File]::Exists($_) })
if ($aindaExiste.Count -or $stats.Reboot -or $stats.Falhas) {
    Log 'REINICIE o PC e rode este script de novo. Se continuar voltando, rode em Modo de Seguranca.' Yellow
}
Log 'IMPORTANTE: variantes do TJprojMain tambem infectam outros .exe. Um script nao desinfeta isso;' Yellow
Log 'faca uma varredura completa (Windows Defender / Defender Offline, KVRT ou similar).' Yellow

$mp = "$env:ProgramFiles\Windows Defender\MpCmdRun.exe"
if (-not $DryRun -and (Test-Path -LiteralPath $mp)) {
    $r = Read-Host 'Atualizar e executar varredura COMPLETA do Windows Defender agora? (S/N)'
    if ($r -match '^[sS]') {
        & $mp -SignatureUpdate
        Log 'Varredura completa iniciada (pode levar bastante tempo)...' White
        & $mp -Scan -ScanType 2
        Log "Defender terminou com codigo $LASTEXITCODE (0 = nada encontrado, 2 = ameaca tratada/encontrada)." White
    }
}
