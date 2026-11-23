<#
.SYNOPSIS
    End-to-end Windows integration test for Curb's LocalSystem service, CLI,
    Named Pipe IPC (both elevated and non-elevated standard user), ACL lockdown,
    service lifecycle (stop/start/reinstall/uninstall), and optional NSIS installer.

.NOTES
    Always seeds Curb's config in `Disabled` mode before starting `CurbService`
    so WFP default-deny filters and adapter DNS redirection are NOT activated
    (which would sever a CI runner's outbound connection to GitHub).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CliPath,

    [Parameter(Mandatory = $true)]
    [string]$ServicePath,

    [Parameter(Mandatory = $false)]
    [string]$SetupExePath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$CliPath = (Resolve-Path $CliPath).Path
$ServicePath = (Resolve-Path $ServicePath).Path
if ($SetupExePath) {
    $SetupExePath = (Resolve-Path $SetupExePath).Path
}

$DataDir = Join-Path $env:ProgramData "Curb"
$BinDir = Join-Path $DataDir "bin"
$ServiceName = "CurbService"
$TempRoot = Join-Path $env:PUBLIC "curb-e2e-$([Guid]::NewGuid().ToString('N').Substring(0, 8))"
$MigrateDir = Join-Path $TempRoot "standard-migrate"
$TestUserName = "curb_e2e_std"
$TestUserPass = "CurbE2E!Std#9482"
$CreatedTestUser = $false

function Write-Step([string]$Message) {
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw "ASSERTION FAILED: $Message"
    }
    Write-Host "  [OK] $Message" -ForegroundColor Green
}

function Invoke-CurbIpc([hashtable]$Request, [int]$TimeoutMs = 5000) {
    $pipe = [System.IO.Pipes.NamedPipeClientStream]::new(
        ".",
        "curb-ipc",
        [System.IO.Pipes.PipeDirection]::InOut
    )
    try {
        $pipe.Connect($TimeoutMs)
        $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
        $writer = [System.IO.StreamWriter]::new($pipe, $utf8NoBom, 4096, $true)
        $writer.AutoFlush = $true
        $reader = [System.IO.StreamReader]::new($pipe, $utf8NoBom, $false, 4096, $true)

        $json = $Request | ConvertTo-Json -Depth 10 -Compress
        $writer.WriteLine($json)
        $line = $reader.ReadLine()
        if ([string]::IsNullOrWhiteSpace($line)) {
            throw "Empty IPC response for request: $json"
        }
        return ($line | ConvertFrom-Json)
    }
    finally {
        $pipe.Dispose()
    }
}

function Wait-ForCurbPipe([int]$MaxSeconds = 15) {
    $deadline = (Get-Date).AddSeconds($MaxSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $resp = Invoke-CurbIpc @{ op = "get_snapshot" } 1000
            if ($resp.status -eq "snapshot") {
                return $resp
            }
        }
        catch {
            Start-Sleep -Milliseconds 300
        }
    }
    throw "Timed out waiting for \\.\pipe\curb-ipc to answer GetSnapshot"
}

try {
    New-Item -ItemType Directory -Force -Path $TempRoot | Out-Null
    New-Item -ItemType Directory -Force -Path $MigrateDir | Out-Null

    # -------------------------------------------------------------------------
    # Stage 0: Clean slate & prepare Standard Mode migration data (Disabled mode)
    # -------------------------------------------------------------------------
    Write-Step "Stage 0: Preparing clean state and Standard Mode migration fixtures"
    & $CliPath uninstall | Out-Null
    if (Test-Path $DataDir) {
        Remove-Item -Recurse -Force $DataDir
    }

    # Use curb-cli itself so config.json and auth.json match the exact live schema.
    # Setting Disabled mode ensures CurbService never blocks the CI runner's network.
    & $CliPath --data-dir $MigrateDir emergency-disable
    Assert-True ($LASTEXITCODE -eq 0) "Seeded Disabled config.json in migration dir"

    & $CliPath --data-dir $MigrateDir set-password --password "e2e-initial-pass"
    Assert-True ($LASTEXITCODE -eq 0) "Seeded Argon2 auth.json in migration dir"

    # -------------------------------------------------------------------------
    # Stage 1: Install & start CurbService via native Windows SCM
    # -------------------------------------------------------------------------
    Write-Step "Stage 1: Installing and starting CurbService via curb-cli install"
    & $CliPath install --service-bin $ServicePath --migrate-from $MigrateDir
    Assert-True ($LASTEXITCODE -eq 0) "curb-cli install exited with code 0"

    $svc = Get-Service -Name $ServiceName
    Assert-True ($svc.Status -eq "Running") "CurbService status is Running (got: $($svc.Status))"
    Assert-True ($svc.DisplayName -eq "Curb Internet Limiter Service") "DisplayName matches"
    Assert-True ($svc.StartType -eq "Automatic") "StartType is Automatic (got: $($svc.StartType))"
    Assert-True ($svc.ServiceType -eq "Win32OwnProcess") "ServiceType is Win32OwnProcess (got: $($svc.ServiceType))"

    $reg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    $expectedBin = Join-Path $BinDir "curb-service.exe"
    Assert-True ($reg.ImagePath.Trim('"') -eq $expectedBin) "Registry ImagePath is clean and uncorrupted ($($reg.ImagePath))"
    Assert-True (-not $reg.ImagePath.StartsWith(" ")) "Registry ImagePath has no leading whitespace"
    Assert-True ($reg.Type -eq 16) "Registry Type is 0x10 (WIN32_OWN_PROCESS)"
    Assert-True ($reg.ObjectName -eq "LocalSystem") "Service runs as LocalSystem"

    Assert-True (Test-Path $expectedBin) "curb-service.exe copied to ProgramData\Curb\bin"
    Assert-True (Test-Path (Join-Path $BinDir "curb-cli.exe")) "curb-cli.exe copied to ProgramData\Curb\bin"
    Assert-True (Test-Path (Join-Path $DataDir "config.json")) "config.json migrated to ProgramData\Curb"
    Assert-True (Test-Path (Join-Path $DataDir "auth.json")) "auth.json migrated to ProgramData\Curb"

    $acl = Get-Acl $DataDir
    Assert-True ($acl.AreAccessRulesProtected) "ProgramData\Curb disables inherited ACLs"
    $usersRules = @($acl.Access | Where-Object {
        $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq "S-1-5-32-545"
    })
    Assert-True ($usersRules.Count -gt 0) "BUILTIN\Users ACE exists on ProgramData\Curb"
    foreach ($rule in $usersRules) {
        Assert-True (($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Write) -eq 0) "BUILTIN\Users ACE does NOT grant Write access on ProgramData\Curb"
    }

    # -------------------------------------------------------------------------
    # Stage 2: Full IPC round-trip (elevated)
    # -------------------------------------------------------------------------
    Write-Step "Stage 2: Verifying IPC protocol, Authenticode inspection, and auth lifecycle"
    $snap = Wait-ForCurbPipe 15
    Assert-True ($snap.status -eq "snapshot") "GetSnapshot returned snapshot"
    Assert-True ($snap.data.protection_tier -eq "full_service") "protection_tier is full_service"
    Assert-True ($snap.data.password_configured -eq $true) "migrated password is recognized"
    Assert-True ($snap.data.config.mode.kind -eq "disabled") "mode is disabled (runner-safe)"

    $apps = Invoke-CurbIpc @{ op = "list_running_apps" }
    Assert-True ($apps.status -eq "running_apps" -and $apps.apps.Count -gt 0) "ListRunningApps returned $($apps.apps.Count) live Windows apps"

    $signedCandidate = @(
        (Get-Command pwsh -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source),
        (Get-Command node -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source),
        "$env:WINDIR\explorer.exe",
        "$env:WINDIR\System32\notepad.exe"
    ) | Where-Object { $_ -and (Test-Path $_) } | ForEach-Object {
        $sig = Get-AuthenticodeSignature -FilePath $_ -ErrorAction SilentlyContinue
        if ($sig -and $sig.Status -eq "Valid" -and -not $sig.IsOSBinary) { $_ }
    } | Select-Object -First 1

    $inspectTarget = if ($signedCandidate) { $signedCandidate } else { "$env:WINDIR\System32\notepad.exe" }
    $expectedFileName = Split-Path -Leaf $inspectTarget
    $inspected = Invoke-CurbIpc @{
        op   = "inspect_executable"
        path = $inspectTarget
    }
    Assert-True ($inspected.status -eq "inspected") "InspectExecutable succeeded on $expectedFileName"
    Assert-True ($inspected.identity.filename -eq $expectedFileName) "Inspected filename matches ($expectedFileName)"
    Assert-True ($inspected.identity.sha256.Length -eq 64) "Inspected SHA-256 hash is 64 hex chars"
    if ($signedCandidate) {
        Assert-True ($null -ne $inspected.identity.signature -and $inspected.identity.signature.trusted -eq $true) "Embedded Authenticode signature verified as trusted ($($inspected.identity.signature.subject_cn))"
    }

    $unauth = Invoke-CurbIpc @{
        op       = "update_baseline"
        token    = "bogus-session-token"
        baseline = @{ dhcp = $true; loopback = $true; ntp = $true; ncsi = $true }
    }
    Assert-True ($unauth.status -eq "error") "Unauthenticated mutation rejected"

    $unlocked = Invoke-CurbIpc @{ op = "unlock"; password = "e2e-initial-pass" }
    Assert-True ($unlocked.status -eq "unlocked" -and -not [string]::IsNullOrEmpty($unlocked.token)) "Unlock succeeded with migrated password"
    $token = $unlocked.token

    $updated = Invoke-CurbIpc @{
        op    = "update_steam_preset"
        token = $token
        steam = @{
            enabled                = $true
            store_and_library      = $true
            community_and_workshop = $true
            friends_and_voice      = $false
        }
    }
    Assert-True ($updated.status -eq "snapshot" -and $updated.data.config.presets.steam.community_and_workshop -eq $true) "Authenticated config mutation persisted"

    $pwChange = Invoke-CurbIpc @{
        op               = "change_password"
        token            = $token
        current_password = "e2e-initial-pass"
        new_password     = "e2e-rotated-pass"
    }
    Assert-True ($pwChange.status -eq "ok") "ChangePassword succeeded"

    $locked = Invoke-CurbIpc @{ op = "lock"; token = $token }
    Assert-True ($locked.status -eq "ok") "Lock succeeded"

    $oldUnlock = Invoke-CurbIpc @{ op = "unlock"; password = "e2e-initial-pass" }
    Assert-True ($oldUnlock.status -eq "error") "Old password rejected after rotation"

    $newUnlock = Invoke-CurbIpc @{ op = "unlock"; password = "e2e-rotated-pass" }
    Assert-True ($newUnlock.status -eq "unlocked") "New password accepted after rotation"
    $null = Invoke-CurbIpc @{ op = "lock"; token = $newUnlock.token }

    # -------------------------------------------------------------------------
    # Stage 3: Non-elevated standard user IPC + tamper-resistance test
    # -------------------------------------------------------------------------
    Write-Step "Stage 3: Testing Named Pipe access & ProgramData tamper resistance as a standard (non-admin) user"
    $secPass = ConvertTo-SecureString $TestUserPass -AsPlainText -Force
    if (Get-LocalUser -Name $TestUserName -ErrorAction SilentlyContinue) {
        Remove-LocalUser -Name $TestUserName
    }
    New-LocalUser -Name $TestUserName -Password $secPass -PasswordNeverExpires -UserMayNotChangePassword | Out-Null
    $CreatedTestUser = $true
    # Ensure member of Users only (never Administrators)
    try {
        Add-LocalGroupMember -Group "Users" -Member $TestUserName -ErrorAction SilentlyContinue
    }
    catch { }

    # Ensure Secondary Logon service is running so Start-Process -Credential succeeds
    $seclogon = Get-Service -Name "seclogon"
    if ($seclogon.Status -ne "Running") {
        if ($seclogon.StartType -eq "Disabled") {
            Set-Service -Name "seclogon" -StartupType Manual
        }
        Start-Service -Name "seclogon"
    }

    # Grant the temp folder write access for the standard test user so it can write its test result
    & icacls.exe $TempRoot /grant "*S-1-5-32-545:(OI)(CI)M" | Out-Null

    $stdScript = Join-Path $TempRoot "std_user_check.ps1"
    $stdOut = Join-Path $TempRoot "std_user_out.json"
    $stdErr = Join-Path $TempRoot "std_user_err.txt"

    @"
`$ErrorActionPreference = 'Stop'
try {
    # 1. Non-admin standard user MUST be able to read+write \\.\pipe\curb-ipc
    `$pipe = [System.IO.Pipes.NamedPipeClientStream]::new('.', 'curb-ipc', [System.IO.Pipes.PipeDirection]::InOut)
    `$pipe.Connect(5000)
    `$enc = [System.Text.UTF8Encoding]::new(`$false)
    `$w = [System.IO.StreamWriter]::new(`$pipe, `$enc, 4096, `$true)
    `$w.AutoFlush = `$true
    `$r = [System.IO.StreamReader]::new(`$pipe, `$enc, `$false, 4096, `$true)
    `$w.WriteLine('{"op":"get_snapshot"}')
    `$resp = `$r.ReadLine() | ConvertFrom-Json
    `$pipe.Dispose()

    # 2. Non-admin standard user MUST be blocked from tampering with ProgramData\Curb
    `$tamperBlocked = `$false
    try {
        [System.IO.File]::WriteAllText('C:\ProgramData\Curb\tamper.txt', 'nope')
    } catch [System.UnauthorizedAccessException] {
        `$tamperBlocked = `$true
    }

    `$result = @{
        ipc_status      = `$resp.status
        protection_tier = `$resp.data.protection_tier
        tamper_blocked  = `$tamperBlocked
        whoami          = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    }
    `$result | ConvertTo-Json -Compress | Set-Content -Path '$stdOut' -Encoding UTF8
    exit 0
} catch {
    `$_ | Out-String | Set-Content -Path '$stdErr' -Encoding UTF8
    exit 1
}
"@ | Set-Content -Path $stdScript -Encoding UTF8

    $cred = [System.Management.Automation.PSCredential]::new(".\$TestUserName", $secPass)
    $proc = Start-Process -FilePath "powershell.exe" `
        -ArgumentList @("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $stdScript) `
        -Credential $cred `
        -WorkingDirectory $TempRoot `
        -WindowStyle Hidden `
        -Wait `
        -PassThru

    if ($proc.ExitCode -ne 0) {
        $errDetail = if (Test-Path $stdErr) { Get-Content $stdErr -Raw } else { "(no stderr captured)" }
        throw "Standard-user E2E check failed (exit $($proc.ExitCode)): $errDetail"
    }

    $stdResult = Get-Content $stdOut -Raw | ConvertFrom-Json
    Assert-True ($stdResult.ipc_status -eq "snapshot") "Standard user ($($stdResult.whoami)) received Snapshot over \\.\pipe\curb-ipc"
    Assert-True ($stdResult.protection_tier -eq "full_service") "Standard user saw protection_tier = full_service"
    Assert-True ($stdResult.tamper_blocked -eq $true) "Standard user was denied write access to C:\ProgramData\Curb"

    # -------------------------------------------------------------------------
    # Stage 4: Graceful Stop, Restart, In-Place Reinstall, and Self-Install Guard
    # -------------------------------------------------------------------------
    Write-Step "Stage 4: Testing graceful service stop, restart, in-place upgrade, and self-copy guard"
    $stopTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Stop-Service -Name $ServiceName
    $stopTimer.Stop()
    Assert-True ((Get-Service -Name $ServiceName).Status -eq "Stopped") "CurbService stopped cleanly"
    Assert-True ($stopTimer.Elapsed.TotalSeconds -lt 10) "CurbService stopped promptly ($([Math]::Round($stopTimer.Elapsed.TotalSeconds, 2))s < 10s)"

    Start-Service -Name $ServiceName
    Assert-True ((Get-Service -Name $ServiceName).Status -eq "Running") "CurbService restarted cleanly"
    $null = Wait-ForCurbPipe 10

    # Re-run install while CurbService is already running (upgrade / repair path)
    & $CliPath install --service-bin $ServicePath
    Assert-True ($LASTEXITCODE -eq 0) "In-place reinstall succeeded while CurbService was running"
    Assert-True ((Get-Service -Name $ServiceName).Status -eq "Running") "CurbService is Running after in-place reinstall"
    $null = Wait-ForCurbPipe 10

    # Run curb-cli install directly from ProgramData\Curb\bin (tests self-copy guard)
    $installedCli = Join-Path $BinDir "curb-cli.exe"
    $origSize = (Get-Item $expectedBin).Length
    & $installedCli install
    Assert-True ($LASTEXITCODE -eq 0) "Self-hosted ProgramData\Curb\bin\curb-cli.exe install succeeded"
    Assert-True ((Get-Item $expectedBin).Length -eq $origSize) "curb-service.exe was not truncated on self-install ($origSize bytes)"
    Assert-True ((Get-Service -Name $ServiceName).Status -eq "Running") "CurbService is Running after self-install"

    $statusOut = & $installedCli status | Out-String
    Assert-True ($statusOut -match "Disabled") "curb-cli status reports Disabled mode"
    Assert-True ($statusOut -match "configured") "curb-cli status reports password configured"

    # -------------------------------------------------------------------------
    # Stage 5: Clean Uninstall & Teardown
    # -------------------------------------------------------------------------
    Write-Step "Stage 5: Testing curb-cli uninstall teardown"
    & $CliPath uninstall
    Assert-True ($LASTEXITCODE -eq 0) "curb-cli uninstall exited with code 0"

    # Wait briefly for SCM to finish removing the deleted service entry
    $removed = $false
    for ($i = 0; $i -lt 20; $i++) {
        if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
            $removed = $true
            break
        }
        Start-Sleep -Milliseconds 250
    }
    Assert-True $removed "CurbService removed from Windows SCM"
    Assert-True (-not (Test-Path $BinDir)) "C:\ProgramData\Curb\bin cleaned up"

    # -------------------------------------------------------------------------
    # Stage 6 (Optional): NSIS Silent Install & Uninstall Hook Verification
    # -------------------------------------------------------------------------
    if ($SetupExePath) {
        Write-Step "Stage 6: Testing NSIS per-user installer and post-uninstall cleanup hook"
        $installDir = Join-Path $env:LOCALAPPDATA "Curb"
        $instProc = Start-Process -FilePath $SetupExePath -ArgumentList "/S" -Wait -PassThru
        Assert-True ($instProc.ExitCode -eq 0) "NSIS installer completed silently (exit 0)"

        Assert-True (Test-Path (Join-Path $installDir "curb-app.exe")) "curb-app.exe installed in %LOCALAPPDATA%\Curb"
        $bundledCli = Join-Path $installDir "resources\curb-cli.exe"
        $bundledSvc = Join-Path $installDir "resources\curb-service.exe"
        Assert-True (Test-Path $bundledCli) "Bundled curb-cli.exe present in NSIS resources"
        Assert-True (Test-Path $bundledSvc) "Bundled curb-service.exe present in NSIS resources"

        # Seed Standard Mode artifacts to verify hooks.nsh cleans them up on uninstall
        $runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        $inetKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        Set-ItemProperty -Path $runKey -Name "Curb" -Value "`"$(Join-Path $installDir 'curb-app.exe')`""
        Set-ItemProperty -Path $inetKey -Name "ProxyEnable" -Value 1 -Type DWord
        Set-ItemProperty -Path $inetKey -Name "ProxyServer" -Value "127.0.0.1:48921"
        Set-Content -Path (Join-Path $installDir "standard_mode.flag") -Value "standard"

        Get-Process -Name "curb-app" -ErrorAction SilentlyContinue | Stop-Process -Force
        $uninstaller = Join-Path $installDir "uninstall.exe"
        Assert-True (Test-Path $uninstaller) "NSIS uninstaller present"
        # _?=<dir> runs NSIS uninstaller synchronously so -Wait finishes after post-uninstall hooks
        $uninstProc = Start-Process -FilePath $uninstaller -ArgumentList @("/S", "_?=$installDir") -Wait -PassThru
        Assert-True ($uninstProc.ExitCode -eq 0) "NSIS uninstaller completed silently (exit 0)"

        Assert-True (-not (Test-Path (Join-Path $installDir "curb-app.exe"))) "curb-app.exe removed by uninstaller"
        Assert-True (-not (Test-Path (Join-Path $installDir "standard_mode.flag"))) "NSIS hook removed standard_mode.flag"
        $runVal = (Get-Item -Path $runKey).GetValue("Curb", $null)
        Assert-True ($null -eq $runVal) "NSIS hook removed HKCU\...\Run\Curb"
        $proxyEnable = (Get-Item -Path $inetKey).GetValue("ProxyEnable", $null)
        $proxyServer = (Get-Item -Path $inetKey).GetValue("ProxyServer", $null)
        Assert-True ($proxyEnable -eq 0) "NSIS hook reset HKCU ProxyEnable to 0"
        Assert-True ($null -eq $proxyServer) "NSIS hook deleted Curb HKCU ProxyServer"

        if (Test-Path $installDir) {
            Remove-Item -Recurse -Force $installDir -ErrorAction SilentlyContinue
        }
    }

    Write-Host "`nALL WINDOWS E2E TESTS PASSED!" -ForegroundColor Green
}
finally {
    # Best-effort cleanup so CI runners and local dev boxes stay clean even on failure
    try {
        if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
            & $CliPath uninstall | Out-Null
        }
    }
    catch { }

    if ($CreatedTestUser) {
        try {
            Remove-LocalUser -Name $TestUserName -ErrorAction SilentlyContinue
        }
        catch { }
    }

    if (Test-Path $TempRoot) {
        Remove-Item -Recurse -Force $TempRoot -ErrorAction SilentlyContinue
    }
    if (Test-Path $DataDir) {
        Remove-Item -Recurse -Force $DataDir -ErrorAction SilentlyContinue
    }
}
