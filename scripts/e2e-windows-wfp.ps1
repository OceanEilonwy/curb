<#
.SYNOPSIS
    Live Windows WFP & Virtual Network Adapter E2E test suite for Curb.

.DESCRIPTION
    Exercises Curb in real Enforcing mode on Windows (including GitHub Actions
    windows-latest runners) with defensive guardrails:
      - Pre-allows GitHub Actions runner binaries and pwsh before enabling WFP.
      - Arms a detached dead-man's switch watchdog that forces emergency-disable
        and restores adapter DNS if the suite hangs.
      - Creates a Microsoft KM-TEST Loopback Adapter with a static IP and canary
        DNS server (10.200.0.53) to verify real adapter DNS backup/redirect/restore.
      - Tests WFP default-deny (WSAEACCES), blocked-event telemetry, loopback
        baseline, per-app on/off toggling, protocol scoping (TCP/UDP), hash
        integrity, cross-app live-socket isolation, DNS whitelist toggling,
        live-socket survival across Enforcing -> Disabled (ALE teardown order),
        rapid global toggle storms (Wi-Fi/DNS drop regression), and service
        stop/restart/uninstall recovery.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CliPath,

    [Parameter(Mandatory = $true)]
    [string]$ServicePath,

    [Parameter(Mandatory = $false)]
    [string]$ProbeSourcePath = (Join-Path $PSScriptRoot "e2e_probe.rs"),

    [Parameter(Mandatory = $false)]
    [int]$WatchdogTimeoutSec = 300
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$CliPath = (Resolve-Path $CliPath).Path
$ServicePath = (Resolve-Path $ServicePath).Path
$ProbeSourcePath = (Resolve-Path $ProbeSourcePath).Path

$DataDir = Join-Path $env:ProgramData "Curb"
$ServiceName = "CurbService"
$TempRoot = Join-Path $env:PUBLIC "curb-wfp-e2e-$([Guid]::NewGuid().ToString('N').Substring(0, 8))"
$MigrateDir = Join-Path $TempRoot "seed"
$WatchdogCancelFile = Join-Path $TempRoot "watchdog.cancel"
$TestPassword = "wfp-e2e-pass-9482"

$VirtualAdapterPnpId = $null
$VirtualAdapterIdx = $null
$VirtualAdapterCanaryIp = "10.200.0.1"
$VirtualAdapterCanaryDns = "10.200.0.53"
$PrimaryAdapterBackup = @()

function Write-Step([string]$Message) {
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw "ASSERTION FAILED: $Message"
    }
    Write-Host "  [OK] $Message" -ForegroundColor Green
}

function Wait-Until([scriptblock]$Condition, [int]$TimeoutSec = 15, [int]$PollMs = 250, [string]$Description = "condition") {
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $lastErr = $null
    while ((Get-Date) -lt $deadline) {
        try {
            $res = & $Condition
            if ($res) {
                return $res
            }
        }
        catch {
            $lastErr = $_
        }
        Start-Sleep -Milliseconds $PollMs
    }
    $extra = if ($lastErr) { " (last error: $lastErr)" } else { "" }
    throw "Timed out after ${TimeoutSec}s waiting for: $Description$extra"
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

        $json = $Request | ConvertTo-Json -Depth 12 -Compress
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
    return Wait-Until -TimeoutSec $MaxSeconds -PollMs 250 -Description "CurbService IPC pipe" -Condition {
        $resp = Invoke-CurbIpc @{ op = "get_snapshot" } 1000
        if ($resp.status -eq "snapshot") { return $resp }
        return $null
    }
}

function Invoke-Probe([string]$ExePath, [string[]]$ProbeArgs) {
    $out = & $ExePath @ProbeArgs 2>&1
    $code = $LASTEXITCODE
    $text = ($out | Out-String).Trim()
    $parsed = $null
    try {
        $parsed = $text | ConvertFrom-Json
    }
    catch {
        $parsed = [PSCustomObject]@{ ok = ($code -eq 0); raw = $text }
    }
    return [PSCustomObject]@{
        ExitCode = $code
        Data     = $parsed
        Raw      = $text
    }
}

function New-ProbeCopy([string]$BaseExe, [string]$DestExe, [byte]$MarkerByte) {
    Copy-Item -Path $BaseExe -Destination $DestExe -Force
    # Appending distinct overlay bytes after the PE image preserves a valid Windows
    # executable while giving each probe a unique SHA-256 hash.
    $fs = [System.IO.File]::Open($DestExe, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write)
    try {
        $payload = [byte[]]@(0x43, 0x55, 0x52, 0x42, $MarkerByte)
        $fs.Write($payload, 0, $payload.Length)
    }
    finally {
        $fs.Dispose()
    }
}

function New-HashRule([string]$RuleId, [string]$Name, [string]$ExePath, [string]$Sha256, [bool]$Enabled = $true, [bool]$AllowTcp = $true, [bool]$AllowUdp = $true, $DnsWhitelist = $null) {
    return @{
        id           = $RuleId
        name         = $Name
        enabled      = $Enabled
        matcher      = @{
            kind          = "hash"
            sha256        = $Sha256
            filename_hint = (Split-Path -Leaf $ExePath)
        }
        network      = @{
            allow_tcp     = $AllowTcp
            allow_udp     = $AllowUdp
            dns_whitelist = $DnsWhitelist
        }
        subprocesses = "disabled"
        exe_hint     = (Split-Path -Leaf $ExePath)
        exe_path     = $ExePath
        created_at   = (Get-Date).ToUniversalTime().ToString("o")
    }
}

function Set-CurbMode([string]$Token, [string]$Kind) {
    $resp = Invoke-CurbIpc @{
        op    = "set_mode"
        token = $Token
        mode  = @{ kind = $Kind }
    }
    Assert-True ($resp.status -eq "snapshot" -and $resp.data.config.mode.kind -eq $Kind) "Switched Curb mode to $Kind"
    return $resp
}

function Get-AdapterV4Dns([int]$InterfaceIndex) {
    $info = Get-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
    if (-not $info) { return @() }
    return @($info.ServerAddresses | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function Install-KmTestLoopbackAdapter {
    $csharp = @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class KmTestInstaller {
    private const uint DICD_GENERATE_ID = 0x00000001;
    private const uint SPDRP_HARDWAREID = 0x00000001;
    private const uint DIF_REGISTERDEVICE = 0x00000019;
    private const uint INSTALLFLAG_FORCE = 0x00000001;

    [StructLayout(LayoutKind.Sequential)]
    private struct SP_DEVINFO_DATA {
        public uint cbSize;
        public Guid ClassGuid;
        public uint DevInst;
        public IntPtr Reserved;
    }

    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern IntPtr SetupDiCreateDeviceInfoList(ref Guid ClassGuid, IntPtr hwndParent);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetupDiCreateDeviceInfoW(
        IntPtr DeviceInfoSet,
        string DeviceName,
        ref Guid ClassGuid,
        string DeviceDescription,
        IntPtr hwndParent,
        uint CreationFlags,
        ref SP_DEVINFO_DATA DeviceInfoData);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetupDiSetDeviceRegistryPropertyW(
        IntPtr DeviceInfoSet,
        ref SP_DEVINFO_DATA DeviceInfoData,
        uint Property,
        byte[] PropertyBuffer,
        uint PropertyBufferSize);

    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern bool SetupDiCallClassInstaller(
        uint InstallFunction,
        IntPtr DeviceInfoSet,
        ref SP_DEVINFO_DATA DeviceInfoData);

    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

    [DllImport("newdev.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool UpdateDriverForPlugAndPlayDevicesW(
        IntPtr hwndParent,
        string HardwareId,
        string FullInfPath,
        uint InstallFlags,
        out bool bRebootRequired);

    public static void Install() {
        Guid netClass = new Guid("4d36e972-e325-11ce-bfc1-08002be10318");
        IntPtr devInfoSet = SetupDiCreateDeviceInfoList(ref netClass, IntPtr.Zero);
        if (devInfoSet == new IntPtr(-1)) {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "SetupDiCreateDeviceInfoList failed");
        }
        try {
            var devInfoData = new SP_DEVINFO_DATA();
            devInfoData.cbSize = (uint)Marshal.SizeOf(typeof(SP_DEVINFO_DATA));
            if (!SetupDiCreateDeviceInfoW(devInfoSet, "Net", ref netClass, null, IntPtr.Zero, DICD_GENERATE_ID, ref devInfoData)) {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "SetupDiCreateDeviceInfoW failed");
            }
            byte[] hwid = Encoding.Unicode.GetBytes("*msloop\0\0");
            if (!SetupDiSetDeviceRegistryPropertyW(devInfoSet, ref devInfoData, SPDRP_HARDWAREID, hwid, (uint)hwid.Length)) {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "SetupDiSetDeviceRegistryPropertyW failed");
            }
            if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, devInfoSet, ref devInfoData)) {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "SetupDiCallClassInstaller failed");
            }
            string infPath = Environment.ExpandEnvironmentVariables(@"%SystemRoot%\inf\netloop.inf");
            bool reboot = false;
            if (!UpdateDriverForPlugAndPlayDevicesW(IntPtr.Zero, "*msloop", infPath, INSTALLFLAG_FORCE, out reboot)) {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "UpdateDriverForPlugAndPlayDevicesW failed");
            }
        }
        finally {
            SetupDiDestroyDeviceInfoList(devInfoSet);
        }
    }
}
"@
    if (-not ([System.Management.Automation.PSTypeName]'KmTestInstaller').Type) {
        Add-Type -TypeDefinition $csharp -Language CSharp
    }

    $beforeIds = @(Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object -ExpandProperty InterfaceGuid)
    [KmTestInstaller]::Install()

    $adapter = Wait-Until -TimeoutSec 20 -PollMs 500 -Description "KM-TEST Loopback Adapter to appear" -Condition {
        $all = @(Get-NetAdapter -ErrorAction SilentlyContinue)
        $newOne = $all | Where-Object {
            ($beforeIds -notcontains $_.InterfaceGuid) -and ($_.InterfaceDescription -like "*KM-TEST*")
        } | Select-Object -First 1
        if ($newOne) { return $newOne }
        return $null
    }

    return $adapter
}

function Start-Watchdog([string]$CancelFile, [int]$TimeoutSec, [string]$CliExe, [array]$SavedAdapters) {
    $watchdogScript = Join-Path $TempRoot "watchdog.ps1"
    $backupJsonPath = Join-Path $TempRoot "primary_dns_backup.json"
    $SavedAdapters | ConvertTo-Json -Depth 5 | Set-Content -Path $backupJsonPath -Encoding UTF8

    @"
`$deadline = (Get-Date).AddSeconds($TimeoutSec)
while ((Get-Date) -lt `$deadline) {
    if (Test-Path '$CancelFile') { exit 0 }
    Start-Sleep -Seconds 1
}
# Dead-man's switch triggered: force Curb offline and restore runner DNS
try { & '$CliExe' emergency-disable | Out-Null } catch { }
try { Stop-Service -Name '$ServiceName' -Force -ErrorAction SilentlyContinue } catch { }
try {
    `$saved = Get-Content '$backupJsonPath' -Raw | ConvertFrom-Json
    foreach (`$a in @(`$saved)) {
        if (`$a.Servers -and `$a.Servers.Count -gt 0) {
            Set-DnsClientServerAddress -InterfaceIndex `$a.Index -ServerAddresses `$a.Servers -ErrorAction SilentlyContinue
        } else {
            Set-DnsClientServerAddress -InterfaceIndex `$a.Index -ResetServerAddresses -ErrorAction SilentlyContinue
        }
    }
    Clear-DnsClientCache -ErrorAction SilentlyContinue
} catch { }
"@ | Set-Content -Path $watchdogScript -Encoding UTF8

    Start-Process -FilePath "powershell.exe" `
        -ArgumentList @("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $watchdogScript) `
        -WindowStyle Hidden | Out-Null
}

function Start-HoldProbe([string]$ProbeExe, [string]$Tag) {
    $ready = Join-Path $TempRoot "hold-$Tag.ready"
    $stop = Join-Path $TempRoot "hold-$Tag.stop"
    $stdout = Join-Path $TempRoot "hold-$Tag.out"
    $stderr = Join-Path $TempRoot "hold-$Tag.err"
    foreach ($f in @($ready, $stop, $stdout, $stderr)) {
        if (Test-Path $f) { Remove-Item -Force $f }
    }

    $proc = Start-Process -FilePath $ProbeExe `
        -ArgumentList @("hold", "www.msftconnecttest.com", "80", "/connecttest.txt", $ready, $stop, "400") `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr `
        -WindowStyle Hidden `
        -PassThru

    Wait-Until -TimeoutSec 15 -PollMs 200 -Description "hold probe ($Tag) to establish persistent TCP socket" -Condition {
        if ($proc.HasExited) {
            $outTxt = if (Test-Path $stdout) { Get-Content $stdout -Raw } else { "" }
            $errTxt = if (Test-Path $stderr) { Get-Content $stderr -Raw } else { "" }
            throw "Hold probe ($Tag) exited early (code $($proc.ExitCode)): $outTxt $errTxt"
        }
        return (Test-Path $ready)
    } | Out-Null

    return [PSCustomObject]@{
        Process = $proc
        Stop    = $stop
        Stdout  = $stdout
        Stderr  = $stderr
        Tag     = $Tag
    }
}

function Stop-AndAssertHoldProbe($Hold) {
    Set-Content -Path $Hold.Stop -Value "stop" -Encoding ASCII
    if (-not $Hold.Process.WaitForExit(15000)) {
        try { $Hold.Process.Kill() } catch { }
        throw "Hold probe ($($Hold.Tag)) did not exit within 15s after stop signal"
    }
    $outTxt = if (Test-Path $Hold.Stdout) { (Get-Content $Hold.Stdout -Raw).Trim() } else { "" }
    $errTxt = if (Test-Path $Hold.Stderr) { (Get-Content $Hold.Stderr -Raw).Trim() } else { "" }
    Assert-True ($Hold.Process.ExitCode -eq 0) "Hold probe ($($Hold.Tag)) kept persistent TCP socket alive without drops ($outTxt $errTxt)"
    $parsed = $outTxt | ConvertFrom-Json
    Assert-True ($parsed.ok -eq $true -and $parsed.probes -ge 2) "Hold probe ($($Hold.Tag)) completed $($parsed.probes) consecutive keep-alive requests on one socket"
}

try {
    New-Item -ItemType Directory -Force -Path $TempRoot | Out-Null
    New-Item -ItemType Directory -Force -Path $MigrateDir | Out-Null

    # -------------------------------------------------------------------------
    # Stage 0: Snapshot runner DNS, build probe binaries, create virtual adapter,
    #          install CurbService in Disabled mode, pre-allow CI runner, arm watchdog
    # -------------------------------------------------------------------------
    Write-Step "Stage 0: Preparing probes, KM-TEST virtual adapter, runner allowlist, and watchdog"

    $activeIfaces = @(Get-NetIPInterface -ConnectionState Connected -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object {
            $ips = @(Get-NetIPAddress -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' })
            $ips.Count -gt 0
        } | Select-Object -ExpandProperty InterfaceIndex -Unique)

    foreach ($idx in $activeIfaces) {
        $PrimaryAdapterBackup += [PSCustomObject]@{
            Index   = $idx
            Servers = @(Get-AdapterV4Dns $idx)
        }
    }
    Assert-True ($PrimaryAdapterBackup.Count -gt 0) "Captured original DNS for $($PrimaryAdapterBackup.Count) active runner adapter(s)"

    # Compile standalone Rust probe and create 4 distinct binaries (unique SHA-256 hashes)
    $baseProbe = Join-Path $TempRoot "probe-base.exe"
    & rustc -O $ProbeSourcePath -o $baseProbe
    Assert-True ($LASTEXITCODE -eq 0 -and (Test-Path $baseProbe)) "Compiled standalone e2e_probe.rs"

    $probeA = Join-Path $TempRoot "probe-a.exe"
    $probeB = Join-Path $TempRoot "probe-b.exe"
    $probeBlocked = Join-Path $TempRoot "probe-blocked.exe"
    $probeTampered = Join-Path $TempRoot "probe-tampered.exe"
    New-ProbeCopy $baseProbe $probeA 0x01
    New-ProbeCopy $baseProbe $probeB 0x02
    New-ProbeCopy $baseProbe $probeBlocked 0x03
    New-ProbeCopy $baseProbe $probeTampered 0x04

    $baselineCheck = Invoke-Probe $probeBlocked @("tcp", "1.1.1.1:443", "5000")
    Assert-True ($baselineCheck.ExitCode -eq 0 -and $baselineCheck.Data.ok -eq $true) "Baseline sanity: probe-blocked.exe reaches 1.1.1.1:443 before Curb is enabled"
    $baselineUdpCheck = Invoke-Probe $probeBlocked @("udp", "1.1.1.1:53", "2000")
    Assert-True ($baselineUdpCheck.ExitCode -eq 0 -and $baselineUdpCheck.Data.ok -eq $true) "Baseline sanity: probe-blocked.exe gets UDP reply from 1.1.1.1:53 before Curb is enabled ($($baselineUdpCheck.Raw))"

    # Install virtual network adapter with canary static IP and DNS
    $vAdapter = Install-KmTestLoopbackAdapter
    $VirtualAdapterPnpId = $vAdapter.PnPDeviceID
    $VirtualAdapterIdx = $vAdapter.ifIndex
    Set-NetIPInterface -InterfaceIndex $VirtualAdapterIdx -InterfaceMetric 9999 -ErrorAction SilentlyContinue
    New-NetIPAddress -InterfaceIndex $VirtualAdapterIdx -IPAddress $VirtualAdapterCanaryIp -PrefixLength 24 -ErrorAction Stop | Out-Null
    Set-DnsClientServerAddress -InterfaceIndex $VirtualAdapterIdx -ServerAddresses @($VirtualAdapterCanaryDns) -ErrorAction Stop
    Assert-True ((Get-AdapterV4Dns $VirtualAdapterIdx) -contains $VirtualAdapterCanaryDns) "Created KM-TEST virtual adapter (ifIndex=$VirtualAdapterIdx) with canary DNS $VirtualAdapterCanaryDns"

    # Clean install CurbService in Disabled mode
    & $CliPath uninstall | Out-Null
    if (Test-Path $DataDir) { Remove-Item -Recurse -Force $DataDir }
    & $CliPath --data-dir $MigrateDir emergency-disable
    Assert-True ($LASTEXITCODE -eq 0) "Seeded Disabled config"
    & $CliPath --data-dir $MigrateDir set-password --password $TestPassword
    Assert-True ($LASTEXITCODE -eq 0) "Seeded test password"
    & $CliPath install --service-bin $ServicePath --migrate-from $MigrateDir
    Assert-True ($LASTEXITCODE -eq 0) "Installed CurbService"
    $null = Wait-ForCurbPipe 15

    $unlock = Invoke-CurbIpc @{ op = "unlock"; password = $TestPassword }
    Assert-True ($unlock.status -eq "unlocked") "Unlocked Curb IPC session"
    $token = $unlock.token

    # Pre-allow CI runner processes + PowerShell so Enforcing mode never severs GitHub Actions
    $runnerPaths = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
    Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.ProcessName -like "Runner.*" -or $_.ProcessName -in @("pwsh", "powershell")
    } | ForEach-Object {
        try {
            if ($_.Path -and (Test-Path $_.Path)) { [void]$runnerPaths.Add($_.Path) }
        }
        catch { }
    }
    foreach ($rp in $runnerPaths) {
        $insp = Invoke-CurbIpc @{ op = "inspect_executable"; path = $rp }
        if ($insp.status -eq "inspected") {
            $rule = New-HashRule ([Guid]::NewGuid().ToString()) ("CI Allow: " + (Split-Path -Leaf $rp)) $rp $insp.identity.sha256 $true $true $true $null
            $up = Invoke-CurbIpc @{ op = "upsert_rule"; token = $token; rule = $rule }
            Assert-True ($up.status -eq "snapshot") "Pre-allowed CI binary: $(Split-Path -Leaf $rp)"
        }
    }

    # Inspect our test probes once while Disabled
    $inspA = (Invoke-CurbIpc @{ op = "inspect_executable"; path = $probeA }).identity
    $inspB = (Invoke-CurbIpc @{ op = "inspect_executable"; path = $probeB }).identity
    Assert-True ($inspA.sha256 -ne $inspB.sha256) "probe-a.exe and probe-b.exe have distinct SHA-256 hashes"

    # Arm dead-man's switch watchdog before enabling WFP
    Start-Watchdog -CancelFile $WatchdogCancelFile -TimeoutSec $WatchdogTimeoutSec -CliExe $CliPath -SavedAdapters $PrimaryAdapterBackup
    Write-Host "  [OK] Armed ${WatchdogTimeoutSec}s dead-man's switch watchdog" -ForegroundColor Green

    # -------------------------------------------------------------------------
    # Stage 1: Enable Enforcing Mode & Verify Virtual Adapter DNS Redirection
    # -------------------------------------------------------------------------
    Write-Step "Stage 1: Enabling Enforcing mode and verifying virtual adapter DNS redirection"
    $null = Set-CurbMode $token "enforcing"

    Wait-Until -TimeoutSec 15 -PollMs 300 -Description "virtual adapter DNS to redirect to 127.0.0.1" -Condition {
        $dns = @(Get-AdapterV4Dns $VirtualAdapterIdx)
        return ($dns.Count -eq 1 -and $dns[0] -eq "127.0.0.1")
    } | Out-Null
    Assert-True $true "Virtual adapter DNS redirected to 127.0.0.1"

    $backupPath = Join-Path $DataDir "dns_backup.json"
    Assert-True (Test-Path $backupPath) "dns_backup.json created in C:\ProgramData\Curb"
    $backupContent = Get-Content $backupPath -Raw
    Assert-True ($backupContent -match [Regex]::Escape($VirtualAdapterCanaryDns)) "dns_backup.json captured virtual adapter canary DNS ($VirtualAdapterCanaryDns)"

    # -------------------------------------------------------------------------
    # Stage 2: WFP Default-Deny Enforcement, Telemetry, and Loopback Baseline
    # -------------------------------------------------------------------------
    Write-Step "Stage 2: Verifying WFP default-deny (WSAEACCES), blocked telemetry, and loopback baseline"

    $tcpBlock = Wait-Until -TimeoutSec 10 -PollMs 300 -Description "WFP to block probe-blocked.exe TCP" -Condition {
        $r = Invoke-Probe $probeBlocked @("tcp", "1.1.1.1:443", "3000")
        if ($r.ExitCode -ne 0 -and $r.Data.os_error -eq 10013) { return $r }
        return $null
    }
    Assert-True ($tcpBlock.Data.os_error -eq 10013) "probe-blocked.exe TCP blocked immediately by WFP (WSAEACCES 10013)"

    $udpBlock = Invoke-Probe $probeBlocked @("udp", "1.1.1.1:53", "1500")
    Assert-True ($udpBlock.ExitCode -ne 0) "probe-blocked.exe UDP blocked by WFP ($($udpBlock.Raw))"

    $seenBlockedEvent = Wait-Until -TimeoutSec 10 -PollMs 500 -Description "BlockedEvent for probe-blocked.exe in IPC snapshot" -Condition {
        $snap = Invoke-CurbIpc @{ op = "get_snapshot" }
        $hit = $snap.data.blocked_events | Where-Object { $_.exe -ieq "probe-blocked.exe" } | Select-Object -First 1
        return $hit
    }
    Assert-True ($null -ne $seenBlockedEvent) "WFP net-event telemetry recorded BlockedEvent for probe-blocked.exe (-> $($seenBlockedEvent.destination))"

    # Verify baseline.loopback = true still permits localhost TCP from blocked probe
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try {
        $localPort = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
        $acceptTask = $listener.AcceptTcpClientAsync()
        $loopRes = Invoke-Probe $probeBlocked @("tcp", "127.0.0.1:$localPort", "3000")
        Assert-True ($loopRes.ExitCode -eq 0 -and $loopRes.Data.ok -eq $true) "baseline.loopback permits probe-blocked.exe -> 127.0.0.1:$localPort while external traffic is denied"
        if ($acceptTask.Wait(2000)) { $acceptTask.Result.Dispose() }
    }
    finally {
        $listener.Stop()
    }

    # -------------------------------------------------------------------------
    # Stage 3: Per-App On/Off, Protocol Scoping, Hash Integrity & Cross-App Isolation
    # -------------------------------------------------------------------------
    Write-Step "Stage 3: Testing per-app on/off toggling, TCP/UDP scoping, hash integrity, and cross-app isolation"

    $ruleAId = [Guid]::NewGuid().ToString()
    $ruleBId = [Guid]::NewGuid().ToString()

    # 3a. Create rule for probe-a.exe in OFF state (enabled = false) -> must be blocked
    $rAOff = New-HashRule $ruleAId "Probe A" $probeA $inspA.sha256 $false $true $false $null
    $null = Invoke-CurbIpc @{ op = "upsert_rule"; token = $token; rule = $rAOff }
    Start-Sleep -Milliseconds 600
    $aOffRes = Invoke-Probe $probeA @("tcp", "1.1.1.1:443", "3000")
    Assert-True ($aOffRes.ExitCode -ne 0 -and $aOffRes.Data.os_error -eq 10013) "probe-a.exe is blocked when its rule is enabled=false"

    # 3b. Toggle probe-a.exe ON (TCP=true, UDP=false) -> TCP allowed, UDP blocked, tampered hash blocked
    $rAOnTcpOnly = New-HashRule $ruleAId "Probe A" $probeA $inspA.sha256 $true $true $false $null
    $null = Invoke-CurbIpc @{ op = "upsert_rule"; token = $token; rule = $rAOnTcpOnly }

    Wait-Until -TimeoutSec 25 -PollMs 400 -Description "probe-a.exe TCP allow filter to activate" -Condition {
        $r = Invoke-Probe $probeA @("tcp", "1.1.1.1:443", "4000")
        return ($r.ExitCode -eq 0 -and $r.Data.ok -eq $true)
    } | Out-Null
    Assert-True $true "probe-a.exe TCP allowed after toggling rule enabled=true"

    $aUdpDenied = Invoke-Probe $probeA @("udp", "1.1.1.1:53", "1500")
    Assert-True ($aUdpDenied.ExitCode -ne 0) "probe-a.exe UDP still blocked while allow_udp=false ($($aUdpDenied.Raw))"

    $tamperedDenied = Invoke-Probe $probeTampered @("tcp", "1.1.1.1:443", "3000")
    Assert-True ($tamperedDenied.ExitCode -ne 0 -and $tamperedDenied.Data.os_error -eq 10013) "probe-tampered.exe (different SHA-256) remains blocked"

    # 3c. Flip allow_udp = true -> UDP allowed, then back to false -> UDP blocked again
    $rAOnBoth = New-HashRule $ruleAId "Probe A" $probeA $inspA.sha256 $true $true $true $null
    $null = Invoke-CurbIpc @{ op = "upsert_rule"; token = $token; rule = $rAOnBoth }
    Wait-Until -TimeoutSec 25 -PollMs 400 -Description "probe-a.exe UDP allow filter to activate" -Condition {
        $r = Invoke-Probe $probeA @("udp", "1.1.1.1:53", "1500")
        return ($r.ExitCode -eq 0 -and $r.Data.ok -eq $true)
    } | Out-Null
    Assert-True $true "probe-a.exe UDP allowed after toggling allow_udp=true"

    $null = Invoke-CurbIpc @{ op = "upsert_rule"; token = $token; rule = $rAOnTcpOnly }
    Wait-Until -TimeoutSec 25 -PollMs 400 -Description "probe-a.exe UDP filter to revoke" -Condition {
        $r = Invoke-Probe $probeA @("udp", "1.1.1.1:53", "1500")
        return ($r.ExitCode -ne 0)
    } | Out-Null
    Assert-True $true "probe-a.exe UDP immediately re-blocked after toggling allow_udp=false"

    # 3d. Cross-app isolation: hold a live TCP socket in probe-b.exe while toggling/deleting probe-a.exe
    $rBOn = New-HashRule $ruleBId "Probe B" $probeB $inspB.sha256 $true $true $true $null
    $null = Invoke-CurbIpc @{ op = "upsert_rule"; token = $token; rule = $rBOn }
    Wait-Until -TimeoutSec 25 -PollMs 400 -Description "probe-b.exe allow filter to activate" -Condition {
        $r = Invoke-Probe $probeB @("tcp", "1.1.1.1:443", "4000")
        return ($r.ExitCode -eq 0 -and $r.Data.ok -eq $true)
    } | Out-Null

    $holdB = Start-HoldProbe $probeB "cross-app-isolation"

    # Toggle probe-a OFF -> ON -> DELETE -> UPSERT while probe-b holds its socket open
    $null = Invoke-CurbIpc @{ op = "upsert_rule"; token = $token; rule = $rAOff }
    Wait-Until -TimeoutSec 25 -PollMs 400 -Description "probe-a.exe to block on toggle OFF" -Condition {
        $r = Invoke-Probe $probeA @("tcp", "1.1.1.1:443", "3000")
        return ($r.ExitCode -ne 0 -and $r.Data.os_error -eq 10013)
    } | Out-Null
    Assert-True $true "probe-a.exe blocked on per-app toggle OFF"

    $null = Invoke-CurbIpc @{ op = "upsert_rule"; token = $token; rule = $rAOnBoth }
    Wait-Until -TimeoutSec 25 -PollMs 400 -Description "probe-a.exe to allow on toggle ON" -Condition {
        $r = Invoke-Probe $probeA @("tcp", "1.1.1.1:443", "4000")
        return ($r.ExitCode -eq 0 -and $r.Data.ok -eq $true)
    } | Out-Null
    Assert-True $true "probe-a.exe allowed on per-app toggle ON"

    $null = Invoke-CurbIpc @{ op = "delete_rule"; token = $token; id = $ruleAId }
    Wait-Until -TimeoutSec 25 -PollMs 400 -Description "probe-a.exe to block after delete_rule" -Condition {
        $r = Invoke-Probe $probeA @("tcp", "1.1.1.1:443", "3000")
        return ($r.ExitCode -ne 0 -and $r.Data.os_error -eq 10013)
    } | Out-Null
    Assert-True $true "probe-a.exe blocked after delete_rule"

    $null = Invoke-CurbIpc @{ op = "upsert_rule"; token = $token; rule = $rAOnBoth }
    Wait-Until -TimeoutSec 25 -PollMs 400 -Description "probe-a.exe to allow after re-upsert" -Condition {
        $r = Invoke-Probe $probeA @("tcp", "1.1.1.1:443", "4000")
        return ($r.ExitCode -eq 0 -and $r.Data.ok -eq $true)
    } | Out-Null

    Stop-AndAssertHoldProbe $holdB

    # -------------------------------------------------------------------------
    # Stage 4: Per-App DNS Whitelist Toggle
    # -------------------------------------------------------------------------
    Write-Step "Stage 4: Testing per-app DNS whitelist enforcement and removal"

    $rAWhitelist = New-HashRule $ruleAId "Probe A" $probeA $inspA.sha256 $true $true $false @("www.msftconnecttest.com")
    $null = Invoke-CurbIpc @{ op = "upsert_rule"; token = $token; rule = $rAWhitelist }

    Wait-Until -TimeoutSec 25 -PollMs 400 -Description "probe-a.exe to reach whitelisted domain" -Condition {
        $r = Invoke-Probe $probeA @("http", "www.msftconnecttest.com", "80", "/connecttest.txt", "4000")
        return ($r.ExitCode -eq 0 -and $r.Data.ok -eq $true)
    } | Out-Null
    Assert-True $true "probe-a.exe reached whitelisted domain www.msftconnecttest.com"

    $nonWhitelisted = Invoke-Probe $probeA @("http", "example.com", "80", "/", "4000")
    Assert-True ($nonWhitelisted.ExitCode -ne 0) "probe-a.exe blocked from non-whitelisted domain example.com ($($nonWhitelisted.Raw))"

    # Remove DNS whitelist -> example.com should work again
    $null = Invoke-CurbIpc @{ op = "upsert_rule"; token = $token; rule = $rAOnBoth }
    Wait-Until -TimeoutSec 25 -PollMs 400 -Description "probe-a.exe to reach example.com after clearing whitelist" -Condition {
        $r = Invoke-Probe $probeA @("http", "example.com", "80", "/", "4000")
        return ($r.ExitCode -eq 0 -and $r.Data.ok -eq $true)
    } | Out-Null
    Assert-True $true "probe-a.exe reached example.com after removing DNS whitelist"

    # -------------------------------------------------------------------------
    # Stage 5: Wi-Fi / Connectivity-Drop Regressions
    #   5a. Live-socket survival across Enforcing -> Disabled (ALE teardown order)
    #   5b. Rapid global toggle storm (DNS upstream & NCSI preservation)
    # -------------------------------------------------------------------------
    Write-Step "Stage 5: Testing Wi-Fi/connectivity-drop regressions (ALE teardown + rapid global toggle storm)"

    # 5a. Hold a persistent socket in probe-b.exe while tearing down Enforcing -> Disabled
    $holdTeardown = Start-HoldProbe $probeB "global-disable-teardown"
    $null = Set-CurbMode $token "disabled"

    Wait-Until -TimeoutSec 15 -PollMs 300 -Description "virtual adapter DNS to restore to $VirtualAdapterCanaryDns on Disabled" -Condition {
        $dns = @(Get-AdapterV4Dns $VirtualAdapterIdx)
        return ($dns -contains $VirtualAdapterCanaryDns -and ($dns -notcontains "127.0.0.1"))
    } | Out-Null
    Assert-True $true "Virtual adapter DNS restored to $VirtualAdapterCanaryDns after Enforcing -> Disabled"

    foreach ($orig in $PrimaryAdapterBackup) {
        $curDns = @(Get-AdapterV4Dns $orig.Index)
        Assert-True ($curDns -notcontains "127.0.0.1") "Primary adapter (ifIndex=$($orig.Index)) no longer points to 127.0.0.1 after Disabled"
    }

    Stop-AndAssertHoldProbe $holdTeardown

    # 5b. Rapid global toggle storm: 3 back-to-back Enforcing <-> Disabled cycles
    for ($cycle = 1; $cycle -le 3; $cycle++) {
        Write-Host "  -- Global toggle storm cycle $cycle/3 --" -ForegroundColor DarkCyan
        $null = Set-CurbMode $token "enforcing"

        Wait-Until -TimeoutSec 15 -PollMs 300 -Description "cycle $cycle Enforcing DNS redirect" -Condition {
            $dns = @(Get-AdapterV4Dns $VirtualAdapterIdx)
            return ($dns.Count -eq 1 -and $dns[0] -eq "127.0.0.1")
        } | Out-Null

        # Verify NCSI / DNS proxy still resolves cleanly (no lost last_good_upstreams)
        Wait-Until -TimeoutSec 12 -PollMs 400 -Description "cycle $cycle Enforcing NCSI/DNS resolution" -Condition {
            $r = Invoke-Probe $probeA @("http", "www.msftconnecttest.com", "80", "/connecttest.txt", "4000")
            return ($r.ExitCode -eq 0 -and $r.Data.ok -eq $true)
        } | Out-Null

        # Verify blocked probe is actually blocked
        Wait-Until -TimeoutSec 10 -PollMs 300 -Description "cycle $cycle Enforcing WFP block" -Condition {
            $r = Invoke-Probe $probeBlocked @("tcp", "1.1.1.1:443", "3000")
            return ($r.ExitCode -ne 0 -and $r.Data.os_error -eq 10013)
        } | Out-Null

        $null = Set-CurbMode $token "disabled"

        Wait-Until -TimeoutSec 15 -PollMs 300 -Description "cycle $cycle Disabled DNS restore" -Condition {
            $dns = @(Get-AdapterV4Dns $VirtualAdapterIdx)
            return ($dns -contains $VirtualAdapterCanaryDns -and ($dns -notcontains "127.0.0.1"))
        } | Out-Null

        Wait-Until -TimeoutSec 10 -PollMs 300 -Description "cycle $cycle Disabled unblock" -Condition {
            $r = Invoke-Probe $probeBlocked @("tcp", "1.1.1.1:443", "4000")
            return ($r.ExitCode -eq 0 -and $r.Data.ok -eq $true)
        } | Out-Null

        Assert-True $true "Toggle storm cycle $cycle/3 preserved DNS upstreams, NCSI, and clean teardown"
    }

    # -------------------------------------------------------------------------
    # Stage 6: Graceful Service Stop/Restart Recovery & Clean Uninstall
    # -------------------------------------------------------------------------
    Write-Step "Stage 6: Testing graceful service stop/restart recovery and zero-residue uninstall"

    $null = Set-CurbMode $token "enforcing"
    Wait-Until -TimeoutSec 10 -PollMs 300 -Description "WFP block active before service stop" -Condition {
        $r = Invoke-Probe $probeBlocked @("tcp", "1.1.1.1:443", "3000")
        return ($r.ExitCode -ne 0 -and $r.Data.os_error -eq 10013)
    } | Out-Null

    # Graceful Stop-Service must restore DNS & clear filters so machine is never stranded
    Stop-Service -Name $ServiceName
    Wait-Until -TimeoutSec 15 -PollMs 300 -Description "DNS restore on graceful service stop" -Condition {
        $dns = @(Get-AdapterV4Dns $VirtualAdapterIdx)
        return ($dns -contains $VirtualAdapterCanaryDns -and ($dns -notcontains "127.0.0.1"))
    } | Out-Null
    $unblockedOnStop = Invoke-Probe $probeBlocked @("tcp", "1.1.1.1:443", "4000")
    Assert-True ($unblockedOnStop.ExitCode -eq 0) "Graceful CurbService stop cleared WFP filters and restored adapter DNS"

    # Restarting CurbService must automatically re-engage Enforcing mode
    Start-Service -Name $ServiceName
    $null = Wait-ForCurbPipe 15
    Wait-Until -TimeoutSec 15 -PollMs 300 -Description "Enforcing mode to re-engage on service restart" -Condition {
        $r = Invoke-Probe $probeBlocked @("tcp", "1.1.1.1:443", "3000")
        return ($r.ExitCode -ne 0 -and $r.Data.os_error -eq 10013)
    } | Out-Null
    Assert-True $true "CurbService automatically re-engaged WFP enforcement after restart"

    # Emergency-disable + uninstall must leave zero Curb WFP filters and restored DNS
    & $CliPath emergency-disable
    Assert-True ($LASTEXITCODE -eq 0) "curb-cli emergency-disable exited 0"
    & $CliPath uninstall
    Assert-True ($LASTEXITCODE -eq 0) "curb-cli uninstall exited 0"

    Wait-Until -TimeoutSec 15 -PollMs 300 -Description "virtual adapter DNS restored after uninstall" -Condition {
        $dns = @(Get-AdapterV4Dns $VirtualAdapterIdx)
        return ($dns -contains $VirtualAdapterCanaryDns -and ($dns -notcontains "127.0.0.1"))
    } | Out-Null

    $postUninstallConn = Invoke-Probe $probeBlocked @("tcp", "1.1.1.1:443", "4000")
    Assert-True ($postUninstallConn.ExitCode -eq 0) "Outbound connectivity fully restored after uninstall"

    # Dump live WFP filters and verify zero Curb filters remain
    $wfpXml = Join-Path $TempRoot "wfp-filters.xml"
    & netsh wfp show filters file=$wfpXml | Out-Null
    if (Test-Path $wfpXml) {
        $wfpText = Get-Content $wfpXml -Raw
        Assert-True ($wfpText -notmatch "Curb Internet Limiter") "Zero Curb WFP filters remain in BFE after uninstall"
    }

    Write-Host "`nALL WINDOWS LIVE WFP & VIRTUAL ADAPTER E2E TESTS PASSED!" -ForegroundColor Green
}
finally {
    # Disarm watchdog first
    try { Set-Content -Path $WatchdogCancelFile -Value "done" -Encoding ASCII } catch { }

    # Always ensure Curb is disabled and uninstalled even on test failure
    try { & $CliPath emergency-disable | Out-Null } catch { }
    try {
        if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
            & $CliPath uninstall | Out-Null
        }
    }
    catch { }

    # Ensure primary runner adapters are never left pointing at 127.0.0.1
    foreach ($orig in $PrimaryAdapterBackup) {
        try {
            $cur = @(Get-AdapterV4Dns $orig.Index)
            if ($cur -contains "127.0.0.1") {
                if ($orig.Servers -and $orig.Servers.Count -gt 0) {
                    Set-DnsClientServerAddress -InterfaceIndex $orig.Index -ServerAddresses $orig.Servers -ErrorAction SilentlyContinue
                }
                else {
                    Set-DnsClientServerAddress -InterfaceIndex $orig.Index -ResetServerAddresses -ErrorAction SilentlyContinue
                }
            }
        }
        catch { }
    }

    # Remove the KM-TEST virtual adapter
    if ($VirtualAdapterPnpId) {
        try {
            & pnputil.exe /remove-device $VirtualAdapterPnpId | Out-Null
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
