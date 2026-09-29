param(
    [string]$ServiceName = "almighty-blocker",
    [string]$DisplayName = "Almighty Blocker",
    [string]$Description = "Keeps hosts redirects enforced in background",
    [string]$ExecutablePath = ".\dist\almighty-blocker-windows-amd64.exe",
    [string]$StateDir = "$env:ProgramData\almighty-blocker",
    [switch]$StartService
)

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script as Administrator."
}

$resolvedExe = (Resolve-Path $ExecutablePath).Path
if (-not (Test-Path -LiteralPath $resolvedExe -PathType Leaf)) {
    throw "ExecutablePath must point to a file: $resolvedExe"
}
New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
$installDirectory = Join-Path $env:ProgramFiles "Almighty Blocker"
$installedExe = Join-Path $installDirectory "almighty-blocker.exe"

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -ne $existing -and $existing.Status -ne 'Stopped') {
    Stop-Service -Name $ServiceName -Force
    (Get-Service -Name $ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}

New-Item -ItemType Directory -Path $installDirectory -Force | Out-Null
& icacls.exe $installDirectory /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Could not restrict the protected install directory ACL."
}
Copy-Item -LiteralPath $resolvedExe -Destination $installedExe -Force

$binaryPathName = '"{0}" --role=primary --state-dir="{1}" --service-name="{2}"' -f $installedExe, $StateDir, $ServiceName

if ($null -eq $existing) {
    New-Service -Name $ServiceName -BinaryPathName $binaryPathName -DisplayName $DisplayName -Description $Description -StartupType Automatic
} else {
    sc.exe config $ServiceName binPath= $binaryPathName start= auto | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not update service '$ServiceName'."
    }
}

sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Could not configure crash recovery for service '$ServiceName'."
}
sc.exe failureflag $ServiceName 1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Could not configure non-crash recovery for service '$ServiceName'."
}

if ($StartService) {
    Start-Service -Name $ServiceName
}

Get-Service -Name $ServiceName | Select-Object Name, DisplayName, Status, StartType
Write-Host "Protected executable: $installedExe"
