param(
    [string]$ServiceName = "almighty-blocker"
)

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script as Administrator."
}

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -ne $svc -and $svc.Status -ne 'Stopped') {
    Stop-Service -Name $ServiceName -Force
    (Get-Service -Name $ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}

if ($null -ne $svc) {
    sc.exe delete $ServiceName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not delete service '$ServiceName'."
    }
    Write-Host "Service '$ServiceName' deleted."
} else {
    Write-Host "Service '$ServiceName' does not exist."
}

$installedExe = Join-Path $env:ProgramFiles "Almighty Blocker\almighty-blocker.exe"
if (Test-Path -LiteralPath $installedExe) {
    Remove-Item -LiteralPath $installedExe -Force
    Write-Host "Removed protected executable: $installedExe"
}
