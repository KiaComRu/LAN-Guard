#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $PublishDirectory,
    [Parameter(Mandatory)][uri] $Server,
    [ValidateRange(1, 10080)][int] $ScanMinutes = 720
)

$ErrorActionPreference = 'Stop'
$serviceName = 'LanGuardAgent'
$source = (Resolve-Path -LiteralPath $PublishDirectory).Path
$target = Join-Path $env:ProgramFiles 'LanGuard'
$state = Join-Path $env:ProgramData 'LanGuard'
$binary = Join-Path $target 'LanGuard.Agent.exe'
if ($Server.Scheme -ne 'https' -or $Server.AbsolutePath -ne '/' -or $Server.Query -or $Server.Fragment -or $Server.UserInfo) {
    throw 'Server must be an HTTPS origin.'
}
if (-not (Test-Path -LiteralPath (Join-Path $source 'LanGuard.Agent.exe') -PathType Leaf)) {
    throw 'Published LanGuard.Agent.exe was not found.'
}
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    throw 'LanGuardAgent is already installed.'
}
if (Test-Path -LiteralPath (Join-Path $state 'identity.bin')) {
    throw 'An existing agent identity was found. Review it before reinstalling.'
}
$token = Read-Host 'Enrollment token' -AsSecureString
$plaintext = [System.Net.NetworkCredential]::new('', $token).Password.Trim()
if ($plaintext -notmatch '\A[0-9a-fA-F]{64}\z') {
    throw 'Invalid enrollment token format.'
}

foreach ($folder in @($target, $state)) {
    if (Test-Path -LiteralPath $folder) {
        if ((Get-Item -LiteralPath $folder -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Refusing reparse point: $folder"
        }
        if (Get-ChildItem -LiteralPath $folder -Force | Select-Object -First 1) {
            throw "Target directory must be empty: $folder"
        }
    } else {
        New-Item -ItemType Directory -Path $folder | Out-Null
    }
    # Use well-known SIDs so this also works on localized Windows installations.
    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $administrators = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $acl.SetOwner($administrators)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $identity = [System.Security.Principal.SecurityIdentifier]::new($sid)
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $folder -AclObject $acl
}

Get-ChildItem -LiteralPath $source | Copy-Item -Destination $target -Recurse
$config = @{ Agent = @{ Server = $Server.AbsoluteUri; ScanMinutes = $ScanMinutes; HeartbeatSeconds = 30; RotationDays = 30 } }
$config | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $state 'agent.json') -Encoding UTF8
Set-Content -LiteralPath (Join-Path $state 'enrollment.token') -Value $plaintext -NoNewline -Encoding ASCII
$plaintext = $null
New-Service -Name $serviceName -DisplayName 'LAN Guard Agent' -BinaryPathName ('"' + $binary + '"') -StartupType Automatic |
    Out-Null
Start-Service -Name $serviceName
Get-Service -Name $serviceName
