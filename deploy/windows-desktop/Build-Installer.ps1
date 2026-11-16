[CmdletBinding()]
param(
    [string] $Dotnet = 'dotnet',
    [string] $MakeNsis = 'makensis.exe'
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$project = Join-Path $repo 'src\LanGuard.Desktop\LanGuard.Desktop.csproj'
$icon = Join-Path $repo 'src\LanGuard.Desktop\Assets\LanGuard.ico'
$publish = Join-Path $repo 'artifacts\desktop'
$output = Join-Path $repo 'artifacts'
$installer = Join-Path $output 'LAN-Guard-Setup-x64.exe'

& $Dotnet publish $project -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -p:DebugType=None -o $publish
if ($LASTEXITCODE -ne 0) { throw 'Desktop publish failed.' }

& $MakeNsis '/WX' '/INPUTCHARSET' 'UTF8' "/DPublishDir=$publish" "/DSetupDir=$output" "/DAppIcon=$icon" (Join-Path $PSScriptRoot 'LanGuard.nsi')
if ($LASTEXITCODE -ne 0) { throw 'Setup compilation failed.' }
Get-Item -LiteralPath $installer
