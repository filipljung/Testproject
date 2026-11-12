#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Steg 4 – signerar den utfärdande CA:ns certifikatbegäran på ROOTCA.

.DESCRIPTION
    Skickar in begäran till rot-CA:n, utfärdar den om den hamnar i väntande läge
    och hämtar ut certifikatet. En fristående CA lägger som standard begäran i kö,
    vilket är avsiktligt: varje underordnad CA ska godkännas aktivt.
#>
[CmdletBinding()]
param(
    [string]$RequestFile = 'C:\Transfer\SubCA.req',
    [string]$CertFile    = 'C:\Transfer\SubCA.crt'
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\lib\LabCommon.psm1') -Force
$cfg = Get-LabConfig
$caConfig = "$env:COMPUTERNAME\$($cfg.RootCAName)"

if (-not (Test-Path $RequestFile)) { throw "Hittar inte $RequestFile. Kopiera SubCA.req från SUBCA01 först." }
if (Test-Path $CertFile) { Remove-Item $CertFile -Force }

Write-Step "Visar begäran innan den signeras"
Invoke-Native certutil.exe @('-dump', $RequestFile) | Select-String -Pattern 'Subject:|CN=|Public Key Length' | Out-Host
$answer = Read-Host 'Stämmer ämnesnamnet med den utfärdande CA:n? Skriv JA för att signera'
if ($answer -ne 'JA') { Write-Warning 'Avbrutet.'; return }

Write-Step "Skickar in begäran till $caConfig"
$submit = Invoke-Native certreq.exe @('-config', $caConfig, '-submit', '-f', $RequestFile, $CertFile)
$requestId = [regex]::Match(($submit -join "`n"), 'RequestId:\s*"?(\d+)').Groups[1].Value
if (-not $requestId) { throw "Kunde inte läsa RequestId:`n$($submit -join "`n")" }

if (-not (Test-Path $CertFile)) {
    Write-Step "Begäran $requestId väntar – utfärdar den"
    Invoke-Native certutil.exe @('-config', $caConfig, '-resubmit', $requestId) | Out-Null
    Invoke-Native certreq.exe  @('-config', $caConfig, '-retrieve', '-f', $requestId, $CertFile) | Out-Null
}

$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $CertFile
Write-Host "`nUtfärdat:     $($cert.Subject)"
Write-Host "Utfärdare:    $($cert.Issuer)"
Write-Host "Giltigt till: $($cert.NotAfter)"
Write-Host "Tumavtryck:   $($cert.Thumbprint)"
Write-Host "`nKopiera $CertFile tillbaka till \\$($cfg.SubCA.IP)\Transfer och kör 05-SUBCA-Complete.ps1." -ForegroundColor Green
Write-Host 'Stäng sedan av ROOTCA och koppla bort nätverkskortet.' -ForegroundColor Green
