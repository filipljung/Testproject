#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Steg 5 – installerar det signerade CA-certifikatet på SUBCA01 och konfigurerar CA:n.

.DESCRIPTION
    Installerar certifikatet, sätter giltighetstider, CDP/AIA, delta-CRL och granskning,
    publicerar CRL och verifierar att alla filer i C:\pki nås över HTTP.
#>
[CmdletBinding()]
param([string]$CertFile = 'C:\Transfer\SubCA.crt')

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\lib\LabCommon.psm1') -Force
$cfg = Get-LabConfig

if (-not (Test-Path $CertFile)) { throw "Hittar inte $CertFile. Signera begäran på ROOTCA först." }

Write-Step 'Installerar CA-certifikatet'
Invoke-Native certutil.exe @('-installcert', $CertFile) | Out-Null
Start-Service certsvc

Write-Step 'Konfigurerar giltighetstider, CDP/AIA och granskning'
$enroll = Join-Path $env:windir 'System32\CertSrv\CertEnroll'
$http   = "http://$($cfg.PkiHost)/pki"
# 65 = publicera bas- och delta-CRL till platsen. 6 = ta med i CDP och i delta-CRL:ens "freshest CRL".
Set-CARegistry @{
    ValidityPeriod             = 'Years'
    ValidityPeriodUnits        = 2       # tak för slutcertifikat; mallarna sätter normalt kortare
    CRLPeriod                  = 'Weeks'
    CRLPeriodUnits             = 1
    CRLOverlapPeriod           = 'Days'
    CRLOverlapPeriodUnits      = 3
    CRLDeltaPeriod             = 'Days'
    CRLDeltaPeriodUnits        = 1
    CRLDeltaOverlapPeriod      = 'Hours'
    CRLDeltaOverlapPeriodUnits = 12
    CRLPublicationURLs         = "65:$enroll\%3%8%9.crl\n65:C:\pki\%3%8%9.crl\n6:$http/%3%8%9.crl"
    CACertPublicationURLs      = "1:$enroll\%1_%3%4.crt\n2:$http/%1_%3%4.crt"
    AuditFilter                = 127
}
Enable-CAAuditing

Restart-Service certsvc
Start-Sleep -Seconds 5
Invoke-Native certutil.exe @('-crl') | Out-Null
Copy-Item -Path "$enroll\*.crt" -Destination 'C:\pki' -Force

Write-Step 'Verifierar att CDP/AIA-filerna nås över HTTP'
$ok = $true
foreach ($f in Get-ChildItem 'C:\pki' -File) {
    $url = "$http/$([uri]::EscapeDataString($f.Name))"
    try {
        Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 10 | Out-Null
        Write-Host "  OK    $url" -ForegroundColor Green
    } catch {
        Write-Host "  FEL   $url ($($_.Exception.Message))" -ForegroundColor Red
        $ok = $false
    }
}

Write-Step 'Kontrollerar CA-certifikatets kedja och spärrstatus'
$subCrt = Get-ChildItem 'C:\pki' -Filter "*_$($cfg.SubCAName).crt" | Select-Object -First 1
$verify = Invoke-Native certutil.exe @('-verify', '-urlfetch', $subCrt.FullName)
$verify | Select-String -Pattern 'Verified|revocation|Revocation|ERROR|Error' | Out-Host

if ($ok) {
    Write-Host "`nUtfärdande CA klar. Öppna pkiview.msc och kontrollera att alla rader är OK." -ForegroundColor Green
    Write-Host 'Nästa steg: skapa certifikatmallarna (bygginstruktionen, steg 9) och kör 06-SUBCA-PublishTemplates.ps1.' -ForegroundColor Green
} else {
    Write-Warning 'En eller flera filer nås inte över HTTP. Se felsökningsavsnittet i bygginstruktionen.'
}
