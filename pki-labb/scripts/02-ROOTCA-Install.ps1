#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Steg 2 – installerar den fristående rot-CA:n på ROOTCA (ej domänansluten).

.DESCRIPTION
    Körning 1: statisk IP utan gateway och datornamn, omstart.
    Körning 2: skriver CAPolicy.inf, installerar AD CS som fristående rot-CA, sätter
               giltighetstider, CDP/AIA och granskning, publicerar CRL och lägger
               rotcertifikat och CRL i C:\Transfer för överföring till SUBCA01.
#>
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\lib\LabCommon.psm1') -Force
$cfg = Get-LabConfig
$me  = $cfg.RootCA

# --- Körning 1 -------------------------------------------------------------
if (-not (Get-NetIPAddress -IPAddress $me.IP -ErrorAction SilentlyContinue)) {
    Write-Step 'Sätter statisk IP-adress (ingen gateway – rot-CA:n ska inte nå internet)'
    Set-LabNetwork -IP $me.IP -PrefixLength $cfg.PrefixLength -Dns $cfg.DC.IP
}
if ($env:COMPUTERNAME -ne $me.Name) {
    Write-Step "Byter datornamn till $($me.Name) och startar om"
    Rename-Computer -NewName $me.Name -Restart -Force
    return
}
if (Get-Service certsvc -ErrorAction SilentlyContinue) {
    Write-Warning 'AD CS är redan installerat på den här servern. Avbryter.'
    return
}

# --- Körning 2 -------------------------------------------------------------
Write-Step 'Skriver CAPolicy.inf'
Set-CAPolicyInf @'
[Version]
Signature="$Windows NT$"

[Certsrv_Server]
RenewalKeyLength=4096
RenewalValidityPeriod=Years
RenewalValidityPeriodUnits=20
CRLPeriod=Weeks
CRLPeriodUnits=26
CRLDeltaPeriod=Days
CRLDeltaPeriodUnits=0
AlternateSignatureAlgorithm=0

[BasicConstraintsExtension]
Critical=Yes
'@

Write-Step "Installerar fristående rot-CA $($cfg.RootCAName)"
Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools | Out-Null
Install-AdcsCertificationAuthority -CAType StandaloneRootCA `
    -CACommonName $cfg.RootCAName -CADistinguishedNameSuffix $cfg.CADNSuffix `
    -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -KeyLength 4096 `
    -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 20 -Force | Out-Null

Write-Step 'Konfigurerar giltighetstider, CDP/AIA och granskning'
$enroll = Join-Path $env:windir 'System32\CertSrv\CertEnroll'
$http   = "http://$($cfg.PkiHost)/pki"
# Flagga 1 = publicera till platsen, 2 = ta med i utfärdade certifikat.
# "\n" ska stå bokstavligt; certutil tolkar det som radbrytning.
Set-CARegistry @{
    ValidityPeriod        = 'Years'
    ValidityPeriodUnits   = 10        # underordnade CA-certifikat får 10 år
    CRLPeriod             = 'Weeks'
    CRLPeriodUnits        = 26
    CRLOverlapPeriod      = 'Weeks'
    CRLOverlapPeriodUnits = 2
    CRLDeltaPeriodUnits   = 0         # ingen delta-CRL på en offline-CA
    CRLPublicationURLs    = "1:$enroll\%3%8%9.crl\n2:$http/%3%8%9.crl"
    CACertPublicationURLs = "1:$enroll\%1_%3%4.crt\n2:$http/%1_%3%4.crt"
    AuditFilter           = 127
}
Enable-CAAuditing

Restart-Service certsvc
Start-Sleep -Seconds 5
Invoke-Native certutil.exe @('-crl') | Out-Null

Write-Step 'Lägger rotcertifikat och CRL i C:\Transfer'
New-Item -Path 'C:\Transfer' -ItemType Directory -Force | Out-Null
Copy-Item -Path "$enroll\*.crt", "$enroll\*.crl" -Destination 'C:\Transfer' -Force
Get-ChildItem 'C:\Transfer' | Format-Table Name, Length, LastWriteTime -AutoSize

$rootCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -like "CN=$($cfg.RootCAName),*" | Select-Object -First 1
Write-Host "Rotcertifikat: $($rootCert.Subject)"
Write-Host "Tumavtryck:    $($rootCert.Thumbprint)"
Write-Host "Giltigt till:  $($rootCert.NotAfter)"
Write-Host "`nKopiera filerna i C:\Transfer till \\$($cfg.SubCA.IP)\Transfer (se bygginstruktionen)." -ForegroundColor Green
