#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Steg 6 – publicerar labbens certifikatmallar och skapar en GPO för automatisk registrering.

.DESCRIPTION
    Mallarna skapas först i certtmpl.msc enligt bygginstruktionen. Skriptet kontrollerar
    att de finns i AD, publicerar dem på CA:n och skapar/länkar GPO:n
    "PKI - Automatisk certifikatregistrering" på domännivå (dator- och användardel).
#>
[CmdletBinding()]
param([string[]]$TemplateName = @('LabDator', 'LabAnvandare', 'LabWebbserver'))

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\lib\LabCommon.psm1') -Force
Install-WindowsFeature RSAT-AD-PowerShell, GPMC | Out-Null
Import-Module ActiveDirectory, GroupPolicy, ADCSAdministration

$configNC    = (Get-ADRootDSE).configurationNamingContext
$templatesDN = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
$domainDN    = (Get-ADDomain).DistinguishedName

Write-Step 'Publicerar certifikatmallar'
$published = @(Get-CATemplate | Select-Object -ExpandProperty Name)
foreach ($t in $TemplateName) {
    if (-not (Get-ADObject -SearchBase $templatesDN -SearchScope OneLevel -Filter "cn -eq '$t'")) {
        Write-Warning "Mallen '$t' finns inte i AD. Skapa den i certtmpl.msc (bygginstruktionen, steg 9)."
        continue
    }
    if ($t -in $published) { Write-Host "  $t är redan publicerad"; continue }
    Add-CATemplate -Name $t -Force
    Write-Host "  $t publicerad" -ForegroundColor Green
}

Write-Step 'Skapar GPO för automatisk certifikatregistrering'
$gpoName = 'PKI - Automatisk certifikatregistrering'
if (-not (Get-GPO -Name $gpoName -ErrorAction SilentlyContinue)) {
    New-GPO -Name $gpoName -Comment 'Aktiverar autoenrollment med förnyelse och borttagning av spärrade certifikat.' | Out-Null
}
# AEPolicy 7 = registrera, förnya utgående/väntande och uppdatera certifikat som använder mallar.
foreach ($hive in 'HKLM', 'HKCU') {
    $key = "$hive\Software\Policies\Microsoft\Cryptography\AutoEnrollment"
    Set-GPRegistryValue -Name $gpoName -Key $key -ValueName 'AEPolicy' -Type DWord -Value 7 | Out-Null
    Set-GPRegistryValue -Name $gpoName -Key $key -ValueName 'OfflineExpirationPercent' -Type DWord -Value 10 | Out-Null
    Set-GPRegistryValue -Name $gpoName -Key $key -ValueName 'OfflineExpirationStoreNames' -Type String -Value 'MY' | Out-Null
}
$linked = (Get-GPInheritance -Target $domainDN).GpoLinks | Where-Object DisplayName -eq $gpoName
if (-not $linked) { New-GPLink -Name $gpoName -Target $domainDN -LinkEnabled Yes | Out-Null }
Write-Host "  GPO '$gpoName' länkad till $domainDN" -ForegroundColor Green

Write-Host "`nKör 'gpupdate /force' och 'certutil -pulse' på en klient för att testa direkt." -ForegroundColor Green
