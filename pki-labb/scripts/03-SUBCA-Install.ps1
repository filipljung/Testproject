#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Steg 3 – förbereder SUBCA01 och installerar den utfärdande enterprise-CA:n.

.DESCRIPTION
    Skriptet avgör själv vilken fas som återstår:
      Körning 1: statisk IP, namn och domänanslutning, omstart.
      Körning 2: IIS-plats för CDP/AIA, DNS-alias, utdelningen Transfer.
                 Stannar om rot-CA:ns certifikat och CRL inte finns i C:\Transfer.
      Körning 3: publicerar rotcertifikatet i AD, installerar enterprise-CA:n och
                 skriver certifikatbegäran till C:\Transfer\SubCA.req.
    Kör körning 2 och 3 som domänadministratör (enterprise admin krävs för AD CS).
#>
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\lib\LabCommon.psm1') -Force
$cfg = Get-LabConfig
$me  = $cfg.SubCA

# --- Körning 1 -------------------------------------------------------------
if (-not (Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
    Write-Step 'Nätverk, datornamn och domänanslutning'
    if (-not (Get-NetIPAddress -IPAddress $me.IP -ErrorAction SilentlyContinue)) {
        Set-LabNetwork -IP $me.IP -PrefixLength $cfg.PrefixLength -Gateway $cfg.Gateway -Dns $cfg.DC.IP
    }
    $cred = Get-Credential -Message "Konto som får ansluta datorer till $($cfg.DomainName), t.ex. $($cfg.NetBIOS)\Administrator"
    $join = @{ DomainName = $cfg.DomainName; Credential = $cred; Restart = $true; Force = $true }
    if ($env:COMPUTERNAME -ne $me.Name) { $join.NewName = $me.Name }
    Add-Computer @join
    return
}
if (Get-Service certsvc -ErrorAction SilentlyContinue) {
    Write-Warning 'AD CS är redan installerat. Signera begäran på ROOTCA och kör sedan 05-SUBCA-Complete.ps1.'
    return
}

# --- Körning 2: förberedelser (idempotent) ---------------------------------
Write-Step 'Skapar publiceringsplats i IIS: http://<PkiHost>/pki'
New-Item -Path 'C:\pki', 'C:\Transfer' -ItemType Directory -Force | Out-Null
Install-WindowsFeature Web-Server, RSAT-AD-PowerShell -IncludeManagementTools | Out-Null
Import-Module WebAdministration
if (-not (Get-WebVirtualDirectory -Site 'Default Web Site' -Name 'pki')) {
    New-WebVirtualDirectory -Site 'Default Web Site' -Name 'pki' -PhysicalPath 'C:\pki' | Out-Null
}
# Delta-CRL har '+' i filnamnet; IIS blockerar det annars.
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location 'Default Web Site/pki' `
    -Filter 'system.webServer/security/requestFiltering' -Name 'allowDoubleEscaping' -Value $true
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location 'Default Web Site/pki' `
    -Filter 'system.webServer/directoryBrowse' -Name 'enabled' -Value $true

Write-Step "Skapar DNS-alias $($cfg.PkiHost) -> $($me.Name).$($cfg.DomainName)"
Invoke-Command -ComputerName $cfg.DC.Name -ArgumentList $cfg.DomainName, $cfg.PkiHost.Split('.')[0], "$($me.Name).$($cfg.DomainName)" -ScriptBlock {
    param($zone, $alias, $target)
    if (-not (Get-DnsServerResourceRecord -ZoneName $zone -Name $alias -ErrorAction SilentlyContinue)) {
        Add-DnsServerResourceRecordCName -ZoneName $zone -Name $alias -HostNameAlias $target
    }
}
Clear-DnsClientCache

Write-Step 'Delar ut C:\Transfer till domänadministratörer'
$domainSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.AccountDomainSid
$domainAdmins = (New-Object Security.Principal.SecurityIdentifier(
    [Security.Principal.WellKnownSidType]::AccountDomainAdminsSid, $domainSid)).Translate([Security.Principal.NTAccount]).Value
if (-not (Get-SmbShare -Name 'Transfer' -ErrorAction SilentlyContinue)) {
    New-SmbShare -Name 'Transfer' -Path 'C:\Transfer' -FullAccess $domainAdmins | Out-Null
}
try { Get-NetFirewallRule -Group '@FirewallAPI.dll,-28502' | Enable-NetFirewallRule } catch { Write-Warning "Kunde inte öppna brandväggen för fildelning: $_" }

$rootCrt = Get-ChildItem 'C:\Transfer' -Filter "*_$($cfg.RootCAName).crt" -ErrorAction SilentlyContinue | Select-Object -First 1
$rootCrl = Get-ChildItem 'C:\Transfer' -Filter "$($cfg.RootCAName)*.crl"   -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $rootCrt -or -not $rootCrl) {
    Write-Host "`nFörberedelserna är klara. Bygg ROOTCA (02-ROOTCA-Install.ps1), kopiera rot-CA:ns .crt och .crl till" -ForegroundColor Yellow
    Write-Host "\\$($me.IP)\Transfer och kör det här skriptet igen." -ForegroundColor Yellow
    return
}

# --- Körning 3: installation -----------------------------------------------
Write-Step 'Publicerar rotcertifikat och rot-CRL'
Copy-Item $rootCrt.FullName, $rootCrl.FullName -Destination 'C:\pki' -Force
Invoke-Native certutil.exe @('-dspublish', '-f', $rootCrt.FullName, 'RootCA') | Out-Null
Invoke-Native certutil.exe @('-addstore', '-f', 'Root', $rootCrt.FullName) | Out-Null
Invoke-Native certutil.exe @('-addstore', '-f', 'Root', $rootCrl.FullName) | Out-Null

$testUrl = "http://$($cfg.PkiHost)/pki/$($rootCrl.Name)"
try {
    Invoke-WebRequest -Uri $testUrl -UseBasicParsing -TimeoutSec 10 | Out-Null
    Write-Host "  Rot-CRL nås via $testUrl"
} catch {
    throw "Rot-CRL:en nås inte via $testUrl. Kontrollera DNS-aliaset och IIS innan du fortsätter. ($_)"
}

Write-Step 'Skriver CAPolicy.inf'
Set-CAPolicyInf @'
[Version]
Signature="$Windows NT$"

[Certsrv_Server]
RenewalKeyLength=4096
LoadDefaultTemplates=0
AlternateSignatureAlgorithm=0
'@

Write-Step "Installerar enterprise-CA $($cfg.SubCAName)"
Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools | Out-Null
Install-AdcsCertificationAuthority -CAType EnterpriseSubordinateCA `
    -CACommonName $cfg.SubCAName -CADistinguishedNameSuffix $cfg.CADNSuffix `
    -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -KeyLength 4096 `
    -HashAlgorithmName SHA256 -OutputCertRequestFile 'C:\Transfer\SubCA.req' `
    -Force -WarningAction SilentlyContinue | Out-Null

Write-Host "`nBegäran skriven till C:\Transfer\SubCA.req." -ForegroundColor Green
Write-Host 'Nästa steg: kopiera den till ROOTCA och kör 04-ROOTCA-SignSubCA.ps1.' -ForegroundColor Green
