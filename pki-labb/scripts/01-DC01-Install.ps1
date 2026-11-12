#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Steg 1 – bygger DC01: domänkontrollant, DNS, OU-struktur och testkonton.

.DESCRIPTION
    Skriptet körs tre gånger och avgör själv vilken fas som återstår:
      Körning 1: statisk IP och datornamn, omstart.
      Körning 2: installerar AD DS och skapar skogen, omstart.
      Körning 3: skapar OU-struktur, grupper och testkonton.
#>
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\lib\LabCommon.psm1') -Force
$cfg = Get-LabConfig
$me  = $cfg.DC

# --- Körning 1 -------------------------------------------------------------
if (-not (Get-NetIPAddress -IPAddress $me.IP -ErrorAction SilentlyContinue)) {
    Write-Step 'Sätter statisk IP-adress'
    Set-LabNetwork -IP $me.IP -PrefixLength $cfg.PrefixLength -Gateway $cfg.Gateway -Dns '127.0.0.1'
}
if ($env:COMPUTERNAME -ne $me.Name) {
    Write-Step "Byter datornamn till $($me.Name) och startar om"
    Rename-Computer -NewName $me.Name -Restart -Force
    return
}

# --- Körning 2 -------------------------------------------------------------
$role = (Get-CimInstance Win32_ComputerSystem).DomainRole   # 4/5 = domänkontrollant
if ($role -lt 4) {
    Write-Step "Installerar AD DS och skapar skogen $($cfg.DomainName)"
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
    $dsrm = Read-Host -AsSecureString 'Lösenord för katalogtjänståterställning (DSRM)'
    Install-ADDSForest -DomainName $cfg.DomainName -DomainNetbiosName $cfg.NetBIOS `
        -InstallDns -SafeModeAdministratorPassword $dsrm -Force
    return   # Install-ADDSForest startar om servern
}

# --- Körning 3 -------------------------------------------------------------
Write-Step 'Skapar OU-struktur, grupper och testkonton'
$domainDN = (Get-ADDomain).DistinguishedName
$orgDN    = "OU=$($cfg.OrgOU),$domainDN"

if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$orgDN'" -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name $cfg.OrgOU -Path $domainDN
}
foreach ($ou in 'Anstallda', 'Elever', 'Konsulter', 'Datorer', 'Servrar', 'Grupper', 'Administratorer') {
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq 'OU=$ou,$orgDN'" -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $ou -Path $orgDN
        Write-Host "  OU $ou"
    }
}

$groups = @{
    'PKI-Administratorer'         = 'Förvaltar PKI och certifikatmallar'
    'PKI-Webbserver-Registrerare' = 'Får begära webbservercertifikat (mallen LabWebbserver)'
}
foreach ($g in $groups.Keys) {
    if (-not (Get-ADGroup -Filter "Name -eq '$g'" -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name $g -GroupScope Global -GroupCategory Security -Path "OU=Grupper,$orgDN" -Description $groups[$g]
        Write-Host "  Grupp $g"
    }
}

$password = Read-Host -AsSecureString 'Gemensamt lösenord för testkontona'
foreach ($u in $cfg.TestUsers) {
    if (Get-ADUser -Filter "SamAccountName -eq '$($u.Sam)'" -ErrorAction SilentlyContinue) { continue }
    New-ADUser -Name "$($u.GivenName) $($u.Surname)" -GivenName $u.GivenName -Surname $u.Surname `
        -SamAccountName $u.Sam -UserPrincipalName "$($u.Sam)@$($cfg.DomainName)" `
        -Path "OU=$($u.OU),$orgDN" -AccountPassword $password -Enabled $true
    Write-Host "  Användare $($u.Sam)"
}

Write-Host "`nDC01 är klar. Fortsätt med 03-SUBCA-Install.ps1 på SUBCA01." -ForegroundColor Green
