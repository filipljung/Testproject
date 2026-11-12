<#
.SYNOPSIS
    Inventerar certifikat och spärrlistor och varnar för sådana som snart löper ut.

.DESCRIPTION
    Skriptet läser från en eller flera källor och ändrar ingenting:
      CA     Utfärdade certifikat i CA-databasen (certutil -view).
      Store  Certifikat i LocalMachine\My på en eller flera servrar (lokalt eller via WinRM).
      Crl    Spärrlistor (.crl) i en publiceringsmapp, t.ex. C:\pki.

    Varje post får status OK, Varning, Kritisk, Utgånget eller Fel.
    Spärrlistor har egna tröskelvärden eftersom de är kortlivade: en delta-CRL som gäller
    ett dygn är normal, men en rot-CRL som inte förnyas i tid stoppar all spärrkontroll.

    Avslutningskod: 0 = allt OK, 1 = minst en varning, 2 = minst en kritisk, utgången eller felaktig post.

.PARAMETER IncludeSuperseded
    Som standard visas bara det senast utfärdade certifikatet per namn och mall från
    CA-databasen, eftersom automatisk förnyelse lämnar det äldre certifikatet giltigt.

.PARAMETER ExpiredGraceDays
    Certifikat i CA-databasen som gick ut för mer än så här många dagar sedan tas inte med.

.PARAMETER OfflineCrlPattern
    Filnamnsmönster för CRL:er från offline-CA:er. Dessa förnyas manuellt och får
    därför tröskelvärden i dagar i stället för timmar.

.EXAMPLE
    .\Get-PkiExpiryReport.ps1
    Körs på den utfärdande CA:n. Kontrollerar CA-databasen och CRL:erna i C:\pki.

.EXAMPLE
    .\Get-PkiExpiryReport.ps1 -Source Store -ComputerName DC01, SUBCA01 -WarningDays 90

.EXAMPLE
    .\Get-PkiExpiryReport.ps1 -Source CA, Crl, Store -OutputPath C:\Rapporter\pki.csv

.NOTES
    Datum tolkas enligt systemets språkinställningar. CRL-kontrollen läser fältet
    NextUpdate ur certutil -dump och är testad på engelskspråkig Windows Server.
#>
[CmdletBinding()]
param(
    [ValidateSet('CA', 'Store', 'Crl')]
    [string[]]$Source = @('CA', 'Crl'),
    [string]$CAConfig,
    [string[]]$ComputerName = @($env:COMPUTERNAME),
    [string]$CrlFolder = 'C:\pki',

    [ValidateRange(1, 3650)][int]$WarningDays = 60,
    [ValidateRange(0, 3650)][int]$CriticalDays = 14,
    [ValidateRange(0, 3650)][int]$ExpiredGraceDays = 30,

    [ValidateRange(1, 720)][int]$CrlWarningHours = 24,
    [ValidateRange(0, 720)][int]$CrlCriticalHours = 6,
    [string]$OfflineCrlPattern = '*Root*',
    [ValidateRange(1, 365)][int]$OfflineCrlWarningDays = 30,
    [ValidateRange(0, 365)][int]$OfflineCrlCriticalDays = 7,

    [switch]$IncludeSuperseded,
    [string]$OutputPath,
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
$now = Get-Date
$certWarn = [timespan]::FromDays($WarningDays)
$certCrit = [timespan]::FromDays($CriticalDays)

function ConvertTo-DateOrNull {
    param([string]$Text)
    if (-not $Text) { return $null }
    $Text = $Text.Trim().Trim('"')
    $d = [datetime]::MinValue
    foreach ($culture in [Globalization.CultureInfo]::CurrentCulture, [Globalization.CultureInfo]::InvariantCulture) {
        if ([datetime]::TryParse($Text, $culture, [Globalization.DateTimeStyles]::AllowWhiteSpaces, [ref]$d)) { return $d }
    }
    return $null
}

function New-ReportRow {
    param(
        [string]$Source, [string]$Object, [string]$Template, [string]$Issuer,
        [Nullable[datetime]]$NotAfter, [string]$Detail,
        [timespan]$Warn = $certWarn, [timespan]$Crit = $certCrit,
        [string]$ForceStatus
    )
    $status = $ForceStatus
    $days = $null
    if ($NotAfter) {
        $left = $NotAfter.Value - $now
        $days = [math]::Round($left.TotalDays, 1)
        if (-not $status) {
            $status = if ($left.Ticks -lt 0) { 'Utgånget' }
                      elseif ($left -le $Crit) { 'Kritisk' }
                      elseif ($left -le $Warn) { 'Varning' }
                      else { 'OK' }
        }
    }
    if (-not $status) { $status = 'Fel' }
    [pscustomobject]@{
        Status     = $status
        DagarKvar  = $days
        GiltigTill = $NotAfter
        Kalla      = $Source
        Objekt     = $Object
        Mall       = $Template
        Utfardare  = $Issuer
        Detalj     = $Detail
    }
}

function Get-CARows {
    $config = $CAConfig
    if (-not $config) {
        $active = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration' -ErrorAction SilentlyContinue).Active
        if (-not $active) { throw 'Ange -CAConfig ("server\CA-namn") eller kör skriptet på CA-servern.' }
        $config = "$([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName)\$active"
    }

    # Mallar med schemaversion 2+ visas som OID i CA-databasen. Översätt till visningsnamn om AD finns.
    $templateNames = @{}
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        try {
            $cn = (Get-ADRootDSE).configurationNamingContext
            Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$cn" -SearchScope OneLevel `
                -Filter "objectClass -eq 'pKICertificateTemplate'" -Properties displayName, 'msPKI-Cert-Template-OID' |
                ForEach-Object {
                    $templateNames[$_.Name] = $_.displayName
                    if ($_.'msPKI-Cert-Template-OID') { $templateNames[$_.'msPKI-Cert-Template-OID'] = $_.displayName }
                }
        } catch { Write-Verbose "Kunde inte läsa mallnamn från AD: $_" }
    }

    $cols = 'RequestID', 'RequesterName', 'CommonName', 'CertificateTemplate', 'NotAfter', 'SerialNumber'
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $raw = & certutil.exe -config $config -view -restrict 'Disposition=20' -out ($cols -join ',') csv 2>&1 | ForEach-Object { "$_" }
    $code = $LASTEXITCODE; $ErrorActionPreference = $prev
    if ($code -ne 0) { throw "certutil -view mot $config misslyckades (kod $code):`n$($raw -join "`n")" }

    $rows = $raw | Select-Object -Skip 1 | ConvertFrom-Csv -Header $cols | Where-Object { $_.RequestID -match '^\d+$' }

    $items = foreach ($r in $rows) {
        $tpl = ("$($r.CertificateTemplate)".Trim() -split '\s+')[0]
        if ($tpl -eq 'EMPTY') { $tpl = '' }
        $name = if ($r.CommonName -and $r.CommonName -ne 'EMPTY') { $r.CommonName } else { $r.RequesterName }
        [pscustomobject]@{
            Name     = $name
            Template = if ($templateNames.ContainsKey($tpl)) { $templateNames[$tpl] } else { $tpl }
            NotAfter = ConvertTo-DateOrNull $r.NotAfter
            Request  = $r.RequestID
            Serial   = $r.SerialNumber
        }
    }

    if (-not $IncludeSuperseded) {
        $items = $items | Group-Object Name, Template | ForEach-Object {
            $_.Group | Sort-Object NotAfter -Descending | Select-Object -First 1
        }
    }

    foreach ($i in $items) {
        if (-not $i.NotAfter) {
            New-ReportRow -Source 'CA' -Object $i.Name -Template $i.Template -Issuer $config `
                -Detail "Begäran $($i.Request): kunde inte tolka slutdatum" -ForceStatus 'Fel'
            continue
        }
        if ($i.NotAfter -lt $now.AddDays(-$ExpiredGraceDays)) { continue }
        New-ReportRow -Source 'CA' -Object $i.Name -Template $i.Template -Issuer $config `
            -NotAfter $i.NotAfter -Detail "Begäran $($i.Request), serienr $($i.Serial)"
    }
}

function Get-StoreRows {
    $sb = {
        Get-ChildItem -Path Cert:\LocalMachine\My | ForEach-Object {
            $ext = $_.Extensions | Where-Object { $_.Oid.Value -in '1.3.6.1.4.1.311.21.7', '1.3.6.1.4.1.311.20.2' } | Select-Object -First 1
            [pscustomobject]@{
                Subject    = $_.Subject
                Issuer     = $_.Issuer
                NotAfter   = $_.NotAfter
                Thumbprint = $_.Thumbprint
                Template   = if ($ext) { (($ext.Format($false) -split ',')[0] -replace '^Template=', '') -replace '\(\d[\d\.]+\)$', '' } else { '' }
            }
        }
    }
    foreach ($c in $ComputerName) {
        try {
            $certs = if ($c -in @($env:COMPUTERNAME, 'localhost', '.')) { & $sb } else { Invoke-Command -ComputerName $c -ScriptBlock $sb }
            foreach ($x in $certs) {
                New-ReportRow -Source "Store:$c" -Object $x.Subject -Template $x.Template -Issuer $x.Issuer `
                    -NotAfter $x.NotAfter -Detail "Tumavtryck $($x.Thumbprint)"
            }
        } catch {
            New-ReportRow -Source "Store:$c" -Object $c -Detail "Kunde inte läsa certifikatarkivet: $($_.Exception.Message)" -ForceStatus 'Fel'
        }
    }
}

function Get-CrlRows {
    if (-not (Test-Path $CrlFolder)) { Write-Warning "Mappen $CrlFolder finns inte – hoppar över CRL-kontrollen."; return }
    foreach ($f in Get-ChildItem -Path $CrlFolder -Filter '*.crl' -File) {
        $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        $dump = & certutil.exe -dump $f.FullName 2>&1 | ForEach-Object { "$_" }
        $ErrorActionPreference = $prev

        $kind = if ($f.BaseName.EndsWith('+')) { 'Delta-CRL' } else { 'Bas-CRL' }
        $offline = $f.Name -like $OfflineCrlPattern
        if ($offline) {
            $kind += ' (offline-CA)'
            $warn = [timespan]::FromDays($OfflineCrlWarningDays); $crit = [timespan]::FromDays($OfflineCrlCriticalDays)
        } else {
            $warn = [timespan]::FromHours($CrlWarningHours); $crit = [timespan]::FromHours($CrlCriticalHours)
        }

        $m = $dump | Select-String -Pattern '^\s*NextUpdate:\s*(.+?)\s*$' | Select-Object -First 1
        $next = if ($m) { ConvertTo-DateOrNull $m.Matches[0].Groups[1].Value } else { $null }
        if (-not $next) {
            New-ReportRow -Source 'CRL' -Object $f.Name -Template $kind -Detail 'Kunde inte läsa NextUpdate' -ForceStatus 'Fel'
            continue
        }
        New-ReportRow -Source 'CRL' -Object $f.Name -Template $kind -NotAfter $next -Detail $f.FullName -Warn $warn -Crit $crit
    }
}

# --- Huvudflöde -------------------------------------------------------------
$report = @()
if ('CA'    -in $Source) { $report += @(Get-CARows) }
if ('Store' -in $Source) { $report += @(Get-StoreRows) }
if ('Crl'   -in $Source) { $report += @(Get-CrlRows) }

$order  = @{ 'Utgånget' = 0; 'Fel' = 1; 'Kritisk' = 2; 'Varning' = 3; 'OK' = 4 }
$report = @($report | Sort-Object @{ Expression = { $order[$_.Status] } }, DagarKvar)

$report | Format-Table Status, DagarKvar, GiltigTill, Kalla, Objekt, Mall -AutoSize | Out-Host
$summary = $report | Group-Object Status | ForEach-Object { "$($_.Name): $($_.Count)" }
Write-Host ("Sammanfattning – " + ($(if ($summary) { $summary -join ', ' } else { 'inga poster' })))

if ($OutputPath) {
    $report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 -Delimiter ';'
    Write-Host "Rapport sparad: $OutputPath"
}
if ($PassThru) { $report }

if ($report | Where-Object { $_.Status -in 'Utgånget', 'Kritisk', 'Fel' }) { exit 2 }
if ($report | Where-Object { $_.Status -eq 'Varning' }) { exit 1 }
exit 0
