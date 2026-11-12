<#
.SYNOPSIS
    Granskar AD CS-certifikatmallar och utfärdande CA:er efter kända felkonfigurationer.

.DESCRIPTION
    Skriptet läser konfigurationen i AD och på CA:erna och ändrar ingenting.
    Det letar efter de felkonfigurationer som SpecterOps beskrev i "Certified Pre-Owned"
    (2021) och senare tillägg:

      ESC1   Ansökaren anger själv ämnesnamn/SAN i en mall för klientautentisering
             som breda grupper får registrera sig på utan godkännande.
      ESC2   Mall med EKU "Any Purpose" eller utan EKU, öppen för breda grupper.
      ESC3   Mall för registreringsagent (Certificate Request Agent) öppen för breda grupper.
      ESC4   Breda grupper har skrivrättigheter till mallen eller äger den.
      ESC6   CA:n har flaggan EDITF_ATTRIBUTESUBJECTALTNAME2 (SAN i begäran accepteras för alla mallar).
      ESC8   Webbregistrering (certsrv) svarar över okrypterad HTTP (NTLM-relä).
      ESC9   Mall med CT_FLAG_NO_SECURITY_EXTENSION för klientautentisering (svag certifikatmappning).
      ESC15  Schemaversion 1-mall där ansökaren anger ämnesnamn (CVE-2024-49019, opatchade CA:er).

    "Breda grupper" är Everyone, Authenticated Users, BUILTIN\Users, Anonymous,
    Domain Users, Domain Guests och Domain Computers. Neka-poster (Deny) tas inte med i
    bedömningen, vilket gör granskningen försiktig: den kan rapportera för mycket men
    missar inte tillåtna rättigheter.

    Avslutningskod: 0 = inga fynd med allvarlighet Hög eller Kritisk, 2 = sådana fynd finns.

.PARAMETER IncludeUnpublished
    Granska även mallar som inte är publicerade på någon CA (med lägre allvarlighet).

.PARAMETER OutputPath
    Spara resultatet. Filändelsen .html ger en rapport, annars sparas CSV.

.EXAMPLE
    .\Test-AdcsTemplateSecurity.ps1

.EXAMPLE
    .\Test-AdcsTemplateSecurity.ps1 -IncludeUnpublished -OutputPath C:\Rapporter\adcs-granskning.html

.NOTES
    Kräver modulen ActiveDirectory (RSAT). ESC7 (behörigheter på själva CA:n) och ESC5
    (behörigheter på PKI-objekt och CA-servern) kontrolleras inte automatiskt utan listas
    som manuella kontrollpunkter.
#>
#Requires -Modules ActiveDirectory
[CmdletBinding()]
param(
    [switch]$IncludeUnpublished,
    [switch]$SkipCAChecks,
    [string]$OutputPath,
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

$configNC  = (Get-ADRootDSE).configurationNamingContext
$pksDN     = "CN=Public Key Services,CN=Services,$configNC"
$domainSid = (Get-ADDomain).DomainSID.Value

$lowPriv = @{
    'S-1-1-0'          = 'Everyone'
    'S-1-5-7'          = 'Anonymous'
    'S-1-5-11'         = 'Authenticated Users'
    'S-1-5-32-545'     = 'BUILTIN\Users'
    "$domainSid-513"   = 'Domain Users'
    "$domainSid-514"   = 'Domain Guests'
    "$domainSid-515"   = 'Domain Computers'
}

$oid = @{
    ClientAuth     = '1.3.6.1.5.5.7.3.2'
    PkinitClient   = '1.3.6.1.5.2.3.4'
    SmartCardLogon = '1.3.6.1.4.1.311.20.2.2'
    AnyPurpose     = '2.5.29.37.0'
    RequestAgent   = '1.3.6.1.4.1.311.20.2.1'
}
$authOids = @($oid.ClientAuth, $oid.PkinitClient, $oid.SmartCardLogon, $oid.AnyPurpose)

$guidEnroll     = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
$guidAutoEnroll = [guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
$adRights       = [System.DirectoryServices.ActiveDirectoryRights]
$sidType        = [System.Security.Principal.SecurityIdentifier]

$findings = New-Object System.Collections.Generic.List[object]
function Add-Finding {
    param([string]$Severity, [string]$Esc, [string]$Object, [string]$Description, [string]$Remediation, [string[]]$Principals)
    $findings.Add([pscustomobject]@{
        Allvarlighet = $Severity
        ESC          = $Esc
        Objekt       = $Object
        Beskrivning  = $Description
        Principaler  = ($Principals | Select-Object -Unique) -join ', '
        Atgard       = $Remediation
    })
}

function Get-BroadRights {
    param([System.DirectoryServices.ActiveDirectorySecurity]$Acl)
    $enroll = @(); $modify = @()
    foreach ($ace in $Acl.GetAccessRules($true, $true, $sidType)) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        $sid = $ace.IdentityReference.Value
        if (-not $lowPriv.ContainsKey($sid)) { continue }
        $r = $ace.ActiveDirectoryRights
        $name = $lowPriv[$sid]
        $genericAll = $r.HasFlag($adRights::GenericAll)
        if ($genericAll -or ($r.HasFlag($adRights::ExtendedRight) -and $ace.ObjectType -in @($guidEnroll, $guidAutoEnroll, [guid]::Empty))) {
            $enroll += $name
        }
        if ($genericAll -or $r.HasFlag($adRights::WriteDacl) -or $r.HasFlag($adRights::WriteOwner) -or $r.HasFlag($adRights::WriteProperty)) {
            $modify += $name
        }
    }
    $owner = $Acl.GetOwner($sidType).Value
    if ($lowPriv.ContainsKey($owner)) { $modify += "$($lowPriv[$owner]) (ägare)" }
    [pscustomobject]@{ Enroll = @($enroll | Select-Object -Unique); Modify = @($modify | Select-Object -Unique) }
}

# --- Läs CA:er och mallar ---------------------------------------------------
$cas = @(Get-ADObject -SearchBase "CN=Enrollment Services,$pksDN" -SearchScope OneLevel `
    -Filter "objectClass -eq 'pKIEnrollmentService'" -Properties certificateTemplates, dNSHostName)

$publishedOn = @{}
foreach ($ca in $cas) {
    foreach ($t in $ca.certificateTemplates) {
        if (-not $publishedOn.ContainsKey($t)) { $publishedOn[$t] = @() }
        $publishedOn[$t] += $ca.Name
    }
}

$props = 'displayName', 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag', 'msPKI-RA-Signature',
         'pKIExtendedKeyUsage', 'msPKI-Certificate-Application-Policy', 'msPKI-Template-Schema-Version', 'nTSecurityDescriptor'
$templates = Get-ADObject -SearchBase "CN=Certificate Templates,$pksDN" -SearchScope OneLevel `
    -Filter "objectClass -eq 'pKICertificateTemplate'" -Properties $props

Write-Host "Granskar $(@($templates).Count) mallar och $($cas.Count) CA:er i $((Get-ADDomain).DNSRoot)..." -ForegroundColor Cyan

# --- Mallar -----------------------------------------------------------------
foreach ($t in $templates) {
    $isPublished = $publishedOn.ContainsKey($t.Name)
    if (-not $isPublished -and -not $IncludeUnpublished) { continue }

    $nameFlag = [int64]$t.'msPKI-Certificate-Name-Flag'
    $enrFlag  = [int64]$t.'msPKI-Enrollment-Flag'
    $raSig    = [int]$t.'msPKI-RA-Signature'
    $schema   = [int]$t.'msPKI-Template-Schema-Version'
    $ekus     = @(@($t.pKIExtendedKeyUsage) + @($t.'msPKI-Certificate-Application-Policy') | Where-Object { $_ } | Select-Object -Unique)

    $suppliesSubject = ($nameFlag -band 0x1) -ne 0        # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
    $needsApproval   = ($enrFlag  -band 0x2) -ne 0        # CT_FLAG_PEND_ALL_REQUESTS
    $noSecExtension  = ($enrFlag  -band 0x80000) -ne 0    # CT_FLAG_NO_SECURITY_EXTENSION
    $noEku           = $ekus.Count -eq 0
    $authEku         = $noEku -or [bool]($ekus | Where-Object { $_ -in $authOids })
    $anyPurpose      = $ekus -contains $oid.AnyPurpose
    $requestAgent    = $ekus -contains $oid.RequestAgent
    $unguarded       = -not $needsApproval -and $raSig -eq 0

    $rights     = Get-BroadRights -Acl $t.nTSecurityDescriptor
    $openEnroll = $rights.Enroll.Count -gt 0

    $label = "$($t.displayName) [$($t.Name)]"
    if ($isPublished) { $label += " på $($publishedOn[$t.Name] -join ', ')" } else { $label += ' (ej publicerad)' }

    # Opublicerade mallar kan inte användas förrän de publiceras – sänk allvarligheten ett steg.
    $sev = { param($s) if ($isPublished) { $s } else { @{ 'Kritisk' = 'Hög'; 'Hög' = 'Medel'; 'Medel' = 'Låg'; 'Låg' = 'Info'; 'Info' = 'Info' }[$s] } }

    $esc1 = $suppliesSubject -and $authEku -and $openEnroll -and $unguarded
    if ($esc1) {
        Add-Finding (& $sev 'Kritisk') 'ESC1' $label `
            'Ansökaren anger själv ämnesnamn/SAN i en mall som ger klientautentisering. Vem som helst i gruppen kan begära ett certifikat som en annan användare, t.ex. en domänadministratör.' `
            'Sätt Subject Name till "Build from this Active Directory information", eller begränsa registreringsrätten till en smal grupp och kräv godkännande av certifikathanterare.' `
            $rights.Enroll
    }
    if (($anyPurpose -or $noEku) -and $openEnroll -and $unguarded) {
        Add-Finding (& $sev 'Hög') 'ESC2' $label `
            'Mallen har EKU "Any Purpose" eller saknar EKU och kan därmed användas för autentisering och för att signera andra certifikat.' `
            'Ange endast de EKU:er som behövs och begränsa registreringsrätten.' `
            $rights.Enroll
    }
    if ($requestAgent -and $openEnroll -and $unguarded) {
        Add-Finding (& $sev 'Hög') 'ESC3' $label `
            'Mallen utfärdar registreringsagentcertifikat som kan användas för att begära certifikat för andra användare.' `
            'Begränsa registreringsrätten till en dedikerad grupp och konfigurera restriktioner för registreringsagenter på CA:n.' `
            $rights.Enroll
    }
    if ($rights.Modify.Count -gt 0) {
        Add-Finding (& $sev 'Kritisk') 'ESC4' $label `
            'Breda grupper kan ändra mallen (skriva egenskaper, ändra behörigheter eller äger den) och kan därmed göra den sårbar för ESC1.' `
            'Ta bort skrivrättigheter och ägarskap för breda grupper. Endast PKI-administratörer ska kunna ändra mallar.' `
            $rights.Modify
    }
    if ($noSecExtension -and $authEku -and $openEnroll) {
        Add-Finding (& $sev 'Medel') 'ESC9' $label `
            'Mallen saknar SID-säkerhetstillägget (szOID_NTDS_CA_SECURITY_EXT). Det försvagar certifikatmappningen vid inloggning.' `
            'Ta bort flaggan CT_FLAG_NO_SECURITY_EXTENSION och se till att domänkontrollanterna kör stark certifikatmappning (KB5014754).' `
            $rights.Enroll
    }
    if (-not $esc1 -and $schema -eq 1 -and $suppliesSubject -and $openEnroll -and $unguarded) {
        Add-Finding (& $sev 'Hög') 'ESC15' $label `
            'Schemaversion 1-mall där ansökaren anger ämnesnamn. På CA:er utan säkerhetsuppdateringen från november 2024 kan programprinciper injiceras i begäran (CVE-2024-49019).' `
            'Installera säkerhetsuppdateringen på CA:n, ersätt mallen med en duplicerad version 2+-mall eller begränsa registreringsrätten.' `
            $rights.Enroll
    }
    if ($suppliesSubject -and -not $esc1) {
        Add-Finding (& $sev 'Info') 'Info' $label `
            'Ansökaren anger själv ämnesnamnet. Inget direkt fynd, men kontrollera att registreringsrätten är begränsad och att mallen inte ger klientautentisering.' `
            'Dokumentera vilka grupper som får registrera sig och varför.' `
            @()
    }
}

# --- CA:er ------------------------------------------------------------------
if (-not $SkipCAChecks) {
    foreach ($ca in $cas) {
        $cfgString = "$($ca.dNSHostName)\$($ca.Name)"

        $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        $editFlags = & certutil.exe -config $cfgString -getreg policy\EditFlags 2>&1 | ForEach-Object { "$_" }
        $code = $LASTEXITCODE; $ErrorActionPreference = $prev
        if ($code -ne 0) {
            Add-Finding 'Info' 'ESC6' $cfgString 'Kunde inte läsa EditFlags från CA:n (kräver behörighet och nåbar RPC).' 'Kör granskningen med ett konto som har läsrätt på CA:n.' @()
        } elseif ($editFlags -match 'EDITF_ATTRIBUTESUBJECTALTNAME2') {
            Add-Finding 'Kritisk' 'ESC6' $cfgString `
                'CA:n accepterar SAN-attribut i begäran för alla mallar. Det gör varje mall för klientautentisering sårbar för ESC1.' `
                'Kör: certutil -config "<CA>" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2 och starta om certsvc.' `
                @()
        }

        $url = "http://$($ca.dNSHostName)/certsrv/"
        $status = $null
        try {
            $status = [int](Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5 -MaximumRedirection 0).StatusCode
        } catch {
            if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
        }
        if ($status -in 200, 401) {
            Add-Finding 'Hög' 'ESC8' $cfgString `
                "Webbregistreringen svarar över okrypterad HTTP ($url, status $status). NTLM-autentisering kan reläas hit för att få certifikat i en annan dators namn." `
                'Ta bort rollen Web Enrollment om den inte behövs. Annars: kräv HTTPS, aktivera Extended Protection for Authentication och stäng av NTLM för IIS.' `
                @()
        }

        Add-Finding 'Info' 'ESC7' $cfgString `
            'Manuell kontroll: behörigheter på själva CA:n (Manage CA, Issue and Manage Certificates) ska bara ges till PKI-administratörer.' `
            'Granska fliken Security i certsrv.msc och dokumentera resultatet.' `
            @()
    }
}

# --- Resultat ---------------------------------------------------------------
$order = @{ 'Kritisk' = 0; 'Hög' = 1; 'Medel' = 2; 'Låg' = 3; 'Info' = 4 }
$result = @($findings | Sort-Object @{ Expression = { $order[$_.Allvarlighet] } }, ESC, Objekt)

if ($result.Count -eq 0) {
    Write-Host 'Inga fynd.' -ForegroundColor Green
} else {
    $colors = @{ 'Kritisk' = 'Red'; 'Hög' = 'Red'; 'Medel' = 'Yellow'; 'Låg' = 'Yellow'; 'Info' = 'Gray' }
    foreach ($f in $result) {
        Write-Host ("[{0}] {1}  {2}" -f $f.Allvarlighet, $f.ESC, $f.Objekt) -ForegroundColor $colors[$f.Allvarlighet]
        Write-Host "    $($f.Beskrivning)"
        if ($f.Principaler) { Write-Host "    Gäller: $($f.Principaler)" }
        Write-Host "    Åtgärd: $($f.Atgard)" -ForegroundColor DarkCyan
    }
    $summary = $result | Group-Object Allvarlighet | ForEach-Object { "$($_.Name): $($_.Count)" }
    Write-Host "`nSammanfattning – $($summary -join ', ')"
}

if ($OutputPath) {
    if ($OutputPath -like '*.htm*') {
        $css = 'body{font-family:Segoe UI,Arial,sans-serif;margin:2em}table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:6px;vertical-align:top}th{background:#eee}'
        $result | ConvertTo-Html -Title 'AD CS-granskning' -Head "<style>$css</style>" `
            -PreContent "<h1>AD CS-granskning</h1><p>$((Get-ADDomain).DNSRoot) – $(Get-Date -Format 'yyyy-MM-dd HH:mm')</p>" |
            Set-Content -Path $OutputPath -Encoding UTF8
    } else {
        $result | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 -Delimiter ';'
    }
    Write-Host "Rapport sparad: $OutputPath"
}
if ($PassThru) { $result }

if ($result | Where-Object { $_.Allvarlighet -in 'Kritisk', 'Hög' }) { exit 2 }
exit 0
