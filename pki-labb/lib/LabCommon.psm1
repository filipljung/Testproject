# Gemensamma hjälpfunktioner för labbskripten.

function Get-LabConfig {
    Import-PowerShellDataFile -Path (Join-Path $PSScriptRoot '..\lab-config.psd1')
}

function Write-Step {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Invoke-Native {
    <# Kör ett kommandoradsverktyg (certutil, certreq, auditpol) och kastar fel om det misslyckas. #>
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @()
    )
    $ErrorActionPreference = 'Continue'   # stderr från inbyggda verktyg ska inte bli terminerande fel
    $output = & $FilePath @ArgumentList 2>&1 | ForEach-Object { "$_" }
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath $($ArgumentList -join ' ') misslyckades (kod $LASTEXITCODE):`n$($output -join "`n")"
    }
    $output
}

function Set-LabNetwork {
    param(
        [Parameter(Mandatory)][string]$IP,
        [Parameter(Mandatory)][int]$PrefixLength,
        [string]$Gateway,
        [Parameter(Mandatory)][string[]]$Dns
    )
    $nic = Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Select-Object -First 1
    if (-not $nic) { throw 'Hittade inget aktivt nätverkskort.' }

    Set-NetIPInterface -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -Dhcp Disabled
    Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
    Get-NetRoute -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

    $params = @{ InterfaceIndex = $nic.ifIndex; IPAddress = $IP; PrefixLength = $PrefixLength }
    if ($Gateway) { $params.DefaultGateway = $Gateway }
    New-NetIPAddress @params | Out-Null
    Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses $Dns
    Write-Host "IP-adress $IP/$PrefixLength satt på $($nic.Name)."
}

function Set-CAPolicyInf {
    <# CAPolicy.inf måste finnas i %windir% innan AD CS installeras. #>
    param([Parameter(Mandatory)][string]$Content)
    Set-Content -Path (Join-Path $env:windir 'CAPolicy.inf') -Value $Content -Encoding ASCII
}

function Set-CARegistry {
    param([Parameter(Mandatory)][hashtable]$Settings)
    foreach ($key in $Settings.Keys) {
        Invoke-Native -FilePath certutil.exe -ArgumentList @('-setreg', "CA\$key", "$($Settings[$key])") | Out-Null
        Write-Host "  CA\$key = $($Settings[$key])"
    }
}

function Enable-CAAuditing {
    <# Underkategorin "Certification Services" anges med GUID så att det fungerar oavsett OS-språk. #>
    Invoke-Native -FilePath auditpol.exe -ArgumentList @(
        '/set', '/subcategory:{0CCE9221-69AE-11D9-BED3-505054503030}', '/success:enable', '/failure:enable'
    ) | Out-Null
}

Export-ModuleMember -Function *
