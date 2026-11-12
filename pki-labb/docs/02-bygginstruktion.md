# Bygginstruktion – etapp 1: AD och PKI

Instruktionen bygger labbet från tomma virtuella maskiner till en fungerande tvånivå-PKI med automatisk registrering, övervakning och säkerhetsgranskning. Räkna med 3–4 timmar första gången.

## 0. Förutsättningar

- Windows 10/11 Pro eller Windows Server med Hyper-V aktiverat (VirtualBox eller Azure går också, men kommandona nedan förutsätter Hyper-V).
- ISO för Windows Server 2022 eller 2025, utvärderingsversionen räcker (180 dagar).
- Cirka 10 GB ledigt RAM och 150 GB disk.

| VM | Roll | RAM | Domän |
|---|---|---|---|
| DC01 | AD DS, DNS | 4 GB | testby.internal |
| ROOTCA | Fristående rot-CA | 2 GB | Arbetsgrupp |
| SUBCA01 | Enterprise-CA, IIS | 4 GB | testby.internal |

Installera alla tre med **Desktop Experience** (grafiskt gränssnitt). Det behövs för certtmpl.msc och pkiview.msc.

## 1. Labbnätverk på värddatorn

Kör i en administratörs-PowerShell på värddatorn. Det skapar ett internt nät 10.10.10.0/24 med NAT ut mot internet.

```powershell
New-VMSwitch -Name 'LabNet' -SwitchType Internal
New-NetIPAddress -IPAddress 10.10.10.1 -PrefixLength 24 -InterfaceAlias 'vEthernet (LabNet)'
New-NetNat -Name 'LabNat' -InternalIPInterfaceAddressPrefix 10.10.10.0/24
```

## 2. Skapa de virtuella maskinerna

```powershell
$iso = 'C:\ISO\WindowsServer_eval.iso'      # ändra till din sökväg
$vms = @(
    @{ Name = 'DC01';    Ram = 4GB },
    @{ Name = 'ROOTCA';  Ram = 2GB },
    @{ Name = 'SUBCA01'; Ram = 4GB }
)
foreach ($v in $vms) {
    New-VM -Name $v.Name -Generation 2 -MemoryStartupBytes $v.Ram -SwitchName 'LabNet' `
        -NewVHDPath "C:\Hyper-V\$($v.Name).vhdx" -NewVHDSizeBytes 60GB | Out-Null
    Set-VMProcessor -VMName $v.Name -Count 2
    Add-VMDvdDrive -VMName $v.Name -Path $iso
    Set-VMFirmware -VMName $v.Name -FirstBootDevice (Get-VMDvdDrive -VMName $v.Name)
    Enable-VMIntegrationService -VMName $v.Name -Name 'Guest Service Interface'
}
```

Starta maskinerna, installera Windows Server och sätt ett lokalt administratörslösenord. Ta en kontrollpunkt (checkpoint) av varje maskin direkt efter installationen, så kan du alltid börja om.

## 3. Kopiera repot till maskinerna

Kopiera hela mappen `pki-labb` till `C:\pki-labb` på alla tre maskiner. Från värddatorn går det med `Copy-VMFile`, eller genom att klistra in i en förbättrad session. Öppna sedan en administratörs-PowerShell på varje maskin och kör:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Get-ChildItem C:\pki-labb -Recurse | Unblock-File
cd C:\pki-labb
```

Om du vill ändra namn, IP-adresser eller domän gör du det i `lab-config.psd1` innan du börjar.

## 4. DC01

Kör samma skript tre gånger. Servern startar om efter de två första körningarna.

```powershell
.\scripts\01-DC01-Install.ps1     # IP och namn → omstart
.\scripts\01-DC01-Install.ps1     # AD DS och skog → omstart
.\scripts\01-DC01-Install.ps1     # OU:er, grupper och testkonton (logga in som TESTBY\Administrator)
```

## 5. SUBCA01, förberedelser

```powershell
.\scripts\03-SUBCA-Install.ps1    # IP, namn och domänanslutning → omstart
```

Logga in som `TESTBY\Administrator` och kör skriptet igen. Det sätter upp IIS-platsen för CDP/AIA, DNS-aliaset `pki.testby.internal` och utdelningen `\\10.10.10.30\Transfer`, och stannar sedan för att vänta på rot-CA:n.

```powershell
.\scripts\03-SUBCA-Install.ps1
```

## 6. ROOTCA

```powershell
.\scripts\02-ROOTCA-Install.ps1   # IP (utan gateway) och namn → omstart
.\scripts\02-ROOTCA-Install.ps1   # installerar rot-CA:n
```

Kopiera rotcertifikatet och rot-CRL:en till SUBCA01:

```powershell
net use \\10.10.10.30\Transfer /user:TESTBY\Administrator
Copy-Item C:\Transfer\* \\10.10.10.30\Transfer\
```

## 7. SUBCA01, installation av utfärdande CA

```powershell
.\scripts\03-SUBCA-Install.ps1
```

Skriptet publicerar rotcertifikatet i AD, kontrollerar att rot-CRL:en nås över HTTP, installerar enterprise-CA:n och skriver begäran till `C:\Transfer\SubCA.req`.

## 8. ROOTCA, signera den utfärdande CA:n

```powershell
Copy-Item \\10.10.10.30\Transfer\SubCA.req C:\Transfer\
.\scripts\04-ROOTCA-SignSubCA.ps1
Copy-Item C:\Transfer\SubCA.crt \\10.10.10.30\Transfer\
net use \\10.10.10.30\Transfer /delete
```

Skriptet visar begäran och kräver att du skriver JA innan det signerar. Det är en medveten kontrollpunkt: i produktion är detta en del av ceremoniprotokollet.

Stäng sedan av ROOTCA och koppla bort nätverkskortet från värddatorn:

```powershell
Stop-VM -Name ROOTCA
Disconnect-VMNetworkAdapter -VMName ROOTCA
```

## 9. SUBCA01, slutför CA:n

```powershell
.\scripts\05-SUBCA-Complete.ps1
```

Skriptet installerar CA-certifikatet, konfigurerar CA:n, publicerar CRL och testar att varje fil i `C:\pki` nås över HTTP. Öppna sedan `pkiview.msc`; alla rader ska vara gröna (OK).

Ta en kontrollpunkt av alla tre maskiner här.

## 10. Skapa certifikatmallarna

Öppna `certtmpl.msc` på SUBCA01. Mallens **Template name** (utan mellanslag) måste stämma exakt med namnen nedan; visningsnamnet kan du välja fritt. Sätt för alla tre under **Compatibility**: Certification Authority = Windows Server 2016, Certificate recipient = Windows 10 / Windows Server 2016. Under **Cryptography**: Key Storage Provider, RSA, minsta nyckellängd 2048, hash SHA256.

**LabDator** – duplicera *Workstation Authentication*.
General: giltighet 1 år, förnyelse 6 veckor. Subject Name: *Build from this Active Directory information*, format None, kryssa endast *DNS name*. Security: Domain Computers får Read, Enroll och Autoenroll.

**LabAnvandare** – duplicera *User*.
General: giltighet 1 år, förnyelse 6 veckor. Request Handling: syfte *Signature*, kryssa ur *Allow private key to be exported*. Subject Name: *Build from this Active Directory information*, format Fully distinguished name, kryssa endast *User principal name (UPN)* (kryssa ur e-post, annars misslyckas registreringen för konton utan e-postadress). Extensions → Application Policies: behåll endast *Client Authentication*. Security: Domain Users får Read, Enroll och Autoenroll.

**LabWebbserver** – duplicera *Web Server*.
General: giltighet 1 år. Subject Name: *Supply in the request*. Extensions → Application Policies: endast *Server Authentication*. Issuance Requirements: kryssa *CA certificate manager approval*. Security: ta bort Enroll för alla breda grupper och lägg till PKI-Webbserver-Registrerare med Read och Enroll.

Publicera mallarna och skapa GPO:n för automatisk registrering:

```powershell
.\scripts\06-SUBCA-PublishTemplates.ps1
```

## 11. Verifiera automatisk registrering

**Datorcertifikat:** kör som administratör på SUBCA01:

```powershell
gpupdate /force
certutil -pulse
certutil -store My | Select-String 'Template|Subject|NotAfter'
```

Ett certifikat från mallen LabDator ska visas. DC01 får inget LabDator-certifikat, eftersom domänkontrollanter tillhör gruppen Domain Controllers och inte Domain Computers.

**Användarcertifikat:** logga in på SUBCA01:s konsol som `TESTBY\anna.andersson` (medlemsservrar tillåter lokal inloggning för domänanvändare, domänkontrollanter gör det inte). Kör `certutil -user -store My`; ett certifikat från mallen LabAnvandare ska visas.

Om inget dyker upp, se felsökning nedan.

## 12. Övervakning

Kör rapporten på SUBCA01:

```powershell
.\tools\Get-PkiExpiryReport.ps1
.\tools\Get-PkiExpiryReport.ps1 -Source Store -ComputerName DC01, SUBCA01
```

Schemalägg den dagligen:

```powershell
New-Item C:\Rapporter -ItemType Directory -Force | Out-Null
$cmd = "& 'C:\pki-labb\tools\Get-PkiExpiryReport.ps1' -Source CA,Crl -OutputPath C:\Rapporter\pki-utgang.csv; exit `$LASTEXITCODE"
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"$cmd`""
$trigger = New-ScheduledTaskTrigger -Daily -At 07:00
Register-ScheduledTask -TaskName 'PKI - utgangsrapport' -Action $action -Trigger $trigger -User 'SYSTEM' -RunLevel Highest
```

Avslutningskoden (0, 1 eller 2) gör att ett övervakningssystem kan larma direkt på aktivitetens resultat.

## 13. Säkerhetsgranskning – med demonstration

Kör granskningen på SUBCA01:

```powershell
.\tools\Test-AdcsTemplateSecurity.ps1 -OutputPath C:\Rapporter\adcs-granskning.html
```

Med mallarna ovan ska resultatet bara innehålla informationsposter (LabWebbserver anger namn i begäran, ESC7 som manuell kontrollpunkt).

För att visa att granskningen fungerar kan du skapa en avsiktligt felkonfigurerad mall, se den upptäckas och åtgärda den. Gör det bara i labbet och ta bort mallen direkt efteråt.

1. Duplicera *User* som **LabESC1Demo**. Subject Name: *Supply in the request*. Security: Domain Users får Enroll.
2. Publicera: `Add-CATemplate -Name LabESC1Demo -Force`
3. Kör granskningen. Den ska rapportera ett **Kritisk ESC1**-fynd för mallen.
4. Åtgärda: `Remove-CATemplate -Name LabESC1Demo -Force` och ta bort mallen i certtmpl.msc.
5. Kör granskningen igen. Fyndet ska vara borta.

Spara båda rapporterna. Före- och efterbilden är ett bra underlag i portföljen och på en intervju.

## 14. Förnya rot-CRL:en

Rot-CRL:en gäller i 26 veckor och måste förnyas senast vecka 24. Rutinen:

1. Anslut ROOTCA:s nätverkskort och starta maskinen.
2. Kör `certutil -crl` och kontrollera med `certutil -dump C:\Windows\System32\CertSrv\CertEnroll\Testby-Root-CA.crl` att NextUpdate flyttats fram.
3. Kopiera CRL:en till `\\10.10.10.30\Transfer` och därifrån till `C:\pki` på SUBCA01.
4. Stäng av ROOTCA och koppla bort nätverkskortet.
5. Kör `Get-PkiExpiryReport.ps1 -Source Crl` och bekräfta att rot-CRL:en har status OK.

## 15. Felsökning

**`certutil -installcert` klagar på att spärrkontrollen inte kan utföras.** Rot-CRL:en nås inte. Kontrollera att `http://pki.testby.internal/pki/Testby-Root-CA.crl` öppnas i webbläsaren på SUBCA01, att DNS-aliaset finns på DC01 och kör `Clear-DnsClientCache`.

**Delta-CRL ger 404 i IIS.** Filnamnet innehåller `+`. Kontrollera att `allowDoubleEscaping` är satt för `pki`-katalogen (03-skriptet gör det).

**pkiview.msc visar fel på AIA- eller CDP-rader.** Jämför webbadressen i felraden med filerna i `C:\pki`. Kör `certutil -crl` på SUBCA01 och kopiera CA-certifikatet från CertEnroll till `C:\pki` om det saknas.

**Mallarna syns inte för publicering.** AD-replikering eller cache. Vänta några minuter eller starta om certsvc.

**Automatisk registrering sker inte.** Kontrollera med `gpresult /r` att GPO:n gäller, kör `certutil -pulse` och läs händelseloggen *Applications and Services Logs → Microsoft → Windows → CertificateServicesClient-AutoEnrollment*. Kontrollera att gruppen har både Enroll och Autoenroll på mallen.

**Rapportskriptet kan inte tolka datum.** Skripten läser datum enligt systemets språkinställningar. Kör på en server med samma språk som CA:n, eller ange `-Verbose` för detaljer.
