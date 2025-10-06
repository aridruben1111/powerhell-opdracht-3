<#
.SYNOPSIS
    Een "slim" en compleet script dat een Windows werkstation configureert en toevoegt
    aan een domein. Het script kan veilig meerdere keren worden uitgevoerd.

.DESCRIPTION
    Dit script stelt de tijdzone, computernaam, netwerkinstellingen, en de client 
    firewall in. Het maakt ook een extra lokaal admin-account aan en schakelt Windows Update uit.
    Het forceert ook de tijdsynchronisatie met de DC, wat cruciaal is.
    Het voegt de computer alleen toe aan het domein als deze nog geen
    lid is en herstart alleen als er wijzigingen zijn die dit vereisen.

.NOTES
    Auteur: Gemini (Google AI)
    Versie: 5.0 (Aangepast aan Aventus Opdracht 5)
    Datum: 05-10-2025
#>

#region Hulpfuncties
# --- Functies voor gekleurde statusmeldingen ---
function Write-Status { param([string]$Message); Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message); Write-Host "[+] $Message" -ForegroundColor Green }
function Write-Warning-Msg { param([string]$Message); Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Error-Msg { param([string]$Message); Write-Host "[-] $Message" -ForegroundColor Red }
#endregion

#region Gebruikersinvoer en Variabelen
Clear-Host
Write-Host "--- Start van Slim Werkstation Configuratie Script ---" -ForegroundColor Green

# Vraag om de benodigde informatie
do {
    $StudentNummer = Read-Host -Prompt "Voer je studentnummer in (van de DC server, bijv. 778899)"
} while ([string]::IsNullOrWhiteSpace($StudentNummer))

do {
    $DC_IP = Read-Host -Prompt "Voer het IP-adres van je Domain Controller in (standaard: 172.16.2.10)"
    if ([string]::IsNullOrWhiteSpace($DC_IP)) {
        $DC_IP = "172.16.2.10"
    }
} while ($DC_IP -notmatch "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# Definieer variabelen
$TimeZone = "W. Europe Standard Time"
$HostName = "WS$StudentNummer"
$DomainName = "AventusRocks$StudentNummer.local"
$DomainNetBiosName = "AVENTUSROCKS"

# Variabele om bij te houden of een herstart nodig is
$rebootRequired = $false
#endregion

#region Systeemconfiguratie

# --- STAP 1: TIJDZONE ---
Clear-Host
Write-Host "--- STAP 1: TIJDZONE INSTELLEN ---" -ForegroundColor Green
if ((Get-TimeZone).Id -ne $TimeZone) {
    Write-Host "De tijdzone wordt ingesteld op '$TimeZone' (Amsterdam)."
    Set-TimeZone -Id $TimeZone
    Write-Host "[+] Tijdzone succesvol ingesteld."
} else {
    Write-Warning-Msg "Tijdzone is al correct ingesteld. Stap wordt overgeslagen."
}

# --- STAP 2: NETWERKCONFIGURATIE ---
Write-Host "`n--- STAP 2: NETWERKADAPTER CONFIGUREREN ---" -ForegroundColor Green
try {
    $nic = Get-NetAdapter -Name "LAN" -ErrorAction SilentlyContinue
    if (-not $nic) {
        Write-Host "Netwerkadapter 'LAN' niet gevonden. Poging om eerste actieve adapter te hernoemen..."
        $nic = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Virtual -eq $false } | Select-Object -First 1
        Rename-NetAdapter -InputObject $nic -NewName "LAN"
        Write-Host "[+] Adapter hernoemd naar 'LAN'."
    } else {
        Write-Warning-Msg "Netwerkadapter 'LAN' bestaat al."
    }

    $ipv6Binding = Get-NetAdapterBinding -Name "LAN" -ComponentID ms_tcpip6
    if ($ipv6Binding.Enabled) {
        Write-Host "IPv6 wordt uitgeschakeld op 'LAN'..."
        Disable-NetAdapterBinding -Name "LAN" -ComponentID ms_tcpip6
        Write-Host "[+] IPv6 succesvol uitgeschakeld."
    } else {
        Write-Warning-Msg "IPv6 is al uitgeschakeld op 'LAN'."
    }

} catch { 
    Write-Error-Msg "Fout bij het basis-configureren van de netwerkadapter: $($_.Exception.Message)" 
}

# --- STAP 3: DNS INSTELLEN ---
Write-Host "`n--- STAP 3: DNS-SERVER INSTELLEN ---" -ForegroundColor Green
$currentDnsServers = (Get-DnsClientServerAddress -InterfaceAlias "LAN").ServerAddresses
if ($currentDnsServers -notcontains $DC_IP -or $currentDnsServers.Count -ne 1) {
    Write-Host "De DNS-server wordt geforceerd ingesteld op $DC_IP..."
    Set-DnsClientServerAddress -InterfaceAlias "LAN" -ServerAddresses $DC_IP
    Write-Host "[+] DNS-server succesvol ingesteld op $DC_IP."
} else {
    Write-Warning-Msg "DNS-server is al correct ingesteld. Stap wordt overgeslagen."
}

# --- STAP 4: COMPUTERNAAM ---
Clear-Host
Write-Host "--- STAP 4: COMPUTERNAAM INSTELLEN ---" -ForegroundColor Green
if ($env:COMPUTERNAME -ne $HostName) {
    Write-Host "De computernaam wordt ingesteld op '$HostName'."
    Rename-Computer -NewName $HostName -Force
    $rebootRequired = $true
    Write-Host "[+] Computernaam succesvol ingesteld. Herstart is vereist."
} else {
    Write-Warning-Msg "Computernaam is al correct ingesteld. Stap wordt overgeslagen."
}

# --- STAP 5: LOKAAL ADMIN ACCOUNT AANMAKEN ---
Write-Host "`n--- STAP 5: LOKAAL ADMIN ACCOUNT AANMAKEN ---" -ForegroundColor Green
$localAdminUser = "LocalAdmin"
if (-not (Get-LocalUser -Name $localAdminUser -ErrorAction SilentlyContinue)) {
    Write-Status "Lokaal account '$localAdminUser' wordt aangemaakt..."
    $password = ConvertTo-SecureString "Welkom01!" -AsPlainText -Force
    $newUser = New-LocalUser -Name $localAdminUser -Password $password -FullName "Lokale Administrator" -Description "Extra lokaal admin account."
    Add-LocalGroupMember -Group "Administrators" -Member $newUser.Name
    Write-Success "Lokaal account '$localAdminUser' succesvol aangemaakt en toegevoegd aan de Administrators groep."
} else {
    Write-Warning-Msg "Lokaal account '$localAdminUser' bestaat al. Stap wordt overgeslagen."
}

# --- STAP 6: WINDOWS UPDATE UITSCHAKELEN ---
Write-Host "`n--- STAP 6: WINDOWS UPDATE UITSCHAKELEN ---" -ForegroundColor Green
$updateService = Get-Service -Name wuauserv
if ($updateService.Status -ne 'Stopped' -or $updateService.StartType -ne 'Disabled') {
    Write-Host "De Windows Update service wordt gestopt en permanent uitgeschakeld."
    $updateService | Stop-Service -Force
    $updateService | Set-Service -StartupType Disabled
    Write-Host "[+] Windows Update service is uitgeschakeld."
} else {
    Write-Warning-Msg "Windows Update service is al uitgeschakeld. Stap wordt overgeslagen."
}

# --- STAP 7: TOEVOEGEN AAN DOMEIN ---
Clear-Host
Write-Host "--- STAP 7: TOEVOEGEN AAN DOMEIN ---" -ForegroundColor Green
$computerInfo = Get-ComputerInfo
if ($computerInfo.Domain -ne $DomainName) {
    Write-Host "Computer is nog geen lid van het domein. Voorbereidingen worden getroffen..."
    
    # Client firewall tijdelijk uitzetten om tests te garanderen
    Write-Warning-Msg "Client firewall voor 'Private' profiel wordt tijdelijk uitgezet."
    Set-NetFirewallProfile -Profile Private -Enabled False
    
    # --- NIEUWE CRUCIALE STAP: TIJDSYNCHRONISATIE ---
    Write-Host "`n[*] Tijd synchroniseren met de Domain Controller..." -ForegroundColor Cyan
    try {
        w32tm /config /manualpeerlist:"$DC_IP" /syncfromflags:manual /reliable:yes /update | Out-Null
        Restart-Service w32time
        Write-Success "Tijdsynchronisatie met $DC_IP is geforceerd."
    } catch {
        Write-Error-Msg "Kon de tijd niet synchroniseren. Fout: $($_.Exception.Message)"
    }
    
    # Connectiviteitstest
    Write-Host "`n[*] Connectiviteit testen..." -ForegroundColor Cyan
    $pingSuccess = Test-Connection -ComputerName $DC_IP -Count 1 -Quiet
    $dnsSuccess = $false
    try { $dnsSuccess = (Resolve-DnsName -Name $DomainName -ErrorAction Stop).IPAddress -eq $DC_IP } catch {}

    if ($pingSuccess -and $dnsSuccess) {
        Write-Success "Ping en DNS-tests zijn geslaagd."
        
        Write-Warning-Msg "BELANGRIJK: Zorg ervoor dat de firewall op de DC-server ($DC_IP) ook is uitgeschakeld."
        
        $DomainAdminCredential = Get-Credential -UserName "$DomainNetBiosName\Administrator" -Message "Voer het wachtwoord van de Domein Administrator in"
        
        Write-Host "Poging tot toevoegen aan domein..."
        try {
            Add-Computer -DomainName $DomainName -Credential $DomainAdminCredential -Force -ErrorAction Stop
            $rebootRequired = $true
            Write-Success "Computer succesvol toegevoegd aan het domein '$DomainName'. Herstart is vereist."
        } catch {
            Write-Error-Msg "Kon de computer niet toevoegen aan het domein. Fout: $($_.Exception.Message)"
        }
    } else {
        Write-Error-Msg "Connectiviteitstest mislukt! Kan de server niet bereiken of de domeinnaam niet vinden."
        Write-Warning-Msg "Ping naar ${DC_IP}: $($pingSuccess)"
        Write-Warning-Msg "DNS-resolutie voor ${DomainName}: $($dnsSuccess)"
        Write-Error-Msg "De computer wordt NIET aan het domein toegevoegd."
    }
} else {
    Write-Warning-Msg "Computer is al lid van het domein '$DomainName'. Stap wordt overgeslagen."
}
#endregion

#region Afsluiting en Herstart
Write-Host "------------------------------------------------------------" -ForegroundColor Green
Write-Host "`n[!] CONFIGURATIE VOLTOOID!" -ForegroundColor Yellow
if ($rebootRequired) {
    Write-Host "    Wijzigingen zijn doorgevoerd die een herstart vereisen." -ForegroundColor Yellow
    Write-Host "    De computer wordt nu automatisch opnieuw opgestart over 10 seconden." -ForegroundColor Yellow
    Start-Sleep -Seconds 10
    Restart-Computer -Force
} else {
    Write-Host "    Geen wijzigingen doorgevoerd die een herstart vereisen." -ForegroundColor Yellow
    Write-Host "    Het script is klaar."
}
Write-Host "------------------------------------------------------------" -ForegroundColor Green
#endregion