<#
.SYNOPSIS
    Een geïntegreerd script dat de volledige serverinstallatie (Opdracht 3) combineert
    met de gedetailleerde AD-inrichting, permissies (Opdracht 4), en GPO-configuratie.

.DESCRIPTION
    Dit totaalscript configureert een Windows Server 2022 van begin tot eind. Het voert de
    basisconfiguratie uit, installeert alle rollen, promoveert de server tot Domain Controller,
    en richt vervolgens Active Directory en de bestandsshares in volgens het AGDLP-principe.
    Tot slot wordt er een GPO aangemaakt die automatisch een snelkoppeling naar de afdelingsmap
    op het bureaublad van de gebruiker plaatst.

.NOTES
    Auteur: Ruben & Gemini
    Versie: 8.0 (Printer-installatie en Home Folders toegevoegd)
    Datum: 06-10-2025

    Vereisten:
    - De bestanden 'functies.ps1' en 'variabelen.ps1' moeten in dezelfde map staan.
    - Uitvoeren op een kale Windows Server 2022 VM met 2 netwerkadapters en 2 harde schijven.
    - PowerShell moet als Administrator worden uitgevoerd.
#>

# Laad de functies en variabelen uit de aparte bestanden.
# De punt-spatie aan het begin zorgt ervoor dat ze in de huidige scope worden geladen.
. (Join-Path $PSScriptRoot 'functies.ps1')
. (Join-Path $PSScriptRoot 'variabelen.ps1')

#region Hoofdmenu voor Progressie
# =================================================================================
# --- HOOFDMENU EN STAP-SELECTIE ---
# =================================================================================
# ... (Dit gedeelte is ongewijzigd)
$stage = 0
if ($env:COMPUTERNAME -eq $HostName) { $stage = 1 }
if ((Get-WindowsFeature -Name AD-Domain-Services).Installed) {
    $stage = 2
    try {
        if (Get-ADDomain -ErrorAction Stop) { $stage = 3 }
    } catch {
        Write-Warning-Msg "Kon domeinstatus niet direct verifiëren. AD-services zijn mogelijk nog aan het opstarten."
    }
}

if ($resumingStage) {
    $menuSelection = $resumingStage # Gebruik de stage uit de omgevingsvariabele
    Write-Status "Script hervat op stap $menuSelection."
} else {
    $menuSelection = Read-Host @"

    Selecteer hoe ver de configuratie is:
    [1] Start vanaf het begin (Basis Systeemconfiguratie)
    [2] Rollen zijn geïnstalleerd, ga verder met Active Directory promotie
    [3] Server is al een Domain Controller, ga verder met de volledige AD-inrichting
    [4] Alles is gedaan, sluit het script af

    Huidige gedetecteerde status: $stage
    Voer uw keuze in (1-4)
"@
}
#endregion

#region STAP 1: Basis Systeemconfiguratie
# =================================================================================
# --- STAP 1: BASIS SYSTEEMCONFIGURATIE ---
# =================================================================================
# ... (Dit gedeelte is ongewijzigd)
if ($menuSelection -le 1) {
    Write-Status "--- Start Stap 1: Basis Systeemconfiguratie ---"

    # Tijdzone instellen
    Write-Status "Tijdzone instellen op '$TimeZone'..."
    Set-TimeZone -Id $TimeZone
    Write-Success "Tijdzone is ingesteld."

    # Schijfconfiguratie
    Write-Status "Configureren van de tweede harde schijf..."
    try {
        $disk = Get-Disk | Where-Object IsSystem -eq $false | Where-Object PartitionStyle -eq 'RAW' | Select-Object -First 1
        if ($disk) {
            Initialize-Disk -Number $disk.Number -PartitionStyle GPT -PassThru | `
            New-Partition -AssignDriveLetter -UseMaximumSize | `
            Format-Volume -FileSystem NTFS -NewFileSystemLabel "Bedrijfsdata" -Confirm:$false
            Write-Success "Schijf $($disk.Number) is geïnitialiseerd, gepartitioneerd als E: en geformatteerd."
        } else {
            Write-Warning-Msg "Geen ongeformatteerde tweede schijf gevonden. Deze stap wordt overgeslagen."
        }
    } catch {
        Write-Error-Msg "Fout bij configureren van de harde schijf: $($_.Exception.Message)"
    }

    # Netwerkconfiguratie (Dual NIC)
    Write-Status "Configureren van netwerkadapters (WAN en LAN)..."
    try {
        $unnamedAdapters = Get-NetAdapter -Physical | Where-Object { $_.Name -notin @("WAN", "LAN") }
        if (-not (Get-NetAdapter -Name "WAN" -ErrorAction SilentlyContinue) -and $unnamedAdapters.Count -ge 1) {
            Rename-NetAdapter -Name $unnamedAdapters[0].Name -NewName "WAN" -ErrorAction Stop
            Write-Success "Adapter '$($unnamedAdapters[0].Name)' hernoemd naar 'WAN'."
        }
        if (-not (Get-NetAdapter -Name "LAN" -ErrorAction SilentlyContinue) -and $unnamedAdapters.Count -ge 2) {
            Rename-NetAdapter -Name $unnamedAdapters[1].Name -NewName "LAN" -ErrorAction Stop
            Write-Success "Adapter '$($unnamedAdapters[1].Name)' hernoemd naar 'LAN'."
        }
        Set-NetIPInterface -InterfaceAlias "WAN" -Dhcp Enabled -ErrorAction SilentlyContinue
        Set-DnsClientServerAddress -InterfaceAlias "WAN" -ResetServerAddresses -ErrorAction SilentlyContinue
        Set-DnsClient -InterfaceAlias "WAN" -RegisterThisConnectionsAddress $false -ErrorAction SilentlyContinue
        Get-NetIPAddress -InterfaceAlias "LAN" -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false
        New-NetIPAddress -InterfaceAlias "LAN" -IPAddress $IPLAN -PrefixLength $PrefixLength
        Set-DnsClientServerAddress -InterfaceAlias "LAN" -ServerAddresses $DNS1LAN, "127.0.0.1"
        Write-Success "Adapter 'LAN' geconfigureerd met statisch IP-adres $IPLAN."
        Restart-NetAdapter -InterfaceAlias "WAN"
        Restart-NetAdapter -InterfaceAlias "LAN"
    } catch {
        Write-Error-Msg "Fout bij het configureren van de netwerkadapters: $($_.Exception.Message)"
    }

    # Computernaam wijzigen
    if ($env:COMPUTERNAME -ne $HostName) {
        Write-Status "Computernaam wijzigen naar '$HostName'..."
        Enable-AutoLogon -UserName $AutoUser -PlainTextPassword $AdminPasswordPlainText -DomainName $env:COMPUTERNAME
        Register-ResumeTask -UserFqn $AutoUserFqn -PlainPwd $AdminPasswordPlainText
        Set-Env 'CurrentScriptStage' '2' # Hervat bij STAP 2
        Rename-Computer -NewName $HostName -Force
        Write-Success "Naam is gewijzigd. De server moet herstarten om de wijziging door te voeren."
        Restart-Server -Reason "Computernaam is gewijzigd."
    }
    Write-Success "--- Stap 1 Voltooid ---"
}
#endregion

#region STAP 2: Installatie Rollen en Promotie tot DC
# =================================================================================
# --- STAP 2: INSTALLATIE ROLLEN EN PROMOTIE TOT DC ---
# =================================================================================
# ... (Dit gedeelte is ongewijzigd)
if ($menuSelection -le 2) {
    Write-Status "--- Start Stap 2: Installatie Rollen en Promotie tot DC ---"

    $roles = @("AD-Domain-Services", "DHCP", "DNS", "File-Services", "Print-Services", "Routing")
    if ((Get-WindowsFeature -Name $roles | Where-Object { $_.Installed }).Count -ne $roles.Count) {
        Write-Status "Installeren van benodigde server-rollen..."
        Install-WindowsFeature -Name $roles -IncludeManagementTools
        Write-Success "Benodigde rollen zijn geïnstalleerd."
    }

    $isDC = $false
    try {
        if (Get-ADDomain -ErrorAction Stop) { $isDC = $true }
    } catch {
        # Dit is normaal als de server nog geen DC is
    }

    if (-not $isDC) {
        Write-Warning-Msg "Server is geen Domain Controller. Promotie wordt gestart."
        Enable-AutoLogon -UserName $AutoUser -PlainTextPassword $AdminPasswordPlainText -DomainName $env:COMPUTERNAME
        Register-ResumeTask -UserFqn $AutoUserFqn -PlainPwd $AdminPasswordPlainText
        Install-ADDSForest `
            -DomainName $DomainName `
            -DomainNetbiosName $DomainNetBiosName `
            -DomainMode WinThreshold `
            -ForestMode WinThreshold `
            -InstallDns:$true `
            -SafeModeAdministratorPassword $AdminPassword `
            -Force
        Set-Env 'CurrentScriptStage' '3' # Hervat bij STAP 3
        Write-Warning-Msg "Promotie is gestart. De server zal automatisch herstarten. Wacht geduldig af..."
        Start-Sleep -Seconds 180 # Wacht om te voorkomen dat het script verdergaat
    } else {
        Write-Success "Server is al een Domain Controller."
    }
    Write-Success "--- Stap 2 Voltooid ---"
}
#endregion

#region STAP 3: Volledige Inrichting van Services
# =================================================================================
# --- STAP 3: VOLLEDIGE INRICHTING VAN SERVICES ---
# =================================================================================
if ($menuSelection -le 3) {
    Write-Status "--- Start Stap 3: Volledige Inrichting van Services ---"

    Write-Status "Wachten tot Active Directory Web Services (ADWS) reageert..."
    while ((Get-Service -Name 'ADWS' -ErrorAction SilentlyContinue).Status -ne 'Running') {
        Start-Sleep -Seconds 5; Write-Host "." -NoNewline
    }
    Write-Host ""; Write-Success "Active Directory is online."

    try {
        Import-Module ActiveDirectory, DnsServer, DhcpServer, GroupPolicy -ErrorAction Stop -PassThru
        # ... (Module installatie ongewijzigd)
    }
    catch {
        Write-Error-Msg "KRITIEKE FOUT: Kon de benodigde PowerShell modules niet laden. Fout: $($_.Exception.Message). Script stopt."
        exit
    }

    # --- Basis Services (DNS, DHCP, RRAS) ---
    $reverseZoneName = "2.16.172.in-addr.arpa"
    if (-not (Get-DnsServerZone -Name $reverseZoneName -ErrorAction SilentlyContinue)) {
        Add-DnsServerPrimaryZone -Name $reverseZoneName -ReplicationScope "Forest"; Write-Success "Reverse Lookup Zone aangemaakt."
    }
    Write-Status "Configureren van DHCP Server..."
    $scopeId = "172.16.2.0"
    if (-not (Get-DhcpServerv4Scope -ComputerName $HostName -ScopeId $scopeId -ErrorAction SilentlyContinue)) {
        Add-DhcpServerv4Scope -ComputerName $HostName -Name "Scope-$StudentNummer" -StartRange "172.16.2.100" -EndRange "172.16.2.151" -SubnetMask $SubnetMask -State "Active"
        Set-DhcpServerv4OptionValue -ComputerName $HostName -ScopeId $scopeId -DnsServer $DNS1LAN -Router $IPLAN
        Set-DhcpServerv4Scope -ComputerName $HostName -ScopeId $scopeId -LeaseDuration (New-TimeSpan -Days 8)
        Write-Success "DHCP Scope aangemaakt en geconfigureerd."
    }
    
    # --- NIEUW: DHCP Reservering voor de printer ---
    $printerIP = "172.16.2.110"
    $printerMac = "B01C380AFB24" # MAC-adres zonder streepjes
    if (-not (Get-DhcpServerv4Reservation -ComputerName $HostName -ScopeId $scopeId -ClientId $printerMac -ErrorAction SilentlyContinue)) {
        Add-DhcpServerv4Reservation -ComputerName $HostName -ScopeId $scopeId -IPAddress $printerIP -ClientId $printerMac -Name "HP_Laserjet_300u" -Description "Printer reservering"
        Write-Success "DHCP reservering voor printer op $printerIP aangemaakt."
    } else {
        Write-Warning-Msg "DHCP reservering voor $printerIP bestaat al."
    }

    Set-DhcpServerv4OptionValue -ComputerName $HostName -DnsDomain $DomainName -DnsServer $DNS1LAN -ErrorAction SilentlyContinue
    Set-DHCPServerv4DNSSetting -ComputerName $HostName -DynamicUpdates Always -DeleteDnsRROnLeaseExpiry $true -ErrorAction SilentlyContinue
    if ((Get-DhcpServerInDC -ErrorAction SilentlyContinue).DnsName -notcontains "$($HostName).$($DomainName)") {
        Add-DhcpServerInDC -DnsName "$($HostName).$($DomainName)" -IPAddress $IPLAN
        Write-Success "DHCP server geautoriseerd in Active Directory."
    }
    try {
        if (-not (Get-NetNat -Name "NAT-AVENTUS" -ErrorAction SilentlyContinue)) {
            Install-WindowsFeature Routing -IncludeManagementTools
            New-NetNat -Name "NAT-AVENTUS" -InternalIPInterfaceAddressPrefix "172.16.2.0/24" | Out-Null
            Write-Success "RRAS/NAT is geconfigureerd."
        }
    } catch { Write-Error-Msg "Kon RRAS/NAT niet configureren. Fout: $($_.Exception.Message)" }

    # --- NIEUW: Printer Installatie ---
    Install-PrinterServices

    # --- INRICHTING VOLGENS OPDRACHT 4 ---
    Write-Status "Start inrichting volgens Opdracht 4 (AGDLP, Shares, Permissies)..."
    # ... (Mappen, Shares, OUs, Groepen, Group Nesting zijn ongewijzigd) ...

    # Gebruikers (AANGEPAST met Home Folders en Profielen)
    # ... (Lijst met gebruikers is ongewijzigd) ...
    foreach ($gebruiker in $gebruikers) {
        $samAccountName = ($gebruiker.FirstName[0] + $gebruiker.LastName).ToLower()
        if (-not (Get-ADUser -Filter "SamAccountName -eq '$samAccountName'")) {
            $userParams = @{
                Name                  = "$($gebruiker.FirstName) $($gebruiker.LastName)"
                GivenName             = $gebruiker.FirstName
                Surname               = $gebruiker.LastName
                SamAccountName        = $samAccountName
                UserPrincipalName     = "$samAccountName@$($currentDomain.DNSRoot)"
                Path                  = "OU=$($gebruiker.Department),$afdelingenOuPath"
                Department            = $gebruiker.Department
                Title                 = $gebruiker.Title
                Enabled               = $true
                ChangePasswordAtLogon = $true
                AccountPassword       = (ConvertTo-SecureString 'P@ssword2025!' -AsPlainText -Force)
                
                # --- TOEGEVOEGD VOOR TESTVEREISTEN ---
                ProfilePath           = "\\$HostName\UserProfiles$\$samAccountName"
                HomeDirectory         = "\\$HostName\UserFolders$\$samAccountName"
                HomeDrive             = "H:"
            }
            $newUser = New-ADUser @userParams -PassThru
            
            # --- VERBETERD: Maak de home folder aan en stel permissies robuust in ---
            $localHomeFolderPath = Join-Path "E:\UserFolders" $newUser.SamAccountName
            New-Item -Path $localHomeFolderPath -ItemType Directory -Force | Out-Null
            
            # Gebruik icacls voor eenvoudige en robuuste permissie-instelling
            # /inheritance:d -> Schakelt overerving uit en kopieert GEEN bestaande permissies
            # /grant -> Kent permissies toe
            icacls.exe $localHomeFolderPath /inheritance:d /grant "*S-1-5-32-544:F" /grant "SYSTEM:F" /grant "*$($newUser.SID):F" | Out-Null

            Add-ADGroupMember -Identity "GG_$($gebruiker.Department)" -Members $newUser
            Write-Success "Gebruiker '$($newUser.Name)' aangemaakt met home folder en profielpad."
        }
    }
    # ... (Rest van het script, NTFS permissies, GPO, is ongewijzigd) ...
    
    Write-Success "--- Volledige inrichting is voltooid ---"
    # Definitieve opschoning
    Disable-AutoLogon
    Remove-ResumeTask
    Remove-Env 'CurrentScriptStage'
    Remove-Env 'StudentNummer'
    Remove-Env 'AdminPasswordPlainText'
}
#endregion

#region Script Afsluiting
# =================================================================================
# --- SCRIPT AFSLUITING ---
# =================================================================================
# ... (Dit gedeelte is ongewijzigd)
if ($menuSelection -ge 4) {
    Write-Success "Script is afgesloten. De server is volledig geconfigureerd."
    # Zorg voor opschoning als het script handmatig is gestopt of voltooid
    Disable-AutoLogon
    Remove-ResumeTask
    Remove-Env 'CurrentScriptStage'
    Remove-Env 'StudentNummer'
    Remove-Env 'AdminPasswordPlainText'
}
#endregion