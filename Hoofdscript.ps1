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
    Auteur: Ruben
    Versie: 6.0 (Volledig script, inclusief STAP 1)
    Datum: 03-10-2025

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
        if (-not (Get-Module -ListAvailable -Name GroupPolicyDSC)) {
            Write-Status "De 'GroupPolicyDSC' module is niet gevonden. Poging tot installatie..."
            if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
            }
            if ((Get-PSRepository -Name 'PSGallery').InstallationPolicy -ne 'Trusted') {
                Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
            }
            Install-Module -Name GroupPolicyDSC -Repository PSGallery -Force -SkipPublisherCheck -AllowClobber -ErrorAction Stop
            Write-Success "Module 'GroupPolicyDSC' is succesvol geïnstalleerd."
        }
        Import-Module GroupPolicyDSC -Force -PassThru
        Write-Success "Alle benodigde PowerShell modules zijn geladen."
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
    if (-not (Get-DhcpServerv4Scope -ComputerName $HostName -ErrorAction SilentlyContinue)) {
        Add-DhcpServerv4Scope -ComputerName $HostName -Name "Scope-$StudentNummer" -StartRange "172.16.2.100" -EndRange "172.16.2.151" -SubnetMask $SubnetMask -State "Active"
        Set-DhcpServerv4OptionValue -ComputerName $HostName -ScopeId "172.16.2.0" -DnsServer $DNS1LAN -Router $IPLAN
        Set-DhcpServerv4Scope -ComputerName $HostName -ScopeId "172.16.2.0" -LeaseDuration (New-TimeSpan -Days 8)
        Write-Success "DHCP Scope aangemaakt en geconfigureerd."
    }
    Set-DhcpServerv4OptionValue -ComputerName $HostName -DnsDomain $DomainName -DnsServer $DNS1LAN -ErrorAction SilentlyContinue
    Set-DHCPServerv4DNSSetting -ComputerName $HostName -DynamicUpdates Always -DeleteDnsRROnLeaseExpiry $true -ErrorAction SilentlyContinue
    if ((Get-DhcpServerInDC -ErrorAction SilentlyContinue).DnsName -notcontains "$($HostName).$($DomainName)") {
        Add-DhcpServerInDC -DnsName "$($HostName).$($DomainName)" -IPAddress $IPLAN
        Write-Success "DHCP server geautoriseerd in Active Directory."
    }
    try {
        if (-not (Get-NetNat -Name "NAT-AVENTUS" -ErrorAction SilentlyContinue)) {
            Write-Status "Installeren en configureren van RRAS/NAT..."
            Install-WindowsFeature Routing -IncludeManagementTools
            New-NetNat -Name "NAT-AVENTUS" -InternalIPInterfaceAddressPrefix "172.16.2.0/24" | Out-Null
            Write-Success "RRAS/NAT is geconfigureerd."
        }
    } catch { Write-Error-Msg "Kon RRAS/NAT niet configureren. Fout: $($_.Exception.Message)" }

    # --- INRICHTING VOLGENS OPDRACHT 4 ---
    Write-Status "Start inrichting volgens Opdracht 4 (AGDLP, Shares, Permissies)..."
    $afdelingen = @("Directie", "Productie", "Staf", "Verkoop", "ITStaf")
    $basePath = "E:\"
    $userFoldersPath = Join-Path -Path $basePath -ChildPath "UserFolders"
    $afdelingsMappenPath = Join-Path -Path $basePath -ChildPath "Afdelingsmappen"
    $currentDomain = Get-ADDomain
    $currentDomainPath = $currentDomain.DistinguishedName
    $usersContainerPath = "CN=Users,$currentDomainPath"
    $afdelingenOuPath = "OU=Afdelingen,$currentDomainPath"

    # Mappen, Shares, OUs en Groepen
    $foldersToCreate = @($userFoldersPath, (Join-Path $basePath "UserProfiles"), $afdelingsMappenPath)
    $afdelingen | ForEach-Object { $foldersToCreate += Join-Path -Path $afdelingsMappenPath -ChildPath $_ }
    $foldersToCreate | ForEach-Object { if (-not (Test-Path $_)) { New-Item -Path $_ -ItemType Directory | Out-Null } }
    $sharesToCreate = @{ "UserFolders$" = $userFoldersPath; "UserProfiles$" = (Join-Path $basePath "UserProfiles"); "Afdelingsmappen$" = $afdelingsMappenPath }
    $sharesToCreate.GetEnumerator() | ForEach-Object { if (-not (Get-SmbShare -Name $_.Name -ErrorAction SilentlyContinue)) { New-SmbShare -Name $_.Name -Path $_.Value -FullAccess "Authenticated Users" | Out-Null } }
    Set-SmbShare -Name "Afdelingsmappen$" -FolderEnumerationMode AccessBased -Confirm:$false
    Write-Success "Mappen en shares voor Opdracht 4 zijn aangemaakt."

    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq 'Afdelingen'")) { New-ADOrganizationalUnit -Name "Afdelingen" -Path $currentDomainPath }
    foreach ($afdeling in $afdelingen) {
        if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$afdeling'" -SearchBase $afdelingenOuPath -ErrorAction SilentlyContinue)) { New-ADOrganizationalUnit -Name $afdeling -Path $afdelingenOuPath }
        $ggGroupName = "GG_$afdeling"
        if (-not (Get-ADGroup -Filter "Name -eq '$ggGroupName'")) { New-ADGroup -Name $ggGroupName -GroupCategory Security -GroupScope Global -Path "OU=$afdeling,$afdelingenOuPath" }
    }
    $dlGroups = @("DL_AfdelingsMappen_R")
    $afdelingen | ForEach-Object { $dlGroups += "DL_${_}_R"; $dlGroups += "DL_${_}_RW" }
    $dlGroups | ForEach-Object { if (-not (Get-ADGroup -Filter "Name -eq '$_'")) { New-ADGroup -Name $_ -GroupCategory Security -GroupScope DomainLocal -Path $usersContainerPath } }
    Write-Success "AGDLP OUs en Groepen zijn aangemaakt."

    # Group Nesting
    $afdelingen | ForEach-Object {
        Add-ADGroupMember -Identity "DL_${_}_RW" -Members "GG_$_" -ErrorAction SilentlyContinue
        Add-ADGroupMember -Identity "DL_AfdelingsMappen_R" -Members "GG_$_" -ErrorAction SilentlyContinue
    }
    Add-ADGroupMember -Identity "DL_Verkoop_R" -Members "GG_Staf" -ErrorAction SilentlyContinue
    Add-ADGroupMember -Identity "DL_Staf_R" -Members "GG_Verkoop" -ErrorAction SilentlyContinue
    Write-Success "Group nesting (AGDLP) is voltooid."

    # Gebruikers
    $gebruikers = @(
        [pscustomobject]@{ FirstName = "Madelief"; LastName = "Smets"; Title = "Algemeen Directeur"; Department = "Directie" },
        [pscustomobject]@{ FirstName = "Dick"; LastName = "Brinkman"; Title = "Adjunct Productie"; Department = "Productie" },
        [pscustomobject]@{ FirstName = "Doortje"; LastName = "Heijnen"; Title = "Productontwikkelaar"; Department = "Productie" },
        [pscustomobject]@{ FirstName = "Floris"; LastName = "Flipse"; Title = "Chef Onderhoud"; Department = "Productie" },
        [pscustomobject]@{ FirstName = "Floris"; LastName = "Willemsen"; Title = "CNC Frezer"; Department = "Productie" },
        [pscustomobject]@{ FirstName = "Herman"; LastName = "Bommel"; Title = "Inkoper/Magazijnbeheerder"; Department = "Productie" },
        [pscustomobject]@{ FirstName = "Niels"; LastName = "Smets"; Title = "Productcontroleur"; Department = "Productie" },
        [pscustomobject]@{ FirstName = "Peter"; LastName = "Caprieaux"; Title = "Hoofd Fabricage"; Department = "Productie" },
        [pscustomobject]@{ FirstName = "Will"; LastName = "Snellen"; Title = "Chef Werkplaats"; Department = "Productie" },
        [pscustomobject]@{ FirstName = "Danielle"; LastName = "Voss"; Title = "Hoofd Staf"; Department = "Staf" },
        [pscustomobject]@{ FirstName = "Dirk"; LastName = "Bogert"; Title = "Boekhouder"; Department = "Staf" },
        [pscustomobject]@{ FirstName = "Jolanda"; LastName = "Brands"; Title = "Adjunct Automatisering"; Department = "Staf" },
        [pscustomobject]@{ FirstName = "Karin"; LastName = "Visse"; Title = "Secretaresse"; Department = "Staf" },
        [pscustomobject]@{ FirstName = "Loes"; LastName = "Heijnen"; Title = "Receptioniste"; Department = "Staf" },
        [pscustomobject]@{ FirstName = "Teus"; LastName = "de Jong"; Title = "Adjunct Administratie"; Department = "Staf" },
        [pscustomobject]@{ FirstName = "Henk"; LastName = "Peil"; Title = "Adjunct Verkoop"; Department = "Verkoop" },
        [pscustomobject]@{ FirstName = "Wiel"; LastName = "Nouwen"; Title = "Accountmanager"; Department = "Verkoop" }
    )
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
            }
            $newUser = New-ADUser @userParams -PassThru
            Add-ADGroupMember -Identity "GG_$($gebruiker.Department)" -Members $newUser
            Write-Success "Gebruiker '$($newUser.Name)' aangemaakt."
        }
    }
    Write-Status "Voer de gegevens in voor de nieuwe IT Medewerker."
    do { $itVoornaam = Read-Host -Prompt "Voer de voornaam van de IT Medewerker in" } while ([string]::IsNullOrWhiteSpace($itVoornaam))
    do { $itAchternaam = Read-Host -Prompt "Voer de achternaam van de IT Medewerker in" } while ([string]::IsNullOrWhiteSpace($itAchternaam))
    $samAccountNameIT = ($itVoornaam[0] + $itAchternaam).ToLower()
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$samAccountNameIT'")) {
        $userParamsIT = @{
            Name                  = "$itVoornaam $itAchternaam"
            GivenName             = $itVoornaam
            Surname               = $itAchternaam
            SamAccountName        = $samAccountNameIT
            UserPrincipalName     = "$samAccountNameIT@$($currentDomain.DNSRoot)"
            Path                  = "OU=ITStaf,$afdelingenOuPath"
            Department            = "ITStaf"
            Title                 = "IT Medewerker"
            Enabled               = $true
            ChangePasswordAtLogon = $true
            AccountPassword       = (ConvertTo-SecureString 'Welkom123!' -AsPlainText -Force)
        }
        $newUserIT = New-ADUser @userParamsIT -PassThru
        Add-ADGroupMember -Identity "GG_ITStaf" -Members $newUserIT
        Write-Success "Gebruiker '$($newUserIT.Name)' aangemaakt."
    }

    # NTFS Permissies
    function Set-NTFSPermissions {
        param([string]$FolderPath, [array]$Permissions, [string]$NetBiosDomain)
        $acl = Get-Acl $FolderPath
        $acl.SetAccessRuleProtection($true, $false) # Disable inheritance
        foreach ($perm in $Permissions) {
            $accountName = if ($perm.Account -ne 'SYSTEM') { "$($NetBiosDomain)\$($perm.Account)" } else { 'SYSTEM' }
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($accountName, $perm.Rights, "ContainerInherit, ObjectInherit", "None", $perm.Type)
            $acl.AddAccessRule($rule)
        }
        Set-Acl -Path $FolderPath -AclObject $acl
    }
    $currentDomainNetBiosName = $currentDomain.NetBIOSName
    foreach ($afdeling in $afdelingen) {
        $folderPath = Join-Path $afdelingsMappenPath $afdeling
        $permissions = @(
            @{ Account = "Domain Admins"; Rights = "FullControl"; Type = "Allow" },
            @{ Account = "SYSTEM"; Rights = "FullControl"; Type = "Allow" },
            @{ Account = "DL_${afdeling}_RW"; Rights = "Modify"; Type = "Allow" },
            @{ Account = "DL_${afdeling}_R"; Rights = "ReadAndExecute"; Type = "Allow" }
        )
        if ($afdeling -eq "Verkoop") { $permissions += @{ Account = "DL_Staf_R"; Rights = "ReadAndExecute"; Type = "Allow" } }
        if ($afdeling -eq "Staf") { $permissions += @{ Account = "DL_Verkoop_R"; Rights = "ReadAndExecute"; Type = "Allow" } }
        Set-NTFSPermissions -FolderPath $folderPath -Permissions $permissions -NetBiosDomain $currentDomainNetBiosName
    }
    Write-Success "NTFS permissies zijn correct ingesteld voor alle afdelingsmappen."

    # --- GPO VOOR SNELKOPPELINGEN VIA GROUP POLICY PREFERENCES (GPP) ---
    Write-Status "Configureren van GPO met Group Policy Preferences voor snelkoppelingen..."
    try {
        Import-Module GroupPolicyDSC -Force
        $gpoName = "Snelkoppelingen Afdelingsmappen"
        $sharePath = "\\$($env:COMPUTERNAME)\Afdelingsmappen$"
        if (-not (Get-GPO -Name $gpoName -ErrorAction SilentlyContinue)) {
            Write-Status "GPO '$gpoName' bestaat niet, wordt aangemaakt..."
            $gpo = New-GPO -Name $gpoName -Comment "Plaatst automatisch een snelkoppeling naar de afdelingsmap via GPP."
            Set-GPPermissions -Name $gpo.DisplayName -PermissionLevel GpoRead -TargetName "Authenticated Users" -TargetType Group -ErrorAction SilentlyContinue
            Write-Success "Leesrechten voor 'Authenticated Users' op GPO '$gpoName' ingesteld."

            foreach ($afdeling in $afdelingen) {
                $groupName = "GG_$afdeling"
                $targetGroup = Get-ADGroup -Identity $groupName
                $shortcutName = "Mijn Afdelingsmap ($afdeling).lnk"
                $targetPath = Join-Path -Path $sharePath -ChildPath $afdeling
                Write-Status "   - Snelkoppeling voor afdeling '$afdeling' wordt toegevoegd aan GPO..."
                Set-GPPShortcut -Name $gpoName -Context User `
                    -Action Update -ShortcutFilePath "%DesktopDir%\$shortcutName" `
                    -TargetPath $targetPath `
                    -Description "Snelkoppeling naar de map voor $afdeling"
                Set-GPPItem -Name $gpoName -Context User -Type Shortcuts -Index -1 `
                    -Targeting (New-GPPrefTargeting -SecurityGroup -Name $targetGroup.Name -SID $targetGroup.SID)
            }
            $afdelingenOuObject = Get-ADOrganizationalUnit -Filter "Name -eq 'Afdelingen'"
            New-GPLink -Name $gpo.DisplayName -Target $afdelingenOuObject.DistinguishedName
            Write-Success "GPO '$gpoName' succesvol aangemaakt, geconfigureerd en gekoppeld aan OU 'Afdelingen'."
        } else {
            Write-Warning-Msg "GPO '$gpoName' bestaat al. Configuratie wordt overgeslagen."
        }
    } catch {
        Write-Error-Msg "Kon de GPO voor snelkoppelingen niet configureren. Fout: $($_.Exception.Message)"
    }
    
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