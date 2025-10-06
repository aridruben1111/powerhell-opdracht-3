<#
.SYNOPSIS
    Hulpfuncties voor het Aventus server installatiescript.
.DESCRIPTION
    Dit bestand bevat alle functies voor logging, het beheren van de
    automatische herstart-cyclus (AutoLogon, Scheduled Tasks),
    omgevingsvariabelen, het afhandelen van de herstart en het instellen van permissies.
.NOTES
    Auteur: Ruben & Gemini
    Versie: 8.0 (Printer-installatie en Home Folders toegevoegd)
    Datum: 06-10-2025
#>

# =================================================================================
# --- HULPFUNCTIES ---
# =================================================================================

#region Functies voor AutoLogon en Herstarten

function Enable-AutoLogon {
    param(
        [Parameter(Mandatory=$true)][string]$UserName,
        [Parameter(Mandatory=$true)][string]$PlainTextPassword,
        [string]$DomainName = $env:COMPUTERNAME
    )

    Assert-AutologonBinary
    Write-Warning-Msg "AutoLogon wordt ingeschakeld voor gebruiker '$UserName'. Het wachtwoord wordt tijdelijk opgeslagen door autologon.exe."
    & $Autologon /accepteula $UserName $DomainName $PlainTextPassword | Out-Null
    Write-Success "AutoLogon is succesvol ingeschakeld."
}

function Disable-AutoLogon {
    Assert-AutologonBinary
    Write-Warning-Msg "AutoLogon wordt uitgeschakeld en het opgeslagen wachtwoord wordt verwijderd door autologon.exe."
    & $Autologon /accepteula /delete | Out-Null
    Write-Success "AutoLogon is veilig uitgeschakeld."
}

function Assert-AutologonBinary {
    if (-not (Test-Path $Autologon)) {
        Write-Warning-Msg "autologon.exe niet gevonden. Poging tot automatische download en extractie..."
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $zipUrl = "https://download.sysinternals.com/files/AutoLogon.zip"
            $zipPath = Join-Path $env:TEMP "AutoLogon.zip"
            $extractPath = Join-Path $env:TEMP "AutoLogon"

            Write-Status "   - Downloaden van $zipUrl..."
            Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing

            Write-Status "   - Uitpakken naar $extractPath..."
            Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

            Copy-Item -Path (Join-Path $extractPath "Autologon64.exe") -Destination $Autologon -Force
            Write-Success "autologon.exe succesvol gedownload en geplaatst in $ScriptDir."
        } catch {
            throw "Automatische download van autologon.exe is mislukt. Fout: $($_.Exception.Message). Download het handmatig van Sysinternals en plaats het in dezelfde map als het script."
        }
    }
}

function Restart-Server {
    param([string]$Reason)
    Write-Warning-Msg "$Reason De server wordt over 60 seconden herstart."
    Start-Sleep -Seconds 60
    Restart-Computer -Force
    # Het script stopt hier. Code na Restart-Computer wordt niet uitgevoerd.
}

#endregion

#region Functies voor Scheduled Tasks

function Register-ResumeTask {
    param(
        [Parameter(Mandatory=$true)][string]$UserFqn, # e.g., "COMPUTERNAME\Administrator" or "DOMAIN\Administrator"
        [Parameter(Mandatory=$true)][string]$PlainPwd
    )
    $action  = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $UserFqn
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -RunLevel Highest `
        -User $UserFqn -Password $PlainPwd -Force | Out-Null
    Write-Success "Hervattings-taak '$TaskName' geregistreerd voor gebruiker '$UserFqn'."
}

function Remove-ResumeTask {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Success "Hervattings-taak '$TaskName' verwijderd."
    }
}

#endregion

#region Functies voor Omgevingsvariabelen

function Get-Env { param([string]$Name,[string]$Target='Machine'); [Environment]::GetEnvironmentVariable($Name,$Target) }
function Set-Env { param([string]$Name,[string]$Value,[string]$Target='Machine'); [Environment]::SetEnvironmentVariable($Name,$Value,$Target) }
function Remove-Env { param([string]$Name,[string]$Target='Machine'); [Environment]::SetEnvironmentVariable($Name,$null,$Target) }

#endregion

#region Functies voor Logging, Permissies en Printer

function Write-Status { param([string]$Message); Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message); Write-Host "[+] $Message" -ForegroundColor Green }
function Write-Warning-Msg { param([string]$Message); Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Error-Msg { param([string]$Message); Write-Host "[-] $Message" -ForegroundColor Red }

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

function Install-PrinterServices {
    param(
        [string]$PrinterIP = "172.16.2.110",
        [string]$PrinterName = "HP Laserjet 300u",
        [string]$ShareName = "HP_Laserjet_300u",
        [string]$DriverName = "HP Universal Printing PCL 6"
    )

    Write-Status "Start installatie van printer '$PrinterName'..."
    if (Get-Printer -Name $PrinterName -ErrorAction SilentlyContinue) {
        Write-Warning-Msg "Printer '$PrinterName' is al geïnstalleerd. Stap wordt overgeslagen."
        return
    }

    try {
        # Stap 1: Download en pak de driver uit
        if (-not (Get-PrinterDriver -Name $DriverName -ErrorAction SilentlyContinue)) {
            Write-Status "Printer driver '$DriverName' niet gevonden. Start download..."
            $driverUrl = "https://ftp.hp.com/pub/softlib/software13/printers/UPD/upd-pcl6-x64-7.9.0.26347.zip"
            $zipPath = Join-Path $env:TEMP "HP_UPD_PCL6.zip"
            $extractPath = Join-Path $env:TEMP "HP_UPD_PCL6"

            Invoke-WebRequest -Uri $driverUrl -OutFile $zipPath
            Write-Success "Driver gedownload."

            Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
            Write-Success "Driver uitgepakt naar $extractPath."

            # Stap 2: Vind de .inf en installeer de driver
            $infFile = Get-ChildItem -Path $extractPath -Filter "*.inf" -Recurse | Select-Object -First 1
            if ($infFile) {
                # Haal de exacte drivernaam op uit het .inf bestand. Dit is robuuster.
                $driverInfo = Get-WindowsDriver -Path $infFile.FullName
                $actualDriverName = $driverInfo.Driver.Split(' ')[0] # Neem de eerste naam uit de lijst
                if (-not $actualDriverName) {
                    throw "Kon geen geldige drivernaam vinden in $($infFile.FullName)"
                }

                Write-Status "Driver .inf gevonden: $($infFile.FullName). Exacte naam: '$actualDriverName'. Installatie wordt gestart..."
                pnputil.exe /add-driver $infFile.FullName /install
                
                # De Add-PrinterDriver is niet meer nodig, pnputil /install doet dit al.
                # We gebruiken de dynamisch gevonden naam voor de rest van het proces.
                $DriverName = $actualDriverName
                Write-Success "Printer driver '$DriverName' succesvol geïnstalleerd via PnP."
            } else {
                throw "Kon het .inf-bestand niet vinden in de uitgepakte drivermap."
            }
        } else {
            Write-Warning-Msg "Printer driver '$DriverName' is al aanwezig."
        }

        # Stap 3: Maak de printerpoort aan
        $portName = "IP_$($PrinterIP)"
        if (-not (Get-PrinterPort -Name $portName -ErrorAction SilentlyContinue)) {
            Add-PrinterPort -Name $portName -PrinterHostAddress $PrinterIP
            Write-Success "Printerpoort '$portName' aangemaakt."
        } else {
            Write-Warning-Msg "Printerpoort '$portName' bestaat al."
        }

        # Stap 4: Installeer en deel de printer
        Add-Printer -Name $PrinterName -DriverName $DriverName -PortName $portName -Shared -ShareName $ShareName
        Write-Success "Printer '$PrinterName' is succesvol geïnstalleerd en gedeeld als '$ShareName'."

    } catch {
        Write-Error-Msg "Fout bij installeren van de printer: $($_.Exception.Message)"
    }
}

#endregion