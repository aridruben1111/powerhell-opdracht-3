<#
.SYNOPSIS
    Hulpfuncties voor het Aventus server installatiescript.
.DESCRIPTION
    Dit bestand bevat alle functies voor logging, het beheren van de
    automatische herstart-cyclus (AutoLogon, Scheduled Tasks),
    omgevingsvariabelen, en het afhandelen van de herstart.
.NOTES
    Auteur: Ruben
    Versie: 6.0
    Datum: 03-10-2025
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

#region Functies voor Logging en Feedback

function Write-Status { param([string]$Message); Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message); Write-Host "[+] $Message" -ForegroundColor Green }
function Write-Warning-Msg { param([string]$Message); Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Error-Msg { param([string]$Message); Write-Host "[-] $Message" -ForegroundColor Red }

#endregion