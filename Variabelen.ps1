<#
.SYNOPSIS
    Variabelen en gebruikersinvoer voor het Aventus server installatiescript.
.DESCRIPTION
    Dit bestand definieert alle statische variabelen (zoals hostnaam, IP-adres) en
    vraagt de gebruiker om dynamische invoer (studentnummer, wachtwoord). Het bevat
    ook de logica om de status te herstellen wanneer het script hervat na een herstart.
.NOTES
    Auteur: Ruben
    Versie: 6.0
    Datum: 03-10-2025
#>

# =================================================================================
# --- GEBRUIKERSINVOER EN VARIABELEN ---
# =================================================================================

#region Script Status en Herstel na Herstart

# Autologon/Resume Task specifieke variabelen
$ScriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$ScriptDir  = Split-Path -Parent $ScriptPath
$Autologon  = Join-Path $ScriptDir 'autologon.exe'
$TaskName   = 'AventusScriptResumeTask' # Unieke taaknaam voor dit script

$resumingStage = Get-Env 'CurrentScriptStage'
if ($resumingStage) {
    Clear-Host
    Write-Status "Script hervat na herstart. Huidige stage: $resumingStage."
    # Ruim autologon en de taak op
    Disable-AutoLogon
    Remove-ResumeTask

    # Haal de opgeslagen variabelen op
    $StudentNummer = Get-Env 'StudentNummer'
    $AdminPasswordPlainText = Get-Env 'AdminPasswordPlainText'
    $AdminPassword = ConvertTo-SecureString $AdminPasswordPlainText -AsPlainText -Force

    Write-Success "Autologon en hervattings-taak uitgeschakeld. Variabelen hersteld."
} else {
    Clear-Host
    Write-Status "Start van de serverconfiguratie. Beantwoord de volgende vragen."
    do {
        $StudentNummer = Read-Host -Prompt "Voer uw studentnummer in (bijv. 123456)"
    } while ([string]::IsNullOrWhiteSpace($StudentNummer))
    Set-Env 'StudentNummer' $StudentNummer

    $AdminPassword = Read-Host -Prompt "Voer het Administrator-wachtwoord in" -AsSecureString
    $AdminPasswordPlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AdminPassword))
    Set-Env 'AdminPasswordPlainText' $AdminPasswordPlainText
}

#endregion

#region Statische Variabelen

# Definieer de AutoLogon gebruiker voor de scheduled task (initieel de lokale administrator)
$AutoUser    = 'Administrator'
$AutoDomain  = $env:COMPUTERNAME
$AutoUserFqn = "$AutoDomain\$AutoUser"

# Server en Domein Configuratie
$HostName          = "DC$StudentNummer"
$DomainName        = "AventusRocks$StudentNummer.local"
$DomainNetBiosName = "AVENTUSROCKS"

# Netwerk Configuratie
$IPLAN        = "172.16.2.10"
$DNS1LAN      = "172.16.2.10"
$SubnetMask   = "255.255.255.0"
$PrefixLength = 24

# Systeem Configuratie
$TimeZone = "W. Europe Standard Time"

#endregion