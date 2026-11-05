<#
.SYNOPSIS
    Teste l'état de ports UDP : Ouvert, Fermé ou Ouvert|Filtré.
.DESCRIPTION
    Envoie un datagramme UDP et analyse la réponse. Une charge utile valide est
    fournie pour DNS (53), NTP (123) et SNMP (161). Pour les autres ports, le texte
    de -Message est envoyé, ou la charge utile hexadécimale de -PayloadHex.
.PARAMETER ComputerName
    Nom d'hôte ou adresse IP de la cible.
.PARAMETER Port
    Port(s) à tester : 53 | 53,123 | 5000-5010 | 53,6000-6005.
.PARAMETER PortSource
    Port source imposé (0 = port éphémère choisi par le système).
.PARAMETER TimeoutMs
    Délai d'attente d'une réponse, en millisecondes (défaut : 2000).
.PARAMETER Tentatives
    Nombre d'envois par port (défaut : 3).
.PARAMETER Message
    Texte envoyé sur les ports sans charge utile intégrée (défaut : "test").
.PARAMETER PayloadHex
    Charge utile personnalisée en hexadécimal, par exemple "1B 00 00".
.PARAMETER Aide
    Affiche l'aide du script.
.EXAMPLE
    .\Test-UdpPort.ps1 8.8.8.8 53
.EXAMPLE
    .\Test-UdpPort.ps1 192.168.1.1 53,123,161,5000-5010
.EXAMPLE
    .\Test-UdpPort.ps1 10.0.0.5 514 -PortSource 40000 -Message "<14>test"
.EXAMPLE
    .\Test-UdpPort.ps1 10.0.0.5 (Get-Random -Minimum 1024 -Maximum 65536)
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$ComputerName,
    [Parameter(Position = 1)][string[]]$Port,
    [ValidateRange(0, 65535)][int]$PortSource = 0,
    [ValidateRange(100, 30000)][int]$TimeoutMs = 2000,
    [ValidateRange(1, 10)][int]$Tentatives = 3,
    [string]$Message = "test",
    [string]$PayloadHex,
    [Alias('h', 'help')][switch]$Aide
)

function Show-Aide {
    $nom = Split-Path -Leaf $PSCommandPath
    Write-Host @"

NOM
    $nom - Teste l'état de ports UDP

SYNTAXE
    .\$nom <Hôte> <Ports> [-PortSource <int>] [-TimeoutMs <int>]
                          [-Tentatives <int>] [-Message <texte>]
                          [-PayloadHex "<octets>"] [-Aide]

PARAMÈTRES
    <Hôte>          Nom ou adresse IP de la cible
    <Ports>         53 | 53,123 | 5000-5010 | 53,6000-6005
    -PortSource     Port source imposé (défaut : 0 = automatique)
    -TimeoutMs      Attente d'une réponse en ms (défaut : 2000)
    -Tentatives     Nombre d'envois par port, 1 à 10 (défaut : 3)
    -Message        Texte envoyé hors DNS/NTP/SNMP (défaut : "test")
    -PayloadHex     Charge utile en hexadécimal, ex. "1B 00 00"
    -Aide, -h       Affiche cette aide

ÉTATS RETOURNÉS
    Ouvert          Une réponse a été reçue : le service fonctionne.
    Fermé           ICMP "port unreachable" reçu : hôte joignable, aucun service.
    Ouvert|Filtré   Aucune réponse : service muet ou paquet éliminé par un pare-feu.
    Erreur          Résolution DNS, port source occupé, etc. (voir Détail).

EXEMPLES
    .\$nom 8.8.8.8 53
    .\$nom 192.168.1.1 53,123,161,5000-5010
    .\$nom 10.0.0.5 514 -PortSource 40000 -Message "<14>test"
    .\$nom 10.0.0.5 (Get-Random -Minimum 1024 -Maximum 65536)

REMARQUES
    - Seuls 53, 123 et 161 ont une requête valide intégrée.
    - Sur une plage de ports filtrés, la durée est de l'ordre de
      Tentatives x TimeoutMs par port.
    - Aide complète : Get-Help .\$nom -Full

"@
}

if ($Aide -or -not $ComputerName -or -not $Port) {
    Show-Aide
    return
}

function Expand-Ports {
    param([string[]]$Spec)
    foreach ($s in $Spec) {
        foreach ($part in ($s -split ',')) {
            $part = $part.Trim()
            if (-not $part) { continue }
            if ($part -match '^(\d+)-(\d+)$') {
                $a = [int]$Matches[1]; $b = [int]$Matches[2]
                if ($a -lt 1 -or $b -gt 65535 -or $a -gt $b) { throw "Plage invalide : $part" }
                $a..$b
            }
            elseif ($part -match '^\d+$' -and [int]$part -ge 1 -and [int]$part -le 65535) {
                [int]$part
            }
            else { throw "Port invalide : $part" }
        }
    }
}

function Get-UdpPayload {
    param([int]$PortNumber)

    if ($PayloadHex) {
        return [byte[]]($PayloadHex -split '[\s,-]+' | Where-Object { $_ } |
            ForEach-Object { [Convert]::ToByte($_, 16) })
    }

    switch ($PortNumber) {
        53 {
            return [byte[]](0x12,0x34,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
                            0x07,0x65,0x78,0x61,0x6d,0x70,0x6c,0x65,0x03,0x63,0x6f,0x6d,0x00,
                            0x00,0x01,0x00,0x01)
        }
        123 {
            $ntp = New-Object byte[] 48
            $ntp[0] = 0x1B
            return $ntp
        }
        161 {
            return [byte[]](0x30,0x29,0x02,0x01,0x00,0x04,0x06,0x70,0x75,0x62,0x6c,0x69,0x63,
                            0xa0,0x1c,0x02,0x04,0x00,0x00,0x00,0x01,0x02,0x01,0x00,0x02,0x01,0x00,
                            0x30,0x0e,0x30,0x0c,0x06,0x08,0x2b,0x06,0x01,0x02,0x01,0x01,0x01,0x00,
                            0x05,0x00)
        }
        default { return [byte[]][System.Text.Encoding]::ASCII.GetBytes($Message) }
    }
}

function Test-UdpPort {
    param(
        [string]$Target,
        [int]$PortNumber,
        [int]$SourcePort,
        [byte[]]$Payload,
        [int]$TimeoutMs,
        [int]$Tentatives
    )

    $state  = 'Ouvert|Filtré'
    $detail = "Aucune réponse après $Tentatives tentative(s)"
    $client = $null

    try {
        $client = if ($SourcePort -gt 0) {
            New-Object System.Net.Sockets.UdpClient($SourcePort)
        } else {
            New-Object System.Net.Sockets.UdpClient
        }
        $client.Client.ReceiveTimeout = $TimeoutMs
        $client.Connect($Target, $PortNumber)
        $done = $false

        for ($i = 1; $i -le $Tentatives -and -not $done; $i++) {
            try {
                [void]$client.Send($Payload, $Payload.Length)
                $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                $null = $client.Receive([ref]$ep)
                $state  = 'Ouvert'
                $detail = "Réponse reçue de $($ep.Address)"
                $done   = $true
            }
            catch {
                $e = if ($_.Exception.InnerException) { $_.Exception.InnerException } else { $_.Exception }
                if ($e -is [System.Net.Sockets.SocketException]) {
                    if ($e.SocketErrorCode -eq 'ConnectionReset') {
                        $state  = 'Fermé'
                        $detail = 'ICMP port unreachable reçu'
                        $done   = $true
                    }
                    elseif ($e.SocketErrorCode -ne 'TimedOut') {
                        $state  = 'Erreur'
                        $detail = [string]$e.SocketErrorCode
                        $done   = $true
                    }
                }
                else {
                    $state  = 'Erreur'
                    $detail = $e.Message
                    $done   = $true
                }
            }
        }
    }
    catch {
        $e = if ($_.Exception.InnerException) { $_.Exception.InnerException } else { $_.Exception }
        $state  = 'Erreur'
        $detail = $e.Message
    }
    finally { if ($client) { $client.Close() } }

    [PSCustomObject]@{
        Hote       = $Target
        Port       = $PortNumber
        PortSource = if ($SourcePort -gt 0) { $SourcePort } else { 'auto' }
        Etat       = $state
        Detail     = $detail
    }
}

$ports = @(Expand-Ports -Spec $Port)
if ($ports.Count -gt 100) {
    Write-Warning "$($ports.Count) ports à tester : durée maximale estimée $([math]::Round($ports.Count * $Tentatives * $TimeoutMs / 60000, 1)) min."
}

foreach ($p in $ports) {
    $payload = Get-UdpPayload -PortNumber $p
    Test-UdpPort -Target $ComputerName -PortNumber $p -SourcePort $PortSource `
                 -Payload $payload -TimeoutMs $TimeoutMs -Tentatives $Tentatives
}
