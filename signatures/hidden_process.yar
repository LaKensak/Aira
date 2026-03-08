/*
    Détection de spawning de processus cachés / exécution silencieuse
    CREATE_NO_WINDOW, SW_HIDE, PowerShell encodé, LOLBins
*/

rule HiddenProcess_CreateNoWindow
{
    meta:
        description = "Constante CREATE_NO_WINDOW (0x08000000) — cache la fenêtre du processus fils"
        severity     = "high"
    strings:
        $cnw = { 00 00 00 08 }
    condition:
        $cnw
}

rule HiddenProcess_SwHide_Startupinfo
{
    meta:
        description = "STARTF_USESHOWWINDOW + SW_HIDE dans STARTUPINFO — fenêtre enfant cachée"
        severity     = "high"
    strings:
        $startf = { 01 00 00 00 00 00 }
    condition:
        $startf
}

rule HiddenProcess_DetachedProcess
{
    meta:
        description = "DETACHED_PROCESS (0x00000008) — processus sans console"
        severity     = "medium"
    strings:
        $detach = { 08 00 00 00 }
    condition:
        $detach
}

rule HiddenProcess_PowerShell_Encoded
{
    meta:
        description = "PowerShell avec commande encodée (-EncodedCommand/-enc)"
        severity     = "critical"
    strings:
        $enc1 = "-EncodedCommand" nocase ascii wide
        $enc2 = "-enc " nocase ascii wide
        $enc3 = "-e " nocase ascii wide
        $hidden = "-WindowStyle Hidden" nocase ascii wide
        $noprofile = "-NoProfile" nocase ascii wide
        $nop = "-nop " nocase ascii wide
    condition:
        ($enc1 or $enc2) or
        ($hidden and $noprofile) or
        ($nop and $hidden)
}

rule HiddenProcess_CmdSpawn_Suspicious
{
    meta:
        description = "Lancement CMD/PowerShell avec flags de dissimulation"
        severity     = "high"
    strings:
        $cmd     = "cmd.exe" nocase ascii wide
        $ps      = "powershell" nocase ascii wide
        $wscript = "wscript.exe" nocase ascii wide
        $mshta   = "mshta.exe" nocase ascii wide
        $create  = "CreateProcessA" ascii
        $createw = "CreateProcessW" ascii
        $pipe    = "CreatePipe" ascii
    condition:
        ($cmd or $ps or $wscript or $mshta) and
        ($create or $createw) and
        $pipe
}

rule HiddenProcess_WMI_Exec
{
    meta:
        description = "Exécution via WMI (Win32_Process.Create) — évite la détection"
        severity     = "high"
    strings:
        $wmi1 = "Win32_Process" ascii wide
        $wmi2 = "wmic.exe" nocase ascii wide
        $wmi3 = "WbemLocator" ascii wide
        $wmi4 = "IWbemServices" ascii wide
        $wmi5 = "ExecMethod" ascii wide
    condition:
        2 of them
}

rule HiddenProcess_PipeRedirection
{
    meta:
        description = "Redirection I/O via pipes + création processus — capture de sortie silencieuse"
        severity     = "high"
    strings:
        $pipe1  = "CreatePipe" ascii
        $pipe2  = "SetHandleInformation" ascii
        $pipe3  = "PeekNamedPipe" ascii
        $create = "CreateProcessA" ascii
        $createw= "CreateProcessW" ascii
        $read   = "ReadFile" ascii
    condition:
        ($pipe1 or $pipe3) and ($create or $createw) and $read
}
