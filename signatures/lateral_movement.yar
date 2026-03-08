/*
    Détection de mouvement latéral
    Pass-the-Hash, PsExec, WMI, SMB, RDP, Token manipulation
*/

rule LateralMovement_PsExec
{
    meta:
        description = "PsExec ou pattern similaire d'exécution à distance"
        severity     = "critical"
    strings:
        $psexec1 = "PsExec" ascii wide
        $psexec2 = "psexec" nocase ascii wide
        $psexec3 = "PSEXESVC" ascii wide
        $ipc     = "\\IPC$" ascii wide
        $pipe    = "\\\\.\\pipe\\" ascii wide
        $admin   = "\\ADMIN$" ascii wide
    condition:
        $psexec1 or $psexec2 or $psexec3 or
        ($ipc and $admin and $pipe)
}

rule LateralMovement_WMI_Remote
{
    meta:
        description = "Exécution distante via WMI (mouvements latéraux)"
        severity     = "high"
    strings:
        $wmi1 = "Win32_Process" ascii wide
        $wmi2 = "WbemLocator" ascii wide
        $wmi3 = "IWbemServices" ascii wide
        $wmi4 = "ExecMethod" ascii
        $wmi5 = "ConnectServer" ascii
        $wmi6 = "\\\\.*\\root\\cimv2" ascii wide
    condition:
        ($wmi2 or $wmi3) and $wmi4 and $wmi5
}

rule LateralMovement_PassTheHash
{
    meta:
        description = "Pass-the-Hash — authentification NTLM avec hash"
        severity     = "critical"
    strings:
        $pth1 = "NtlmShared.dll" ascii wide
        $pth2 = "sekurlsa::pth" nocase ascii wide
        $pth3 = "LogonUser" ascii
        $pth4 = "CreateProcessWithLogonW" ascii
        $pth5 = "ImpersonateLoggedOnUser" ascii
        $ntlm = "NTLM" ascii wide
        $hash = "rc4_hmac" nocase ascii wide
    condition:
        ($pth2) or
        (($pth3 or $pth4) and $ntlm and ($pth5 or $hash))
}

rule LateralMovement_SCM_Remote
{
    meta:
        description = "Création de service à distance via SCM (mouvement latéral)"
        severity     = "critical"
    strings:
        $scm1 = "OpenSCManagerA" ascii
        $scm2 = "OpenSCManagerW" ascii
        $scm3 = "CreateServiceA" ascii
        $scm4 = "CreateServiceW" ascii
        $scm5 = "StartServiceA" ascii
        $scm6 = "StartServiceW" ascii
        $net   = "\\\\" ascii wide
    condition:
        ($scm1 or $scm2) and ($scm3 or $scm4) and ($scm5 or $scm6) and $net
}

rule LateralMovement_SMB_Lateral
{
    meta:
        description = "Utilisation de SMB pour mouvement latéral"
        severity     = "high"
    strings:
        $smb1 = "\\\\*\\ADMIN$" ascii wide
        $smb2 = "\\\\*\\C$" ascii wide
        $smb3 = "NetUseAdd" ascii
        $smb4 = "NetUseDel" ascii
        $smb5 = "\\IPC$" ascii wide
    condition:
        ($smb1 or $smb2) or ($smb3 and $smb4) or (2 of ($smb1, $smb2, $smb5))
}

rule LateralMovement_RDP_Enable
{
    meta:
        description = "Activation / exploitation RDP à distance"
        severity     = "high"
    strings:
        $rdp1 = "fDenyTSConnections" ascii wide
        $rdp2 = "Terminal Services" ascii wide
        $rdp3 = "Remote Desktop" ascii wide
        $rdp4 = "mstsc" nocase ascii wide
        $rdp5 = "\\\\TSCLIENT\\" ascii wide
        $reg  = "REG ADD" nocase ascii wide
    condition:
        ($rdp1 and $reg) or
        ($rdp5 and $rdp4) or
        ($rdp2 and $reg)
}

rule LateralMovement_TokenImpersonation
{
    meta:
        description = "Vol et impersonation de tokens — élévation de privilèges + mouvement latéral"
        severity     = "critical"
    strings:
        $tok1 = "ImpersonateLoggedOnUser" ascii
        $tok2 = "DuplicateTokenEx" ascii
        $tok3 = "SetThreadToken" ascii
        $tok4 = "CreateProcessWithTokenW" ascii
        $tok5 = "OpenProcessToken" ascii
        $tok6 = "AdjustTokenPrivileges" ascii
    condition:
        ($tok1 or $tok3 or $tok4) and ($tok2 or $tok5) and $tok6
}

rule LateralMovement_DCOM_Exec
{
    meta:
        description = "Exécution distante via DCOM — mouvement latéral silencieux"
        severity     = "high"
    strings:
        $dcom1 = "CoCreateInstanceEx" ascii
        $dcom2 = "IDispatch" ascii
        $dcom3 = "ShellWindows" ascii wide
        $dcom4 = "ShellBrowserWindow" ascii wide
        $dcom5 = "MMC20.Application" ascii wide
    condition:
        $dcom1 and ($dcom3 or $dcom4 or $dcom5)
}
