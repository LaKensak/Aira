/*
    Détection de credential dumping
    LSASS, SAM, NTDS.dit, Mimikatz, sekurlsa
*/

rule CredDump_Mimikatz_Strings
{
    meta:
        description = "Strings Mimikatz dans le binaire"
        severity     = "critical"
    strings:
        $m1 = "sekurlsa" nocase ascii wide
        $m2 = "kerberos" nocase ascii wide
        $m3 = "lsadump" nocase ascii wide
        $m4 = "mimikatz" nocase ascii wide
        $m5 = "mimilib" nocase ascii wide
        $m6 = "logonPasswords" nocase ascii wide
        $m7 = "wdigest" nocase ascii wide
        $m8 = "dpapi" nocase ascii wide
        $m9 = "gentilkiwi" nocase ascii wide
    condition:
        2 of them
}

rule CredDump_LSASS_Access
{
    meta:
        description = "Accès au processus LSASS — extraction de credentials"
        severity     = "critical"
    strings:
        $lsass1  = "lsass.exe" nocase ascii wide
        $lsass2  = "lsass" nocase ascii wide
        $openproc= "OpenProcess" ascii
        $minidump= "MiniDumpWriteDump" ascii
        $readmem = "ReadProcessMemory" ascii
        $ntdll   = "NtReadVirtualMemory" ascii
    condition:
        ($lsass1 or $lsass2) and
        ($minidump or $readmem or $ntdll or $openproc)
}

rule CredDump_SAM_Registry
{
    meta:
        description = "Dump de la base SAM via registre"
        severity     = "critical"
    strings:
        $sam1  = "\\SAM\\Domains\\Account" ascii wide
        $sam2  = "SAM\\Domains" ascii wide
        $sam3  = "SYSTEM\\CurrentControlSet\\Control\\Lsa" ascii wide
        $sam4  = "SECURITY" ascii wide
        $sam5  = "RegSaveKey" ascii
        $sam6  = "reg save" nocase ascii wide
        $sam7  = "HKLM\\SAM" nocase ascii wide
    condition:
        ($sam1 or $sam2 or $sam7) or
        ($sam5 and ($sam3 or $sam4)) or
        ($sam6 and $sam4)
}

rule CredDump_NTDS_Dit
{
    meta:
        description = "Accès à NTDS.dit (base Active Directory) — dump AD"
        severity     = "critical"
    strings:
        $ntds1 = "ntds.dit" nocase ascii wide
        $ntds2 = "NTDS.DIT" ascii
        $ntds3 = "ntdsutil" nocase ascii wide
        $ntds4 = "dc,snapshot" nocase ascii wide
        $vss   = "vssadmin" nocase ascii wide
    condition:
        $ntds1 or $ntds2 or $ntds3 or ($ntds4 and $vss)
}

rule CredDump_DCSync
{
    meta:
        description = "DCSync attack — réplication des credentials AD"
        severity     = "critical"
    strings:
        $dc1 = "DsGetDcName" ascii
        $dc2 = "DsReplicaGetInfo" ascii
        $dc3 = "IDL_DRSGetNCChanges" ascii
        $dc4 = "drsr.h" ascii
        $dc5 = "MS-DRSR" ascii wide
        $dc6 = "DRSBind" ascii
    condition:
        2 of them
}

rule CredDump_Browser_Credentials
{
    meta:
        description = "Vol de credentials stockés dans les navigateurs"
        severity     = "high"
    strings:
        $chrome1 = "Login Data" ascii wide
        $chrome2 = "\\Google\\Chrome\\User Data" nocase ascii wide
        $firefox1= "\\Mozilla\\Firefox\\Profiles" nocase ascii wide
        $firefox2= "key4.db" ascii wide
        $edge1   = "\\Microsoft\\Edge\\User Data" nocase ascii wide
        $dpapi   = "CryptUnprotectData" ascii
    condition:
        ($chrome1 or $chrome2 or $firefox1 or $firefox2 or $edge1) and $dpapi
}

rule CredDump_Procdump_LSASS
{
    meta:
        description = "Utilisation de procdump ou comsvcs.dll pour dumper LSASS"
        severity     = "critical"
    strings:
        $procdump = "procdump" nocase ascii wide
        $comsvcs  = "comsvcs.dll" nocase ascii wide
        $minidump = "MiniDump" nocase ascii wide
        $lsass    = "lsass" nocase ascii wide
        $full     = "full" nocase ascii wide
    condition:
        ($procdump and $lsass) or
        ($comsvcs and $minidump and $lsass) or
        ($comsvcs and $full)
}

rule CredDump_Kerberos_Tickets
{
    meta:
        description = "Vol / forgeage de tickets Kerberos (Golden Ticket, Pass-The-Ticket)"
        severity     = "critical"
    strings:
        $k1 = "LsaCallAuthenticationPackage" ascii
        $k2 = "KERB_SUBMIT_TKT_REQUEST" ascii
        $k3 = "KERB_RETRIEVE_TKT_REQUEST" ascii
        $k4 = "kerberos::golden" nocase ascii wide
        $k5 = "kerberos::ptt" nocase ascii wide
        $k6 = "KerbSubmitTicket" ascii
    condition:
        any of them
}
