/*
  AIRA — Détection techniques Anti-VM / Anti-Sandbox
*/

rule VMware_Artifacts {
    meta:
        description = "Références à des artefacts VMware (fichiers, registry, ports)"
        severity = "high"
    strings:
        $s1  = "vmware" nocase wide ascii
        $s2  = "VMware SVGA" nocase wide ascii
        $s3  = "vmtoolsd.exe" nocase wide ascii
        $s4  = "vmwaretray.exe" nocase wide ascii
        $s5  = "vmacthlp.exe" nocase wide ascii
        $s6  = "SOFTWARE\\VMware, Inc." wide ascii
        $s7  = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0" wide ascii
        $b1  = { 56 4D 57 61 72 65 }  // "VMWare"
        $io1 = { 66 BA 58 01 }         // mov dx, 0x158 — VMware backdoor port
        $io2 = { B8 58 4D 56 77 }      // mov eax, 0x564D5658 — "VMXh" magic
    condition:
        2 of them
}

rule VirtualBox_Artifacts {
    meta:
        description = "Références à des artefacts VirtualBox"
        severity = "high"
    strings:
        $s1 = "VirtualBox" nocase wide ascii
        $s2 = "VBoxService.exe" nocase wide ascii
        $s3 = "VBoxTray.exe" nocase wide ascii
        $s4 = "VBOX" nocase wide ascii
        $s5 = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" wide ascii
        $s6 = "\\\\.\\\\ VBoxGuest" wide ascii
        $s7 = "VBoxHook.dll" nocase wide ascii
        $s8 = "vboxdrv" nocase wide ascii
    condition:
        2 of them
}

rule Sandboxie_Detection {
    meta:
        description = "Tentative de détection de Sandboxie"
        severity = "medium"
    strings:
        $s1 = "SbieDll.dll" nocase wide ascii
        $s2 = "Sandboxie" nocase wide ascii
        $s3 = "SandboxieRpcSs" nocase wide ascii
        $s4 = "SBIE" wide ascii
    condition:
        any of them
}

rule Cuckoo_Sandbox_Detection {
    meta:
        description = "Tentative de détection de Cuckoo sandbox"
        severity = "medium"
    strings:
        $s1 = "cuckoomon.dll" nocase wide ascii
        $s2 = "cuckoo" nocase wide ascii
        $s3 = "analyzer.py" nocase ascii
        $s4 = "agent.py" nocase ascii
        $p1 = "\\\\.\\pipe\\cuckoo" wide ascii
    condition:
        any of them
}

rule RDTSC_Timing_Check {
    meta:
        description = "Utilisation de RDTSC pour timing anti-debug/anti-VM"
        severity = "medium"
    strings:
        $rdtsc = { 0F 31 }         // RDTSC instruction
        $cpuid = { 0F A2 }         // CPUID instruction
    condition:
        #rdtsc >= 2 or (#cpuid >= 3 and $rdtsc)
}

rule Low_Physical_Memory {
    meta:
        description = "Vérification de faible mémoire physique (sandbox detection)"
        severity = "low"
    strings:
        $api1 = "GlobalMemoryStatusEx" ascii wide
        $api2 = "GlobalMemoryStatus" ascii wide
        $str1 = "MemoryStatus" ascii wide
    condition:
        any of them
}

rule Wine_Detection {
    meta:
        description = "Détection de l'environnement Wine"
        severity = "medium"
    strings:
        $s1 = "wine_get_version" ascii
        $s2 = "HKLM\\Software\\Wine" wide ascii
        $s3 = "mscoree.dll" nocase ascii wide
        $dll = "kernel32.dll" nocase ascii wide
    condition:
        $s1 or $s2 or ($s3 and $dll)
}
