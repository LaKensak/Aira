/*
  AIRA — Détection de techniques d'injection de code
*/

rule Classic_DLL_Injection {
    meta:
        description = "Injection DLL classique (OpenProcess + WriteProcessMemory + CreateRemoteThread)"
        severity = "critical"
        technique = "T1055.001"
    strings:
        $a1 = "OpenProcess" ascii wide
        $a2 = "VirtualAllocEx" ascii wide
        $a3 = "WriteProcessMemory" ascii wide
        $a4 = "CreateRemoteThread" ascii wide
        $a5 = "LoadLibraryA" ascii wide
        $a6 = "LoadLibraryW" ascii wide
    condition:
        $a1 and $a2 and $a3 and ($a4 or $a5 or $a6)
}

rule Process_Hollowing {
    meta:
        description = "Process Hollowing (CREATE_SUSPENDED + NtUnmapViewOfSection)"
        severity = "critical"
        technique = "T1055.012"
    strings:
        $a1 = "CreateProcess" ascii wide
        $a2 = "NtUnmapViewOfSection" ascii wide
        $a3 = "ZwUnmapViewOfSection" ascii wide
        $a4 = "NtMapViewOfSection" ascii wide
        $a5 = "VirtualAllocEx" ascii wide
        $a6 = "WriteProcessMemory" ascii wide
        $a7 = "SetThreadContext" ascii wide
        $a8 = "ResumeThread" ascii wide
        // CREATE_SUSPENDED constant
        $c1 = { 04 00 00 00 }
    condition:
        $a1 and ($a2 or $a3) and ($a5 or $a6) and ($a7 or $a8)
}

rule APC_Injection {
    meta:
        description = "Injection via APC (Asynchronous Procedure Call)"
        severity = "critical"
        technique = "T1055.004"
    strings:
        $a1 = "QueueUserAPC" ascii wide
        $a2 = "NtQueueApcThread" ascii wide
        $a3 = "ZwQueueApcThread" ascii wide
        $a4 = "VirtualAllocEx" ascii wide
        $a5 = "WriteProcessMemory" ascii wide
        $a6 = "OpenThread" ascii wide
    condition:
        ($a1 or $a2 or $a3) and ($a4 or $a5)
}

rule Reflective_DLL_Injection {
    meta:
        description = "Injection DLL réflective — chargement en mémoire sans disk"
        severity = "critical"
        technique = "T1055.001"
    strings:
        $r1 = "ReflectiveDllInjection" nocase ascii wide
        $r2 = "ReflectiveLoader" ascii wide
        $r3 = "LoadRemoteLibraryR" ascii wide
        // Common reflective DLL pattern: VirtualAlloc + memcpy + callback
        $h1 = { 58 55 89 E5 60 FC }      // push eax; push ebp; ... typical stub
    condition:
        any of them
}

rule Shellcode_Injection_Pattern {
    meta:
        description = "Pattern shellcode — VirtualAlloc + memcpy + CreateThread"
        severity = "critical"
        technique = "T1059"
    strings:
        $a1 = "VirtualAlloc" ascii wide
        $a2 = "VirtualProtect" ascii wide
        $a3 = "CreateThread" ascii wide
        $a4 = "RtlMoveMemory" ascii wide
        $a5 = "memcpy" ascii wide
        $a6 = "FlushInstructionCache" ascii wide
    condition:
        ($a1 or $a2) and ($a3) and ($a4 or $a5 or $a6)
}

rule Thread_Hijacking {
    meta:
        description = "Détournement de thread (GetThreadContext + SetThreadContext)"
        severity = "critical"
        technique = "T1055.003"
    strings:
        $a1 = "GetThreadContext" ascii wide
        $a2 = "SetThreadContext" ascii wide
        $a3 = "SuspendThread" ascii wide
        $a4 = "ResumeThread" ascii wide
        $a5 = "OpenThread" ascii wide
        $a6 = "VirtualAllocEx" ascii wide
        $a7 = "WriteProcessMemory" ascii wide
    condition:
        $a1 and $a2 and ($a3 or $a5) and ($a6 or $a7)
}

rule COM_Hijacking {
    meta:
        description = "Potentiel COM hijacking / détournement COM"
        severity = "high"
        technique = "T1546.015"
    strings:
        $c1 = "CoCreateInstance" ascii wide
        $c2 = "CoInitialize" ascii wide
        $r1 = "CLSID" wide ascii
        $r2 = "InprocServer32" wide ascii
        $r3 = "RegSetValueEx" ascii wide
    condition:
        ($c1 and $r1 and $r2 and $r3)
}

rule Atom_Bombing {
    meta:
        description = "Atom Bombing injection technique"
        severity = "critical"
        technique = "T1055"
    strings:
        $a1 = "GlobalAddAtom" ascii wide
        $a2 = "NtQueueApcThread" ascii wide
        $a3 = "GlobalFindAtom" ascii wide
    condition:
        all of them
}

rule DLL_Search_Order_Hijacking {
    meta:
        description = "Possible DLL search order hijacking"
        severity = "high"
        technique = "T1574.001"
    strings:
        $a1 = "SetDllDirectoryA" ascii wide
        $a2 = "SetDllDirectoryW" ascii wide
        $a3 = "AddDllDirectory" ascii wide
    condition:
        any of them
}
