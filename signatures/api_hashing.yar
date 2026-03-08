/*
    Détection d'API hashing — résolution d'APIs sans import table
    Techniques : ROR13, DJB2, PEB walk, GetProcAddress dynamique
*/

rule APIHashing_ROR13_PEBWalk
{
    meta:
        description = "Résolution d'API par ROR13 + PEB walk — shellcode/Cobalt Strike/Metasploit"
        severity     = "critical"
    strings:
        $ror13   = { C1 CF 0D }
        $peb_x86 = { 64 A1 30 00 00 00 }
        $peb_x64 = { 65 48 8B 04 25 60 00 00 00 }
    condition:
        $ror13 and ($peb_x86 or $peb_x64)
}

rule APIHashing_DJB2
{
    meta:
        description = "Algorithme DJB2 de hashing (hash = hash * 33 + c)"
        severity     = "high"
    strings:
        $djb2_mul = { 8D 04 40 }
        $djb2_shl = { C1 E0 05 }
        $peb_x86  = { 64 A1 30 00 00 00 }
    condition:
        ($djb2_mul or $djb2_shl) and $peb_x86
}

rule APIHashing_Dynamic_GetProcAddress
{
    meta:
        description = "Résolution dynamique d'API via GetProcAddress — évite l'IAT"
        severity     = "high"
    strings:
        $gpa1 = "GetProcAddress" ascii
        $gpa2 = "LoadLibraryA" ascii
        $gpa3 = "LoadLibraryW" ascii
        $gpa4 = "GetModuleHandleA" ascii
        $gpa5 = "GetModuleHandleW" ascii
    condition:
        $gpa1 and ($gpa2 or $gpa3) and ($gpa4 or $gpa5) and
        not for any i in (1..#gpa1) : (uint8(@gpa1[i] - 4) == 0xFF)
}

rule APIHashing_Reflective_DLL
{
    meta:
        description = "Reflective DLL Injection — chargement sans LoadLibrary"
        severity     = "critical"
    strings:
        $refl1 = "ReflectiveLoader" ascii
        $refl2 = "ReflectivDllInjection" ascii
        $refl3 = { 4D 5A 52 45 46 4C }
    condition:
        any of them
}

rule APIHashing_LdrLoadDll
{
    meta:
        description = "Appel direct LdrLoadDll (NTAPI) — évite l'import visible"
        severity     = "high"
    strings:
        $ldr1 = "LdrLoadDll" ascii
        $ldr2 = "LdrGetProcedureAddress" ascii
        $ldr3 = "LdrFindExportedRoutineByName" ascii
    condition:
        any of them
}

rule APIHashing_NoBlatantImport
{
    meta:
        description = "Binaire sans imports clés mais avec PEB walk — résolution d'API cachée"
        severity     = "critical"
    strings:
        $peb    = { 64 A1 30 00 00 00 }
        $ror13  = { C1 CF 0D }
        $nofunc = "VirtualAlloc" ascii
    condition:
        $peb and $ror13 and not $nofunc
}
