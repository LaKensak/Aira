/*
    Détection de shellcode générique
    Patterns : GetPC, PEB walk, ROR13, egg hunters, NOP sleds, trampolines
*/

rule Shellcode_GetPC_CallPop
{
    meta:
        description = "GetPC via CALL $+5 / POP reg — shellcode self-location"
        severity     = "high"
    strings:
        $call_pop_eax = { E8 00 00 00 00 58 }
        $call_pop_ecx = { E8 00 00 00 00 59 }
        $call_pop_edx = { E8 00 00 00 00 5A }
        $call_pop_ebx = { E8 00 00 00 00 5B }
        $call_pop_esp = { E8 00 00 00 00 5C }
        $call_pop_ebp = { E8 00 00 00 00 5D }
        $call_pop_esi = { E8 00 00 00 00 5E }
        $call_pop_edi = { E8 00 00 00 00 5F }
    condition:
        any of them
}

rule Shellcode_GetPC_FPU
{
    meta:
        description = "FNSTENV trick pour obtenir l'EIP via FPU"
        severity     = "high"
    strings:
        $fnstenv = { D9 74 24 F4 }
        $fldz    = { D9 EE }
    condition:
        $fnstenv and $fldz
}

rule Shellcode_PEB_Walk_x86
{
    meta:
        description = "Accès direct au PEB x86 via FS:[30h] — résolution API sans IAT"
        severity     = "critical"
    strings:
        $peb_x86 = { 64 A1 30 00 00 00 }
    condition:
        $peb_x86
}

rule Shellcode_PEB_Walk_x64
{
    meta:
        description = "Accès direct au PEB x64 via GS:[60h] — résolution API sans IAT"
        severity     = "critical"
    strings:
        $peb_x64 = { 65 48 8B 04 25 60 00 00 00 }
    condition:
        $peb_x64
}

rule Shellcode_ROR13_API_Hashing
{
    meta:
        description = "Algorithme de hashing ROR13 — Cobalt Strike, Metasploit"
        severity     = "critical"
    strings:
        $ror13      = { C1 CF 0D 01 C7 }
        $ror13_alt  = { D1 CF 01 C7 }
        $ror13_add  = { C1 C8 0D }
    condition:
        any of them
}

rule Shellcode_EggHunter
{
    meta:
        description = "Egg hunter NtAccessCheckAndAuditAlarm — multi-stage shellcode"
        severity     = "critical"
    strings:
        $egg = { 66 81 CA FF 0F 42 52 6A 02 58 CD 2E 3C 05 5A 74 }
    condition:
        $egg
}

rule Shellcode_NOP_Sled
{
    meta:
        description = "NOP sled détecté — préparation pour shellcode/exploit"
        severity     = "medium"
    strings:
        $nop16 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
        $nop32 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90
                   90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
    condition:
        $nop32 or (2 of ($nop16))
}

rule Shellcode_Stack_Pivot
{
    meta:
        description = "JMP ESP / CALL ESP — gadgets d'exploitation stack overflow"
        severity     = "high"
    strings:
        $jmp_esp  = { FF E4 }
        $call_esp = { FF D4 }
        $push_ret = { FF 34 24 C3 }
    condition:
        (#jmp_esp + #call_esp) > 3 or $push_ret
}

rule Shellcode_WinExec_Hash
{
    meta:
        description = "Hash WinExec via ROR13 — exécution de commande depuis shellcode"
        severity     = "critical"
    strings:
        $winexec_hash      = { 98 FE 8A 0E }
        $exitprocess_hash  = { 56 A2 EB 73 }
        $virtualalloc_hash = { 91 7C A5 17 }
        $loadlibrary_hash  = { EC 0E 4E 8E }
    condition:
        2 of them
}
