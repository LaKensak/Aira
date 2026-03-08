rule Win32_IsDebuggerPresent_API {
    meta: desc = "Calls to IsDebuggerPresent"
    strings:
        $a = "IsDebuggerPresent" ascii wide
    condition:
        $a
}

rule Win32_CheckRemoteDebuggerPresent_API {
    strings:
        $a = "CheckRemoteDebuggerPresent" ascii wide
    condition:
        $a
}

rule PEB_BeingDebugged_Check {
    meta: desc = "PEB BeingDebugged flag access"
    strings:
        $a1 = { 64 A1 30 00 00 00 }  // mov eax, fs:[30h]
        $a2 = { 64 A1 18 00 00 00 }  // mov eax, fs:[18h] (TEB)
        $b1 = { 83 78 02 00 }        // cmp dword ptr [eax+2], 0
        $b2 = { 0F 94 C0 }          // sete al
    condition:
        any of ($a*) and any of ($b*)
}

rule NtGlobalFlag_Check {
    strings:
        $a = { 64 A1 30 00 00 00 } // PEB
        $b = { 0F B3 40 68 }       // bt dword ptr [eax+68h],
    condition:
        $a and $b
}

