/*
  AIRA — Détection de packers et protecteurs
*/

rule UPX_Packed {
    meta:
        description = "Binaire compressé avec UPX"
        severity = "medium"
        tool = "UPX"
    strings:
        $h1 = "UPX0" ascii
        $h2 = "UPX1" ascii
        $h3 = "UPX2" ascii
        $h4 = "UPX!" ascii
        $s1 = "$Info: This file is packed with the UPX" ascii
        $s2 = "UPX loader" ascii nocase
    condition:
        2 of them
}

rule MPRESS_Packed {
    meta:
        description = "Binaire compressé avec MPRESS"
        severity = "medium"
        tool = "MPRESS"
    strings:
        $s1 = ".MPRESS1" ascii
        $s2 = ".MPRESS2" ascii
        $s3 = "MPRESS" ascii
    condition:
        any of them
}

rule ASPack_Packed {
    meta:
        description = "Binaire compressé avec ASPack"
        severity = "medium"
        tool = "ASPack"
    strings:
        $s1 = ".aspack" ascii
        $s2 = ".adata" ascii
        $h1 = { 60 E8 ?? ?? ?? ?? 5D 81 ED }  // ASPack stub pattern
    condition:
        ($s1 and $s2) or $h1
}

rule Themida_Protected {
    meta:
        description = "Binaire protégé avec Themida/WinLicense"
        severity = "high"
        tool = "Themida"
    strings:
        $s1 = ".winapi" ascii
        $s2 = "Themida" nocase ascii wide
        $s3 = "WinLicense" nocase ascii wide
        $s4 = "SOFTWARE\\Oreans Technologies" wide ascii
    condition:
        any of them
}

rule VMProtect_Protected {
    meta:
        description = "Binaire protégé avec VMProtect"
        severity = "high"
        tool = "VMProtect"
    strings:
        $s1 = ".vmp0" ascii
        $s2 = ".vmp1" ascii
        $s3 = "VMProtect" nocase ascii wide
        $h1 = { 9C 60 E8 00 00 00 00 }  // VMProtect stub
    condition:
        any of them
}

rule Enigma_Protector {
    meta:
        description = "Binaire protégé avec Enigma Protector"
        severity = "high"
    strings:
        $s1 = ".enigma1" ascii
        $s2 = ".enigma2" ascii
        $s3 = "Enigma Protector" nocase ascii wide
    condition:
        any of them
}

rule NSPack_Packed {
    meta:
        description = "Binaire compressé avec NSPack"
        severity = "medium"
        tool = "NSPack"
    strings:
        $s1 = ".nsp0" ascii
        $s2 = ".nsp1" ascii
        $s3 = ".nsp2" ascii
    condition:
        any of them
}

rule Petite_Packed {
    meta:
        description = "Binaire compressé avec Petite"
        severity = "medium"
    strings:
        $s1 = ".petite" ascii
    condition:
        $s1
}

rule Generic_Packer_Heuristic {
    meta:
        description = "Heuristique générique — peu d'imports + EP dans dernière section"
        severity = "medium"
    strings:
        $getprocaddr = "GetProcAddress" ascii wide
        $loadlib     = "LoadLibraryA" ascii wide
        $virtalalloc = "VirtualAlloc" ascii wide
    condition:
        ($getprocaddr and $loadlib and $virtalalloc) and
        (uint16(0) == 0x5A4D)
}

rule SFX_Archive {
    meta:
        description = "Archive auto-extractible (SFX)"
        severity = "low"
    strings:
        $s1 = "WinRAR SFX" nocase ascii wide
        $s2 = "7-Zip SFX" nocase ascii wide
        $s3 = "NSIS" nocase ascii wide
        $s4 = "Nullsoft Install System" nocase ascii wide
        $s5 = "InnoSetup" nocase ascii wide
        $s6 = "Inno Setup" nocase ascii wide
    condition:
        any of them
}
