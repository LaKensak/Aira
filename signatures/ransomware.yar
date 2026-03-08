/*
    Détection de ransomware
    Chiffrement de fichiers, suppression de sauvegardes, note de rançon
*/

rule Ransomware_VSSDelete_Shadows
{
    meta:
        description = "Suppression des Volume Shadow Copies (VSS) — comportement ransomware"
        severity     = "critical"
    strings:
        $vss1 = "vssadmin" nocase ascii wide
        $vss2 = "delete shadows" nocase ascii wide
        $vss3 = "shadowcopy" nocase ascii wide
        $vss4 = "Shadow" ascii wide
        $wmic = "wmic" nocase ascii wide
        $bcde = "bcdedit" nocase ascii wide
        $rb1  = "/set {default} recoveryenabled No" nocase ascii wide
        $rb2  = "/set {default} bootstatuspolicy ignoreallfailures" nocase ascii wide
    condition:
        ($vss1 and $vss2) or
        ($wmic and $vss3) or
        ($bcde and ($rb1 or $rb2))
}

rule Ransomware_FileEncryption_APIs
{
    meta:
        description = "Combinaison d'APIs typique d'un ransomware — énumération + chiffrement"
        severity     = "critical"
    strings:
        $find1  = "FindFirstFileA" ascii
        $find2  = "FindFirstFileW" ascii
        $find3  = "FindNextFileA" ascii
        $find4  = "FindNextFileW" ascii
        $crypt1 = "CryptEncrypt" ascii
        $crypt2 = "CryptGenKey" ascii
        $crypt3 = "CryptAcquireContext" ascii
        $delete = "DeleteFileA" ascii
        $deletew= "DeleteFileW" ascii
        $rename = "MoveFileA" ascii
        $renamew= "MoveFileW" ascii
    condition:
        ($find1 or $find2) and ($find3 or $find4) and
        ($crypt1 or $crypt2) and
        ($delete or $deletew or $rename or $renamew)
}

rule Ransomware_NoteFiles
{
    meta:
        description = "Noms de fichiers note de rançon courants"
        severity     = "critical"
    strings:
        $note1 = "README.txt" nocase ascii wide
        $note2 = "HOW_TO_DECRYPT" nocase ascii wide
        $note3 = "DECRYPT_INSTRUCTIONS" nocase ascii wide
        $note4 = "YOUR_FILES_ARE_ENCRYPTED" nocase ascii wide
        $note5 = "RECOVER_FILES" nocase ascii wide
        $note6 = "ransom" nocase ascii wide
        $note7 = "bitcoin" nocase ascii wide
        $note8 = "BTC" ascii
        $note9 = "monero" nocase ascii wide
        $nota  = "tor" nocase ascii wide
        $notb  = ".onion" nocase ascii
    condition:
        2 of ($note1, $note2, $note3, $note4, $note5) or
        (($note6 or $note7 or $note8 or $note9) and ($nota or $notb))
}

rule Ransomware_DisableRecovery
{
    meta:
        description = "Désactivation des options de récupération Windows"
        severity     = "critical"
    strings:
        $r1 = "recoveryenabled" nocase ascii wide
        $r2 = "bootstatuspolicy" nocase ascii wide
        $r3 = "ignoreallfailures" nocase ascii wide
        $r4 = "wbadmin" nocase ascii wide
        $r5 = "delete catalog" nocase ascii wide
    condition:
        ($r1 and $r2) or ($r4 and $r5)
}

rule Ransomware_NetworkShares_Enum
{
    meta:
        description = "Énumération des partages réseau — ransomware ciblant les shares"
        severity     = "high"
    strings:
        $net1 = "NetShareEnum" ascii
        $net2 = "WNetOpenEnum" ascii
        $net3 = "WNetEnumResource" ascii
        $net4 = "\\\\" ascii wide
        $smb  = "\\\\*" ascii wide
    condition:
        ($net1 or $net2 or $net3) and ($net4 or $smb)
}

rule Ransomware_KnownFamilies
{
    meta:
        description = "Strings associées à des familles de ransomware connues"
        severity     = "critical"
    strings:
        $wannacry   = "WanaCrypt0r" ascii wide
        $ryuk       = "RyukReadMe" ascii wide
        $revil      = "randomext" ascii wide
        $conti      = "CONTI" ascii wide
        $lockbit    = "LockBit" ascii wide
        $blackcat   = "ALPHV" ascii wide
        $darkside   = "DarkSide" ascii wide
        $dharma     = ".dharma" ascii wide
        $phobos     = "Phobos" ascii wide
        $maze       = "MAZE" ascii wide
    condition:
        any of them
}

rule Ransomware_CryptoAPI_Key_Export
{
    meta:
        description = "Export de clé RSA/AES — chiffrement asymétrique ransomware"
        severity     = "high"
    strings:
        $rsa1 = "CryptExportKey" ascii
        $rsa2 = "CryptImportKey" ascii
        $rsa3 = "CALG_RSA_KEYX" ascii
        $aes1 = "CALG_AES_256" ascii
        $aes2 = "CALG_AES_128" ascii
        $bcrypt1 = "BCryptEncrypt" ascii
        $bcrypt2 = "BCryptGenerateSymmetricKey" ascii
    condition:
        ($rsa1 and $rsa2) or
        (($rsa1 or $rsa2) and ($aes1 or $aes2)) or
        ($bcrypt1 and $bcrypt2)
}
