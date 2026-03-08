/*
  AIRA — Détection de constantes cryptographiques et patterns de chiffrement
*/

rule AES_SBox_Constants {
    meta:
        description = "S-Box AES détectée — implémentation AES custom probable"
        severity = "medium"
        algorithm = "AES"
    strings:
        // Début de la S-Box AES (16 premiers bytes)
        $sbox = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
        // Inverse S-Box AES
        $inv_sbox = { 52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB }
        // Constantes AES Rijndael
        $rcon = { 01 02 04 08 10 20 40 80 1B 36 }
    condition:
        any of them
}

rule RC4_KSA_Pattern {
    meta:
        description = "Pattern KSA RC4 — initialisation du tableau de 256 bytes"
        severity = "medium"
        algorithm = "RC4"
    strings:
        // KSA loop pattern (i = 0; i < 256)
        $ksa1 = { 31 C0 C6 04 05 00 00 00 00 40 3D 00 01 00 00 75 }
        $ksa2 = { 33 C9 88 0C 31 41 81 F9 00 01 00 00 }
        // S[256] initialization pattern
        $init = { B9 00 01 00 00 }   // mov ecx, 256
    condition:
        any of them
}

rule MD5_Constants {
    meta:
        description = "Constantes MD5 détectées"
        severity = "low"
        algorithm = "MD5"
    strings:
        // MD5 init constants: 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
        $c1 = { 01 23 45 67 }
        $c2 = { 89 AB CD EF }
        $c3 = { FE DC BA 98 }
        $c4 = { 76 54 32 10 }
    condition:
        all of them
}

rule SHA1_Constants {
    meta:
        description = "Constantes SHA-1 détectées"
        severity = "low"
        algorithm = "SHA-1"
    strings:
        // SHA-1 initial hash values
        $h0 = { 67 45 23 01 }
        $h1 = { EF CD AB 89 }
        $h2 = { 98 BA DC FE }
        $h3 = { 10 32 54 76 }
        $h4 = { C3 D2 E1 F0 }
        // SHA-1 constants K
        $k1 = { 5A 82 79 99 }
        $k2 = { 6E D9 EB A1 }
    condition:
        ($h0 and $h1 and $h2) or ($k1 and $k2)
}

rule SHA256_Constants {
    meta:
        description = "Constantes SHA-256 détectées"
        severity = "low"
        algorithm = "SHA-256"
    strings:
        // SHA-256 K constants (first 8)
        $k = { 98 2F 8A 42 91 44 37 71 CF FB C0 B5 A5 DB B5 E9 }
    condition:
        $k
}

rule CRC32_Table {
    meta:
        description = "Table CRC32 standard détectée"
        severity = "low"
        algorithm = "CRC32"
    strings:
        // Début de la table CRC32 standard
        $tbl = { 00 00 00 00 96 30 07 77 2C 61 0E EE BA 51 09 99 }
    condition:
        $tbl
}

rule XOR_Loop_Pattern {
    meta:
        description = "Boucle XOR — déchiffrement simple probable"
        severity = "medium"
        algorithm = "XOR"
    strings:
        // xor [reg+counter], key pattern
        $xor1 = { 30 ?? ?? }         // xor [reg+disp], reg8
        $xor2 = { 34 ?? ?? }         // xor al, imm
        $xor3 = { 80 3? ?? ?? }      // xor [mem], imm8
        // Common XOR decryption loop (dec + jnz)
        $loop = { 30 [1-4] 4? [0-2] 75 }
    condition:
        (#xor1 > 10) or (#xor2 > 5) or $loop
}

rule Base64_Custom_Alphabet {
    meta:
        description = "Alphabet Base64 (custom ou standard) — encodage présent"
        severity = "low"
    strings:
        $std  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ascii
        $url  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" ascii
    condition:
        any of them
}

rule Crypto_API_Suspicious {
    meta:
        description = "Utilisation combinée d'APIs de chiffrement Windows suspecte"
        severity = "high"
    strings:
        $a1 = "CryptEncrypt" ascii wide
        $a2 = "CryptDecrypt" ascii wide
        $a3 = "CryptGenRandom" ascii wide
        $a4 = "BCryptEncrypt" ascii wide
        $a5 = "BCryptDecrypt" ascii wide
        $a6 = "CryptAcquireContext" ascii wide
    condition:
        3 of them
}
