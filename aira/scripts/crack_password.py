"""
Reconstruction du mot de passe a partir du desassemblage de main.

Stack layout:
  [rbp-0x16] = str1 (prompt "Password", XOR-encrypted, 8 bytes)
  [rbp-0x1b] = sfdwe (mot de passe attendu, XOR-encrypted, 4 bytes)
  [rbp-0x23] = buffer succes (encrypted)
  [rbp-0x2e] = buffer echec (encrypted)
  [rbp-0xd]  = key = 0x32

Logique de comparaison (0x140001635):
  al = sfdwe[i] ^ key
  compare user_input[i] avec al
  => l'utilisateur doit entrer: sfdwe[i] ^ 0x32
"""

KEY = 0x32
print(f"Cle XOR: 0x{KEY:02x} = '{chr(KEY)}'")

# --- str1 : "Password" (prompt affiché) ---
# movabs rax, 0x56405d4541415362
# storé little-endian à [rbp-0x16]
import struct
raw = struct.pack('<Q', 0x56405d4541415362)  # 8 bytes LE
str1_enc = list(raw)
str1_dec = bytes(b ^ KEY if b != 0x20 else b for b in str1_enc)
print(f"\nstr1 chiffre : {bytes(str1_enc).hex()} = {str1_enc}")
print(f"str1 dechiffre : {str1_dec}")

# --- sfdwe : mot de passe attendu ---
# mov dword [rbp-0x1b], 0x53425d58
raw2 = struct.pack('<I', 0x53425d58)  # 4 bytes LE
sfdwe_enc = list(raw2)
sfdwe_dec = bytes(b ^ KEY if b != 0x20 else b for b in sfdwe_enc)
print(f"\nsfdwe chiffre : {bytes(sfdwe_enc).hex()} = {sfdwe_enc}")
print(f"sfdwe dechiffre : {sfdwe_dec}")
print(f"\n==> MOT DE PASSE : '{sfdwe_dec.decode()}'")

# --- Message succes ---
raw3 = struct.pack('<Q', 0x575f5d515e5765)
succ_enc = list(raw3)
succ_dec = bytes(b ^ KEY if b != 0x20 else b for b in succ_enc)
print(f"\nSucces chiffre : {bytes(succ_enc).hex()}")
print(f"Succes dechiffre : {succ_dec}")

# --- Message echec ---
raw4 = struct.pack('<Q', 0x46465750204b4066)
# + overwrite last byte: dword 0x405746 at offset 6
raw4_list = list(raw4)
extra = struct.pack('<I', 0x405746)
raw4_list[6] = extra[0]  # overwrite [rbp-0x28]
raw4_list[7] = extra[1]  # overwrite [rbp-0x27]
# puis [rbp-0x26]=extra[2] et [rbp-0x25]=extra[3] mais hors du qword...
# En fait le dword ecrit a [rbp-0x27] qui est byte[7] du qword
# et deborde 3 bytes apres
fail_enc = raw4_list + [extra[2], extra[3], 0x00]
fail_dec = bytes(b ^ KEY if b != 0x20 else b for b in fail_enc)
print(f"\nEchec chiffre : {bytes(fail_enc).hex()}")
print(f"Echec dechiffre : {fail_dec}")
