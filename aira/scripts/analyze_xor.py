import re, struct

with open('F:/Nouveau dossier (10)/data/uploads/crackme.exe', 'rb') as f:
    data = f.read()

# Trouver les strings suspects: sj76f, sfdwe
for target in [b'sj76f', b'sfdwe', b'password', b'access_granted']:
    idx = data.find(target)
    if idx != -1:
        ctx = data[max(0,idx-32):idx+64]
        print(f"[{target.decode()}] @ 0x{idx:x}")
        print(f"  hex: {ctx.hex()}")
        print(f"  repr: {repr(ctx)}")
        print()

# Chercher tous les octets autour de la signature xor_encrypt
xor_sym = b'xor_encrypt'
idx = data.find(xor_sym)
while idx != -1:
    ctx = data[max(0,idx-16):idx+32]
    print(f"[xor_encrypt sym] @ 0x{idx:x}: {repr(ctx)}")
    idx = data.find(xor_sym, idx+1)

# Chercher les strings entre 4 et 20 chars qui ne sont PAS des noms de fonctions/types
print("\n=== Strings courtes dans .rdata ou .data ===")
# Trouver la section .rdata
rdata_match = data.find(b'.rdata')
if rdata_match != -1:
    print(f".rdata name @ 0x{rdata_match:x}")
    # Lire le header de section (IMAGE_SECTION_HEADER = 40 bytes)
    # En fait, cherchons simplement des strings dans les données

# Approche directe: chercher toutes les strings de 4-16 chars
# qui ressemblent a des mots de passe (pas des noms de symboles typiques)
candidates = re.findall(rb'[A-Za-z0-9!@#$%^&*_\-]{4,20}', data)
seen = set()
avoid = {b'char', b'float', b'double', b'WORD', b'DWORD', b'BOOL', b'BYTE',
         b'LONG', b'VOID', b'NULL', b'TRUE', b'FALSE', b'FILE', b'UINT',
         b'main', b'exit', b'free', b'puts', b'fgets', b'malloc', b'calloc',
         b'abort', b'signal', b'sleep', b'Sleep', b'memcpy', b'strlen',
         b'printf', b'fprintf', b'fwrite', b'strncmp', b'strcspn'}
import string
for c in candidates:
    if c in seen or c in avoid:
        continue
    seen.add(c)
    # Garder seulement les strings qui ne ressemblent pas a des symboles courants
    if b'__' in c or b'imp' in c or b'crt' in c.lower():
        continue
    if len(c) >= 4 and len(c) <= 12:
        # Verifier que ce n'est pas un mot commun anglais / C
        if not any(c.lower().startswith(x) for x in [b'image', b'virtual', b'section', b'point', b'alloc',
                                                       b'reserved', b'version', b'minor', b'major']):
            print(repr(c.decode('ascii', errors='replace')))
