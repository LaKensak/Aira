import re, struct

with open('F:/Nouveau dossier (10)/data/uploads/crackme.exe', 'rb') as f:
    data = f.read()

# Parser les sections PE pour trouver .text et .rdata
# MZ header -> PE offset
pe_offset = struct.unpack_from('<I', data, 0x3c)[0]
print(f"PE offset: 0x{pe_offset:x}")

# IMAGE_FILE_HEADER
machine = struct.unpack_from('<H', data, pe_offset + 4)[0]
num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
opt_header_size = struct.unpack_from('<H', data, pe_offset + 20)[0]
print(f"Sections: {num_sections}, OPT header size: {opt_header_size}")

# Sections start after PE sig (4) + FILE_HEADER (20) + OPT_HEADER
sections_offset = pe_offset + 4 + 20 + opt_header_size
sections = {}
for i in range(num_sections):
    s_off = sections_offset + i * 40
    name = data[s_off:s_off+8].rstrip(b'\x00').decode('ascii', errors='replace')
    vsize = struct.unpack_from('<I', data, s_off + 16)[0]
    vaddr = struct.unpack_from('<I', data, s_off + 20)[0]
    raw_size = struct.unpack_from('<I', data, s_off + 24)[0]
    raw_off = struct.unpack_from('<I', data, s_off + 28)[0]
    sections[name] = {'vaddr': vaddr, 'vsize': vsize, 'raw_off': raw_off, 'raw_size': raw_size}
    print(f"  {name}: VA=0x{vaddr:x}, size=0x{vsize:x}, file_off=0x{raw_off:x}")

IMAGEBASE = 0x140000000

def va_to_offset(va):
    rva = va - IMAGEBASE
    for name, s in sections.items():
        if s['vaddr'] <= rva < s['vaddr'] + s['vsize']:
            return s['raw_off'] + (rva - s['vaddr'])
    return None

# Trouver l'adresse de main et xor_encrypt depuis les symboles de debug
# Dans les stabs, on a trouve: _Z11xor_encryptPcci @ 0x140001460 (approximatif)
# Cherchons l'adresse exacte

# Recherche dans la section de symboles (stabs)
# Le contexte trouvait: `\x60\x14\x00@\x01\x00\x00\x00h\x00\x00\x00`
# = little-endian 64-bit: 0x140001460, suivi de 0x68 (taille)
# Cherchons ce pattern
xor_addr_pat = b'_Z11xor_encryptPcci\x00'
idx = data.find(xor_addr_pat)
if idx != -1:
    after = data[idx + len(xor_addr_pat):]
    print(f"\nApres _Z11xor_encryptPcci: {after[:16].hex()}")
    # Essayer de lire une adresse 64-bit
    addr = struct.unpack_from('<Q', after, 0)[0]
    size = struct.unpack_from('<I', after, 8)[0]
    print(f"  Adresse potentielle: 0x{addr:x}, taille: 0x{size:x}")

    xor_file_off = va_to_offset(addr)
    if xor_file_off:
        print(f"  File offset: 0x{xor_file_off:x}")
        xor_code = data[xor_file_off:xor_file_off+size]
        print(f"  Code xor_encrypt: {xor_code.hex()}")

# Chercher le main
main_pat = b'!main\x00'
idx = data.find(main_pat)
if idx != -1:
    after = data[idx + len(main_pat):]
    print(f"\nApres !main: {after[:16].hex()}")

# Regarder directement dans .text pour les appels a strncmp
# et les donnees qui precedent (le buffer chiffre + cle XOR)
text = sections.get('.text', {})
if text:
    text_data = data[text['raw_off']:text['raw_off']+text['raw_size']]
    print(f"\n.text: {len(text_data)} bytes @ file offset 0x{text['raw_off']:x}")

    # Chercher l'import strncmp dans les appels
    # strncmp est importe via IAT, on cherche CALL [rip+offset] pattern
    # Plus simplement: on cherche les octets du debut de main

# Chercher des patterns de push/mov avec des petites valeurs (cle XOR = 1 byte)
# Typiquement: mov dl, KEY; lea rcx, [encrypted_buf]; call xor_encrypt
# KEY est un byte entre 0x01 et 0x7f generalement
