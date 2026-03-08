import pefile, capstone, struct

pe = pefile.PE('F:/Nouveau dossier (10)/data/uploads/crackme.exe')
IMAGEBASE = pe.OPTIONAL_HEADER.ImageBase
print(f"ImageBase: 0x{IMAGEBASE:x}")
print(f"Entry: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint + IMAGEBASE:x}")

# Trouver les fonctions depuis les exports / symboles de debug
# Mais on n'a pas d'exports. On utilise les adresses trouvees dans les stabs.

# xor_encrypt est a 0x140001460
XOR_ENCRYPT_VA = 0x140001460

# Chercher main dans les stabs
with open('F:/Nouveau dossier (10)/data/uploads/crackme.exe', 'rb') as f:
    data = f.read()

# Parser les adresses depuis les stabs (section /19 ou similaire)
# On cherche le pattern d'une adresse 8 bytes suivie d'une taille 4 bytes pour 'main'
# From the symbols found: !main -> address

# Chercher toutes les adresses dans les stabs autour de 'main'
main_sym = b'\x06main\x00'
for idx in [data.find(main_sym)]:
    if idx == -1:
        continue
    # Regarder avant
    before = data[max(0,idx-20):idx]
    after = data[idx+len(main_sym):idx+len(main_sym)+20]
    print(f"\nAutour de 'main' @ 0x{idx:x}:")
    print(f"  before: {before.hex()}")
    print(f"  after:  {after.hex()}")

# Approche: chercher les 3 adresses successives dans la plage valide du binaire
# Scan des adresses 64-bit dans la plage 0x140001000-0x140003000
text_start = 0x140000600
text_end = 0x140002200

candidates = []
for i in range(0, len(data)-8, 4):
    val = struct.unpack_from('<Q', data, i)[0]
    if text_start <= val < text_end and val != XOR_ENCRYPT_VA:
        candidates.append((i, val))

print(f"\nAdresses dans la plage .text: {len(candidates)} candidats")
for file_off, addr in candidates[:20]:
    print(f"  file_off=0x{file_off:x} addr=0x{addr:x}")

# Desassembler xor_encrypt
def va_to_data(va, pe):
    for section in pe.sections:
        s_va = IMAGEBASE + section.VirtualAddress
        if s_va <= va < s_va + section.Misc_VirtualSize:
            off = va - s_va
            return section.get_data()[off:]
    return None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

print("\n=== xor_encrypt ===")
code = va_to_data(XOR_ENCRYPT_VA, pe)
if code:
    for i, insn in enumerate(md.disasm(code[:0x80], XOR_ENCRYPT_VA)):
        print(f"  0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
        if i > 30:
            break

# Chercher main: l'entrypoint appelle __tmainCRTStartup qui appelle main
# On cherche en partant de l'entrypoint
EP = pe.OPTIONAL_HEADER.AddressOfEntryPoint + IMAGEBASE
print(f"\n=== Entry point @ 0x{EP:x} ===")
code = va_to_data(EP, pe)
if code:
    for i, insn in enumerate(md.disasm(code[:0x200], EP)):
        print(f"  0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
        if i > 50:
            break
