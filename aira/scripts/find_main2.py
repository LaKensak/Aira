import pefile, capstone, struct

pe = pefile.PE('F:/Nouveau dossier (10)/data/uploads/crackme.exe')
IMAGEBASE = pe.OPTIONAL_HEADER.ImageBase
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

# Trouver les adresses IAT de fgets, strncmp, puts, MessageBoxA
iat_addrs = {}
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in entry.imports:
        if imp.name:
            name = imp.name.decode('ascii', errors='replace')
            if name in ('fgets', 'strncmp', 'puts', 'strlen', 'strcspn', 'MessageBoxA'):
                iat_addrs[name] = imp.address
                print(f"IAT {name}: 0x{imp.address:x}")

# La fonction main va appeler fgets et strncmp
# On cherche dans .text les CALL [mem] qui pointent vers ces IAT
def va_to_data(va, pe):
    for section in pe.sections:
        s_va = IMAGEBASE + section.VirtualAddress
        if s_va <= va < s_va + section.Misc_VirtualSize:
            off = va - s_va
            return section.get_data()[off:]
    return None

# Scanner .text pour des appels a fgets
text_sec = None
for section in pe.sections:
    if section.Name.rstrip(b'\x00') == b'.text':
        text_sec = section
        break

if not text_sec:
    print("Pas de .text!")
    exit()

text_va = IMAGEBASE + text_sec.VirtualAddress
text_data = text_sec.get_data()
print(f"\n.text: 0x{text_va:x}, taille={len(text_data)}")

# Trouver toutes les fonctions en cherchant les CALL QWORD PTR [RIP+x] qui matchent fgets/strncmp
# Pattern: FF 15 xx xx xx xx
fgets_iat = iat_addrs.get('fgets', 0)
strncmp_iat = iat_addrs.get('strncmp', 0)
msgbox_iat = iat_addrs.get('MessageBoxA', 0)

print(f"\nRecherche des fonctions appelant fgets (IAT: 0x{fgets_iat:x})...")

# Scanner avec capstone
all_insns = list(md.disasm(text_data, text_va))
print(f"Total instructions: {len(all_insns)}")

# Trouver les CALL qui ciblent fgets IAT
interesting_addrs = set()
for insn in all_insns:
    if insn.mnemonic == 'call' and insn.op_str.startswith('qword ptr [rip'):
        # Calculer l'adresse ciblee
        # FF 15 xx xx xx xx: addr = next_insn + offset
        next_va = insn.address + insn.size
        # L'offset est dans les bytes
        raw_off = insn.address - text_va
        rel = struct.unpack_from('<i', text_data, raw_off + 2)[0]
        target = next_va + rel
        for name, iat in iat_addrs.items():
            if target == iat:
                interesting_addrs.add(insn.address)
                print(f"  CALL {name} @ 0x{insn.address:x}")

# Trouver la fonction qui contient ces appels
# Remonter pour trouver le debut de la fonction
def find_func_start(va, all_insns, text_va):
    # Chercher le push rbp ou sub rsp precedant
    for i, insn in enumerate(all_insns):
        if insn.address == va:
            # Remonter
            j = i - 1
            while j >= 0:
                prev = all_insns[j]
                if prev.mnemonic in ('push', 'sub') and 'rsp' in prev.op_str:
                    if j > 0 and all_insns[j-1].mnemonic == 'push' and 'rbp' in all_insns[j-1].op_str:
                        return all_insns[j-1].address
                    return prev.address
                if prev.mnemonic == 'ret' or (prev.mnemonic == 'nop' and i - j > 10):
                    break
                j -= 1
            break
    return None

print("\n=== Fonctions candidates pour main ===")
checked = set()
for addr in interesting_addrs:
    start = find_func_start(addr, all_insns, text_va)
    if start and start not in checked:
        checked.add(start)
        print(f"\n--- Fonction @ 0x{start:x} ---")
        code = va_to_data(start, pe)
        if code:
            for i, insn in enumerate(md.disasm(code[:0x300], start)):
                line = f"  0x{insn.address:x}: {insn.mnemonic} {insn.op_str}"
                # Annoter les appels IAT connus
                if insn.mnemonic == 'call':
                    raw_off = insn.address - text_va
                    if insn.op_str.startswith('qword ptr [rip') and raw_off >= 0:
                        try:
                            rel = struct.unpack_from('<i', text_data, raw_off + 2)[0]
                            target = insn.address + insn.size + rel
                            for name, iat in iat_addrs.items():
                                if target == iat:
                                    line += f"  ; -> {name}"
                        except:
                            pass
                print(line)
                if insn.mnemonic == 'ret':
                    break
